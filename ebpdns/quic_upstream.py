"""QUIC 传输上游客户端：DoQ (RFC 9250, DNS over QUIC) 与 DoH3 (HTTP/3 DoH)。
- 可选依赖：aioquic（pip install aioquic）。未安装时该模块退化为不可用，
  相应 proto 的上游返回错误并给出日志提示，不影响 UDP/TCP/DoH/DoT 路径。
- 每个上游维护一个常驻 asyncio loop 线程 + 一条持久 QUIC 连接（断线自动重连），
  查询通过 run_coroutine_threadsafe 桥接到 loop，多查询在 QUIC 连接上多路复用。
- 同步接口供 upstream.py 调用：query(up, query_bytes, timeout_ms) -> (ok, data, lat_ms, err)。

v1.9.0 修复（长期运行 1.7G 内存泄漏 / 重连风暴）：
1. 退避不再在"连接建立"时立即复位：连接存活 <60s 即断开视为上游不稳定，
   退避继续指数递增(2s→60s 封顶)，遏制 2s 一次的无脑重连风暴。
2. 查询"业务失败"(超时/HTTP 非 200)不再主动关闭整个连接(连接可复用)；
   仅连续 3 次失败才触发重建，避免偶发超时导致重连风暴。
3. _H3Client._streams 只保存活动流：流结束后对端再发数据不再重建条目，
   消除流状态字典无限增长的内存泄漏。
"""
import asyncio
import logging
import gc
import ssl
import struct
import threading
import time
log = logging.getLogger("ebpdns.quic")
_HAVE_AIOQUIC = False
try:
    from aioquic.asyncio.client import connect
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.h3.connection import H3Connection
    from aioquic.h3.events import HeadersReceived, DataReceived
    from aioquic.quic.events import StreamDataReceived, StreamReset
    _HAVE_AIOQUIC = True
except Exception:  # pragma: no cover - 依赖缺失路径
    _HAVE_AIOQUIC = False
_MAX_MSG = 65535
_STABLE_SEC = 60.0      # 连接存活达到该秒数才视为"稳定"并复位退避(60s 内断开均视为不稳定)
_FAIL_RECONNECT = 3     # 连续查询失败达该次数才触发连接重建
def available():
    return _HAVE_AIOQUIC
def _host_port(up):
    addr = up.get("addr", "")
    port = int(up.get("port") or (853 if str(up.get("proto", "")).lower() == "doq" else 443))
    return addr, port
if _HAVE_AIOQUIC:
    class _H3Client(QuicConnectionProtocol):
        """HTTP/3 客户端：按 stream_id 收集响应头/体，支持并发多请求。
        只保存"活动流"状态: 查询结束即 pop, 对端对已结束流的后续数据
        一律忽略(不重建条目), 防止长期运行 _streams 无限增长。
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._http = H3Connection(self._quic)
            self._streams = {}   # sid -> {"status","body","done"}
        def quic_event_received(self, event):
            try:
                for he in self._http.handle_event(event):
                    sid = getattr(he, "stream_id", None)
                    if sid is None:
                        continue
                    st = self._streams.get(sid)
                    if st is None:
                        continue   # 流已结束/未知: 忽略, 不重建条目(防泄漏)
                    if isinstance(he, HeadersReceived):
                        for k, v in he.headers:
                            if k == b":status":
                                st["status"] = int(v)
                    elif isinstance(he, DataReceived):
                        # H4: 响应体累积上限 _MAX_MSG, 恶意上游持续推数据可 OOM。
                        # 未超限时按 room 截断追加; 已达上限则丢弃后续字节。
                        # 达到上限即 set done, 让 waiter 返回并由调用方按失败处理。
                        if len(st["body"]) < _MAX_MSG:
                            room = _MAX_MSG - len(st["body"])
                            st["body"] += he.data[:room]
                        if he.stream_ended or len(st["body"]) >= _MAX_MSG:
                            st["done"].set()
            except Exception:
                pass
    class _DoQClient(QuicConnectionProtocol):
        """DoQ 客户端：底层 QUIC 流收发 DNS 消息(2 字节长度前缀)。
        不使用 asyncio.create_stream()/StreamWriter——QUIC 连接断开/重连后
        残留 StreamWriter 在 __del__ 时对失效连接 send_stream_data 会抛
        ValueError 刷屏。这里直接管理流状态, 彻底规避该问题。
        """
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._doq = {}   # sid -> {"buf": bytearray, "n": int, "done": Event}
        def _new(self, sid):
            st = {"buf": bytearray(), "n": -1, "done": asyncio.Event()}
            self._doq[sid] = st
            return st
        def quic_event_received(self, event):
            try:
                if isinstance(event, StreamDataReceived):
                    st = self._doq.get(event.stream_id)
                    if st is None:
                        return
                    # H4: 流缓冲累积上限 _MAX_MSG, 超限丢弃后续字节并 set done,
                    # 由 _doq_exchange 按长度校验判定失败(防恶意上游 OOM)。
                    if len(st["buf"]) < _MAX_MSG:
                        room = _MAX_MSG - len(st["buf"])
                        st["buf"].extend(event.data[:room])
                    if event.end_stream:
                        if st["n"] < 0 and len(st["buf"]) >= 2:
                            st["n"] = struct.unpack(">H", bytes(st["buf"][:2]))[0]
                        st["done"].set()
                    elif len(st["buf"]) >= _MAX_MSG:
                        st["done"].set()
                elif isinstance(event, StreamReset):
                    st = self._doq.get(event.stream_id)
                    if st is not None:
                        st["done"].set()   # 触发查询超时路径
            except Exception:
                pass
class _QuicUpstream:
    """单个 doq/doh3 上游的常驻连接管理器。"""
    def __init__(self, up):
        self.up = up
        self.proto = str(up.get("proto", "")).lower()
        self.host, self.port = _host_port(up)
        self.path = str(up.get("url") or "/dns-query")
        if not self.path.startswith("/"):
            self.path = "/" + self.path
        self.alpn = "h3" if self.proto == "doh3" else "doq"
        self._loop = None
        self._thread = None
        self._protocol = None
        self._conn_ready = None
        self._conn_gen = 0  # 连接代数，断开后自增触发重建
        self._lock = threading.Lock()
        self._started = False
        self._closing = False  # 优雅退出标志: 置位后 _maintain 不再重连
        self._reconnect_flag = False  # 请求重建标志(连接级失败)
        self._conn_start = 0.0   # 当前连接建立时刻(用于稳定度判定)
        self.reconnects = 0      # 累计重连次数(诊断用)
        self.fail_seq = 0        # 连续查询失败计数(连接级)
    # ---- 线程与 loop ----
    def _ensure_started(self):
        if self._started:
            return
        with self._lock:
            if self._started:
                return
            self._loop = asyncio.new_event_loop()
            self._conn_ready = asyncio.Event()
            self._thread = threading.Thread(
                target=self._run_loop, name="quic-%s-%s" % (self.proto, self.host), daemon=True)
            self._started = True
            self._thread.start()
    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.set_exception_handler(self._loop_exc_handler)
        try:
            self._loop.run_until_complete(self._maintain())
        finally:
            # 无论 _maintain 正常返回还是被取消/抛异常(CancelledError/连接清理期
            # 未预期错误), 都必须关闭事件循环释放 fd/定时器, 否则重连或关闭路径
            # 上一次未收尾的 loop 会泄漏(虽为 daemon 线程, 但 loop 持有的
            # socket/timer 在进程退出前不释放)。
            try:
                self._loop.close()
            except Exception:
                pass

    @staticmethod
    def _loop_exc_handler(loop, context):
        """过滤 aioquic 连接关闭期的已知噪音, 其余走默认处理:
        1. 残留 timer 回调在 transport 已释放(None)后 transmit() 报
           'NoneType' object has no attribute 'sendto' —— 连接关闭的正常收尾噪音;
        2. 'call_exception_handler' None / 'Event loop is closed' —— loop 清理期噪音。
        """
        try:
            msg = str(context.get("exception") or context.get("message") or "")
        except Exception:
            msg = ""
        if "sendto" in msg and "NoneType" in msg:
            return
        if "call_exception_handler" in msg or "Event loop is closed" in msg:
            return
        loop.default_exception_handler(context)
    async def _maintain(self):
        """持久连接维护：连接存活期间挂住，断开后重连。
        - 指数退避 2s→60s 封顶, 避免无脑重连刷屏与风暴。
        - 关键: 退避只在"连接稳定存活 >=60s"(_STABLE_SEC)后复位。若上游不稳定
          (连接建立后 60s 内即断开), 退避持续递增到 60s, 防止重连风暴。
        - 连接成功/失败次数统计供诊断; 连续失败降为 DEBUG 日志。
        """
        backoff = 2.0
        fail_seq = 0
        while True:
            if self._closing:
                return
            try:
                conf = QuicConfiguration(is_client=True, alpn_protocols=[self.alpn],
                                         idle_timeout=60)  # 60s 空闲再断开, 减少频繁重连
                # 启用默认证书校验(不覆盖 verify_mode); server_name 由下方设置
                if self.host:
                    conf.server_name = self.host
                async with connect(self.host, self.port, configuration=conf,
                                   create_protocol=_H3Client if self.proto == "doh3" else _DoQClient) as proto:
                    self._conn_start = time.monotonic()
                    fail_seq = 0
                    log.info("QUIC %s/%s 连接建立", self.proto, self.host)
                    self._protocol = proto
                    self._conn_gen += 1
                    self.reconnects += 1
                    self._conn_ready.set()
                    # 保持打开直至: 连接终止 / transport 关闭 / 请求重建
                    while (proto._quic._close_event is None
                           and not proto._transport.is_closing()
                           and not self._reconnect_flag):
                        await asyncio.sleep(0.3)
                    if self._closing:
                        return
            except Exception as e:
                fail_seq += 1
                msg = str(e)
                # loop 清理期 transport 回调噪音(连接正常关闭时偶尔出现), 不视为真实失败
                if "call_exception_handler" in msg or "Event loop is closed" in msg:
                    log.debug("QUIC %s/%s 连接清理: %s", self.proto, self.host, msg)
                elif fail_seq <= 3:
                    # %r 显示异常类型: aioquic 连接失败的 str(e) 常为空字符串,
                    # 用 %s 时日志"连接失败:"后无任何详情, 无法排错(如 ConnectionRefused)
                    log.warning("QUIC %s/%s 连接失败: %r", self.proto, self.host, e)
                else:
                    log.debug("QUIC %s/%s 连续失败 %d 次, 退避重连中", self.proto, self.host, fail_seq)
            self._protocol = None
            self._conn_ready.clear()
            self._reconnect_flag = False
            # 稳定度判定(关键): backoff 只在"连接稳定存活 >=_STABLE_SEC"后复位。
            # 上游不稳定(连接建立后短时间即断开)时退避持续指数递增到 60s 封顶,
            # 从根本上遏制无脑重连风暴。
            alive = time.monotonic() - self._conn_start
            if alive >= _STABLE_SEC:
                backoff = 2.0
            else:
                backoff = min(backoff * 2, 60.0)
            # 连接对象存在循环引用(aioquic protocol<->quic<->http),
            # 主动 GC 确保重连后旧连接对象被回收, 防止长期累积
            if backoff >= 16.0:
                gc.collect()
            await asyncio.sleep(backoff)
    def _request_reconnect(self):
        """连接级失败触发: 置位重建标志并关闭 transport, 让 _maintain 检测并重建。"""
        with self._lock:
            self._reconnect_flag = True
            proto = self._protocol
            if proto is not None:
                try:
                    tr = getattr(proto, "_transport", None)
                    if tr is not None and not tr.is_closing():
                        tr.close()
                except Exception:
                    pass

    def close(self):
        """优雅关闭: 置位退出标志并唤醒维护循环, 释放线程/事件循环/连接对象。
        供上游删除时回收常驻 QUIC 管理器(防 _pool 残留连接与线程)。"""
        self._closing = True
        self._request_reconnect()
        # 线程为 daemon, 维护循环检测到 _closing 后自行退出并关闭 loop

    # ---- 同步查询入口 ----
    def query(self, query_bytes, timeout_ms):
        if not _HAVE_AIOQUIC:
            return False, None, timeout_ms, "aioquic 未安装 (pip install aioquic)"
        self._ensure_started()
        t0 = time.monotonic()
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._exchange(query_bytes, timeout_ms / 1000.0), self._loop)
            ok, data = fut.result(timeout_ms / 1000.0 + 0.5)
            lat = int((time.monotonic() - t0) * 1000)
            return ok, data, lat, (None if ok else "query failed")
        except asyncio.TimeoutError:
            # 关键: 取消悬挂在 loop 上的协程——否则超时后协程仍持有旧连接
            # proto 引用, 重连多次后旧连接对象无法被 GC, 长期累积成内存泄漏
            try:
                fut.cancel()
            except Exception:
                pass
            return False, None, int((time.monotonic() - t0) * 1000), "timeout"
        except Exception as e:
            return False, None, int((time.monotonic() - t0) * 1000), str(e)
    async def _exchange(self, query, timeout):
        """单次查询。返回 (ok, data)。
        连接级失败(未就绪/已关闭)才触发重建; 业务失败(超时/非200)不关连接,
        连续 _FAIL_RECONNECT 次业务失败才触发重建(防死连接长期阻塞)。
        """
        try:
            await asyncio.wait_for(self._conn_ready.wait(), timeout)
        except asyncio.TimeoutError:
            return False, None
        proto = self._protocol
        if proto is None or proto._quic._close_event is not None:
            # 连接已失效: 触发重建
            self._request_reconnect()
            return False, None
        try:
            if self.proto == "doq":
                ok, data = await self._doq_exchange(proto, query, timeout)
            else:
                ok, data = await self._doh3_exchange(proto, query, timeout)
        except Exception:
            ok, data = False, None
        if not ok:
            self.fail_seq += 1
            if self.fail_seq >= _FAIL_RECONNECT:
                # 连续多次失败: 连接可能已死, 触发重建(若连接实际正常会立刻恢复)
                self.fail_seq = 0
                self._request_reconnect()
        else:
            self.fail_seq = 0
        return ok, data
    async def _doq_exchange(self, proto, query, timeout):
        # 底层 QUIC 双向流: 2 字节长度前缀 + DNS 消息, 不用 asyncio StreamWriter
        sid = proto._quic.get_next_available_stream_id()
        st = proto._new(sid)
        try:
            proto._quic.send_stream_data(
                sid, struct.pack(">H", len(query)) + query, end_stream=True)
            proto.transmit()
            try:
                await asyncio.wait_for(st["done"].wait(), timeout)
            except asyncio.TimeoutError:
                return False, None
            if st["n"] < 0 or st["n"] > _MAX_MSG:
                return False, None
            body = bytes(st["buf"])
            if len(body) < 2 + st["n"]:
                return False, None
            return True, body[2:2 + st["n"]]
        finally:
            proto._doq.pop(sid, None)
    async def _doh3_exchange(self, proto, query, timeout):
        sid = proto._quic.get_next_available_stream_id()
        proto._streams[sid] = {"status": 0, "body": b"", "done": asyncio.Event()}
        proto._http.send_headers(sid, [
            (b":method", b"POST"), (b":scheme", b"https"),
            (b":authority", ("%s:%d" % (self.host, self.port)).encode()),
            (b":path", self.path.encode()),
            (b"content-type", b"application/dns-message"),
            (b"accept", b"application/dns-message"),
        ])
        proto._http.send_data(sid, query, end_stream=True)
        proto.transmit()
        st = proto._streams[sid]
        try:
            try:
                await asyncio.wait_for(st["done"].wait(), timeout)
            except asyncio.TimeoutError:
                return False, None
            if st["status"] != 200 or not st["body"]:
                return False, None
            return True, st["body"]
        finally:
            # 查询结束即清理该 stream 状态, 防止长期运行 _streams 无限增长(内存泄漏)
            try:
                proto._streams.pop(sid, None)
            except Exception:
                pass
_pool = {}
_pool_lock = threading.Lock()
def get_quic_upstream(up):
    """按 (proto, host, port, path) 复用常驻连接管理器。
    key 含 path: 同一 host:port 不同 DoH3 路径(如 NextDNS /4d5525 vs /dns-query)
    必须独立连接管理器, 否则连接会发到错误路径。"""
    proto = str(up.get("proto", "")).lower()
    host, port = _host_port(up)
    path = str(up.get("url") or "/dns-query")
    if not path.startswith("/"):
        path = "/" + path
    key = (proto, host, port, path)
    with _pool_lock:
        u = _pool.get(key)
        if u is None:
            u = _QuicUpstream(up)
            _pool[key] = u
        return u
def query_doq(up, query_bytes, timeout_ms=1500):
    return get_quic_upstream(up).query(query_bytes, timeout_ms)
def query_doh3(up, query_bytes, timeout_ms=1500):
    return get_quic_upstream(up).query(query_bytes, timeout_ms)
def stats():
    """QUIC 连接诊断: 各上游当前状态(供控制台/API)。"""
    with _pool_lock:
        return [
            {"proto": u.proto, "host": u.host, "port": u.port, "path": u.path,
             "connected": u._protocol is not None and u._conn_ready is not None and u._conn_ready.is_set(),
             "reconnects": u.reconnects, "fail_seq": u.fail_seq}
            for u in _pool.values()
        ]

def discard_upstream(up):
    """删除上游时回收常驻 QUIC 连接管理器(释放线程/事件循环/连接对象),
    防止 _pool 中残留已删除上游的连接对象造成内存/线程泄漏。"""
    proto = str(up.get("proto", "")).lower()
    host, port = _host_port(up)
    path = str(up.get("url") or "/dns-query")
    if not path.startswith("/"):
        path = "/" + path
    key = (proto, host, port, path)
    with _pool_lock:
        u = _pool.pop(key, None)
    if u is not None:
        try:
            u.close()
        except Exception:
            pass
