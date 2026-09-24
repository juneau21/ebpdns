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
import concurrent.futures as _cf
import logging
import gc
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
    # R5 P3-2: 处理 IPv6 字面量 [v6]:port 格式, 与 upstream._host_port 对齐。
    # 原实现直接返回带方括号的 addr, 传入 aioquic connect() 及 conf.server_name
    # 作为 SNI 时, 带方括号的 SNI 在 TLS 中是非法的, 会导致连接失败或证书校验异常。
    if addr.startswith("["):
        idx = addr.find("]")
        return addr[1:idx], port
    return addr, port
def _is_conn_closed(proto):
    """P3-LOW: 防御性判断 QUIC 连接是否已关闭, 替代直接访问 aioquic 私有属性
    proto._quic._close_event。aioquic 版本升级可能重命名/移除该私有属性, 直接
    访问会 AttributeError 穿透保活循环/查询路径。这里用 getattr 逐层防御,
    任一私有层缺失即视为"无法确认关闭"(返回 False), 由后续
    transport.is_closing()/超时/异常兜底, 安全方向不退化。"""
    quic = getattr(proto, '_quic', None)
    if quic is None:
        return False
    return getattr(quic, '_close_event', None) is not None
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
                # R32 P3-1: 与 _DoQClient 对称——aioquic H3Connection.handle_event
                # 对 StreamReset 直接返回空列表, 若不单独处理, 对端 RESET_STREAM 时
                # st["done"] 永不置位, 查询将悬挂到完整超时(默认 1500ms)才失败。
                # 这里找到对应 stream 立即 set done, 让 _doh3_exchange 快速失败
                # (status 仍为 0 / body 为空 → return False, None)。
                if isinstance(event, StreamReset):
                    st = self._streams.get(event.stream_id)
                    if st is not None:
                        # R33 P2-1: 对端在部分响应后 RESET_STREAM 时, 必须标记
                        # truncated=True, 否则 _doh3_exchange 的校验链
                        # (status==200 / body 非空 / truncated=False) 会全部通过,
                        # 把残缺 DNS 报文当作成功响应上交。与 DoQ(n<=0 拒绝)、
                        # 明文 DoH(IncompleteRead 异常拒绝) 路径对齐。
                        # R34 P3-2: 更正时序表述。asyncio.Event.set() 经 call_soon 异步
                        # 唤醒, 并不在本调用栈内同步恢复协程; aioquic 在一个报文批次内
                        # 连续 drain 全部事件(不 yield)。若 DataReceived(stream_ended) 与
                        # StreamReset 在同一批次连到, DataReceived 分支已 set done 但
                        # 协程尚未恢复、_streams 尚未 pop, 本分支 _streams.get(sid) 仍
                        # 返回条目 → 会把完整合法响应也标 truncated。此窄窗口触发前提是
                        # 服务器对同一流同时发 FIN 与 RESET(QUIC/HTTP3 语义异常), 行为
                        # 为保守失败到备用上游(安全方向, 不返回残缺/伪造数据), 故不改
                        # 代码。若未来观测到合规上游在此处偶发误拒, 可加守卫: 仅在
                        # done 未置位时才置 truncated。
                        st["truncated"] = True
                        st["done"].set()
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
                                # R38 P3-2: 畸形/非数字 :status 头(中间设备篡改/对端
                                # 协议错位)会让 int(v) 抛 ValueError, 被外层 except
                                # Exception 以 debug 吞掉, 但 st["done"] 未置位 →
                                # waiter(_doh3_exchange) 白等完整 timeout(默认 1500ms)
                                # 才失败。这里快速失败: 置 status=-1 并 set done,
                                # 与 StreamReset/truncated 快速失败路径一致, 由
                                # _doh3_exchange 的 status==200 校验链立即拒绝。
                                # 安全中性(失败方向, 不上交残缺/伪造数据), 仅省等待。
                                try:
                                    st["status"] = int(v)
                                except ValueError:
                                    st["status"] = -1
                                    st["done"].set()
                            elif k == b"content-type":
                                # P2-21: 记录响应 Content-Type, 供 _doh3_exchange
                                # 校验是否为 application/dns-message(RFC 8484/9250)。
                                try:
                                    st["content-type"] = v.decode("ascii", "replace")
                                except Exception:
                                    st["content-type"] = ""
                    elif isinstance(he, DataReceived):
                        # H4: 响应体累积上限 _MAX_MSG, 恶意上游持续推数据可 OOM。
                        # 未超限时按 room 截断追加; 已达上限则丢弃后续字节。
                        # 达到上限即 set done, 让 waiter 返回并由调用方按失败处理。
                        # v1.9.84 QUIC-03: 用 bytearray 替代 bytes, 避免每帧 O(n) 拷贝。
                        if len(st["body"]) < _MAX_MSG:
                            room = _MAX_MSG - len(st["body"])
                            if len(he.data) > room:
                                # v1.9.84-r2: 本帧超出 room 的字节被丢弃 → 响应确被截断。
                                # 即使本帧 stream_ended=True(单帧超大响应), 也必须标记,
                                # 否则残缺 body 会被当作有效响应返回(QUIC-02 的边界遗漏)。
                                st["truncated"] = True
                            st["body"].extend(he.data[:room])
                        else:
                            # 已满, 且本帧仍带数据 → 这些字节被丢弃 → 截断。
                            # 注意: 空帧(仅 stream_ended 收尾)不视为截断, 避免把恰好
                            # 65535B 的合法完整响应误判为截断。
                            if len(he.data) > 0:
                                st["truncated"] = True
                        # v1.9.84 QUIC-02: 流正常结束, 或因超限截断, 都 set done。
                        # truncated 仅在确有字节被丢弃时置位, 调用方据此按失败处理。
                        if he.stream_ended or st["truncated"]:
                            st["done"].set()
            # R17 P3-3: 事件处理器异常不再静默吞掉。H3 事件高频触发, 用 debug 级别
            # 记录, 便于排查对端异常帧/协议状态错位, 不影响热路径。
            except Exception as e:
                log.debug("DoH3 H3 event handler error: %r", e)
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
                    # H4: 流缓冲累积上限 = 2 字节长度前缀 + _MAX_MSG 报文 = 65537,
                    # 与 upstream.py TCP/DoT 路径(65535+2)对齐; 超限丢弃后续字节
                    # 并 set done, 由 _doq_exchange 按长度校验判定失败(防 OOM)。
                    if len(st["buf"]) < _MAX_MSG + 2:
                        room = _MAX_MSG + 2 - len(st["buf"])
                        st["buf"].extend(event.data[:room])
                    if event.end_stream:
                        if st["n"] < 0 and len(st["buf"]) >= 2:
                            st["n"] = struct.unpack(">H", bytes(st["buf"][:2]))[0]
                        st["done"].set()
                    elif len(st["buf"]) >= _MAX_MSG + 2:
                        st["done"].set()
                elif isinstance(event, StreamReset):
                    st = self._doq.get(event.stream_id)
                    if st is not None:
                        st["done"].set()   # 触发查询超时路径
            # R17 P3-3: 事件处理器异常不再静默吞掉。QUIC 流事件高频触发, 用 debug
            # 级别记录, 便于排查对端异常重置/乱序, 不影响热路径。
            except Exception as e:
                log.debug("DoQ event handler error: %r", e)
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
        # 连接代数, 断开后自增触发重建。当前仅作诊断/观测字段保留(连接重建计数),
        # 不在热路径读取 —— 保留以备后续按代数驱逐旧连接的诊断用途, 不删除。
        self._conn_gen = 0
        self._lock = threading.Lock()
        self._started = False
        self._closing = False  # 优雅退出标志: 置位后 _maintain 不再重连
        self._reconnect_flag = False  # 请求重建标志(连接级失败)
        self._conn_start = 0.0   # 当前连接建立时刻(用于稳定度判定)
        self._ever_connected = False  # v1.9.76: 是否曾成功建连(首次连接失败也参与退避递增)
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
            # R17 P3-1: 仅在 thread.start() 成功后才置 _started=True。
            # 若 start() 抛异常(如资源耗尽), _started 保持 False, 下次调用重试;
            # 避免 _started=True 但线程未启动的不一致状态。
            # R24 P3-2: thread.start() 极端失败时, _run_loop 从未执行, 其 finally
            # 中的 loop.close() 不会触发, 已创建的 event loop 无引用泄漏(fd/timer 不释放),
            # 下次重试又会新建一个。此处显式关闭 loop 并重置 _loop/_thread/_started,
            # 保证下次 _ensure_started 干净重建。
            try:
                self._thread.start()
            except Exception:
                try:
                    self._loop.close()
                except Exception:
                    pass
                self._loop = None
                self._thread = None
                self._conn_ready = None
                self._started = False
                raise
            self._started = True
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
            # R8 P2-2: 标记本次迭代是否已成功建连。仅建连阶段(connect/handshake)
            # 失败才说明 bootstrap IP 可能已坏需 invalidate; 连接建立后进入保活
            # while 循环, 传输阶段网络抖动导致的异常不应判定 bootstrap IP 已坏。
            # 连接成功后断开会经 async with 正常退出走重连(不进本 except), 故本
            # except 内的异常原则上都在建连阶段。该标志用于防御性收紧: 万一保活
            # 期异常(如 transport 回调抛错)穿透到这里, 也不会误 invalidate 好 IP。
            established = False
            try:
                conf = QuicConfiguration(is_client=True, alpn_protocols=[self.alpn],
                                         idle_timeout=60)  # 60s 空闲再断开, 减少频繁重连
                # 启用默认证书校验(不覆盖 verify_mode); server_name 由下方设置
                if self.host:
                    conf.server_name = self.host
                # 复用 bootstrap 预解析的 IP 直连(与 DoH/DoT 同源), 彻底摆脱
                # 系统 getaddrinfo 依赖; conf.server_name 仍为原始 hostname,
                # SNI 与证书名校验不受影响。
                # R8 P3-6: 已知权衡 —— 当 bootstrap 缓存未命中/已失效时
                # connect_host 回退为 self.host(hostname), aioquic 内部的
                # getaddrinfo 在事件循环线程中执行, 不受 upstream.py 的
                # _DNS_RESOLVE_POOL 线程池硬截断保护。这是 aioquic 异步栈的
                # 固有限制(其 connect() 内部用 loop.getaddrinfo 或阻塞解析),
                # 无法在不侵入 aioquic 的前提下套用同步线程池超时。实际影响有限:
                # 该路径仅在 bootstrap 缓存完全冷启动/失效后触发一次, 且
                # conf.server_name 已固定 hostname 不重复解析; 热路径命中
                # bootstrap 缓存 IP 直连不受影响。
                connect_host = self.host
                try:
                    from .upstream import _bootstrap_ip
                    bip = _bootstrap_ip(self.host)
                    if bip and bip != self.host:
                        connect_host = bip
                except Exception:
                    pass
                async with connect(connect_host, self.port, configuration=conf,
                                   create_protocol=_H3Client if self.proto == "doh3" else _DoQClient) as proto:
                    established = True  # R8 P2-2: 建连成功, 此后异常属传输阶段
                    self._conn_start = time.monotonic()
                    self._ever_connected = True
                    fail_seq = 0
                    log.info("QUIC %s/%s 连接建立", self.proto, self.host)
                    self._protocol = proto
                    self._conn_gen += 1
                    self.reconnects += 1
                    self._conn_ready.set()
                    # 保持打开直至: 连接终止 / transport 关闭 / 请求重建
                    while (not _is_conn_closed(proto)
                           and not (getattr(proto, "_transport", None) and proto._transport.is_closing())
                           and not self._reconnect_flag):
                        await asyncio.sleep(0.3)
                    if self._closing:
                        return
            except Exception as e:
                # R7 P1-2: 经 bootstrap IP 直连失败(CDN 迁移/IP 变更)时, 失效 bootstrap
                # 缓存, 与 DoH/DoT 路径对等。否则旧 IP 钉住最长 _BOOTSTRAP_TTL=600s。
                # R8 P2-2: 收紧为"仅建连阶段失败"才 invalidate。established=False 表示
                # connect/handshake 尚未完成, bootstrap IP 可能已坏; established=True
                # 表示已建连成功(异常来自传输期网络抖动), 不应误删好 IP。
                # 用 try 守卫: connect_host 在 try 内赋值, 若异常发生在其赋值之前
                # (理论上极罕见), 引用 NameError 被兜住不影响主失败流程。
                try:
                    if not established and connect_host != self.host:
                        from .upstream import _bootstrap_invalidate
                        _bootstrap_invalidate(self.host)
                except Exception:
                    pass
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
            # P3-19: clear 后不主动唤醒等待者(_conn_ready.wait() 的查询需等自身超时)。
            # 这是合理折中——重连通常很快成功, 成功后 _conn_ready.set() 会让等待者
            # 自动走新连接; 仅当重连退避较长时查询才需等超时(可接受, 避免在退避
            # 期间反复唤醒查询空转)。
            self._conn_ready.clear()
            self._reconnect_flag = False
            # 稳定度判定(关键): backoff 只在"连接稳定存活 >=_STABLE_SEC"后复位。
            # 上游不稳定(连接建立后短时间即断开)时退避持续指数递增到 60s 封顶,
            # 从根本上遏制无脑重连风暴。
            alive = time.monotonic() - self._conn_start
            # v1.9.76: 仅当曾成功建连且稳定存活 >=_STABLE_SEC 才复位退避。
            # 首次连接失败(_ever_connected=False)时旧逻辑 alive≈进程 uptime 巨大,
            # 误判"稳定"把 backoff 复位成 2s, 持续连接失败时 2s 一次无脑重连。
            if self._ever_connected and alive >= _STABLE_SEC:
                backoff = 2.0
            else:
                backoff = min(backoff * 2, 60.0)
            # 连接对象存在循环引用(aioquic protocol<->quic<->http),
            # 主动 GC 确保重连后旧连接对象被回收, 防止长期累积。
            # v1.9.84 QUIC-05: 先 sleep 再 GC, 避免在事件循环上同步阻塞
            # (gc.collect 可能耗时数十~数百 ms, 影响已排队查询)。
            # P3-20: 拆分退避睡眠为 1s 间隔, 快速响应 _closing 关闭信号。
            # 原实现一次 await asyncio.sleep(backoff) 最长 60s, close() 后维护
            # 线程最多 60s 才检测到 _closing 退出; 拆为 1s 片后最多 1s 内响应,
            # close() 的 join(timeout=2.0) 才能及时等到线程退出。
            sleep_end = time.monotonic() + backoff
            while time.monotonic() < sleep_end and not self._closing:
                await asyncio.sleep(min(1.0, sleep_end - time.monotonic()))
            if backoff >= 16.0:
                # UP-LOW-02: gc.collect 可能耗时数十~数百 ms, 在事件循环线程同步
                # 执行会阻塞已排队查询。放到独立 daemon 线程异步回收, 不阻塞事件循环。
                threading.Thread(target=gc.collect, daemon=True).start()
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
        # P2-2: _closing/_reconnect_flag/_protocol 跨线程读写。GIL 下单次赋值原子,
        # 但 loop 线程可能正阻塞在 asyncio.sleep(0.3)/backoff 中, 看不到新置的 _closing。
        # 通过 call_soon_threadsafe 向 loop 投递一个 no-op 回调, 触发其 thread-safe
        # wakeup(self-pipe), 使其从 poll/sleep 提前返回并尽快检测 _closing 退出。
        # loop 可能为 None(close 早于 _ensure_started) 或已在 _run_loop finally 中关闭,
        # 故加守卫与 try/except。
        _loop = self._loop
        if _loop is not None:
            try:
                _loop.call_soon_threadsafe(lambda: None)
            except Exception:
                pass
        # v1.9.84-r2 QUIC-08: 短暂等待维护线程退出(通常在 0.3s 轮询窗口内检测到
        # _closing 即退出); 若正处于 backoff 睡眠(最长 60s)则 join 超时返回,
        # 线程随后自行退出。缩短删除后新旧 _QuicUpstream 并存的窗口。
        t = self._thread
        if t is not None and t.is_alive():
            try:
                t.join(timeout=2.0)
            except Exception:
                pass
        # 线程为 daemon, 维护循环检测到 _closing 后自行退出并关闭 loop

    # ---- 同步查询入口 ----
    def query(self, query_bytes, timeout_ms):
        # P3-8(第八轮): close() 与在途 query() 竞态致假性超时。已关闭的上游立即
        # 返回失败, 不再 fut.result() 等待超时。
        if self._closing:
            return False, None, 0, "upstream closed"
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
        except (asyncio.TimeoutError, _cf.TimeoutError):
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
        v1.9.84 QUIC-01: 用累计 deadline 替代两次独立 timeout, 避免 conn_ready
        等待消耗大部分预算后 stream 等待被外层 fut.result() 过早 cancel。
        P3-06(R2): deadline 用 time.monotonic() 而非 self._loop.time(), 与外层
        query()(同样用 time.monotonic 计时 + fut.result 兜底)同源。两者在 Unix 上
        通常同为 CLOCK_MONOTONIC, 但统一时钟后不再依赖 loop 默认时钟与单调时钟恰好
        相等的隐式耦合, 跨平台/自定义 loop 时钟也不会错位。
        R3-N4: 注意 asyncio.wait_for(..., timeout) 内部仍基于 loop.time() 度量自身
        timeout, 而非 time.monotonic()。这是 asyncio 框架限制——wait_for 不接受外部
        deadline, 只能传一个相对秒数, 其计时锚点是 loop 时钟。在 Unix 默认事件循环下
        loop.time() 即 CLOCK_MONOTONIC, 与 time.monotonic() 同源, 行为正确; 仅在
        自定义 loop 时钟(loop.time() 被覆写为非单调时钟)或非 Unix 平台存在理论错位。
        此处 remain 已按 monotonic 预算折算为相对秒数再传入 wait_for, 外层 fut.result
        (query() 中, time.monotonic 兜底) 是最终硬超时, 即使 wait_for 内部时钟错位也
        有外层兜底, 不构成实际 bug。
        """
        deadline = time.monotonic() + timeout
        try:
            await asyncio.wait_for(self._conn_ready.wait(), timeout)
        except (asyncio.TimeoutError, _cf.TimeoutError):
            return False, None
        proto = self._protocol
        if proto is None or _is_conn_closed(proto):
            # 连接已失效: 触发重建
            self._request_reconnect()
            return False, None
        # v1.9.84 QUIC-01: 计算剩余时间传给 stream 等待
        # P3-06(R2): 用 time.monotonic() 与上面的 deadline 同源。
        remain = deadline - time.monotonic()
        if remain <= 0:
            return False, None
        try:
            if self.proto == "doq":
                ok, data = await self._doq_exchange(proto, query, remain)
            else:
                ok, data = await self._doh3_exchange(proto, query, remain)
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
            except (asyncio.TimeoutError, _cf.TimeoutError):
                return False, None
            if st["n"] <= 0 or st["n"] > _MAX_MSG:
                return False, None
            if len(st["buf"]) < 2 + st["n"]:
                return False, None
            if len(st["buf"]) > 2 + st["n"]:
                log.warning("DoQ stream %d 收到多余字节(声明 %d, 实际 %d), 截断",
                            sid, st["n"], len(st["buf"]) - 2)
            # v1.9.84 QUIC-07: 直接从 bytearray slice 一次拷贝返回
            return True, bytes(st["buf"][2:2 + st["n"]])
        finally:
            proto._doq.pop(sid, None)
    async def _doh3_exchange(self, proto, query, timeout):
        sid = proto._quic.get_next_available_stream_id()
        # v1.9.84 QUIC-03: body 用 bytearray 累积; truncated 标记超限截断
        # P2-21: 新增 content-type 字段, 供响应校验。
        proto._streams[sid] = {"status": 0, "body": bytearray(), "done": asyncio.Event(),
                               "truncated": False, "content-type": ""}
        # R8 P2-3: 整个 send + 等待 + 收尾全部纳入同一个 try/finally。原实现把
        # send_headers/send_data/transmit 放在 try 块之外, 若这些调用抛异常
        # (如连接已关闭/H3 协议错误), 异常穿透到 _exchange 的兜底 except, 但
        # proto._streams[sid] 已写入却从未 pop, 造成流状态(含 Event/bytearray)
        # 在长期运行中泄漏。现在无论 send 阶段还是等待阶段抛异常, finally 都会
        # pop 该 stream 状态。连接重建时 _streams 随旧 protocol 对象一起被 GC,
        # 此处 pop 保证同一活跃连接上不残留死流条目。
        try:
            # R6 P3-2: _host_port 已剥离 IPv6 字面量外的方括号, self.host 现为裸 v6
            # (如 2001:db8::1)。直接 "%s:%d" 拼得 2001:db8::1:853, 多冒号与端口分隔
            # 歧义, 不符合 RFC 3986/HTTP authority 对 IPv6 字面量必须 [v6]:port 的格式。
            # 检测裸冒号(IPv6 字面量必然含 ':')后补回方括号, 与 HTTP/1.1 规范一致。
            authority = "[%s]:%d" % (self.host, self.port) if ":" in self.host else "%s:%d" % (self.host, self.port)
            proto._http.send_headers(sid, [
                (b":method", b"POST"), (b":scheme", b"https"),
                (b":authority", authority.encode()),
                (b":path", self.path.encode()),
                (b"content-type", b"application/dns-message"),
                (b"accept", b"application/dns-message"),
            ])
            proto._http.send_data(sid, query, end_stream=True)
            proto.transmit()
            st = proto._streams[sid]
            try:
                await asyncio.wait_for(st["done"].wait(), timeout)
            except (asyncio.TimeoutError, _cf.TimeoutError):
                return False, None
            if st["status"] != 200 or not st["body"] or st.get("truncated"):
                return False, None
            # P2-21: 校验 Content-Type 必须为 application/dns-message(RFC 8484/9250),
            # 与明文 DoH 路径(upstream.py)对齐。若头存在但类型不符, 按失败处理。
            # P2-01(R2): 去掉 `if ctype and` 守卫——原实现当响应完全没有 Content-Type
            # 头(ctype=="")时条件不触发, 响应被接受; 而明文 DoH(L616)在 ctype 为空时
            # "application/dns-message" not in "" 为 True 会拒绝。改为无条件严格校验,
            # 缺失 Content-Type 的 200 响应(可能是 JSON/HTML 错误页)一律按失败处理,
            # 保证 DoH3 与 DoH 协议对等。
            ctype = st.get("content-type", "")
            # R7 P3-5: 子串匹配转小写, 兼容大写/混合大小写的 Content-Type。
            if "application/dns-message" not in ctype.lower():
                log.debug("DoH3 unexpected Content-Type: %r", ctype)
                return False, None
            return True, bytes(st["body"])
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
