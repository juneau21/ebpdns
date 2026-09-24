"""DNS 服务器：UDP 主线程 + 线程池，TCP 多线程。监听 53 端口（可配置）。"""

import logging
import os
import socket
import socketserver
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import dnsmsg

log = logging.getLogger("ebpdns")


def parse_bind(spec, default_port=53):
    """解析 '0.0.0.0:53' / '127.0.0.1' / '[::]:53' / '[::1]:5353' / '::1' -> (host, port)。

    IPv6 带端口必须使用方括号格式 [addr]:port（避免歧义）；裸 IPv6 视为纯地址。
    """
    spec = (spec or "").strip()
    if not spec:
        return "0.0.0.0", default_port
    if spec.startswith("["):
        # [::1]:53 / [::]:53
        end = spec.find("]")
        if end == -1:
            return spec[1:], default_port
        host = spec[1:end]
        rest = spec[end + 1:]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, default_port
        return host, default_port
    if spec.count(":") == 1:
        # IPv4 host:port
        host, port = spec.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return host, default_port
    # 裸 IPv6 地址（无端口，如 ::1 / ::）
    return spec, default_port


def is_ipv6_host(host):
    return ":" in host


def make_udp_socket(host):
    """按地址族创建 UDP socket，IPv6 使用 V6ONLY=1 独立监听（与 0.0.0.0 不冲突）。"""
    family = socket.AF_INET6 if is_ipv6_host(host) else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass
    if family == socket.AF_INET6:
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        except OSError:
            pass
    return sock


class _UDPHandler:
    """UDP 报文处理：recvfrom 主循环 + 线程池。"""

    def __init__(self, resolver, workers=None):
        self.resolver = resolver
        if workers is None:
            # 上游查询会阻塞 worker, 但线程过多在低核数下加剧 GIL 竞争
            # 低核(<4) 用 24(纯 I/O 等待场景可承受), 高核按 cpu*8, 上限 64
            cpu = os.cpu_count() or 4
            workers = 24 if cpu < 4 else min(64, cpu * 8)
        self.pool = ThreadPoolExecutor(max_workers=workers)
        # miss 处理队列有界信号量: 防止攻击/异常流量下线程池无界积压耗尽内存。
        # 池满时丢弃该 miss 包(UDP 客户端会重试), 不阻塞主收包循环。
        # 容量 = workers*3: 允许一定排队(DoH/DoT 多连接池并行后吞吐显著提高),
        # 同时保留丢弃上限防止内存堆积。
        self._slots = threading.BoundedSemaphore(workers * 3)
        self.sock = None
        self._stop = threading.Event()
        # #6 UDP 丢弃计数器: 池满(miss 处理队列满)时丢弃的 UDP 包数。
        # 主线程写, /api/status 读, 用锁保护计数。
        self._drop_lock = threading.Lock()
        self._dropped = 0
        # v1.9.76 P0-2: UDP recv 瞬时 OSError 计数(网卡抖动/ICMP port unreachable 等
        # 偶发错误不应 break 整个收包线程)。连续错误达阈值才重建 socket(置 stop 退出
        # serve_forever, 由上层重绑); 成功收包即清零。
        self._recv_errs = 0
        # 致命回调: socket 连续接收失败判定网络栈不可用时, 由上层注入
        # (回调内先持久化缓存再非零退出, systemd Restart=on-failure 重启)。
        self.fatal_callback = None

    def _inc_dropped(self):
        with self._drop_lock:
            self._dropped += 1

    def dropped(self):
        with self._drop_lock:
            return self._dropped

    def bind(self, spec):
        host, port = parse_bind(spec)
        self.sock = make_udp_socket(host)
        try:
            self.sock.bind((host, port))
        except OSError:
            # bind 失败(如 udp6 无 IPv6 栈): 关闭已创建的 socket 防 fd 泄漏, 再向上抛
            try:
                self.sock.close()
            except OSError:
                pass
            raise
        self.sock.settimeout(0.5)
        return self.sock.getsockname()

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                # v1.9.84 SV-02: 65535 与上游接收路径对齐, 防带大 EDNS OPT 的查询被内核静默截断
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError as e:
                # P1-12: 优雅退出时 stop() 先置 _stop 再 close socket, 在途 recvfrom
                # 会抛 EBADF(errno=9)。此时退出标志已置位, 该错误是预期的关闭信号,
                # 静默 break 退出收包线程, 不再打 WARNING/累计错误计数。
                if self._stop.is_set():
                    break
                # v1.9.76 P0-2: 偶发 OSError(ICMP port unreachable/网卡抖动)不应直接
                # break 收包线程(那会永久停止该 UDP 监听)。计数+告警, 连续达阈值才
                # 置 stop 重建 socket; 成功收包即清零。
                self._recv_errs += 1
                if self._recv_errs <= 3:
                    log.warning("UDP recv error: %r", e)
                # v1.9.77 R3: 阈值 10→20。偶发 ICMP port unreachable/网卡抖动在生产上
                # 可能连续触发十几次, 10 次过激进导致正常流量被误判为线程故障、交给
                # systemd 反复重启。保持 stop 让 systemd 拉起的行为不变, 只放宽阈值与
                # 日志措辞。
                if self._recv_errs >= 20:
                    # socket 连续错误达阈值, 判定网络栈不可用: 走致命退出流程
                    # (先持久化缓存再非零退出交 systemd 重启), 不再 os._exit
                    # 硬退出丢失最多一个周期的缓存/预取状态。
                    self._fatal_shutdown()
                continue
            self._recv_errs = 0
            # 缓存命中快路径: 主线程直接查 LRU 回包, 避免线程池调度。
            # 报文只解析一次: miss 时把解析结果传给完整路径, 避免线程池重复解析。
            msg = None
            try:
                msg = dnsmsg.parse_message(data)
            except Exception:
                pass
            if msg is not None:
                try:
                    fast = self.resolver.answer_fast(data, addr, msg=msg)
                except Exception:
                    fast = None
                if fast is not None:
                    try:
                        self.sock.sendto(fast, addr)
                    except OSError:
                        pass
                    continue
            if self._slots.acquire(blocking=False):
                try:
                    self.pool.submit(self._handle, data, addr, msg)
                except Exception:
                    self._slots.release()
            else:
                # #6 池满: 丢弃本包, UDP 客户端会重试, 避免积压拖垮主循环; 计一次丢弃
                self._inc_dropped()

    def _fatal_shutdown(self):
        """socket 连续接收失败, 判定网络栈不可用: 置停止标志, 触发注入的致命
        回调(回调内先持久化缓存再非零退出, systemd Restart=on-failure 自动
        重启), 避免直接 os._exit 丢失缓存/预取状态。无回调时兜底硬退出。"""
        try:
            log.error("UDP recv 连续 %d 次错误, 触发致命退出(先持久化)",
                      self._recv_errs)
        except Exception:
            pass
        try:
            self._stop.set()
        except Exception:
            pass
        cb = self.fatal_callback
        if cb is not None:
            try:
                cb()
            except Exception:
                try:
                    log.exception("fatal_callback 异常, 兜底硬退出")
                except Exception:
                    pass
        os._exit(1)

    def _handle(self, data, addr, msg=None):
        try:
            resp = self.resolver.answer_raw(data, addr, parsed=msg)
            if resp:
                self.sock.sendto(resp, addr)
        except Exception:
            try:
                err = dnsmsg.build_error_response(data, 2)
                if err:
                    self.sock.sendto(err, addr)
            except Exception:
                pass
        finally:
            self._slots.release()

    def stop(self):
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
        # P3-LOW(保留): cancel_futures=True 会取消队列中尚未执行的任务, 这些任务
        # 的 finally(信号量 release)不会执行, 造成信号量计数"泄漏"。但此处是服务
        # 关闭语义——线程池随之丢弃、不再被任何查询路径使用, 泄漏的信号量计数随
        # 进程退出回收, 无实际影响。故不修改行为, 仅在此标注。
        self.pool.shutdown(wait=False, cancel_futures=True)


class _TCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        # v1.9.84 SV-03: 用 bytearray 累积, 避免 bytes += 每次 O(n) 拷贝
        buf = bytearray()
        # v1.9.84 SV-04: 总生命周期上限 30s, 防慢速客户端每 4s 发 1 字节占住线程槽
        conn_deadline = time.monotonic() + 30.0
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                # 内存保护: 单连接缓冲上限 1MB, 超限断开(防恶意客户端无帧边界无限投喂)
                if len(buf) > 1 << 20:
                    log.warning("TCP 客户端 %s 缓冲超限(%d B), 断开连接", self.client_address[0], len(buf))
                    break
                # 一次性处理缓冲区内所有完整帧（粘包批量）
                while True:
                    try:
                        msg, buf = dnsmsg.parse_tcp_frame(buf)
                    except Exception:
                        break  # 帧不完整，等待更多数据
                    # v1.9.84 SV-03: parse_tcp_frame 对 bytearray 返回 bytearray slice,
                    # 转 bytes 再传给上层(answer_raw 期望 bytes)
                    msg_bytes = bytes(msg)
                    # 与 UDP _handle 对齐: answer_raw 异常时回 SERVFAIL, 避免连接裸崩
                    try:
                        resp = self.server.resolver.answer_raw(msg_bytes, self.client_address)
                    except Exception:
                        try:
                            resp = dnsmsg.build_error_response(msg_bytes, 2)
                        except Exception:
                            resp = None
                    if resp:
                        try:
                            sock.sendall(dnsmsg.tcp_frame(resp))
                        except OSError as e:
                            # v1.9.84-r2: 连接已坏, 断开前记一笔(缓冲区内可能还有已收未处理帧,
                            # 随连接关闭丢弃——管道化多查询时客户端会重试, 记录便于排查)。
                            log.debug("TCP 响应发送失败(%s), 断开: %r",
                                      self.client_address[0], e)
                            break
                # v1.9.84 SV-04: 总生命周期检查, 超时断开
                if time.monotonic() > conn_deadline:
                    break
        # R34 P3-4: socket.timeout 自 PEP 3151(Py3.3)起即为 OSError 子类, Py3.10 起是
        # TimeoutError 别名(亦继承自 OSError)。显式列出冗余, 统一为 OSError 即可覆盖。
        except OSError:
            pass


class TCPDNSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    # 绑定失败重试: 重启时旧进程 socket 可能仍在 TIME_WAIT, 重试 3 次(间隔 200ms)
    # 覆盖绝大多数 systemd 快速重启场景, 避免 TCP6/TCP 端口冲突告警
    _bind_retries = 3
    _bind_retry_interval = 0.2
    # 并发连接数上限: ThreadingTCPServer 每连接一线程, 无上限会被海量短连接
    # 拖垮线程数。用有界信号量限流(类变量, tcp/tcp6 共享总额度)。
    # 达到上限时 process_request 在 accept 线程阻塞等待, 形成背压而非炸线程。
    _conn_slots = threading.BoundedSemaphore(256)

    def __init__(self, resolver, spec):
        self.resolver = resolver
        host, port = parse_bind(spec)
        if is_ipv6_host(host):
            self.address_family = socket.AF_INET6
        super().__init__((host, port), _TCPRequestHandler)

    def process_request(self, request, client_address):
        # 新连接先占槽位; 满了就在此处阻塞(背压), 而不是无界派生线程
        self._conn_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._conn_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            # 连接处理结束(无论正常/异常)释放槽位
            self._conn_slots.release()

    def server_bind(self):
        """绑定 socket, 失败时自动重试(解决重启 TIME_WAIT 端口冲突)。"""
        last_err = None
        for attempt in range(self._bind_retries):
            try:
                # SO_REUSEPORT: 允许新旧进程同时绑定同一端口(内核负载均衡),
                # 重启时新进程无需等待旧进程释放, 零停机切换
                try:
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except (AttributeError, OSError):
                    pass  # 内核不支持 SO_REUSEPORT 时跳过
                super().server_bind()
                return
            except OSError as e:
                last_err = e
                if attempt < self._bind_retries - 1:
                    time.sleep(self._bind_retry_interval)
        raise last_err

    def server_close(self):
        """关闭时设置 SO_LINGER=0, 避免 TIME_WAIT 占用端口(加速重启)。"""
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                   struct.pack("ii", 1, 0))
        except (AttributeError, OSError):
            pass
        super().server_close()


class DNSServer:
    """组合 UDP4/UDP6 + TCP4/TCP6 DNS 服务。IPv6 监听失败仅告警不阻断（无 IPv6 栈环境自动跳过）。"""

    def __init__(self, resolver, cfg, fatal_callback=None):
        self.resolver = resolver
        self.cfg = cfg
        # 致命回调下发给全部 UDP 处理器(udp4 + udp6)
        self.fatal_callback = fatal_callback
        self.udp = _UDPHandler(resolver)
        self.udp.fatal_callback = fatal_callback
        self.udp6 = None
        self.tcp = None
        self.tcp6 = None
        self._threads = []
        self.udp_addr = None
        self.udp6_addr = None
        self.tcp_addr = None
        self.tcp6_addr = None

    def _start_udp(self, spec, attr, name):
        handler = _UDPHandler(self.resolver)
        handler.fatal_callback = self.fatal_callback
        try:
            addr = handler.bind(spec)
        except OSError:
            # bind 失败: 回收 __init__ 已创建的线程池, 防 worker 线程残留
            handler.stop()
            raise
        setattr(self, attr, handler)
        t = threading.Thread(target=handler.serve_forever, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        return addr

    def _start_tcp(self, spec, attr, name):
        srv = TCPDNSServer(self.resolver, spec)
        setattr(self, attr, srv)
        t = threading.Thread(target=srv.serve_forever, name=name, daemon=True)
        t.start()
        self._threads.append(t)
        return srv.server_address

    def start(self):
        listen = self.cfg.get("listen", {})
        udp_spec = listen.get("udp", "0.0.0.0:53")
        tcp_spec = listen.get("tcp", "0.0.0.0:53")
        udp6_spec = listen.get("udp6")
        tcp6_spec = listen.get("tcp6")

        # UDP4（主服务，失败视为启动失败）
        try:
            self.udp_addr = self.udp.bind(udp_spec)
            t = threading.Thread(target=self.udp.serve_forever, name="dns-udp", daemon=True)
            t.start()
            self._threads.append(t)
        except OSError as e:
            # v1.9.84 SV-01: bind 失败必须回收预创建的 ThreadPoolExecutor(最多 64 worker),
            # 否则上层重试 start() 时线程会累积泄漏。
            self.udp.stop()
            raise RuntimeError("UDP 监听失败 (%s): %s" % (udp_spec, e))

        # UDP6（可选：无 IPv6 栈时告警跳过）
        if udp6_spec:
            try:
                self.udp6_addr = self._start_udp(udp6_spec, "udp6", "dns-udp6")
            except OSError as e:
                self.udp6 = None
                log.warning("UDP6 监听失败 (%s), IPv6 UDP 服务不可用: %s", udp6_spec, e)

        # TCP4（失败降级为仅 UDP）
        try:
            self.tcp_addr = self._start_tcp(tcp_spec, "tcp", "dns-tcp")
        except OSError as e:
            self.tcp = None
            log.warning("TCP 监听失败 (%s), 仅提供 UDP 服务: %s", tcp_spec, e)

        # TCP6（可选：无 IPv6 栈时告警跳过）
        if tcp6_spec:
            try:
                self.tcp6_addr = self._start_tcp(tcp6_spec, "tcp6", "dns-tcp6")
            except OSError as e:
                self.tcp6 = None
                log.warning("TCP6 监听失败 (%s), IPv6 TCP 服务不可用: %s", tcp6_spec, e)
        return self

    def stop(self):
        self.udp.stop()
        if self.udp6:
            self.udp6.stop()
        for srv in (self.tcp, self.tcp6):
            if srv:
                try:
                    srv.shutdown()
                    srv.server_close()
                except Exception:
                    pass
        for t in self._threads:
            try:
                t.join(timeout=1)
            except Exception:
                pass

    def _fmt(self, addr):
        """socket 地址元组 → host:port（IPv6 getsockname 返回 4 元组）。"""
        if not addr:
            return None
        return "%s:%d" % (addr[0], addr[1])

    def endpoints(self):
        return {
            "udp": self._fmt(self.udp_addr),
            "udp6": self._fmt(self.udp6_addr),
            "tcp": self._fmt(self.tcp_addr),
            "tcp6": self._fmt(self.tcp6_addr),
        }

    def udp_dropped(self):
        """#6 UDP 丢弃总数: udp4 + udp6 池满丢弃计数之和。"""
        n = self.udp.dropped() if getattr(self, "udp", None) else 0
        if getattr(self, "udp6", None):
            n += self.udp6.dropped()
        return n
