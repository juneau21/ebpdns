"""DNS 服务器：UDP 主线程 + 线程池，TCP 多线程。监听 53 端口（可配置）。"""

import logging
import os
import socket
import socketserver
import threading
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

    def bind(self, spec):
        host, port = parse_bind(spec)
        self.sock = make_udp_socket(host)
        self.sock.bind((host, port))
        self.sock.settimeout(0.5)
        return self.sock.getsockname()

    def serve_forever(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
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
            # 池满: 丢弃本包, UDP 客户端会重试, 避免积压拖垮主循环

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
        self.pool.shutdown(wait=False, cancel_futures=True)


class _TCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
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
                    resp = self.server.resolver.answer_raw(msg, self.client_address)
                    if resp:
                        sock.sendall(dnsmsg.tcp_frame(resp))
        except (socket.timeout, OSError):
            pass


class TCPDNSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, resolver, spec):
        self.resolver = resolver
        host, port = parse_bind(spec)
        if is_ipv6_host(host):
            self.address_family = socket.AF_INET6
        super().__init__((host, port), _TCPRequestHandler)


class DNSServer:
    """组合 UDP4/UDP6 + TCP4/TCP6 DNS 服务。IPv6 监听失败仅告警不阻断（无 IPv6 栈环境自动跳过）。"""

    def __init__(self, resolver, cfg):
        self.resolver = resolver
        self.cfg = cfg
        self.udp = _UDPHandler(resolver)
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
        addr = handler.bind(spec)
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
