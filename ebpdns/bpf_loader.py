"""ebpdns eBPF XDP 用户态加载器 (bpf_loader.py)。

严格按 EBPF_DESIGN.md 第 4 节实现:
  - 优先 ctypes 调 libbpf.so.0 (open_file / load / find_map_by_name / map_fd / attach_xdp)
  - 降级 bpftool CLI
  - 再降级纯用户态 (active=False, reason 记录具体原因, 不抛异常, 不影响 daemon)

Map 键值布局与 bpf/ebpdns_xdp.h 严格一致 (字段偏移自然对齐, 与 clang 生成的 BTF 一致):
  - dns_cache_key : qname_hash(u64@0) + qtype(u16@8) + pad(u16@10), ABI sizeof=16
                    (设计文档标称的 12 是字段原始长度之和; C ABI 在尾部补 4 字节对齐到 8)
  - dns_cache_val : naddr(u8@0) + rcode(u8@1) + flags(u8@2) + addr_af(u8[8]@3)
                    + ttl(u32@12, offset 11 处 1 字节内补对齐) + expires_at(u64@16)
                    + rdata(u8[8][16]@24), ABI sizeof=152
                    (设计文档标称的 151 是字段原始长度之和; 内补 1 字节对齐 ttl)

权限/降级: 非 root 且无 CAP_BPF / 无 libbpf / 无 .o / verifier 拒绝 / attach 失败
一律 active=False 并把具体原因写进 self._reason, 绝不向调用方抛异常。
"""
from __future__ import annotations

import ctypes
import logging
import os
import multiprocessing
import shutil
import struct
import subprocess
import time
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("ebpdns")

# ---------------------------------------------------------------------------
# 与 bpf/ebpdns_xdp.h 对应的 ctypes 结构 (字段偏移严格一致, 自然对齐)
# ---------------------------------------------------------------------------
_EBP_MAX_ADDRS = 8


class _dns_cache_key(ctypes.Structure):
    """与 C `struct dns_cache_key` 内存布局一致。
    qname_hash@0, qtype@8, pad@10; ABI sizeof=16 (尾部对齐补 4 字节)。"""
    _fields_ = [
        ("qname_hash", ctypes.c_uint64),
        ("qtype", ctypes.c_uint16),
        ("pad", ctypes.c_uint16),
    ]


class _dns_cache_val(ctypes.Structure):
    """与 C `struct dns_cache_val` 内存布局一致。
    naddr@0, rcode@1, flags@2, addr_af@3, ttl@12, expires_at@16, rdata@24;
    ABI sizeof=152 (offset 11 处 1 字节内补, 使 ttl 4 字节对齐)。"""
    # rdata[EBP_MAX_ADDRS][16]: 8 行, 每行 16 字节 —— 与 C 的二维行主序一致。
    # v1.9.161 R-fix: 原声明 c_uint8*8*16 被 ctypes 解释成"16 行×8 列", 与 C 语义
    # 相反。因 _build_val 始终按字节偏移 24+i*16 手工写(不依赖元素行索引), 内存字节
    # 一直正确; 但改成 (c_uint8*16)*8 后 v.rdata[i] 即一行 16 字节, 语义与 C 对齐,
    # sizeof(仍 128)/rdata.offset(仍 24) 不变, 不影响 map 读写。
    _rdata_row = ctypes.c_uint8 * 16
    _fields_ = [
        ("naddr", ctypes.c_uint8),
        ("rcode", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("addr_af", ctypes.c_uint8 * _EBP_MAX_ADDRS),
        ("ttl", ctypes.c_uint32),
        ("expires_at", ctypes.c_uint64),
        ("rdata", _rdata_row * _EBP_MAX_ADDRS),
    ]


# v1.9.158 P3-1: 与 bpf/ebpdns_xdp.h 的 C ABI 做运行期对齐断言。
# 一旦有人改动结构体(或编译器对齐漂移), 启动即失败而非静默写错 map。
assert ctypes.sizeof(_dns_cache_key) == 16, \
    f"dns_cache_key sizeof={ctypes.sizeof(_dns_cache_key)} != 16 (与 ebpdns_xdp.h 不一致)"
assert ctypes.sizeof(_dns_cache_val) == 152, \
    f"dns_cache_val sizeof={ctypes.sizeof(_dns_cache_val)} != 152 (与 ebpdns_xdp.h 不一致)"
assert _dns_cache_val.ttl.offset == 12, f"ttl offset={_dns_cache_val.ttl.offset} != 12"
assert _dns_cache_val.expires_at.offset == 16, \
    f"expires_at offset={_dns_cache_val.expires_at.offset} != 16"
assert _dns_cache_val.rdata.offset == 24, f"rdata offset={_dns_cache_val.rdata.offset} != 24"


# bpf() syscall (x86_64 为 321) 的 map_operation 参数块布局:
#   map_fd(u32@0) + pad(u32@4) + key(u64@8) + value(u64@16) + flags(u64@24) = 32 字节
class _bpf_attr_map(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("_pad", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


# bpf() 命令常量 (linux/bpf.h)
_BPF_MAP_LOOKUP_ELEM = 1
_BPF_MAP_UPDATE_ELEM = 2
_BPF_MAP_DELETE_ELEM = 3
_BPF_MAP_GET_NEXT_KEY = 4   # v1.9.158 P1-3: 用于 clear_cache 枚举遍历
_BPF_ANY = 0  # map update flags

# 计数器索引 (与 .h 枚举一致)
_CNT_TOTAL = 0
_CNT_HIT = 1
_CNT_MISS = 2
_CNT_KERNEL_DIRECT = 3

# libbpf 函数名 (优先加载 libbpf.so.0)
_LIBBPF_CANDIDATES = ("libbpf.so.0", "libbpf.so")

# v1.9.161 审查修复: bpf() 走 libc syscall()。原先每次 _bpf_syscall 都
# ctypes.CDLL(None) 新建主程序句柄(反复 dlopen), 且未设 restype——默认 c_int
# 在 64 位上把 syscall 的 long 返回值截断成 32 位(负 errno 高位符号丢失)。
# 这里把句柄提升为模块级缓存只解析一次, 并显式声明 restype=c_long(64 位安全)。
_libc_handle: Optional[ctypes.CDLL] = None


def _get_libc() -> ctypes.CDLL:
    """返回进程级单例的 libc(CDLL(None)) 句柄, syscall.restype 固定为 c_long。
    只在首次调用时 dlopen 主程序; 后续复用同一指针, 避免热路径反复新建 CDLL。"""
    global _libc_handle
    if _libc_handle is None:
        libc = ctypes.CDLL(None, use_errno=True)
        # syscall(long number, ...): 返回 long(64 位)。restype 默认 c_int 会截断,
        # 显式置 c_long 保证负 errno 高位符号不丢。
        libc.syscall.restype = ctypes.c_long
        # 仅声明固定参数 number; 可变参数(cmd/byref/sizeof)由 ctypes 按对象类型
        # 自动转换, x86_64/aarch64 System V 下安全。
        libc.syscall.argtypes = [ctypes.c_long]
        _libc_handle = libc
    return _libc_handle


class BpfLoader:
    """eBPF XDP 加载器。

    生命周期: __init__ 仅记录配置与状态; load() 真正尝试 open/load/attach;
    unload() 销毁 link 并关闭 fd。任何一步失败都降级为 inactive, 不抛异常。
    """

    def __init__(self, cfg: dict, logger_: Optional[logging.Logger] = None) -> None:
        self._cfg = cfg or {}
        self.log = logger_ or logger
        # 运行期状态
        self._active: bool = False
        self._reason: str = ""
        self._iface: str = ""
        self._load_mode: Optional[str] = None  # "libbpf" | "bpftool" | None
        self._max_entries: int = int(self._cfg.get("kernel_cache_max", 65536) or 65536)
        # libbpf 句柄 (防止 GC 回收)
        self._libbpf: Optional[ctypes.CDLL] = None
        self._obj: Any = None          # struct bpf_object *
        self._link: Any = None          # struct bpf_link *
        self._prog_fd: int = -1
        self._dns_map_fd: int = -1
        self._cnt_map_fd: int = -1
        self._prog_id: int = -1
        self._bpftool_pin: Optional[str] = None
        # v1.9.158 P2-5 / v1.9.159 N3: PERCPU_ARRAY 读取缓冲必须覆盖内核 nr_cpu_ids
        # (possible CPU 数), 否则内核按 possible 返回会导致缓冲偏小 → LOOKUP EFAULT
        # (计数器读 0, 不崩溃但指标失效)。取三个口径的上界:
        #   - sched_getaffinity(0): 当前可用/在线 CPU 数
        #   - SC_NPROCESSORS_CONF: 内核配置/possible CPU 数(含 offline)
        #   - multiprocessing.cpu_count(): 兜底
        try:
            _aff = len(os.sched_getaffinity(0))
        except Exception:
            _aff = 1
        try:
            _conf = os.sysconf("SC_NPROCESSORS_CONF")
        except Exception:
            _conf = 1
        self._ncpus: int = max(1, _aff, _conf, multiprocessing.cpu_count())

    # ------------------------------------------------------------------
    # 静态工具
    # ------------------------------------------------------------------
    @staticmethod
    def _qname_djb2(qname: str) -> int:
        """djb2 64 位哈希, 涵盖每个标签的长度字节 + 标签内容字节。

        与 ebpdns_xdp.bpf.c parse_qname() 严格一致: 先喂标签长度字节,
        再逐字节喂标签内容。qname 为点分形式 (如 'www.baidu.com'),
        内部按 '.' 切分后转 wire format 顺序哈希。空标签 (根/末尾点) 跳过。
        """
        h = 5381
        for label in qname.lower().split("."):
            if not label:
                continue
            # v1.9.158 F3: 与 resolver._ebpf_qname_djb2 统一为 errors="ignore",
            # 避免 replace/ignore 分歧导致哈希不一致(合法 ASCII DNS 无影响)。
            lb = label.encode("ascii", errors="ignore")
            # 先哈希标签长度字节 (wire format 的长度前缀)
            h = (((h << 5) + h) + len(lb)) & 0xFFFFFFFFFFFFFFFF
            for b in lb:
                h = (((h << 5) + h) + b) & 0xFFFFFFFFFFFFFFFF
        return h

    # ------------------------------------------------------------------
    # 属性 / 状态
    # ------------------------------------------------------------------
    @property
    def active(self) -> bool:
        return self._active

    def status(self) -> dict:
        """返回 /api/status 需要的 ebpf 字段快照。"""
        return {
            "active": self._active,
            "iface": self._iface,
            "reason": self._reason,
            "max_entries": self._max_entries,
            "prog_id": (self._prog_id if self._prog_id > 0 else None),
            "map_fd": (self._dns_map_fd if self._dns_map_fd >= 0 else None),
            "load_mode": self._load_mode,
        }

    # ------------------------------------------------------------------
    # 权限 / 环境探测
    # ------------------------------------------------------------------
    @staticmethod
    def _has_cap_bpf() -> bool:
        """检查当前进程是否具备 CAP_BPF 或 CAP_NET_ADMIN (root 直接视为具备)。

        读取 /proc/self/status 的 CapEff 位掩码:
          CAP_NET_ADMIN = 12, CAP_SYS_ADMIN = 21, CAP_BPF = 39 (Linux 5.8+)。
        """
        try:
            if os.geteuid() == 0:
                return True
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("CapEff:"):
                        cap = int(line.split()[1], 16)
                        # 任一即可: BPF(39) / NET_ADMIN(12) / SYS_ADMIN(21)
                        if (cap >> 39) & 1 or (cap >> 12) & 1 or (cap >> 21) & 1:
                            return True
                        return False
        except Exception as e:
            logger.debug("eBPF: 读取 CapEff 失败: %s", e)
        return False

    def _resolve_iface(self) -> str:
        """把 kernel_cache_iface 配置解析成真实网卡名。

        'auto' 时的解析顺序:
          1) /proc/net/route 中 Destination=00000000 的默认路由网卡(最准);
          2) /sys/class/net 下第一个非 lo 的物理网卡;
          3) "" (空串) —— 表示**无法确定**, 由调用方给出明确 reason, 不再猜名字。

        v1.9.161 R-fix(严重, Debian 13 实测): 原实现在 (1) 失败时**硬编码返回 "eth0"**。
        而本项目的 systemd 单元带有 `ProcSubset=pid`(隐藏 /proc 下非 pid 子集的内容),
        因此在 systemd 托管下 `/proc/net/route` **根本不存在**, (1) 必然失败:
            DEBUG eBPF: 解析默认网卡失败: [Errno 2] No such file or directory: '/proc/net/route'
        于是永远回退到 "eth0"; 而现代 Debian 网卡名是 ens18/enp1s0 这类预测名,
        "eth0" 不存在 → `_iface_to_index()` 返回 -1 → 报
            "eBPF 内核态缓存未启用: 无法解析网卡 eth0 的 ifindex"
        结果: **kernel_cache=true 在 systemd 下 100% 无法生效**(与校验器是否通过无关)。

        `/sys/class/net` 在 `ProcSubset=pid` 下**依然可见**(实测), 故用它做 (2) 兜底。
        """
        cfg_if = self._cfg.get("kernel_cache_iface", "auto") or "auto"
        if cfg_if != "auto":
            return cfg_if

        # (1) 默认路由网卡
        try:
            with open("/proc/net/route", "r") as f:
                next(f, None)  # 跳过表头
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].upper() == "00000000":
                        return parts[0]
        except Exception as e:
            self.log.debug("eBPF: 解析默认网卡失败: %s", e)

        # (2) /sys/class/net 兜底(在 ProcSubset=pid 沙箱内仍可用)
        try:
            names = sorted(
                n for n in os.listdir("/sys/class/net")
                if n != "lo" and os.path.exists(os.path.join("/sys/class/net", n, "ifindex"))
            )
            if names:
                # 倾向真实物理网卡(有 device 符号链接), 没有则取字典序第一个
                for n in names:
                    if os.path.exists(os.path.join("/sys/class/net", n, "device")):
                        self.log.debug(
                            "eBPF: /proc/net/route 不可用, 经 /sys/class/net 选定网卡 %s", n)
                        return n
                self.log.debug(
                    "eBPF: /proc/net/route 不可用, 经 /sys/class/net 选定网卡 %s", names[0])
                return names[0]
        except Exception as e:
            self.log.debug("eBPF: 枚举 /sys/class/net 失败: %s", e)

        # (3) 不确定就明确返回空 —— 不再猜 "eth0"
        return ""

    def _find_object_file(self) -> Optional[str]:
        """定位预编译的 ebpdns_xdp.o。
        搜索顺序: 包目录旁 ../bpf/, /usr/lib/ebpdns/, 当前工作目录。"""
        candidates = []
        try:
            here = os.path.dirname(os.path.abspath(__file__))
            candidates.append(os.path.join(here, "..", "bpf", "ebpdns_xdp.o"))
        except Exception:
            pass
        candidates.append("/usr/lib/ebpdns/ebpdns_xdp.o")
        candidates.append("/usr/local/lib/ebpdns/ebpdns_xdp.o")
        candidates.append("ebpdns_xdp.o")
        for c in candidates:
            try:
                if c and os.path.isfile(c):
                    return os.path.abspath(c)
            except Exception:
                continue
        return None

    # ------------------------------------------------------------------
    # 主加载入口
    # ------------------------------------------------------------------
    def load(self) -> bool:
        """加载 .o + attach XDP。成功 True, 失败 False (reason 已记录)。"""
        try:
            # 1) 权限检查
            if not self._has_cap_bpf():
                self._set_inactive("缺少 CAP_BPF 权限（需 root 或 setcap）")
                return False

            self._iface = self._resolve_iface()
            # v1.9.161 R-fix: _resolve_iface() 无法确定时返回 ""(以前硬编码猜 "eth0")。
            # 提前给出可诊断的 reason, 而不是等到底层报 "无法解析网卡  的 ifindex"。
            if not self._iface:
                self._set_inactive(
                    "无法自动确定网卡(kernel_cache_iface=auto): /proc/net/route 不可用且 "
                    "/sys/class/net 未找到物理网卡; 请在 config.json 显式设置 "
                    "kernel_cache_iface 为实际网卡名(如 ens18)")
                return False

            # 2) 找 .o
            obj = self._find_object_file()
            if not obj:
                self._set_inactive("未找到 ebpdns_xdp.o（需 clang 编译或 make install）")
                return False

            # 3) 优先 libbpf ctypes
            if self._try_libbpf(obj):
                self._active = True
                self._reason = ""
                self.log.warning(
                    "eBPF 内核态缓存已启用 (libbpf, iface=%s, map=%d, max=%d)",
                    self._iface, self._dns_map_fd, self._max_entries)
                return True

            # 4) 降级 bpftool CLI
            # v1.9.161 R-fix: _try_bpftool 的兜底异常可能覆盖 _try_libbpf 记录的真实
            # 原因(如 verifier 拒绝 vs 通用 PermissionError)。记录 libbpf 的原因, 若
            # bpftool 也失败且其原因是笼统异常, 保留 libbpf 的更有诊断价值的原因。
            libbpf_reason = self._reason
            if self._try_bpftool(obj):
                self._active = True
                self._reason = ""
                self.log.warning(
                    "eBPF 内核态缓存已启用 (bpftool, iface=%s, map=%d)",
                    self._iface, self._dns_map_fd)
                return True

            # 5) 全部失败
            if not self._reason:
                self._reason = "未找到 libbpf 或 bpftool，且自动加载失败"
            elif libbpf_reason and self._reason.startswith("bpftool 加载异常:"):
                # bpftool 只给了笼统异常(无具体原因), 回退用 libbpf 的具体诊断
                self._reason = libbpf_reason
            return False
        except Exception as e:
            self._set_inactive(f"加载异常: {e!r}")
            return False

    def _set_inactive(self, reason: str) -> None:
        self._active = False
        self._reason = reason
        # 降级可观测性统一交给 daemon 调用方 (cli._ebpf_load_and_wire) 打单行
        # "eBPF 内核态缓存未启用: <reason>，将以纯用户态运行" WARNING；此处降为 debug，
        # 避免 no-CAP / 无 .o 早退路径与 cli 侧重复打印两行同样内容(内部 libbpf/bpftool
        # 失败本就只写 self._reason、不打日志, 由 cli 统一输出)。独立调用 load() 排障时
        # 开 debug 仍可见。
        self.log.debug("eBPF 内核态缓存未启用(debug): %s", reason)

    # ------------------------------------------------------------------
    # libbpf ctypes 路径
    # ------------------------------------------------------------------
    def _load_libbpf(self) -> Optional[ctypes.CDLL]:
        for name in _LIBBPF_CANDIDATES:
            try:
                return ctypes.CDLL(name)
            except OSError:
                continue
        return None

    def _try_libbpf(self, obj_path: str) -> bool:
        lib = self._load_libbpf()
        if lib is None:
            # 不覆盖已有的更具体 reason (如 bpftool 路径后续再试)
            if not self._reason:
                self._reason = "未找到 libbpf.so.0"
            return False

        try:
            # 设置函数原型
            lib.bpf_object__open_file.restype = ctypes.c_void_p
            lib.bpf_object__open_file.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
            lib.bpf_object__load.restype = ctypes.c_int
            lib.bpf_object__load.argtypes = [ctypes.c_void_p]
            lib.bpf_object__close.restype = None
            lib.bpf_object__close.argtypes = [ctypes.c_void_p]
            lib.bpf_object__find_map_by_name.restype = ctypes.c_void_p
            lib.bpf_object__find_map_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            lib.bpf_object__next_program.restype = ctypes.c_void_p
            lib.bpf_object__next_program.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            lib.bpf_map__fd.restype = ctypes.c_int
            lib.bpf_map__fd.argtypes = [ctypes.c_void_p]
            lib.bpf_map__max_entries.restype = ctypes.c_size_t
            lib.bpf_map__max_entries.argtypes = [ctypes.c_void_p]
            # v1.9.158 P2-1: load 前改 map 容量(BTF-defined map 支持)
            lib.bpf_map__set_max_entries.restype = ctypes.c_int
            lib.bpf_map__set_max_entries.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            lib.bpf_program__attach_xdp.restype = ctypes.c_void_p
            lib.bpf_program__attach_xdp.argtypes = [ctypes.c_void_p, ctypes.c_int]
            # v1.9.158 P1-5: attach 等返回 ERR_PTR 的 API 用 libbpf_get_error 判定
            lib.libbpf_get_error.restype = ctypes.c_long
            lib.libbpf_get_error.argtypes = [ctypes.c_void_p]
            lib.bpf_link__destroy.restype = ctypes.c_int
            lib.bpf_link__destroy.argtypes = [ctypes.c_void_p]

            obj = None  # F2: 便于通用 except 分支判断 open 是否成功
            obj = lib.bpf_object__open_file(obj_path.encode("utf-8"), None)
            if not obj:
                self._reason = f"bpf_object__open_file 失败: {obj_path}"
                return False

            # v1.9.158 P2-1/P2-6: 先找 dns_cache map, load 前按配置改容量;
            # 此后任一步失败都 bpf_object__close(obj) 释放, 避免泄漏已加载内核的
            # map/prog。
            dns_map = lib.bpf_object__find_map_by_name(obj, b"dns_cache")
            if not dns_map:
                self._reason = "未找到 dns_cache map"
                lib.bpf_object__close(obj)
                return False
            try:
                lib.bpf_map__set_max_entries(dns_map, ctypes.c_size_t(self._max_entries))
            except Exception:
                pass  # 失败则沿用 .o 内编译期默认容量, 不阻断

            if lib.bpf_object__load(obj) != 0:
                self._reason = "eBPF verifier 拒绝加载 (bpf_object__load 非零)"
                lib.bpf_object__close(obj)
                return False

            dns_fd = lib.bpf_map__fd(dns_map)
            if dns_fd < 0:
                self._reason = "bpf_map__fd(dns_cache) 失败"
                lib.bpf_object__close(obj)
                return False

            cnt_map = lib.bpf_object__find_map_by_name(obj, b"counters")
            cnt_fd = lib.bpf_map__fd(cnt_map) if cnt_map else -1

            # 读实际生效的 max_entries 回写状态
            try:
                me = lib.bpf_map__max_entries(dns_map)
                if me > 0:
                    self._max_entries = int(me)
            except Exception:
                pass

            # 找第一个 xdp 程序并 attach
            ifindex = self._iface_to_index(self._iface)
            if ifindex < 0:
                self._reason = f"无法解析网卡 {self._iface} 的 ifindex"
                lib.bpf_object__close(obj)
                return False

            # v1.9.158 P1-4: 取首个程序必须用 bpf_object__next_program(obj, NULL);
            # 原 bpf_program__next(obj,None) 参数/API 均错, 会把 bpf_object* 当
            # bpf_program* 解引用 → UB。
            prog = lib.bpf_object__next_program(obj, None)
            if not prog:
                self._reason = "未找到 XDP 程序"
                lib.bpf_object__close(obj)
                return False
            link = lib.bpf_program__attach_xdp(prog, ifindex)
            # v1.9.158 P1-5: attach_xdp 失败返回 ERR_PTR(非 NULL 负错误指针),
            # 必须用 libbpf_get_error 判定, 不能 `if not link`。
            if lib.libbpf_get_error(link):
                self._reason = f"网卡 {self._iface} 不支持 XDP (attach_xdp 失败)"
                lib.bpf_object__close(obj)
                return False

            # 成功: 保存句柄
            self._libbpf = lib
            self._obj = obj
            self._link = link
            self._dns_map_fd = int(dns_fd)
            self._cnt_map_fd = int(cnt_fd)
            self._load_mode = "libbpf"
            return True
        except Exception as e:
            self._reason = f"libbpf 加载异常: {e!r}"
            # F2: open 成功后(obj 非空)中途抛异常, 也要 close obj, 否则 detached
            # 的 XDP 程序与 map 驻留内核泄漏。
            try:
                if obj is not None:
                    lib.bpf_object__close(obj)
            except Exception:
                pass
            return False

    # ------------------------------------------------------------------
    # bpftool CLI 降级路径
    # ------------------------------------------------------------------
    def _try_bpftool(self, obj_path: str) -> bool:
        bpftool = shutil.which("bpftool")
        iproute2 = shutil.which("ip")
        if not bpftool or not iproute2:
            if not self._reason:
                self._reason = "未找到 libbpf 或 bpftool"
            return False

        ifindex = self._iface_to_index(self._iface)
        if ifindex < 0:
            self._reason = f"无法解析网卡 {self._iface} 的 ifindex"
            return False

        pin_dir = "/sys/fs/bpf/ebpdns"
        try:
            os.makedirs(pin_dir, exist_ok=True)
            prog_pin = os.path.join(pin_dir, "xdp")
            dns_map_pin = os.path.join(pin_dir, "dns_cache")
            cnt_map_pin = os.path.join(pin_dir, "counters")

            # prog load, 把 dns_cache 与 counters 两个 map 都 pin 下来, 便于后续按
            # pin 取 fd。v1.9.158 P2-3: 原先只 pin dns_cache, counters 从未 pin →
            # cnt_fd 恒 -1, /metrics 指标恒 0。
            r = subprocess.run(
                [bpftool, "prog", "load", obj_path, prog_pin,
                 "type", "xdp",
                 "map", "name", "dns_cache", "pinned", dns_map_pin,
                 "map", "name", "counters", "pinned", cnt_map_pin],
                capture_output=True, text=True, timeout=15)
            if r.returncode != 0:
                self._reason = f"eBPF verifier 拒绝加载 (bpftool): {r.stderr.strip()[:200]}"
                return False

            # attach 到网卡
            r2 = subprocess.run(
                [iproute2, "link", "set", "dev", self._iface, "xdp", "pinned", prog_pin],
                capture_output=True, text=True, timeout=15)
            if r2.returncode != 0:
                self._reason = f"网卡 {self._iface} 不支持 XDP: {r2.stderr.strip()[:200]}"
                # 清理已 load 的 prog
                subprocess.run([bpftool, "prog", "unload", "pinned", prog_pin],
                               capture_output=True, timeout=10)
                # v1.9.159 N4: 同时清理同目录 pinned 的 dns_cache/counters map 文件,
                # 避免残留(下次成功 load 会重新 pin 覆盖, 影响轻微但保持整洁)。
                for pin in (dns_map_pin, cnt_map_pin):
                    try:
                        if os.path.exists(pin):
                            os.remove(pin)
                    except Exception:
                        pass
                return False

            # 打开 pinned map 取 fd
            try:
                dns_fd = os.open(dns_map_pin, os.O_RDWR)
            except OSError as e:
                self._reason = f"打开 pinned dns_cache 失败: {e}"
                return False
            cnt_fd = -1
            try:
                if os.path.exists(cnt_map_pin):
                    cnt_fd = os.open(cnt_map_pin, os.O_RDWR)
            except OSError:
                cnt_fd = -1

            self._dns_map_fd = dns_fd
            self._cnt_map_fd = cnt_fd
            self._bpftool_pin = prog_pin
            self._load_mode = "bpftool"
            return True
        except Exception as e:
            self._reason = f"bpftool 加载异常: {e!r}"
            return False

    @staticmethod
    def _iface_to_index(iface: str) -> int:
        """读 /sys/class/net/<iface>/ifindex。"""
        try:
            with open(f"/sys/class/net/{iface}/ifindex", "r") as f:
                return int(f.read().strip())
        except Exception:
            return -1

    # ------------------------------------------------------------------
    # 卸载
    # ------------------------------------------------------------------
    def unload(self) -> None:
        obj = self._obj
        lib = self._libbpf
        try:
            if self._load_mode == "libbpf" and lib and self._link:
                try:
                    lib.bpf_link__destroy(self._link)
                except Exception:
                    pass
                # v1.9.158 F1: close obj 会一并关闭其拥有的 map/prog fd。
                # 顺序: 先 destroy link(detach XDP), 再 close obj(关 prog+map)。
                # bpf_map__fd 返回的 fd 归 obj 所有, 这里不能再 os.close, 否则 double-close。
                try:
                    if obj:
                        lib.bpf_object__close(obj)
                except Exception:
                    pass
                # 标记 -1, 让下方 finally 不再重复关闭 obj 已关闭的 fd。
                self._dns_map_fd = -1
                self._cnt_map_fd = -1
            elif self._load_mode == "bpftool" and self._bpftool_pin:
                try:
                    subprocess.run(["ip", "link", "set", "dev", self._iface, "xdp", "off"],
                                   capture_output=True, timeout=10)
                    shutil.rmtree("/sys/fs/bpf/ebpdns", ignore_errors=True)
                except Exception:
                    pass
        except Exception as e:
            self.log.debug("eBPF unload 异常(忽略): %s", e)
        finally:
            # 仅关闭"自有"fd(bpftool 路径 os.open(pin) 取得); libbpf 路径的 fd
            # 已被 bpf_object__close 关闭并在上面置 -1, 此处跳过。
            for fd in (self._dns_map_fd, self._cnt_map_fd):
                try:
                    if fd >= 0:
                        os.close(fd)
                except Exception:
                    pass
            self._active = False
            self._dns_map_fd = -1
            self._cnt_map_fd = -1
            self._link = None
            self._obj = None
            self._load_mode = None

    # ------------------------------------------------------------------
    # map 操作 (bpf() syscall)
    # ------------------------------------------------------------------
    def _bpf_syscall(self, cmd: int, map_fd: int, key_addr: int, value_addr: int,
                     flags: int = 0) -> int:
        """直接调 bpf(2) syscall。返回 0 成功, -1 失败 (errno)。"""
        if map_fd < 0:
            return -1
        attr = _bpf_attr_map()
        attr.map_fd = map_fd
        attr.key = key_addr
        attr.value = value_addr
        attr.flags = flags
        # x86_64 bpf() = 321; 其他架构尝试从 libc 调, 失败返回 -1
        try:
            # v1.9.161: 复用模块级单例 libc 句柄(已设 restype=c_long), 不再每次新建 CDLL。
            libc = _get_libc()
            # syscall 号在 x86_64/aarch64 等平台不同; 这里硬编码 x86_64 (321),
            # 其余平台尝试 __NR_bpf (Linux generic 通常 280/271, 由架构决定)。
            nr = self._bpf_syscall_nr()
            rc = libc.syscall(nr, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
            # rc 为 c_long: 成功 0, 失败 -1(配套 errno)。按 64 位原长判断符号。
            if rc < 0:
                return -ctypes.get_errno()
            return 0
        except Exception:
            return -1

    @staticmethod
    def _bpf_syscall_nr() -> int:
        """x86_64=321, aarch64=280。其他架构退回 321 (会失败但被降级吞掉)。"""
        machine = os.uname().machine
        if machine == "x86_64":
            return 321
        if machine == "aarch64":
            return 280
        return 321

    # ------------------------------------------------------------------
    # 缓存写/读/清
    # ------------------------------------------------------------------
    def _build_val(self, val: dict) -> _dns_cache_val:
        """把 dict {naddr, rcode, ttl, addrs:[(af, bytes),...]} 编码进 ctypes 结构。"""
        v = _dns_cache_val()
        ctypes.memset(ctypes.byref(v), 0, ctypes.sizeof(v))
        v.rcode = int(val.get("rcode", 0)) & 0xFF
        v.flags = 1  # valid
        ttl = int(val.get("ttl", 0) or 0)
        v.ttl = ttl
        # expires_at = boot_ns + ttl*1e9。调用方(put_cache)已保证 ttl>0; 这里再防御。
        try:
            boot_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            v.expires_at = (boot_ns + ttl * 1_000_000_000) if ttl > 0 else 0
        except Exception:
            # 时钟不可得时, 写一个"立即过期"值(=当前 boot_ns), 而非 0(永不过期)。
            try:
                v.expires_at = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            except Exception:
                v.expires_at = 0
        addrs = val.get("addrs", []) or []
        filled = 0
        for i, item in enumerate(addrs[:_EBP_MAX_ADDRS]):
            try:
                af, raw = item[0], item[1]
                v.addr_af[i] = 1 if int(af) == 1 else 0
                n = min(len(raw), 16)
                ctypes.memmove(ctypes.byref(v, type(v).rdata.offset + i * 16),
                               raw, n)
                filled += 1
            except Exception:
                continue
        # v1.9.158 P2-2: naddr 必须与实际填充的 rdata 条数一致(并钳到 8)。
        # 原先直接用调用方传入值, 若传入 naddr>8 而 rdata 只填 8 条, 内核侧
        # ANCOUNT 会通告超出实际 RR 数 → 畸形包。
        v.naddr = min(int(val.get("naddr", 0)), filled, _EBP_MAX_ADDRS) & 0xFF
        return v

    def put_cache(self, qname_hash: int, qtype: int, val: dict) -> bool:
        """写一条缓存到 dns_cache map。失败静默返回 False, 不阻塞热路径。"""
        if not self._active or self._dns_map_fd < 0:
            return False
        # v1.9.158 P2-4: TTL<=0 在 DNS 语义上是"不要缓存/立即过期"。绝不写入内核
        # (否则 _build_val 会把 expires_at 写成 0, 被 C 端当作"永不过期"永久直答)。
        # 预热(warmup→put_cache)同样借此跳过 remaining<=0 的条目。
        try:
            if int(val.get("ttl", 0) or 0) <= 0:
                return False
        except Exception:
            return False
        try:
            k = _dns_cache_key()
            ctypes.memset(ctypes.byref(k), 0, ctypes.sizeof(k))
            k.qname_hash = qname_hash & 0xFFFFFFFFFFFFFFFF
            k.qtype = qtype & 0xFFFF
            v = self._build_val(val)
            rc = self._bpf_syscall(
                _BPF_MAP_UPDATE_ELEM, self._dns_map_fd,
                ctypes.addressof(k), ctypes.addressof(v), _BPF_ANY)
            return rc == 0
        except Exception as e:
            self.log.debug("eBPF put_cache 失败(忽略): %s", e)
            return False

    def get_cache(self, qname_hash: Optional[int] = None,
                  qtype: Optional[int] = None) -> Optional[dict]:
        """读一条缓存。无参数时返回 None (LRU_HASH 不便全量 dump)。"""
        if not self._active or self._dns_map_fd < 0:
            return None
        if qname_hash is None or qtype is None:
            return None
        try:
            k = _dns_cache_key()
            ctypes.memset(ctypes.byref(k), 0, ctypes.sizeof(k))
            k.qname_hash = qname_hash & 0xFFFFFFFFFFFFFFFF
            k.qtype = qtype & 0xFFFF
            v = _dns_cache_val()
            ctypes.memset(ctypes.byref(v), 0, ctypes.sizeof(v))
            rc = self._bpf_syscall(
                _BPF_MAP_LOOKUP_ELEM, self._dns_map_fd,
                ctypes.addressof(k), ctypes.addressof(v), 0)
            if rc != 0:
                return None
            return {
                "naddr": v.naddr, "rcode": v.rcode, "flags": v.flags,
                "ttl": v.ttl, "expires_at": v.expires_at,
            }
        except Exception as e:
            self.log.debug("eBPF get_cache 失败(忽略): %s", e)
            return None

    def clear_cache(self) -> None:
        """清空 dns_cache。v1.9.158 P1-3: 用 BPF_MAP_GET_NEXT_KEY 枚举 +
        BPF_MAP_DELETE_ELEM 逐条删除(原先为空操作, reload/规则变更后内核仍按旧
        答案直答到 TTL 过期)。libbpf 与 bpftool 两条路径都持有 dns_map_fd, 复用
        同一 bpf() syscall 即可, 无需 bpftool dump。

        v1.9.161 审查修复(枚举顺序): 旧实现"先 GET_NEXT_KEY(NULL) 取首条 K1,
        循环内先 DELETE(K1) 再以**已删除的 K1** 为前驱 GET_NEXT_KEY(&K1,&nxt)"——
        前驱 K1 已不存在, htab 立刻返回 -ENOENT, 循环 break, 结果只删第一条,
        N-1 条旧答案残留到 TTL 过期, 规则变更后 XDP 仍按旧 IP 回包。
        标准安全 idiom: 每轮都以 NULL(0) 为前驱枚举"当前第一条", 删除该条后下一轮
        再取新的第一条, 直到 map 空(-ENOENT)终止——可删全部且必然终止。"""
        if not self._active or self._dns_map_fd < 0:
            return
        try:
            deleted = 0
            # v1.9.161 复查(低危): 安全迭代上限。正常 htab 至多 max_entries 条, 每轮
            # DELETE 删一条, 最坏 K 次成功删除 + 1 次 -ENOENT 枚举终止(共 K+1 轮)。
            # 若 DELETE 持续返回非 ENOENT 错误(既不 break 也没删成功), GET_NEXT_KEY
            # 会一直返回同一首条, 循环永不终止(理论 livelock)。以上界 max_entries+16
            # 兜底强制 break: 上界远大于合法 K+1, 不改变正常删除逻辑与 deleted 计数。
            guard_limit = self._max_entries + 16
            _guard = 0
            while True:
                _guard += 1
                if _guard > guard_limit:
                    self.log.debug(
                        "eBPF clear_cache: 达到迭代上限 %d, 强制终止(疑似 DELETE 持续错误)",
                        guard_limit)
                    break
                # 每轮全新零值 key 缓冲; 前驱恒为 NULL(0), 内核返回"当前第一条"。
                nxt = _dns_cache_key()
                ctypes.memset(ctypes.byref(nxt), 0, ctypes.sizeof(nxt))
                r = self._bpf_syscall(_BPF_MAP_GET_NEXT_KEY, self._dns_map_fd,
                                      0, ctypes.addressof(nxt), 0)
                if r != 0:
                    break  # 空了(-ENOENT, _bpf_syscall 返回负 errno)即结束
                # 删除刚枚举到的这一条(本轮新缓冲, 不与前驱复用, 删除即作废)。
                if self._bpf_syscall(_BPF_MAP_DELETE_ELEM, self._dns_map_fd,
                                     ctypes.addressof(nxt), 0, 0) == 0:
                    deleted += 1
            self.log.debug("eBPF clear_cache: 已删除 %d 条", deleted)
        except Exception as e:
            self.log.debug("eBPF clear_cache 异常(忽略): %s", e)

    # ------------------------------------------------------------------
    # 计数器 (PERCPU_ARRAY 汇总所有 CPU)
    # ------------------------------------------------------------------
    def get_counters(self) -> dict:
        """汇总 PERCPU_ARRAY 所有 CPU 的计数器。"""
        out = {"total": 0, "hit": 0, "miss": 0, "kernel_direct": 0}
        if not self._active or self._cnt_map_fd < 0:
            return out
        per_cpu_bytes = 8 * self._ncpus
        try:
            for idx, name in ((_CNT_TOTAL, "total"), (_CNT_HIT, "hit"),
                              (_CNT_MISS, "miss"),
                              (_CNT_KERNEL_DIRECT, "kernel_direct")):
                key_arr = (ctypes.c_uint32 * 1)(idx)
                buf = (ctypes.c_uint8 * per_cpu_bytes)()
                ctypes.memset(buf, 0, per_cpu_bytes)
                rc = self._bpf_syscall(
                    _BPF_MAP_LOOKUP_ELEM, self._cnt_map_fd,
                    ctypes.addressof(key_arr), ctypes.addressof(buf), 0)
                if rc != 0:
                    continue
                total = 0
                for cpu in range(self._ncpus):
                    val = struct.unpack_from("<Q", bytes(buf), cpu * 8)[0]
                    total += val
                out[name] = total
        except Exception as e:
            self.log.debug("eBPF get_counters 异常(忽略): %s", e)
        return out

    # ------------------------------------------------------------------
    # 预热
    # ------------------------------------------------------------------
    def warmup(self, entries: List[Tuple[int, int, dict]]) -> int:
        """批量预热, 返回成功写入条数。entries=[(qname_hash, qtype, val), ...]。"""
        if not self._active:
            return 0
        ok = 0
        for qh, qt, v in entries:
            try:
                if self.put_cache(qh, qt, v):
                    ok += 1
            except Exception:
                continue
        return ok


__all__ = ["BpfLoader"]
