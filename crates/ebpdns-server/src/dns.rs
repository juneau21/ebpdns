//! **[历史归因]** DNS UDP/TCP 监听器，忠实对齐 Python `server.py`：
//!
//! - **双栈**：每个监听地址一个独立 socket（典型 `0.0.0.0:53` + `[::]:53` 同端口），
//!   用 `socket2` 建 socket 以便在 `bind` 前设 `IPV6_V6ONLY=1`（见 [`v6only_for`]）；
//!   每个 socket 一个循环，计数/遥测合并进同一个 `telemetry`。
//! - UDP：不开 `SO_REUSEADDR`（保住「端口已被占用」的 `EADDRINUSE` 检测），
//!   循环 `recv_from(65535)` → `answer_fast` 热路径直接回发；
//!   miss 路径用有界信号量（[`udp_slot_total`] = `max(1024, 64×CPU)` 槽）spawn，
//!   池满即丢包并计 `udp_dropped`（UDP 客户端重试）。
//! - TCP：`TcpListener`（backlog 1024，与 tokio 同口径；保留 `SO_REUSEADDR`），
//!   每连接一个有界并发任务；TCP_NODELAY、
//!   连接总寿命 30s、单连接缓冲上限 1MB；按偏移推进的帧游标处理粘包/半包 → `tcp_frame` 回写。
//! - 异常单请求 fail-closed：回 SERVFAIL，绝不崩监听任务。
//! - 优雅退出：`shutdown` 先置停机标志（`AtomicBool`）再 `notify_waiters()`；循环体内
//!   每轮都检查标志，因此**即使通知早于进入 `select!` 也不会丢**。停机时
//!   UDP 在途 miss 任务 / TCP 在途连接任务会被 join 或 abort，socket 及时释放。
//! - 计数口径（F05）：hit/miss/upstream/error 都在**真正知道结果的时刻**计
//!   （见 [`classify_miss`] 与 [`log_and_count`]），UDP 与 TCP 共用同一套语义。
//! - 错误退避（F25）：`recv_from`/`accept` 持续报错时指数退避 + 连续错误阈值兜底，
//!   绝不因单次 `EINTR` 类可恢复错误退出数据面。

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ebpdns_proto::constants::{
    CLASS_IN, FLAG_KEEP_MASK, FLAG_OPCODE_MASK, FLAG_QR, FLAG_QR_RA, FLAG_RCODE_MASK, FLAG_TC,
    RCODE_FORMERR, RCODE_NOTIMP, RCODE_SERVFAIL, TYPE_A,
};
use ebpdns_proto::edns::question_edns_info;
use ebpdns_proto::message::parse_message;
use ebpdns_proto::record::AnswerInput;
use ebpdns_proto::response::{
    build_error_response, build_error_response_short, build_response, build_simple_response,
    build_udp_response, UdpResp,
};
use ebpdns_proto::tcp::tcp_frame;
use ebpdns_resolver::answer::FastKind;
use ebpdns_resolver::passthrough::PassthroughResult;
use ebpdns_resolver::resolve::ResolveOpts;
use ebpdns_resolver::telemetry::Telemetry;
use ebpdns_resolver::types::{ResolveResult, RuleHit};
use ebpdns_resolver::Resolver;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::telemetry::ServerTelemetry;

/// TCP 连接总寿命上限（对齐 server.py conn_deadline=30s）。
const TCP_CONN_DEADLINE: Duration = Duration::from_secs(30);
/// TCP 单连接读超时（对齐 sock.settimeout(5)）。
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// 单连接缓冲上限（对齐 1MB 防恶意慢滴）。
const TCP_BUF_LIMIT: usize = 1 << 20;
/// UDP recv 缓冲（对齐 recvfrom(65535)）。
const UDP_RECV_BUF: usize = 65535;

/// 连续收包/accept 错误阈值：达阈值判网络栈不可用，做一次 graceful 停机
/// **[历史归因]** （对齐 Python `server.py::_UDPHandler._fatal_shutdown` 的 `_recv_errs >= 20`）。
const ERR_FATAL_AFTER: u32 = 20;
/// **[历史归因]** 退避上限（Python 只 `continue` 空转，Rust 版加 1s 上限防 100% CPU 忙等）。
const ERR_BACKOFF_MAX_MS: u64 = 1000;
/// 停机时给在途 UDP miss 任务的宽限上限（池内查询短则数 ms，慢上游可到数百 ms）。
/// 宽限用尽后 `JoinSet::shutdown()` 立即 abort，端口随 `Arc<UdpSocket>` drop 释放。
const SHUTDOWN_UDP_DRAIN: Duration = Duration::from_secs(2);
/// 停机时给在途 TCP 连接任务的宽限上限（超时后 abort，socket 随 fd 关闭释放）。
const SHUTDOWN_TCP_DRAIN: Duration = Duration::from_secs(2);

/* ======================= 停机信号（F09） ======================= */

/// 停机信号：`AtomicBool` 标志 + `Notify` 唤醒。
///
/// 旧实现只有 `Notify::notify_waiters()`（无 permit），且每轮循环新建
/// `notified()` future —— 通知若发生在两次 `select!` 之间就**永久丢失**，
/// 循环退出不了，2s 超时后 JoinHandle 被 drop（任务 detach、socket 不释放）。
/// 现在标志在前、通知在后，[`Stop::wait`] 先查标志再看 `notified()`，
/// 因此不存在窗口期丢失。
#[derive(Default)]
struct Stop {
    flag: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Stop {
    fn request(&self) {
        // 先置标志再唤醒：等待方要么已在等（被唤醒），要么下一次 `wait` 立刻返回。
        self.flag.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn requested(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// 等待停机（每轮循环调用一次；标志已是 true 时同步返回，无 await 挂起）。
    async fn wait(&self) {
        if self.requested() {
            return;
        }
        self.notify.notified().await;
    }
}

/// `SO_RCVBUF` 目标值（字节）：UDP 监听 socket 的**内核接收缓冲**。
///
/// **2.1.12（256 并发 errors 修复的一部分）**：Linux 默认 `net.core.rmem_default`
/// 是 208 KiB（约 1300 个 155B 查询）。256 并发档实测瞬时入包率可达
/// 6k 包/20s ≈ 300 pkt/s 的尖峰，而收包循环在等待上游时会被 `await` 挂住 ——
/// 208 KiB 在两轮 `recv_from` 之间就可能被写满，内核**静默丢弃**后来的包，
/// 客户端只能等到自己的超时（实测 6s）才失败。
///
/// 设 8 MiB（内核会按 `net.core.rmem_max` 夹取，`setsockopt` 是**尽力而为**：
/// 失败不致命，只记 debug 日志，行为退回默认缓冲）可以把这类尖峰吸收掉。
///
/// 注意：这只解决**内核侧**溢出。应用侧还有一道闸门（[`udp_slot_total`]），
/// 两道都要修，否则包只是从"内核丢"变成"应用丢"。
const UDP_RCVBUF_BYTES: usize = 8 << 20;

/// UDP miss 并发闸门（信号量槽位数）= [`udp_slot_total`]。
///
/// **2.1.14（P0-5）**：本常量是**每 CPU** 的槽位数，总槽位见 [`udp_slot_total`]，
/// 下限硬保证 **1024**。
///
/// 历史（为什么这个值必须被盯住）：
/// - 2.1.11 及更早：`workers * 3`（8 核 = 192 槽）。实测 256 并发 × 20s：
///   客户端 `timeout` 332 次 ↔ 服务端 `udp_dropped` **328**（同一批丢失）；
///   内核 `UdpRcvbufErrors` 恒 0、socket `Recv-Q` 峰值仅 ~0.9 KB ⇒ **不是**内核缓冲
///   溢出；服务端 WARN/ERROR 为空 ⇒ 服务端根本没处理这些包。即：在途 miss 长期超过
///   槽位数，`try_acquire_owned()` 失败 → 直接丢包，客户端 6s 后超时。
/// - 2.1.12 修好过（`workers*16`，8 核 = 1024 槽）；
/// - 2.1.13 **静默回退**：`workers` 被固定成 `1` 且本常量变成 32 ⇒ 只剩 **32** 槽
///   （1024 → 32，缩水 32 倍），同一个丢包缺陷回归，且 `/api/status` / `/metrics`
///   当时**没有任何丢包计数**可见（2.1.14 已补 `udp_dropped`）。
///
/// 取值 64×CPU（且总槽位 ≥ 1024）：单包在途成本只有一次 `resolve()` future
/// （无额外缓冲），1024+ 槽的内存/文件描述符开销可忽略（上游连接由
/// `ebpdns-upstream` 的连接池另行限流，闸门放大**不会**放大上游压力）。
const UDP_MISS_SLOTS_PER_CPU: usize = 64;

/// UDP miss 闸门总槽位下限（硬保证，任何 CPU 数下都不得低于此值）。
///
/// P0-5 的**回归门禁**：2.1.13 的缺陷正是"总槽位被静默压到 32"，因此这里把下限
/// 写成常量 + 单测（[`tests::udp_slots_never_below_floor`]），任何后续改小
/// [`UDP_MISS_SLOTS_PER_CPU`] 或去掉下限的改动都会让单测失败。
const UDP_MISS_SLOTS_MIN: usize = 1024;

/// UDP miss 闸门总槽位 = `max(下限, 64 × CPU数)`。
///
/// **单进程一套闸门**：所有 UDP socket（IPv4 + IPv6）共享同一个 `Semaphore`
/// （见 [`DnsServer::start_multi_workers`]），因此这里**不**乘一个恒为 1 的 `workers`。
fn udp_slot_total(cpus: usize) -> usize {
    UDP_MISS_SLOTS_MIN.max(UDP_MISS_SLOTS_PER_CPU.saturating_mul(cpus.max(1)))
}

/* ======================= 监听句柄 ======================= */

/// DNS 监听句柄：持有**全部**监听任务句柄（IPv4 / IPv6 各自独立 socket），供优雅退出。
///
// **2.1.16（功能 7）**：每个监听循环额外持有自己的 [`Stop`]，因此可以在**不停机**的
/// 前提下只停掉"某一个地址"的循环（`rebind` 用）—— 全局 `stop` 仍然一次停全部。
pub struct DnsServer {
    /// 每个 UDP socket 一个收包循环：`(地址, 该循环的独立停机标志, 句柄)`。
    udp_sockets: Vec<(SocketAddr, Arc<Stop>, tokio::task::JoinHandle<()>)>,
    /// 每个 TCP socket 一个 accept 循环：`(地址, 该循环的独立停机标志, 句柄)`。
    tcp_sockets: Vec<(SocketAddr, Arc<Stop>, tokio::task::JoinHandle<()>)>,
    /// **实际**绑定成功的 UDP 地址（按尝试顺序），供 `/api/status.endpoints` 如实展示。
    udp_bound: Vec<SocketAddr>,
    /// **实际**绑定成功的 TCP 地址（同上）。
    tcp_bound: Vec<SocketAddr>,
    dropped: Arc<AtomicU64>,
    stop: Arc<Stop>,
    /* ---- 2.1.16（功能 7）：热更新所需的全部装配件 ---- */
    resolver: Arc<Resolver>,
    telemetry: Arc<ServerTelemetry>,
    udp_slots: Arc<Semaphore>,
    tcp_slots: Arc<Semaphore>,
    /// 当前生效的 UDP worker 数（`rebind` 为新地址沿用同一值；改该键仍需重启）。
    udp_workers: usize,
}

/// 是否需要给 IPv6 socket 设 `IPV6_V6ONLY=1`：**当且仅当**同一协议的绑定列表里
/// IPv4 与 IPv6 地址**同时**存在时。
///
/// Linux 默认 `net.ipv6.bindv6only=0`，此时 `[::]:53` 是「双栈」socket，会**同时**
/// 占住 IPv4 的 53 端口，随后再绑 `0.0.0.0:53` 直接 `EADDRINUSE` ——
/// 「IPv4 与 IPv6 同时监听同一端口」根本无法成立。设 v6only 后两者互不干涉。
///
/// 只有 `[::]` 一个地址时**故意不设** v6only：那正是历史文档推荐的「单 socket 双栈」
/// 用法（`listen.udp="[::]"` 且 `listen.udp6` 关闭/去重），强行 v6only 会让 IPv4
/// 客户端全部失联（功能回退）。只有 IPv4 地址时列表里根本没有 v6 socket，
/// 这个开关无处可用，同样返回 false。
fn v6only_for(binds: &[SocketAddr]) -> bool {
    binds.iter().any(SocketAddr::is_ipv4) && binds.iter().any(SocketAddr::is_ipv6)
}

/// 创建并绑定一个 UDP socket（非阻塞；v6 按 [`v6only_for`] 决定是否 v6only）。
///
/// **故意不设 `SO_REUSEADDR`**（与旧实现的 `std::net::UdpSocket::bind` 同口径）：目标机
/// 6.12 实测（`bindv6only=0`，UDP）——
/// | `IPV6_V6ONLY` | `SO_REUSEADDR`(v6/v4) | `[::]:P` + `0.0.0.0:P` |
/// |---|---|---|
/// | 0 | 否/否 | `EADDRINUSE`（修复前的真实故障） |
/// | 0 | 是/是 | **两个都绑上**（内核允许，但收包归属不确定） |
/// | 1 | 任意 | 两个都绑上（本实现路径，确定） |
/// 也就是说 UDP 上开了 `SO_REUSEADDR` 会让「端口已被别的实例占用」**静默通过**
/// （两个 ebpdns 各绑一半流量），丢掉 `EADDRINUSE` 这道运维安全网。
fn bind_udp(addr: SocketAddr, v6only: bool) -> std::io::Result<std::net::UdpSocket> {
    bind_udp_ex(addr, v6only, false)
}

/// **2.1.16（功能 1）**：UDP worker 上限（`udp_workers` 自动档的封顶）。
///
/// 取值依据：`SO_REUSEPORT` 的收益来自"每个 socket 一个收包循环 + 内核按 flow 哈希
/// 分流到不同核"，因此 worker 数超过物理核数只会增加「同一核上多路轮转」的调度开销
/// 与 `ss -lunp` 行数；8 是目标机的核数，也是经验上阶梯收益的拐点。
pub const UDP_WORKERS_MAX: usize = 8;

/// 生效的 UDP worker 数（纯函数，便于单测）：
/// - `raw == 0` → 自动 = `clamp(cpus, 1, UDP_WORKERS_MAX)`；
/// - `raw == 1` → **1（退回 2.1.15 单 socket 旧行为）**；
/// - 其余 → `clamp(raw, 1, 64)`（显式配置尊重，但不得为 0/无上界）。
///
/// `cpus == 0`（`available_parallelism` 失败）按 1 处理。
pub fn effective_udp_workers(raw: usize, cpus: usize) -> usize {
    if raw == 1 {
        return 1;
    }
    if raw == 0 {
        return cpus.clamp(1, UDP_WORKERS_MAX);
    }
    raw.clamp(1, 64)
}

/// **2.1.16（功能 1）**：端口占用预检 —— 保护 `SO_REUSEPORT` 下会静默失效的
/// 「端口已被占用」运维安全网。
///
/// 为什么必需：`SO_REUSEPORT` 的语义就是「多个 socket 可以绑同一地址且内核分流」，
/// 因此两个 **ebpdns 实例**（或任何开了 REUSEPORT 的进程）会**都 bind 成功**、
/// 各拿一半流量 —— 这正是 [`bind_udp`] 文档里那条 6.12 实测表格所警告的失败模式
/// （旧实现连 `SO_REUSEADDR` 都不设，就是为了保住 `EADDRINUSE`）。
///
/// 实现：建一个**临时** socket，**不**设 REUSEPORT/REUSEADDR，绑同一地址后立即关闭：
/// - 已被占用 → `AddrInUse`（原样返回给调用方，错误文案由 [`bind_err`] 统一包装）；
/// - 空闲 → 绑定成功后 drop（探测用，不参与收包）。
///
/// 只在 `udp_workers != 1` 时调用：`udp_workers == 1` 走的是**完全未改动**的
/// `bind_udp`，其错误码/文案/单测逐位不变。
fn probe_port_free(addr: SocketAddr, v6only: bool) -> std::io::Result<()> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(v6only)?;
    }
    sock.bind(&addr.into())?;
    // 显式关闭：让端口立刻回到空闲，随后的 REUSEPORT 绑定不会与探测 socket 互斥。
    drop(sock);
    Ok(())
}

/// [`bind_udp`] 的参数化版本：`reuse_port` 为真时在 `bind` **之前**设
/// `SO_REUSEPORT`（必须在 bind 前设，否则不生效）。
///
/// **注意**：开启 REUSEPORT 时**不**设 `SO_REUSEADDR`，因为 UDP 上 REUSEADDR 会让
/// 「另一实例已占端口」静默通过（见 [`bind_udp`] 的实测表格）；REUSEPORT 只用于
/// **同一进程内**的多 socket 分流，其"重复实例"风险由 [`probe_port_free`] 兜住。
fn bind_udp_ex(
    addr: SocketAddr,
    v6only: bool,
    reuse_port: bool,
) -> std::io::Result<std::net::UdpSocket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(v6only)?;
    }
    // 2.1.16（功能 1）：多 worker 分流必须"先设 REUSEPORT 再 bind"。
    if reuse_port {
        sock.set_reuse_port(true)?;
    }
    // 2.1.12：放大内核接收缓冲，吸收 256 并发档的入包尖峰（见 [`UDP_RCVBUF_BYTES`]）。
    // best-effort：内核按 rmem_max 夹取；失败（如权限/不支持）只记日志、不致命。
    if let Err(e) = sock.set_recv_buffer_size(UDP_RCVBUF_BYTES) {
        tracing::debug!(error = %e, want = UDP_RCVBUF_BYTES, "UDP SO_RCVBUF 设置失败（沿用内核默认）");
    }
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// 创建、绑定并 `listen` 一个 TCP socket（非阻塞；v6 同上）。
///
/// TCP **保留 `SO_REUSEADDR`**（与 tokio `TcpListener::bind` 同口径：重启/`TIME_WAIT`
/// 下端口可复用）。它不会削弱「重复实例」检测：内核的 TCP 冲突判定对 `TCP_LISTEN`
/// 状态的既有 socket 无条件算冲突，第二个监听者依然 `EADDRINUSE`。
fn bind_tcp(addr: SocketAddr, v6only: bool) -> std::io::Result<std::net::TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        sock.set_only_v6(v6only)?;
    }
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    // backlog 与 tokio `TcpListener::bind` 一致（256 在突发 accept 下过浅）。
    sock.listen(1024)?;
    Ok(sock.into())
}

/// 把绑定错误包装成带地址与协议的可读 `io::Error`（保留 `kind()`：`AddrInUse` 等
/// 仍可被上层/运维脚本判定），便于日志与 `eprintln!` 直接给出「哪个地址失败」。
fn bind_err(addr: &SocketAddr, proto: &str, e: std::io::Error) -> std::io::Error {
    std::io::Error::new(e.kind(), format!("bind {addr} ({proto}): {e}"))
}

impl DnsServer {
    /// UDP miss 队列满时丢弃的包数（供 `/api/status.udp_dropped` 展示）。
    pub fn dropped(&self) -> Arc<AtomicU64> {
        self.dropped.clone()
    }

    /// 实际绑定成功的 UDP 监听地址（`/api/status.endpoints` 的 `udp`/`udp6` 来源）。
    pub fn udp_bound(&self) -> &[SocketAddr] {
        &self.udp_bound
    }

    /// 实际绑定成功的 TCP 监听地址（`/api/status.endpoints` 的 `tcp`/`tcp6` 来源）。
    pub fn tcp_bound(&self) -> &[SocketAddr] {
        &self.tcp_bound
    }

    /// **2.1.16（功能 1）**：可指定 UDP worker 数的启动入口。
    ///
    /// `udp_workers_raw` 是 `ResolverConfig::udp_workers` 的原始值，语义见
    /// [`effective_udp_workers`]：`0` = 自动（CPU 核数，封顶 [`UDP_WORKERS_MAX`]）、
    /// `1` = **与 2.1.15 逐位等价**（单 socket 单 `udp_loop`）、`N>1` = 每个 UDP 地址
    /// 建 N 个 `SO_REUSEPORT` socket，各跑一个 `udp_loop`，内核按 flow 哈希分流，
    /// 从而让多核并行收包 + 回包。
    ///
    /// 兼容性硬约束（见 [`probe_port_free`] / [`bind_udp_ex`]）：
    /// - `udp_workers == 1` 时**完全不碰** `bind_udp`，端口占用探测语义逐位不变；
    /// - `udp_workers != 1` 时先做**显式端口占用预检**（REUSEPORT 会让重复实例静默
    ///   通过），失败仍返回 `AddrInUse`；
    /// - 绑定失败策略（v4 致命 / v6 降级）与旧实现一致；**所有** worker socket
    ///   （含每个地址的 N 个副本）都成功后才 spawn 任何循环，避免"半启动"。
    pub async fn start_multi_workers(
        resolver: Arc<Resolver>,
        telemetry: Arc<ServerTelemetry>,
        udp_binds: &[SocketAddr],
        tcp_binds: &[SocketAddr],
        udp_workers_raw: usize,
    ) -> std::io::Result<Self> {
        let stop = Arc::new(Stop::default());
        // **2.1.43-A（P2：`udp_dropped` 双源）**：直接复用遥测的**同一个**
        // `Arc<AtomicU64>`（`AppState.udp_dropped` 由 `dns.dropped()` 得到，
        // 而后者就是本句柄）。于是
        // `/api/status.udp_dropped`（顶层）/ `/api/status.counters.udp_dropped` /
        // `/api/snapshot.counters.udp_dropped` / `/metrics` 的
        // `ebpdns_udp_dropped_total` **是同一个计数器**。
        //
        // 2.1.42 在这里另建一个原子，并在丢包分支里对它和
        // `telemetry.inc_n("udp_dropped")` **各 +1**（见 `udp_loop` 的 `Err(_)` 分支）
        // —— 两处都在写、两处都可能漏写，正是"双源"的来源。
        let dropped = telemetry.udp_dropped_handle();

        // 有界并发：UDP miss 路径信号量 = `udp_slot_total(cpus)`（≥1024 槽，见该函数
        // 的 P0-5 说明）；TCP 连接槽 = 256。
        // `cpus` 只用于**放大**闸门（2.1.13 里它被算出来却没用、闸门被硬编码成 32）。
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        // **2.1.16（功能 1）**：生效 worker 数（0=自动 / 1=旧行为 / N）。
        let udp_workers = effective_udp_workers(udp_workers_raw, cpus);
        if udp_workers > 1 {
            tracing::info!(
                udp_workers,
                cpus,
                configured = udp_workers_raw,
                "UDP 收包并行化已启用（SO_REUSEPORT，每 worker 一个收包循环）"
            );
        }

        // ---- 第一阶段：全部绑定（v6 失败降级，v4 失败致命）----
        let udp_v6only = v6only_for(udp_binds);
        let tcp_v6only = v6only_for(tcp_binds);
        // 容量：每个地址 N 个副本。**每个 socket 记住它的逻辑地址**（不用下标反推，
        // 因为 v6 失败降级会跳过地址、让并行数组错位）。
        let mut udp_socks: Vec<(SocketAddr, UdpSocket)> =
            Vec::with_capacity(udp_binds.len().saturating_mul(udp_workers));
        let mut udp_bound: Vec<SocketAddr> = Vec::with_capacity(udp_binds.len());
        for addr in udp_binds {
            // 2.1.16：REUSEPORT 让"端口已被占用"静默通过 → 先做显式预检。
            // `udp_workers == 1` 时跳过（旧路径自身就会 EADDRINUSE，且错误文案/单测不变）。
            if udp_workers > 1 {
                if let Err(e) = probe_port_free(*addr, udp_v6only) {
                    let e = bind_err(addr, "udp", e);
                    if addr.is_ipv6() {
                        tracing::warn!(
                            %addr, error = %e,
                            "IPv6 UDP 监听失败：降级为仅 IPv4（服务继续运行）"
                        );
                        continue;
                    }
                    return Err(e);
                }
            }
            let mut one = Vec::with_capacity(udp_workers);
            let mut failed: Option<std::io::Error> = None;
            for _ in 0..udp_workers {
                // `udp_workers == 1` 走**完全未改动**的 `bind_udp`（无 REUSEPORT、
                // 无 REUSEADDR）：错误码/文案/既有的"端口占用"单测逐位不变。
                let bound = if udp_workers > 1 {
                    bind_udp_ex(*addr, udp_v6only, true)
                } else {
                    bind_udp(*addr, udp_v6only)
                };
                match bound.and_then(UdpSocket::from_std) {
                    Ok(s) => one.push(s),
                    Err(e) => {
                        failed = Some(e);
                        break;
                    }
                }
            }
            match failed {
                // 任一 worker 副本失败 → 整个地址失败（已建副本随 `one` 一同 drop，端口释放）。
                Some(e) if addr.is_ipv6() => {
                    tracing::warn!(
                        %addr,
                        error = %bind_err(addr, "udp", e),
                        "IPv6 UDP 监听失败：降级为仅 IPv4（服务继续运行）"
                    );
                }
                Some(e) => return Err(bind_err(addr, "udp", e)),
                None => {
                    for s in one {
                        udp_socks.push((*addr, s));
                    }
                    udp_bound.push(*addr);
                }
            }
        }
        let mut tcp_socks: Vec<TcpListener> = Vec::with_capacity(tcp_binds.len());
        let mut tcp_bound: Vec<SocketAddr> = Vec::with_capacity(tcp_binds.len());
        for addr in tcp_binds {
            match bind_tcp(*addr, tcp_v6only).and_then(TcpListener::from_std) {
                Ok(s) => {
                    tcp_socks.push(s);
                    tcp_bound.push(*addr);
                }
                Err(e) if addr.is_ipv6() => {
                    tracing::warn!(
                        %addr,
                        error = %e,
                        "IPv6 TCP 监听失败：降级为仅 IPv4（服务继续运行）"
                    );
                }
                Err(e) => return Err(bind_err(addr, "tcp", e)),
            }
        }

        // ---- 第二阶段：每个 socket 一个循环（UDP 与 TCP 共享同一 `telemetry`）----
        // 2.1.14（P0-5）：UDP miss 闸门按 CPU 数放大且**硬保证 ≥ 1024 槽**
        // （见 [`udp_slot_total`]：2.1.13 曾静默缩到 32 槽 → 256 并发下丢包回归）。
        let udp_slots = Arc::new(Semaphore::new(udp_slot_total(cpus)));
        let tcp_slots = Arc::new(Semaphore::new(256));
        let mut udp_sockets = Vec::with_capacity(udp_socks.len());
        for (addr, sock) in udp_socks {
            // 每个循环一个独立 `Stop`（除全局 stop 之外）：`rebind` 只需停掉被替换的地址。
            let own = Arc::new(Stop::default());
            let h = tokio::spawn(udp_loop(
                Arc::new(sock),
                resolver.clone(),
                telemetry.clone(),
                udp_slots.clone(),
                dropped.clone(),
                stop.clone(),
                own.clone(),
            ));
            udp_sockets.push((addr, own, h));
        }
        let mut tcp_sockets = Vec::with_capacity(tcp_socks.len());
        for (i, listener) in tcp_socks.into_iter().enumerate() {
            let own = Arc::new(Stop::default());
            let h = tokio::spawn(tcp_accept_loop(
                listener,
                resolver.clone(),
                telemetry.clone(),
                tcp_slots.clone(),
                stop.clone(),
                own.clone(),
            ));
            tcp_sockets.push((tcp_bound[i], own, h));
        }

        Ok(Self {
            udp_sockets,
            tcp_sockets,
            udp_bound,
            tcp_bound,
            dropped,
            stop,
            resolver,
            telemetry,
            udp_slots,
            tcp_slots,
            udp_workers,
        })
    }

    /// UDP 池满丢弃计数（对齐 api.py udp_dropped）。
    pub fn udp_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// 优雅停止：先置停机标志（通知不会丢），join **全部**收包循环与在途任务。
    ///
    /// 时序推理（「有流量时 shutdown 实际耗时」）：
    /// - `Stop::request()` 先置 `AtomicBool` 再 `notify_waiters()`，所有收包循环的
    ///   `select!` 都有「停标志」分支，因此唤醒是**即时**的（不是轮询、不存在窗口期）；
    ///   循环退出延迟 ≈ 当前一轮 `recv_from`/`accept`/`send_to` 的耗时（微秒级）。
    /// - 多个 socket 的循环**并发**运行，因此顺序 join 它们并不叠加各自的宽限期。
    /// - UDP：宽限 2s 等 `misses` 里的在途解析任务；用尽后 `JoinSet::shutdown()`
    ///   直接 abort，`Arc<UdpSocket>` 引用计数归零即 close，端口立即释放。
    /// - TCP：accept 循环退出时 `conns.shutdown().await` abort 在途连接任务（≤2s）。
    /// - 结论：有流量时上界约 **2s(UDP) + 2s(TCP) ≈ 4s**；无慢上游时通常 < 50ms。
    pub async fn shutdown(self) {
        self.stop.request();
        for (_, own, _) in &self.udp_sockets {
            own.request();
        }
        for (_, own, _) in &self.tcp_sockets {
            own.request();
        }
        for (_, _, h) in self.udp_sockets {
            let _ = timeout(SHUTDOWN_UDP_DRAIN + Duration::from_millis(200), h).await;
        }
        for (_, _, h) in self.tcp_sockets {
            // accept 循环退出时会 abort 自己 JoinSet 里的连接任务。
            let _ = timeout(SHUTDOWN_TCP_DRAIN + Duration::from_millis(200), h).await;
        }
    }

    // **2.1.16（功能 7）：listen / api 段热更新 —— 不停机、可回滚、零丢包。**
    ///
    /// 语义（顺序即安全保证）：
    /// 1. 计算目标地址集合，与当前**已绑定**集合求差：
    ///    - `keep`：目标里已存在 → **原样保留旧 socket/循环**（不动它，因此该地址
    ///      在整个过程中始终有监听 ⇒ 不丢包）；
    ///    - `open`：目标里新增 → **先全部 bind 成功**（沿用与启动完全相同的
    ///      端口占用预检 + v4 致命 / v6 降级策略 + `udp_workers` 个 REUSEPORT 副本）；
    ///    - `close`：旧集合里不再需要 → 等新 socket 就绪后**才**停其循环。
    /// 2. **任何 `open` 的 v4 地址 bind 失败 ⇒ 立即返回 `Err`，本次不做任何改动**
    ///    （已建的部分副本就地 drop、端口释放）—— 旧监听**完整保留**，绝不裸奔。
    /// 3. `open` 全部就绪后才 spawn 新循环，然后停 `close` 的循环。
    ///
    /// 不受影响：缓存、在途请求、上游连接池、规则索引（`rebind` 只碰 socket）。
    /// 已知边界（明确文档化）：`udp_workers` 属于**重启级**键 —— 本函数不会改变
    /// 既有地址的 worker 数（避免在运行中把 1 个 socket 变成 N 个而与既有循环打架）。
    pub async fn rebind(
        &mut self,
        udp_binds: &[SocketAddr],
        tcp_binds: &[SocketAddr],
    ) -> std::io::Result<()> {
        let want_udp: Vec<SocketAddr> = dedupe_binds(udp_binds);
        let want_tcp: Vec<SocketAddr> = dedupe_binds(tcp_binds);
        let udp_v6only = v6only_for(&want_udp);
        let tcp_v6only = v6only_for(&want_tcp);
        let n = self.udp_workers.max(1);

        // ---- 阶段 1：绑定所有**新增**地址（失败即整体回滚）----
        let mut new_udp: Vec<(SocketAddr, Vec<UdpSocket>)> = Vec::new();
        for addr in &want_udp {
            if self.udp_bound.contains(addr) {
                continue; // keep：旧 socket 继续服务
            }
            if n > 1 {
                probe_port_free(*addr, udp_v6only).map_err(|e| bind_err(addr, "udp", e))?;
            }
            let mut one = Vec::with_capacity(n);
            for _ in 0..n {
                let bound = if n > 1 {
                    bind_udp_ex(*addr, udp_v6only, true)
                } else {
                    bind_udp(*addr, udp_v6only)
                };
                match bound.and_then(UdpSocket::from_std) {
                    Ok(s) => one.push(s),
                    Err(e) if addr.is_ipv6() => {
                        tracing::warn!(%addr, error = %e,
                            "热更新：IPv6 UDP 监听失败，降级为仅 IPv4（旧监听保持不变）");
                        one.clear();
                        break;
                    }
                    // v4 失败 = 致命 → `new_udp` 随作用域 drop（端口释放），返回 Err。
                    Err(e) => return Err(bind_err(addr, "udp", e)),
                }
            }
            if !one.is_empty() {
                new_udp.push((*addr, one));
            }
        }
        let mut new_tcp: Vec<(SocketAddr, TcpListener)> = Vec::new();
        for addr in &want_tcp {
            if self.tcp_bound.contains(addr) {
                continue;
            }
            match bind_tcp(*addr, tcp_v6only).and_then(TcpListener::from_std) {
                Ok(s) => new_tcp.push((*addr, s)),
                Err(e) if addr.is_ipv6() => {
                    tracing::warn!(%addr, error = %e,
                        "热更新：IPv6 TCP 监听失败，降级为仅 IPv4（旧监听保持不变）");
                }
                Err(e) => return Err(bind_err(addr, "tcp", e)),
            }
        }

        // ---- 阶段 2：新 socket 已全部就绪 → spawn 新循环 ----
        for (addr, socks) in new_udp {
            for sock in socks {
                let own = Arc::new(Stop::default());
                let h = tokio::spawn(udp_loop(
                    Arc::new(sock),
                    self.resolver.clone(),
                    self.telemetry.clone(),
                    self.udp_slots.clone(),
                    self.dropped.clone(),
                    self.stop.clone(),
                    own.clone(),
                ));
                self.udp_sockets.push((addr, own, h));
            }
            if !self.udp_bound.contains(&addr) {
                self.udp_bound.push(addr);
            }
        }
        for (addr, listener) in new_tcp {
            let own = Arc::new(Stop::default());
            let h = tokio::spawn(tcp_accept_loop(
                listener,
                self.resolver.clone(),
                self.telemetry.clone(),
                self.tcp_slots.clone(),
                self.stop.clone(),
                own.clone(),
            ));
            self.tcp_sockets.push((addr, own, h));
            if !self.tcp_bound.contains(&addr) {
                self.tcp_bound.push(addr);
            }
        }

        // ---- 阶段 3：停掉不再需要的地址（新监听已经在跑，因此不会出现空窗）----
        let (drop_udp, keep_udp): (Vec<_>, Vec<_>) = std::mem::take(&mut self.udp_sockets)
            .into_iter()
            .partition(|(a, _, _)| !want_udp.contains(a));
        let (drop_tcp, keep_tcp): (Vec<_>, Vec<_>) = std::mem::take(&mut self.tcp_sockets)
            .into_iter()
            .partition(|(a, _, _)| !want_tcp.contains(a));
        self.udp_sockets = keep_udp;
        self.tcp_sockets = keep_tcp;
        let closed_udp = drop_udp.len();
        let closed_tcp = drop_tcp.len();
        for (_, own, _) in &drop_udp {
            own.request();
        }
        for (_, own, _) in &drop_tcp {
            own.request();
        }
        for (_, _, h) in drop_udp {
            let _ = timeout(SHUTDOWN_UDP_DRAIN + Duration::from_millis(200), h).await;
        }
        for (_, _, h) in drop_tcp {
            let _ = timeout(SHUTDOWN_TCP_DRAIN + Duration::from_millis(200), h).await;
        }
        self.udp_bound.retain(|a| want_udp.contains(a));
        self.tcp_bound.retain(|a| want_tcp.contains(a));
        tracing::info!(
            udp = ?self.udp_bound,
            tcp = ?self.tcp_bound,
            udp_loops = self.udp_sockets.len(),
            tcp_loops = self.tcp_sockets.len(),
            closed_udp,
            closed_tcp,
            "listen 热更新完成（新 socket 先就绪，旧监听后停；缓存与在途请求未受影响）"
        );
        Ok(())
    }
}

/// 地址去重（保持首次出现顺序）：`listen.udp` 与 `listen.udp6` 可能重复给出同一地址。
fn dedupe_binds(binds: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(binds.len());
    for a in binds {
        if !out.contains(a) {
            out.push(*a);
        }
    }
    out
}

/* ======================= 错误退避（F25） ======================= */

/// 连续错误时的处置决策（纯函数产出，便于单测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnError {
    /// 退避 `ms` 后继续收包。
    Backoff(u64),
    /// 连续错误达阈值，判网络栈不可用：优雅停机（不 panic、不 `process::exit`）。
    Fatal,
}

/// 连续错误计数 + 退避时长（纯函数，无 I/O、无锁）。
#[derive(Debug, Default, Clone, Copy)]
struct ErrBackoff {
    consecutive: u32,
}

impl ErrBackoff {
    /// 记一次错误：返回处置决策（退避时长指数增长，封顶 [`ERR_BACKOFF_MAX_MS`]）。
    fn on_err(&mut self) -> OnError {
        self.consecutive = self.consecutive.saturating_add(1);
        if self.consecutive >= ERR_FATAL_AFTER {
            return OnError::Fatal;
        }
        // 1,2,4,...,512,1000,1000...（位移防溢出：shift 上限 6 位 → 最大 64ms 基数）。
        let shift = (self.consecutive - 1).min(6);
        OnError::Backoff((10u64 << shift).min(ERR_BACKOFF_MAX_MS))
    }

    /// **[历史归因]** 一次成功收包/accept：计数清零（对齐 Python `self._recv_errs = 0`）。
    fn on_ok(&mut self) {
        self.consecutive = 0;
    }

    fn consecutive(&self) -> u32 {
        self.consecutive
    }
}

/// **[历史归因]** 计入退避并在阈值处记 `tracing::error!`（前 3 次为 warn，对齐 Python 限流口径）。
#[inline]
fn backoff_step(bo: &mut ErrBackoff, what: &str, e: &std::io::Error) -> OnError {
    let d = bo.on_err();
    match d {
        OnError::Fatal => {
            tracing::error!(
                "{what} 连续 {} 次失败(最后一次: {e}), 判定网络栈不可用, 优雅停机",
                bo.consecutive()
            );
        }
        OnError::Backoff(ms) => {
            if bo.consecutive() <= 3 {
                tracing::warn!("{what} 失败({e}), 第 {} 次, 退避 {ms}ms", bo.consecutive());
            }
        }
    }
    d
}

/* ======================= 报文解析辅助（零/少分配） ======================= */

/// 跳过（可能压缩的）域名，返回其后的偏移。
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *data.get(pos)? as usize;
        if len == 0 {
            return Some(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // 压缩指针：域名在此结束，占 2 字节。
            return Some(pos + 2);
        }
        if len > 63 {
            return None;
        }
        pos += 1 + len;
    }
}

/// 从应答报文里取首条 A/AAAA 的地址文本（控制台「解析值IP」列；无则 `None`）。
///
/// 性能：**零分配**线性扫描（跳过 header + question，遍历 answer RR），不做完整
/// `parse_message`（后者会为 question/answer 段分配多个 Vec 并解码全部 owner name /
/// rdata）。AAAA 用栈上 `[u8; 64]` 手写十六进制，避免旧实现的 8 个 `String` + `join`。
fn first_answer(data: &[u8]) -> Option<String> {
    let dlen = data.len();
    if dlen < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 12usize;
    // 跳过 question 段（域名可能含压缩指针）。边界用 `remaining >= need` 形式写，
    // 避免 `pos + need` 在 32 位目标上溢出（release 下溢出被丢弃 → 越界读 panic）。
    for _ in 0..qd {
        pos = skip_name(data, pos)? + 4;
        if pos > dlen {
            return None;
        }
    }
    // 遍历 answer 段，取首条 A / AAAA。
    for _ in 0..an {
        pos = skip_name(data, pos)?;
        if dlen - pos < 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if dlen - pos < rdlen {
            return None;
        }
        match (rtype, rdlen) {
            (1, 4) => {
                return Some(format!(
                    "{}.{}.{}.{}",
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3]
                ));
            }
            (28, 16) => return Some(format_ipv6(&data[pos..pos + 16])),
            _ => {}
        }
        pos += rdlen;
    }
    None
}

/// 16 字节 IPv6 rdata → 文本（栈上缓冲，无堆分配；输入长度 ≥16 由调用方保证）。
///
/// **[历史归因]** 严格实现 **RFC 5952 §4.2 零压缩**（与 Python `socket.inet_ntop(AF_INET6, …)` 输出
/// 逐字节一致，控制台「实时日志 - 解析值IP」与 `/api/query` 的答案文本都走这里）：
/// - 每 16 位一组小写十六进制、**无前导零**（§4.1）；
/// - 连续的**全零组**（长度 ≥ 2）用 `::` 取代，只压缩**最长**的一段（§4.2.2）；
/// - 等长时压缩**最靠前**的一段（§4.2.2 规定 must not compress later runs）；
/// - 单个零组**不压缩**（§4.2.2 同样禁止，否则会出现 `1:0:2…` → `1::2` 的歧义）；
/// - `::` 只出现一次且不重复。
///
/// 旧实现只是把零组写成空并照常补 `:`，于是 `2001:db8::1` 被输出成
/// `2001:db8::::::1`（用户可见错误）；全零地址输出 `:::::::` 而非 `::`。
fn format_ipv6(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // 8 个 16 位组（越界读一律按 0，与旧实现一致；调用方保证 ≥16 字节）。
    let mut g = [0u16; 8];
    for (i, slot) in g.iter_mut().enumerate() {
        *slot =
            ((*b.get(i * 2).unwrap_or(&0) as u16) << 8) | *b.get(i * 2 + 1).unwrap_or(&0) as u16;
    }
    // 找出最长连续全零段（RFC 5952：只压最长，等长取最靠前；长度 <2 不压）。
    let (mut zs, mut zl) = (usize::MAX, 0usize);
    let mut i = 0usize;
    while i < 8 {
        if g[i] != 0 {
            i += 1;
            continue;
        }
        let start = i;
        while i < 8 && g[i] == 0 {
            i += 1;
        }
        let len = i - start;
        if len > zl {
            zs = start;
            zl = len;
        }
    }
    if zl < 2 {
        zs = usize::MAX;
        zl = 0;
    }
    // 最长形态：`::`(2) + 7 组 ×4 + 6 个 ':' = 39 字节。
    let mut out = [0u8; 48];
    let mut n = 0usize;
    let mut idx = 0usize;
    while idx < 8 {
        if idx == zs {
            out[n] = b':';
            out[n + 1] = b':';
            n += 2;
            idx += zl;
            continue;
        }
        if n > 0 && out[n - 1] != b':' {
            out[n] = b':';
            n += 1;
        }
        let v = g[idx];
        let mut started = false;
        let mut sh = 12i32;
        while sh >= 0 {
            let d = ((v >> sh) & 0xF) as usize;
            if d != 0 || started || sh == 0 {
                out[n] = HEX[d];
                n += 1;
                started = true;
            }
            sh -= 4;
        }
        idx += 1;
    }
    String::from_utf8_lossy(&out[..n]).into_owned()
}

/// 应答报文的轻量分类信息（只读头部 + answer 计数；rdata 解码交给 [`first_answer`]）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ResponseInfo {
    /// answer 段记录数（RR 总数）。
    an: usize,
    /// header 低 4 位 rcode。
    rcode: u8,
}

impl ResponseInfo {
    fn parse(data: &[u8]) -> Self {
        let mut info = ResponseInfo { an: 0, rcode: 0 };
        if data.len() < 12 {
            return info;
        }
        info.rcode = data[3] & 0x0F;
        info.an = u16::from_be_bytes([data[6], data[7]]) as usize;
        info
    }

    /// 首条非 A/AAAA answer 的类型码（仅在需要类型提示时调用，避免热路径二次遍历）。
    fn first_type(&self, data: &[u8]) -> Option<u16> {
        if self.an == 0 {
            return None;
        }
        first_answer_type(data)
    }

    /// 可读的「解析值」文本（无地址记录时用）：NXDOMAIN / 类型提示；NODATA 由调用方
    /// 用 qtype 补文案（本函数只回答「有没有类型线索」）。
    fn hint(&self, data: &[u8]) -> Option<&'static str> {
        if self.rcode == 3 {
            return Some("NXDOMAIN");
        }
        self.first_type(data).map(type_hint)
    }
}

/// 遍历 answer 段取首条 RR 的类型码（畸形/越界 → None）。
fn first_answer_type(data: &[u8]) -> Option<u16> {
    let dlen = data.len();
    if dlen < 12 {
        return None;
    }
    let qd = u16::from_be_bytes([data[4], data[5]]) as usize;
    let an = u16::from_be_bytes([data[6], data[7]]) as usize;
    let mut pos = 12usize;
    for _ in 0..qd {
        pos = skip_name(data, pos)? + 4;
        if pos > dlen {
            return None;
        }
    }
    // 只取**首条** answer RR：循环体在末尾无条件 `return`，故 `for` 恒只跑一轮
    // （clippy `never_loop` 为 deny 级，会让整条 clippy 流水线失败）。
    // 改成 `if an > 0` 语义完全等价（an == 0 时同样落到末尾 `None`）。
    if an > 0 {
        pos = skip_name(data, pos)?;
        if dlen - pos < 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if dlen - pos < rdlen {
            return None;
        }
        return Some(rtype);
    }
    None
}

/// 类型码 → 控制台提示（与 `type_str` 同口径）。
///
/// **2.1.29**：新增的 SVCB/HTTPS/NAPTR/CAA/TLSA/DS/SSHFP/DNSKEY/CDS/CDNSKEY/URI
/// 也给出名字 —— 否则「解析值IP」列对这些非地址记录只能显示「非地址记录」。
fn type_hint(t: u16) -> &'static str {
    match t {
        1 => "A(无地址)", // 理论不可达（A 且 rdlen!=4）
        28 => "AAAA(无地址)",
        5 => "CNAME",
        2 => "NS",
        15 => "MX",
        16 => "TXT",
        6 => "SOA",
        12 => "PTR",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        44 => "SSHFP",
        48 => "DNSKEY",
        52 => "TLSA",
        59 => "CDS",
        60 => "CDNSKEY",
        64 => "SVCB",
        65 => "HTTPS",
        256 => "URI",
        257 => "CAA",
        _ => "非地址记录",
    }
}

/// 从 DNS 报文头部 + question 段提取 (qname, qtype_str)，供遥测聚合。
///
/// 与 [`ebpdns_proto::name::decode_name`] 的差别：把展开后的名字**借用地写进调用方
/// 复用的 `scratch` 缓冲**，因此热路径不再为每个包分配一个 `String`（F24）。
/// 语义刻意逐条对齐 `decode_name`：压缩指针只允许向后引用、跳数上限 32、展开长度
/// 上限 255、标签非法字节用 U+FFFD 替换、返回名不含结尾点。
/// 失败返回 None（不影响正常解析流程）。
fn extract_qname_into<'a>(data: &[u8], scratch: &'a mut String) -> Option<(&'a str, &'static str)> {
    scratch.clear();
    if data.len() < 12 {
        return None;
    }
    let dlen = data.len();
    let mut pos = 12usize;
    let mut first = true;
    let mut jump_done = false;
    let mut end = pos;
    let mut jumps = 0usize;
    let mut name_len = 0usize;
    loop {
        if pos >= dlen {
            return None;
        }
        let length = data[pos] as usize;
        if length == 0 {
            if !jump_done {
                end = pos + 1;
            }
            break;
        }
        if length & 0xC0 != 0 && length & 0xC0 != 0xC0 {
            return None; // 非法标签长度（0x40/0x80 高两位）
        }
        if length & 0xC0 == 0xC0 {
            if pos + 1 >= dlen {
                return None;
            }
            jumps += 1;
            if jumps > ebpdns_proto::constants::MAX_PTR_JUMPS {
                return None;
            }
            let ptr = ((length & 0x3F) << 8) | data[pos + 1] as usize;
            if ptr >= pos {
                return None; // 只允许向后引用（防自引用环）
            }
            if !jump_done {
                end = pos + 2;
                jump_done = true;
            }
            pos = ptr;
            continue;
        }
        pos += 1;
        if pos > dlen || length > dlen - pos {
            return None;
        }
        if !first {
            scratch.push('.');
        }
        // 标签按 UTF-8 解码并小写（缓存键/规则匹配口径），非法字节 U+FFFD 替换。
        //
        // **2.1.24（热路径分配）**：**逐字符**小写后直接写进复用缓冲，不再为每个标签生成
        // 一个临时 `String`（`str::to_ascii_lowercase()`）—— 一个查询通常 2–3 个标签，
        // 也就是每包省下 2–3 次堆分配。口径**逐位一致**：`char::to_ascii_lowercase` 与
        // `str::to_ascii_lowercase` 都**只**影响 ASCII 字节，非 ASCII 原样保留。
        match std::str::from_utf8(&data[pos..pos + length]) {
            Ok(s) => scratch.extend(s.chars().map(|c| c.to_ascii_lowercase())),
            Err(_) => scratch.push_str(&String::from_utf8_lossy(&data[pos..pos + length])),
        }
        first = false;
        name_len += 1 + length;
        if name_len >= 255 {
            return None;
        }
        pos += length;
    }
    // **2.1.49（AUD-16）**：DNS label 可以携带任意字节，`\n` / `\r` / ESC 会被
    // 原样写进 top_domains 与 debug 日志。本函数是日志/遥测的唯一 qname 提取点：
    // 含控制字符 ⇒ 返回 None（调用方落空域名），从源头消除多行日志注入。
    // 数据面入口 `handle_query` 另外直接拒绝整包（FORMERR），见 `invalid-qname`。
    if scratch.chars().any(char::is_control) {
        return None;
    }
    // question 段一条 = name + qtype(2) + qclass(2)：四字节必须齐全，
    // 与 `ebpdns_proto::message::parse_message` 的 `pos + 4 > data.len()` 截断判定
    // 逐字对齐（message.rs:72-74）。旧实现只校验了 qtype 两字节，于是「缺 qclass 末字节」
    // 的截断查询仍被当成合法问题（dom/qt 被写进遥测与实时日志，面板上是可见的假数据）。
    if end + 4 > dlen {
        return None;
    }
    let qt = u16::from_be_bytes([data[end], data[end + 1]]);
    // **2.1.20（F-13 修复：日志/遥测把 PTR/SRV/CAA/HTTPS 塌缩成 `other`）**：
    // 此前只认 A/AAAA/CNAME/NS/MX/TXT/SOA，其余一律 `"other"`
    // ⇒ `/api/logs` 的 `qtype` 列把 **PTR（反向解析）/ SRV（服务发现）/ CAA（证书签发
    // 授权）/ HTTPS（SVCB 别名）** 这些**常见且语义完全不同**的类型显示成同一个 `other`，
    // 实时日志与审计无法区分它们（`out-a219b` 的日志取样里这四类全是 `other`）。
    //
    // 修法：查 `qtype_log_label` 的**静态表**（含 proto 支持名单 + 这四个常见类型），
    // 只有**真的未知**的码才落 `other`（保持 `&'static str` 返回，热路径零分配）。
    let qtype = qtype_log_label(qt);
    Some((scratch.as_str(), qtype))
}

/// **2.1.20（F-13）**：线格式 qtype 码 → **日志/遥测**用名字（`&'static str`，零分配）。
///
/// 与 [`ebpdns_proto::constants::qtype_name`] 的区别：那是**受理名单**（未列入者数据面回
/// `NOTIMP`）；本表是**显示用**的更大集合 —— 未受理的类型同样会出现在实时日志里
/// （`/api/logs` 记录收到的查询），把它们显示成 `other` 会让"用户查了什么"不可读。
fn qtype_log_label(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        13 => "HINFO",
        15 => "MX",
        16 => "TXT",
        17 => "RP",
        18 => "AFSDB",
        24 => "SIG",
        25 => "KEY",
        28 => "AAAA",
        29 => "LOC",
        33 => "SRV",
        35 => "NAPTR",
        36 => "KX",
        37 => "CERT",
        39 => "DNAME",
        41 => "OPT",
        43 => "DS",
        44 => "SSHFP",
        45 => "IPSECKEY",
        46 => "RRSIG",
        47 => "NSEC",
        48 => "DNSKEY",
        49 => "DHCID",
        50 => "NSEC3",
        51 => "NSEC3PARAM",
        52 => "TLSA",
        53 => "SMIMEA",
        55 => "HIP",
        59 => "CDS",
        60 => "CDNSKEY",
        61 => "OPENPGPKEY",
        62 => "CSYNC",
        63 => "ZONEMD",
        64 => "SVCB",
        65 => "HTTPS",
        99 => "SPF",
        108 => "EUI48",
        109 => "EUI64",
        249 => "TKEY",
        250 => "TSIG",
        251 => "IXFR",
        252 => "AXFR",
        255 => "ANY",
        256 => "URI",
        257 => "CAA",
        32768 => "TA",
        32769 => "DLV",
        _ => "other",
    }
}

/// 类型码 → 名字（**单一来源** = proto 的 [`ebpdns_proto::constants::qtype_name`]）。
///
/// 用于 resolve 的 qtype 参数**与数据面受理判定**（P0-4）：不支持的 qtype 返回
/// `None` → 数据面回 `NOTIMP`。旧实现 `_ => "A"` 兜底把
/// `AXFR(252)` / `ANY(255)` / `TYPE0` / `TYPE65280` 全变成 A 查询。
fn qtype_name(t: u16) -> Option<&'static str> {
    ebpdns_proto::constants::qtype_name(t)
}

/* ======================= 应答构造 ======================= */

/// 一次应答的**来源/结局**——计数口径的**唯一判据**（显式枚举）。
///
/// P1-5 / P1-6 修复：此前用「应答字节的 rcode+ancount 启发式」(`resp_is_good`) 与
/// 「`error_reason` 字符串哨兵」判定 error/upstream，结果是
/// - 已判 err 的结果被 `rcode==0 && ancount>0` **改判 miss**（错误被掩盖）；
/// - `empty-question` 哨兵在 `dns.rs:918` 被写成 `None`，而判据仍比较
///   `!= Some("empty-question")` ⇒ 恒真（空问题被误计上游）。
///
/// 现在把「这次应答从哪来」在**构造点**显式记下，`classify_miss` / `log_and_count`
/// 只做枚举匹配，不再读应答字节、不再比字符串。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum AnswerSource {
    /// 缓存直答（快路径 `answer_fast`，或 `resolve()` 内部二次命中）。
    #[default]
    Cache,
    /// 规则/本地判定，**未发上游**（resolver 的 `no-upstream`）。
    Rule,
    // >>> 242B BEGIN P1-6-source >>> //
    /// **2.1.42-B（P1-6）**：本地规则**直答**（block / forceIp）—— 既没查缓存、
    /// 也没发上游。判据 = `outcome.rule.is_some() && up_name.is_empty()`（结构化，
    /// 不读应答字节）。归入 `MissClass::Rule` -> `counters.rule`，**不计**
    /// hit/miss/upstream/errors；`rule_hits` 因此不再与 `miss` 重叠。
    RuleLocal,
    // <<< 242B END P1-6-source <<< //
    /// **2.1.40**：本地策略短路（`prefer_ipv4=true` 且域名有 A 时的 AAAA 屏蔽、
    /// `ipv6=false` 时的 AAAA 恒 NODATA）。
    ///
    /// 语义：**既没查缓存、也没发上游** —— 计入 hit 或 miss 都会污染命中率口径。
    /// 因此**不计** `hit` / `miss` / `upstream_queries` / `errors`，只自增
    /// `counters.policy_filtered_total`；事件 level 从 2.1.39 的 `miss` 改为 `policy`。
    PolicyFiltered,
    /// 真正走了上游解析并拿到合法结论（含 NXDOMAIN / NODATA / 非 A 类型）。
    Upstream,
    /// 上游解析失败（SERVFAIL / 全部上游无应答 / 组包失败）→ 计 error。
    UpstreamFailed,
    /// 报文畸形 / 空 question / 未进解析引擎 → 计 error，**不计上游**。
    Malformed,
    /// **2.1.19（修复项 5-④）**：**本地应答但内容不受支持** —— NOTIMP 类
    /// （opcode≠0 / 非 IN class / 必须拒绝的 qtype）。
    ///
    /// 为什么必须与 [`AnswerSource::Malformed`] 分开（2.1.19 报告 ⑫(4)）：
    /// 两者此前共用 `Malformed` ⇒ 事件「上游解析」列文案相同（都是
    /// 「本地判定（未发上游）」），运维**无法区分**"报文坏了"与"类型不支持"；
    /// 而报告 ⑨ 又指出这两类是 `?` 收敛后仅剩的"未进解析引擎"集合，
    /// 恰恰最需要一眼可辨。现在两者标签不同，且都不再是 `?`。
    ///
    /// **计数口径不变**（这是刻意的最小改动）：仍计 `miss` + `error`、不计 `upstream`
    /// —— 2.1.19 的 P0-4 回归测试就是这样钉的（NOTIMP 计 miss+error）。
    Unsupported,
    /// **2.1.29**：未知/其他合法 qtype 的**透传成功** —— 按原始 `u16` 发上游、
    /// **原样回传**上游报文（只改头）、**不缓存**。计 `miss` + `upstream` +
    /// `passthrough_qtype_total`，**不计** `error`。
    Passthrough,
    /// **2.1.29**：未知 qtype 的**透传失败**（全部上游超时/无应答）→ 回 SERVFAIL。
    /// 计 `miss` + `error` + `upstream` + `passthrough_qtype_total`。
    PassthroughFailed,
}

/// **2.1.19（修复项 5-④）**：`error_reason` 里表示"本地应答、内容不支持"的哨兵值。
///
/// 取值来源：`answer_wire_ex` 的三处 NOTIMP 分支（`opcode≠0` / `class≠IN` /
/// 不支持的 qtype）。`simple_outcome` 把它写进 `error_reason`，
/// [`event_upstream`] / [`classify_miss`] 据此给出**显式语义标签**。
const REASON_UNSUPPORTED: &str = "unsupported-qtype-or-opcode";

/// 一次查询的应答结果：线格式字节 + **真正的结果口径**。
///
/// `hit` 取自 `ResolveResult.hit` 或 `answer_fast` 命中，因此调用方可以在此之后
/// 才计 hit/miss，避免旧实现「先计 miss、`answer_wire` 内部又命中缓存」导致
/// `miss != total`。
#[derive(Default)]
struct AnswerOutcome {
    resp: Vec<u8>,
    /// 是否由缓存直答（含缓存里的 NXDOMAIN/NODATA）。
    is_hit: bool,
    /// **2.1.12**：本条应答是否由「缓存直答」产生（与 `is_hit` 同源，但**语义更窄**）。
    ///
    /// 为什么要在构造点显式记下：负缓存专用计数 `ebpdns_cache_negative_hits_total`
    /// 的定义是「**缓存直答里**有多少条是负应答」，因此判据必须是
    /// `is_cache_direct && is_negative_answer(resp)`。
    /// `resolved=true && is_hit=true`（`answer_fast` 未命中、`resolve()` 内部二次命中）
    /// 这条路径「由 `resolve()` 代计 hit」—— 若在这里再计一次负缓存命中，同一个
    /// 客户端查询就会被计两次。把这个判据**前移到唯一的构造点**，三个出口
    /// （UDP / TCP / 控制面）才能共用同一个计数函数（见 [`count_negative_cache_hit`]）。
    is_cache_direct: bool,
    /// 是否**已进入 `resolve()`**（因此 total 已由 `resolve()` 内部
    /// `count_query("resolve")` 代计，[`log_and_count`] 不得再计一次）。
    ///
    /// P1-5：**未进解析引擎**的路径（长度不足 / 解析失败 / 空 question）必须是
    /// `false` —— 旧实现让 [`resolve_guarded`] 在这些路径上也置 `true`，于是这些包
    /// **计了 miss 却没计 total**，`total == hit + miss` 不变量被破坏。
    resolved: bool,
    /// **来源/结局**（计数口径的唯一判据，见 [`AnswerSource`]）。
    source: AnswerSource,
    /// `resolve()` 的错误原因（仅用于事件 `answer` 列展示；**不再**参与计数判据）。
    error_reason: Option<String>,
    /// 命中的分流规则（block/allow/group/forceIp）；`None` = 未命中规则。
    ///
    /// 计数（`rule_hits`）已在 resolver 侧**全量**完成；本字段只用于落
    /// `level="rule"` 事件（缺陷 C：规则屏蔽/分流此前被记成 miss「上游解析完成」，
    /// 控制台「实时日志」的规则列恒为空）。
    rule: Option<RuleHit>,
    /// **实际应答本次查询的获胜上游名**（`ResolveResult::up_name`，永远是**单一**
    /// 名字，不是候选列表）。
    ///
    /// 缺陷（P0）：hit/miss/err 事件的 `upstream` 列此前写的是**候选上游列表**
    /// （`"lan235 / lan235tcp / alidoh"`，resolver 侧 `up_names_display` 的 `" / "`
    /// 连接），或恒为空串，控制台「实时日志」的「上游」列看不出谁真正应答。现在透传
    /// 单一获胜上游：上游解析 → 上游 id；缓存直答 → `"缓存直答"`；serve-stale →
    /// `"serve-stale"`；本地判定未发上游 → `"无上游"`。
    /// 为空（仅「未进解析引擎」：畸形包 / 空 question / 组包失败）时由
    /// [`event_upstream`] 回退（调用方兜底值 → [`UPSTREAM_UNKNOWN`]）。
    /// 规则路径（block/allow/group/forceIp）仍用 [`RuleHit::upstream`] 的文案。
    ///
    /// **2.1.25（B9 性能项：`Cow` 化）**：本字段从 `String` 改为 `Cow<'static, str>` ——
    /// 缓存直答 / serve-stale / 本地判定这些**固定文案**改用 `Cow::Borrowed`，
    /// 于是**每次缓存命中**（数据面最热的路径）少一次 `String` 堆分配 + 一次 `memcpy`。
    /// 只有"真上游名"（`ResolveResult::up_name`，运行时才知道的 `String`）走
    /// `Cow::Owned`，与旧实现**逐位等价**（`as_ref()` 拿到的仍是同一串字节）。
    up_name: Cow<'static, str>,
    /// **2.1.15（P1）**：`resolve()` 给出的 SERVFAIL 结构化归因
    /// （`None` = 非 SERVFAIL / 中间态未标记）。数据面唯一出口
    /// [`log_and_count`] 据此自增 `servfail_total` 的原因维度。
    servfail_reason: Option<ebpdns_resolver::types::ServfailReason>,
    /// **2.1.17（修复项 3）**：本应答在解析过程中被 rebind 防护丢弃的
    /// 私有/保留地址条数（`ResolveResult::private_answers_filtered`）。
    ///
    /// 数据面唯一出口 [`log_and_count`] 据此自增
    /// `ServerTelemetry::count_cache_skipped_private` ⇒ `/api/status.counters
    /// .cache_skipped_private_total` 与 `/metrics` 的
    /// `ebpdns_cache_skipped_private_total`。**这两者与 `rebind_blocked` 是
    /// 两个不同的门**（后者统计控制面拦截面，数据面恒 0）。
    private_answers_filtered: u32,
}

/// 事件 `upstream` 列的兜底文案：既没拿到获胜上游名，调用方也没给兜底值时使用。
///
/// 只可能落在「未进解析引擎」的路径（畸形包 / 空 question / 组包失败），对齐
/// v1.9.162 `resolver.py` 里 `r.get("up_name", "?")` 的缺失回退。取 `"?"` 而非空串：
/// 控制台「上游」列不再出现空白行（空白列无法区分「没查到」与「没记录」）。
///
/// **2.1.18（修复项 11）**：本常量现在只在"连来源都没有"的**异常态**下使用
/// （数据面路径已按 [`AnswerSource`] 穷举，见上），保留它是为了
/// ①trait/未来调用方仍有一个明确的"字段缺失"哨兵；②`?` 不得作为正常展示
/// （新单测 `every_answer_source_has_a_readable_upstream_label` 钉死这一点）。
#[allow(dead_code)]
const UPSTREAM_UNKNOWN: &str = "?";

/// 缓存直答在事件 `upstream` 列上的**固定文案**（**2.1.25**：抽成常量，
/// 快路径用 `Cow::Borrowed` 引用它 ⇒ 每次命中不再分配一个 `String`）。
const CACHE_DIRECT_UP_NAME: &str = "缓存直答";

/// 事件 `upstream` 列取值：获胜上游名 > 调用方兜底值 > **按来源合成的可读标签**。
///
/// **2.1.18（修复项 11）**：第三档以前直接落 [`UPSTREAM_UNKNOWN`]（`"?"`）——
/// 用户实测「实时查询日志」的『上游解析』列对 **AAAA / 其它 qtype** 显示大量 `?`：
/// 那些路径（IPv6 关闭、NOTIMP、prefer_ipv4 屏蔽…）在 `resolve()` 里早退且没写
/// `up_name`。现在第三档**按 [`AnswerSource`] 合成**，于是：
/// - 缓存直答 / 规则动作 / 实际获胜上游名 / serve-stale / RFC8020 等**照旧优先**；
/// - 本地判定（未发上游）→「本地判定（未发上游）」，上游失败 →「上游失败（无获胜上游）」；
/// - **2.1.19（修复项 5-④）**：NOTIMP 类本地应答 →「本地应答（类型/opcode 不支持）」，
///   与 `Malformed`（畸形报文）**标签不同**，运维一眼可分；
/// - `"?"` **只在"连来源都没有"的异常态**才可能出现（trait 兜底/未来调用方），
///   正常数据面路径**不可能**再出现（`every_answer_source_has_a_readable_upstream_label`
///   单测把这一点钉死，且该单测**遍历全部变体**）。
fn event_upstream<'a>(up_name: &'a str, fallback: &'a str, source: AnswerSource) -> &'a str {
    if !up_name.is_empty() {
        up_name
    } else if !fallback.is_empty() {
        fallback
    } else {
        match source {
            AnswerSource::Cache => "缓存直答",
            // >>> 242B BEGIN P1-6-label >>> //
            AnswerSource::Rule => "本地判定（规则）",
            AnswerSource::RuleLocal => "本地规则直答（未发上游）",
            AnswerSource::PolicyFiltered => "本地策略应答（未发上游）",
            // <<< 242B END P1-6-label <<< //
            AnswerSource::Upstream => "上游（未记录上游名）",
            AnswerSource::UpstreamFailed => "上游失败（无获胜上游）",
            AnswerSource::Malformed => "本地判定（未发上游）",
            AnswerSource::Unsupported => "本地应答（类型/opcode 不支持）",
            // **2.1.29**：透传与"不支持"必须是**不同**标签（两者都出现在同一列）。
            AnswerSource::Passthrough => "上游（类型未知→透传）",
            AnswerSource::PassthroughFailed => "上游失败（类型未知→透传）",
        }
    }
}

/// 完整应答：先命中快路径（缓存），miss 走 resolve 完整路径并组线格式应答。
/// 任何错误 fail-closed：畸形包 / 解析失败回 SERVFAIL；无法组包返回 None（调用方兜底）。
///
/// 保留原签名（内部调用 [`answer_wire_ex`]），供其它模块/测试按旧契约使用。
pub async fn answer_wire(resolver: &Arc<Resolver>, raw: &[u8]) -> Option<Vec<u8>> {
    answer_wire_ex(resolver, raw).await.map(|o| o.resp)
}

/// [`answer_wire`] 的带口径版本（数据面用：需要知道 hit/err 才能正确计数）。
async fn answer_wire_ex(resolver: &Arc<Resolver>, raw: &[u8]) -> Option<AnswerOutcome> {
    // ---- 报文层预检（P0-4 / P1-3）----
    // DNS 头至少 12 字节。旧实现：`tracing::warn!` **每个**短包一条（畸形包可刷爆日志）
    // 且返回 `None` → 数据面兜底 **SERVFAIL**。现在：限流日志 + 回 **FORMERR**。
    if raw.len() < 12 {
        rate_limited_warn("UDP/TCP 包长度 < 12，回 FORMERR", raw.len() as u64);
        return Some(malformed_outcome(raw, "short-packet"));
    }
    // 查询包不该置 QR（这是响应包）；opcode≠0 本服务不支持 → NOTIMP（对齐
    // `answer_fast` 的预检口径：那里返回 None 交完整路径，由这里给出 rcode）。
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    if flags & FLAG_QR != 0 {
        return Some(malformed_outcome(raw, "response-packet"));
    }
    if (flags & FLAG_OPCODE_MASK) >> 11 != 0 {
        // **2.1.21（DEF-220-04）**：`notimp_outcome` 现在与 `malformed_outcome`
        // **同一个构造器**（只差 rcode），因此 `qdcount` 策略一致。
        return Some(notimp_outcome(raw));
    }

    // 热路径：缓存命中即返回（`answer_fast` 不上游、非阻塞）。
    // >>> PATCH242A P1-1 dns-fast-outcome BEGIN
    // **2.1.42（P1-1）**：`answer_fast_ex` 同时返回命中来源。本地策略过滤
    // （`ipv6=false` / `prefer_ipv4`）**不得**计成 hit / cache_direct，否则
    // `hit_rate` 与负缓存命中口径都会被污染；它只计 `policy_filtered_total`。
    if let Some((resp, kind)) = resolver.answer_fast_ex(raw) {
        let policy = kind == FastKind::PolicyFiltered;
        return Some(AnswerOutcome {
            resp,
            is_hit: !policy,
            is_cache_direct: !policy,
            resolved: false,
            source: if policy {
                AnswerSource::PolicyFiltered
            } else {
                AnswerSource::Cache
            },
            error_reason: None,
            // 快路径不产生规则事件：block 命中在 `answer_fast` 内已返回 None 降级到
            // 完整路径（`resolve` → 复查分支）落 rule 事件；allow/group 不影响快路径。
            rule: None,
            // 事件 `upstream` 列：缓存直答（对齐 v1.9.162 resolver.py:791）；
            // 策略应答留空，由 `event_upstream` 按来源合成可读标签。
            up_name: if policy {
                Cow::Borrowed("")
            } else {
                Cow::Borrowed(CACHE_DIRECT_UP_NAME)
            },
            servfail_reason: None,
            // 2.1.17：缓存快路径不经过答案过滤（过滤只发生在解析路径）。
            private_answers_filtered: 0,
        });
    }
    // <<< PATCH242A P1-1 dns-fast-outcome END
    // 完整路径：解析 question → 校验 → resolve → 组应答。
    // 采样日志（P1-3）：**限流 + debug 级**，不进 info 级日志（旧实现每 1000 包一条
    // `tracing::info!`，生产 INFO 级日志被热路径灌满）。
    rate_limited_debug("parse_sample", raw.len() as u64);
    let msg = match parse_message(raw) {
        Ok(m) => m,
        // 报文解析失败 → FORMERR（旧实现 `?` 返回 None → 兜底 SERVFAIL，P0-4 实测
        // 「该回 FORMERR 却回 SERVFAIL」的 11 例畸形包即此路径）。
        Err(_) => return Some(malformed_outcome(raw, "wire-parse-failed")),
    };
    let q = match msg.questions.first() {
        Some(q) => q,
        // qd=0 / 无 question：FORMERR，且**未进解析引擎**（不计上游）。
        None => return Some(malformed_outcome(raw, "empty-question")),
    };
    // ---- qclass 校验（P0-4）----
    // qclass=0 是**非法** class（RFC 1035 只定义 1..255）→ FORMERR。
    // 其余非 IN 的 class（CH/HS/ANY…）本服务不提供 → NOTIMP。
    // 旧实现完全不校验 qclass（`answer_fast` 只是不命中），畸形查询照样被解析。
    if q.qclass == 0 {
        return Some(malformed_outcome(raw, "bad-qclass"));
    }
    if q.qclass != CLASS_IN {
        return Some(notimp_outcome(raw));
    }
    // ---- qtype 三分派（P0-4 / 2.1.29）----
    //
    // 1. **受理名单**（`SUPPORTED_QTYPES`）→ 正常解析 + 编码 + 缓存；
    // 2. **必须拒绝**（AXFR/IXFR/ANY/TYPE0/OPT/TSIG/TKEY/NULL/NSEC 族…）→ NOTIMP，
    //    绝不静默降级成 A（旧实现三处 `_ => "A"` 让这些查询拿到 A 记录）；
    // 3. **其余未知/其他合法 qtype** → **透传**（按原始 u16 发上游、原样回传、不缓存，
    //    见 `ebpdns_resolver::passthrough`）。注意这不是"放行"：拒绝名单仍优先，
    //    ANY/AXFR 等**永远不会**进透传支。
    let domain = q.name.trim_end_matches('.').to_ascii_lowercase();
    // **2.1.49（AUD-16）**：入口拒绝控制字符（含 `\n` / `\r` / ESC）。这些名字既不是
    // 合法主机名，也会污染 resolver 的 debug/trace；不要把它们送进解析引擎。
    if domain.chars().any(char::is_control) {
        return Some(malformed_outcome(raw, "invalid-qname"));
    }
    let qtype = match classify_qtype(q.qtype) {
        QtypeClass::Rejected => return Some(notimp_outcome(raw)),
        QtypeClass::Supported(n) => n,
        QtypeClass::Passthrough => {
            if domain.is_empty() {
                return Some(malformed_outcome(raw, "empty-question"));
            }
            let res = resolver.clone().resolve_passthrough(&domain, q.qtype).await;
            return Some(finish_passthrough_outcome(raw, res));
        }
    };
    if domain.is_empty() {
        // **[历史归因]** 根/空域名：FORMERR（对齐 Python `answer_raw` → `build_error_response(raw, 1)`），
        // 且**未进解析引擎**（不进 resolve、不算上游）。
        return Some(malformed_outcome(raw, "empty-question"));
    }
    let qtype = qtype.to_string();
    let res = resolver
        .clone()
        .resolve(
            &domain,
            &qtype,
            ResolveOpts {
                silent: false,
                counted: true,
                force_refresh: false,
                client_ip: None,
                depth: 0,
                // 数据面从不读 `res.trace`（只有 api.rs 的手动查询会序列化它）：
                // 关闭后热路径连 `format!` 都不发生。
                trace: false,
                ttl_cap: None,
            },
        )
        .await;
    Some(finish_outcome(raw, res))
}

/// 畸形/未进解析引擎的统一应答：**FORMERR**（组包兜底 SERVFAIL）。
///
/// `resolved=false` → total 由 [`log_and_count`] 补计（P1-5：旧实现这几条路径
/// 只计 miss 不计 total，破坏 `total == hit + miss`）；`source=Malformed`
/// → 计 error 但**不计上游**（P1-5/P1-6 的唯一判据）。
///
/// **2.1.21（DEF-220-04 修复：所有"本地错误应答"共用同一形状）**：
/// 与 [`notimp_outcome`] 一样走 [`simple_outcome`]（同一 `qdcount` 策略），
/// 因此 qd 只取决于"question 段能否解析"，与畸形种类**无关**。
fn malformed_outcome(raw: &[u8], reason: &str) -> AnswerOutcome {
    simple_outcome(raw, RCODE_FORMERR, AnswerSource::Malformed, Some(reason))
}

/// **2.1.19（修复项 5-④）**：NOTIMP 类本地应答的**唯一**构造入口。
///
/// 用途：把"内容不受支持 ⇒ 本地直接回 NOTIMP、从未发上游"这一语义**显式**落到
/// [`AnswerSource::Unsupported`] 与 `error_reason = REASON_UNSUPPORTED` 上，
/// 使事件「上游解析」列不再与"畸形报文"共用同一文案。
///
/// **2.1.21（DEF-220-04）**：与 [`malformed_outcome`] **同一个**构造器
/// （[`simple_outcome`]，只差 rcode）⇒ `qdcount` 策略统一。改前 QR=1 与 opcode≠0
/// 走 `simple_outcome`，而 70 字节 label / 空 question 走 `malformed_outcome`
/// 里**另一条**兜底分支（`build_error_response_short`，qd=0）⇒ 同一类"无法解析
/// 问题段"的畸形包出现 `qd=1,len=25` 与 `qd=0,len=12` 两套形状。
fn notimp_outcome(raw: &[u8]) -> AnswerOutcome {
    simple_outcome(
        raw,
        RCODE_NOTIMP,
        AnswerSource::Unsupported,
        Some(REASON_UNSUPPORTED),
    )
}

/// 无 answer 段的简单应答（NOTIMP / FORMERR / NXDOMAIN…）+ 显式来源口径。
///
/// `raw.len() >= 12` 时回显 question（`build_simple_response`），否则合成最小头，
/// 保证**任何**畸形输入都有可发送的应答（不会退化成空 Vec → 调用方丢包）。
///
/// **2.1.21（DEF-220-04 修复：`qdcount` 策略唯一且写入验收条款）**
///
/// 全树**只有本函数**（+ 它内部的两级兜底）构造"无 answer 段的本地应答"，
/// `malformed_outcome`（FORMERR）与 `notimp_outcome`（NOTIMP）都走它，
/// 因此下面两条规则对**所有**本地错误应答成立、且与畸形种类**无关**：
///
/// | 情形 | `qdcount` | 典型长度 | 依据 |
/// |---|---|---|---|
/// | question 段**可解析**（含 QR=1 / opcode≠0 的正常形状包） | **1**（回显问题段） | 12 + qbytes | RFC 1035：回显 question 是最精确的应答 |
/// | question 段**不可解析**（70 字节 label / 压缩指针环 / 空 question / 长度不足 12 字节） | **0**（不写 question 段） | 12 | 不能声明一段并不存在的内容 |
///
/// `qdcount` 由**实际写入的字节**决定（`qbytes.is_empty()`），因此"声明的段数"
/// 与"报文里真实有的段数"**永远自洽**——这正是 2.1.20（A-09）想修的东西，
/// 只是当时 `malformed_outcome` 还留着一条 `build_error_response_short` 旁路。
/// 矩阵单测见 `crates/ebpdns-server/src/dns.rs::formerr_qdcount_matrix_is_consistent`。
fn simple_outcome(
    raw: &[u8],
    rcode: u8,
    source: AnswerSource,
    reason: Option<&str>,
) -> AnswerOutcome {
    let resp = build_simple_response(raw, rcode)
        .or_else(|| build_error_response_short(raw, rcode))
        .unwrap_or_default();
    AnswerOutcome {
        resp,
        is_hit: false,
        is_cache_direct: false,
        // 未进解析引擎：total 由 `log_and_count` 补计。
        resolved: false,
        source,
        error_reason: reason.map(str::to_string),
        rule: None,
        up_name: Cow::Borrowed(""),
        // `simple_outcome` 只产出 FORMERR/NOTIMP/NXDOMAIN 类应答（`rcode` 由参数给定），
        // 不可能是 SERVFAIL，故无归因（`servfail_reason_of` 会按 rcode 判定）。
        servfail_reason: None,
        // 未进解析引擎 ⇒ 不可能发生答案过滤。
        private_answers_filtered: 0,
    }
}

/* ======================= 2.1.29：qtype 三分派 + 未知类型透传 ======================= */

/// qtype 三分派（数据面受理判定的**唯一**分类器，判据全部来自
/// `ebpdns_proto::constants`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QtypeClass {
    /// 受理名单内：解析 + 编码 + 缓存。
    Supported(&'static str),
    /// 必须拒绝：`NOTIMP`（区传送 / 元查询 / 保留码 / DNSSEC 语义类型）。
    Rejected,
    /// 其他合法 qtype：按原始 `u16` 发上游、原样回传、**不缓存**。
    Passthrough,
}

/// 数据面唯一分类入口（三支互斥且完备，由 proto 单测钉死）。
fn classify_qtype(t: u16) -> QtypeClass {
    if let Some(n) = qtype_name(t) {
        QtypeClass::Supported(n)
    } else if ebpdns_proto::constants::qtype_must_reject(t) {
        QtypeClass::Rejected
    } else {
        QtypeClass::Passthrough
    }
}

/// 透传结果 → `AnswerOutcome`（**不解析、不重新编码 RDATA**）。
///
/// 成功时 `resp` 就是上游报文，仅改写 12 字节头：
/// - ID 回显客户端 query id；
/// - flags = `(客户端 flags & FLAG_KEEP_MASK) | QR | RA | 上游 TC | 上游 rcode`
///   —— 与 [`ebpdns_proto::response::build_response_header`] 的既有位运算同源；
/// - 段计数 / question / answer / authority / additional **原样保留**。
///
/// 超过客户端 EDNS bufsize 时退化为"TC=1 + 只回显 question"（复用
/// [`build_udp_response`]），既不放大、也不会产生"截断到一半的 RR"。
fn finish_passthrough_outcome(raw: &[u8], res: PassthroughResult) -> AnswerOutcome {
    let mut o = AnswerOutcome {
        resp: Vec::new(),
        is_hit: false,
        is_cache_direct: false,
        // 已进 resolver 的透传路径：total 由数据面唯一出口记账。
        resolved: true,
        source: if res.error {
            AnswerSource::PassthroughFailed
        } else {
            AnswerSource::Passthrough
        },
        error_reason: if res.error { res.reason.clone() } else { None },
        rule: res.rule.clone(),
        up_name: if res.up_name.is_empty() {
            Cow::Borrowed("")
        } else {
            Cow::Owned(res.up_name.clone())
        },
        servfail_reason: res.servfail_reason,
        private_answers_filtered: 0,
    };
    if let Some(upstream) = res.resp {
        if upstream.len() >= 12 {
            o.resp = relay_upstream_response(raw, upstream);
            return o;
        }
    }
    // 无上游报文：规则路径（block / forceIp）或上游失败 —— 本地构造。
    o.resp = build_simple_response(raw, res.rcode)
        .or_else(|| build_error_response(raw, res.rcode))
        .unwrap_or_default();
    if res.rule.is_some() {
        // 规则路径保持既有计数口径：`resolve()` 的 block/forceIp 结果同样不是
        // `Unsupported`（source=Upstream、reason=None），事件由
        // [`log_and_count`] 的 rule 分支落 `level="rule"`。
        o.source = AnswerSource::Upstream;
    }
    o
}

/// 透传应答：**只改 12 字节头**，其余字节原样。
fn relay_upstream_response(query: &[u8], mut resp: Vec<u8>) -> Vec<u8> {
    let qflags = u16::from_be_bytes([query[2], query[3]]);
    let rflags = u16::from_be_bytes([resp[2], resp[3]]);
    let flags =
        (qflags & FLAG_KEEP_MASK) | FLAG_QR_RA | (rflags & FLAG_TC) | (rflags & FLAG_RCODE_MASK);
    resp[0..2].copy_from_slice(&query[0..2]);
    resp[2..4].copy_from_slice(&flags.to_be_bytes());
    let info = question_edns_info(query);
    // **question 段回显客户端原始字节**：上游开启 0x20（`dnssec_0x20=true`，出厂默认）时
    // 其响应 question 是**随机大小写**；直接转发会让做 0x20 校验的严格客户端拒收。
    // 只在"上游 question 段长度 == 客户端 question 段长度"时覆盖（防御畸形响应）。
    if let Some(qbytes) = info.qbytes.as_deref() {
        let qd = u16::from_be_bytes([resp[4], resp[5]]);
        if qd == 1 && qbytes.len() >= 4 && skip_name(&resp, 12) == Some(12 + qbytes.len() - 4) {
            resp[12..12 + qbytes.len()].copy_from_slice(qbytes);
        }
    }
    // 客户端 EDNS bufSize 上限（与既有 `build_udp_response` 同口径；TCP 亦沿用）。
    if resp.len() > info.bufsize as usize {
        return build_udp_response(&UdpResp {
            raw_query: query,
            qbytes: info.qbytes.as_deref(),
            answers: &[],
            rcode: (flags & FLAG_RCODE_MASK) as u8,
            abody: None,
            abody_count: None,
            owner_name: None,
            fallback_type: TYPE_A,
            ttl_override: None,
            bufsize_cap: None,
            force_truncated: true,
            enc_owner: None,
            edns_info: Some(&info),
        })
        .unwrap_or(resp);
    }
    resp
}

/// `resolve()` 结果 → 线格式应答 + 口径（纯函数，便于单测）。
///
/// **P1-5 / P1-6**：来源口径在**这里**一次性定死（[`AnswerSource`]），后续
/// `classify_miss` / `log_and_count` 只做枚举匹配 —— 不再有「按 `rcode`/`ancount`
/// 字节启发式把 err 改判 miss」的分支，也不再有 `"empty-question"` 字符串哨兵。
fn finish_outcome(raw: &[u8], res: ResolveResult) -> AnswerOutcome {
    let error_reason = if res.error { res.reason.clone() } else { None };
    let is_hit = res.hit;
    // **2.1.17（修复项 3）**：私网答案过滤计数随结果透传（数据面唯一出口打点）。
    let private_answers_filtered = res.private_answers_filtered;
    // 规则命中信息随结果透传（规则路径的 `level="rule"` 事件唯一来源）。
    let rule = res.rule.clone();
    // 获胜上游名随结果透传（非规则路径事件的 `upstream` 列）。
    // **2.1.25**：真上游名是**运行时才知道**的 `String` ⇒ `Cow::Owned`（与旧实现逐位等价）。
    let up_name = Cow::Owned(res.up_name.clone());
    // 来源判定（**唯一判据**，全部取自 `resolve()` 的结构化结果）：
    // - 缓存直答 → Cache；
    // - 本地判定未发上游（`no-upstream`）→ Rule；
    // - 上游报错 / SERVFAIL → UpstreamFailed（计 error）；
    // - 其余（NOERROR 带答案 / NXDOMAIN / NODATA / 非 A 类型）→ Upstream（合法应答）。
    let source = if is_hit {
        AnswerSource::Cache
    } else if res.reason.as_deref() == Some(ebpdns_resolver::types::REASON_POLICY_FILTERED) {
        // **2.1.40**：本地策略短路（AAAA 屏蔽 / IPv6 关闭）—— 不计 hit/miss/upstream。
        AnswerSource::PolicyFiltered
    // >>> 242B BEGIN P1-6-finish >>> //
    } else if res.rule.is_some() && res.up_name.is_empty() {
        // **2.1.42-B（P1-6）**：block / forceIp 的 `ResolveResult` 带 rule、不带
        // `up_name`（真走上游时 `up_name` 必为获胜上游名）⇒ 本地规则直答。
        AnswerSource::RuleLocal
    } else if res.reason.as_deref() == Some("no-upstream") {
        AnswerSource::Rule
    // <<< 242B END P1-6-finish <<< //
    } else if res.error || res.rcode == RCODE_SERVFAIL {
        AnswerSource::UpstreamFailed
    } else {
        AnswerSource::Upstream
    };
    let mut o = AnswerOutcome {
        resp: Vec::new(),
        is_hit,
        // `res.hit` 就是 `resolver` 的「缓存直答」判定（`ResolveResult::hit`），
        // 因此这里可以如实透传。注意：本条路径上的 `hit` 计数由调用方
        // （`log_and_count`）负责，本字段只服务负缓存判据，见 [`count_negative_cache_hit`]。
        is_cache_direct: is_hit,
        resolved: true,
        source,
        error_reason,
        rule,
        up_name,
        // **2.1.15（P1）**：`resolve()` 的结构化 SERVFAIL 归因随结果透传
        // （`None` = 本条不是 SERVFAIL）。数据面唯一出口据此打点原因维度。
        servfail_reason: res.servfail_reason,
        // **2.1.17（修复项 3）**：私网答案过滤条数随结果透传（唯一出口据此打点）。
        private_answers_filtered,
    };
    // 无答案 / NXDOMAIN / NODATA / FORMERR → 简单响应。
    if res.error || res.rcode == 3 {
        o.resp = build_simple_response(raw, res.rcode)
            .or_else(|| build_error_response(raw, res.rcode))
            .unwrap_or_default();
        return o;
    }
    if res.empty || res.answers.is_empty() {
        o.resp = build_simple_response(raw, res.rcode)
            .or_else(|| build_error_response(raw, res.rcode))
            .unwrap_or_default();
        return o;
    }
    let inputs: Vec<AnswerInput<'_>> = res
        .answers
        .iter()
        .map(|a| AnswerInput {
            rtype: a.rtype,
            value: &a.value,
            ttl: Some(a.ttl as u32),
            name: a.name.as_deref(),
        })
        .collect();
    o.resp = build_response(
        raw,
        &res.domain,
        // `res.qtype` 已过 `answer_wire_ex` 的受理判定（P0-4），故 `None` 不可达；
        // 兜底 A 只影响「答案自带 rtype==0」的畸形条目，不会把未知查询变成 A 查询。
        qtype_code(&res.qtype).unwrap_or(ebpdns_proto::constants::TYPE_A),
        &inputs,
        res.rcode,
        None,
        None,
        res.truncated,
    )
    .or_else(|| build_simple_response(raw, res.rcode))
    .unwrap_or_default();
    o
}

/// qtype 名 → 类型码（`build_response` 的 fallback type；与 [`qtype_name`] 反向同口径）。
///
/// **单一来源** = proto 的 [`ebpdns_proto::constants::qtype_code`]；不支持的 qtype 返回
/// `None`（调用方用 [`TYPE_A`] 作 `build_response` 的兼容兜底，仅影响「答案自带
/// `rtype == 0`」的畸形条目，**不会**把未知查询变成 A 查询：那已在
/// [`answer_wire_ex`] 里被拒为 `NOTIMP`）。
fn qtype_code(name: &str) -> Option<u16> {
    ebpdns_proto::constants::qtype_code(name)
}

/* ======================= 计数口径（F05/F06） ======================= */

/// 一次应答的分类（决定遥测 level + 是否计 errors）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MissClass {
    /// 规则路径（本地判定，未发上游）。
    Rule,
    /// **2.1.40**：本地策略短路（不计 hit/miss/error/upstream，只计
    /// `policy_filtered_total`）。
    PolicyFiltered,
    /// 真正的上游解析（含 NXDOMAIN/NODATA/非 A 类型的**合法**应答）。
    Miss,
    /// 真解析失败：SERVFAIL / 无应答 / 异常。
    Err,
}

/// 分类结果：level 字符串、msg、answer 展示值、分类枚举。
struct MissLog {
    level: &'static str,
    msg: &'static str,
    answer: String,
    class: MissClass,
}

/// 唯一口径：**只有真解析失败才算 err** —— 判据是 [`AnswerSource`]（显式枚举），
/// **不再**读应答字节的 `rcode`/`ancount` 做启发式改判（P1-5）。
///
/// - [`AnswerSource::Cache`]（`is_hit`）→ `hit`：含缓存里的 NXDOMAIN/NODATA；
/// - [`AnswerSource::Rule`] → `rule`：本地判定未发上游，既不算 err 也不算 miss；
/// - [`AnswerSource::Upstream`] → `miss`：NOERROR 带答案 / NXDOMAIN / NODATA /
///   非 A 类型都是**合法应答**，`answer` 填地址或类型提示；
/// - [`AnswerSource::UpstreamFailed`] → `err`：上游全失败 / SERVFAIL / 组包失败；
/// - [`AnswerSource::Malformed`] → `err`：畸形包 / 空 question / 未进解析引擎。
/// - **2.1.19（修复项 5-④）** [`AnswerSource::Unsupported`] → `err`：NOTIMP 类
///   **本地应答**（类型/opcode 不受支持）。计数口径与 2.1.19 的 `Malformed` **逐字不变**，
///   变的只是事件文案（现在能区分"不支持"与"报文坏了"）。
///
/// `error_reason` **只**用于 err 事件的 `answer` 展示文案（可读原因），不参与分类。
///
/// UDP 与 TCP 共用本函数，保证两通道同口径。
fn classify_miss(
    is_hit: bool,
    source: AnswerSource,
    resp: &[u8],
    qtype: &str,
    error_reason: Option<&str>,
) -> MissLog {
    let info = ResponseInfo::parse(resp);
    let first_a = first_answer(resp);
    // 有地址记录时展示地址；否则展示 rcode/类型提示（NXDOMAIN / MX / NS / CNAME…）。
    let base = match &first_a {
        Some(a) => a.clone(),
        None => match info.hint(resp) {
            Some(h) => h.to_string(),
            None => format!("{qtype}(NODATA)"),
        },
    };
    // `is_hit` 与 `source == Cache` 同源（构造点保证）；这里取「或」的关系，
    // 防御性地保证「缓存直答永不判 err」（缓存里的 NXDOMAIN/NODATA 也是 hit）。
    let src = if is_hit { AnswerSource::Cache } else { source };
    match src {
        AnswerSource::Cache => MissLog {
            level: "hit",
            msg: "缓存直答",
            answer: base,
            class: MissClass::Miss,
        },
        AnswerSource::Rule => MissLog {
            level: "rule",
            msg: "规则判定(未发上游)",
            answer: base,
            class: MissClass::Rule,
        },
        // >>> 242B BEGIN P1-6-classify >>> //
        AnswerSource::RuleLocal => MissLog {
            level: "rule",
            msg: "规则直答(未发上游)",
            answer: base,
            class: MissClass::Rule,
        },
        // <<< 242B END P1-6-classify <<< //
        // **2.1.40**：本地策略短路 —— **不再是 miss**（2.1.39 的事件 level 会冒充
        // 「上游解析完成」，把 AAAA 屏蔽算进 misses）。
        AnswerSource::PolicyFiltered => MissLog {
            level: "policy",
            msg: "本地策略应答(未发上游)",
            answer: base,
            class: MissClass::PolicyFiltered,
        },
        AnswerSource::Upstream => MissLog {
            level: "miss",
            msg: "上游解析完成",
            answer: base,
            class: MissClass::Miss,
        },
        AnswerSource::UpstreamFailed => MissLog {
            level: "err",
            msg: "解析失败",
            answer: base,
            class: MissClass::Err,
        },
        // 畸形/未进解析引擎：err，`answer` 用可读原因（无原因则用应答提示值）。
        AnswerSource::Malformed => MissLog {
            level: "err",
            msg: "解析失败",
            answer: match error_reason {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => base,
            },
            class: MissClass::Err,
        },
        // **2.1.19（修复项 5-④）**：NOTIMP 类本地应答：`err` + **显式语义标签**
        // （2.1.19 与 `Malformed` 共用「解析失败」，用户看日志分不出"不支持"与"坏了"）。
        // 计数口径与 2.1.19 **逐字不变**（miss + error、不计 upstream）。
        AnswerSource::Unsupported => MissLog {
            level: "err",
            msg: "本地应答（内容不支持）",
            answer: match error_reason {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => base,
            },
            class: MissClass::Err,
        },
        // **2.1.29**：未知 qtype 透传 —— 成功按 miss + upstream 计（合法上游结论，
        // 与 `Upstream` 同口径），**不**计 error；事件文案带显式"透传"标识。
        AnswerSource::Passthrough => MissLog {
            level: "miss",
            msg: "上游解析完成（类型未知→透传）",
            answer: base,
            class: MissClass::Miss,
        },
        // 透传失败（全部上游超时/无应答）→ err（与 `UpstreamFailed` 同口径）。
        AnswerSource::PassthroughFailed => MissLog {
            level: "err",
            msg: "解析失败（类型未知→透传）",
            answer: match error_reason {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => base,
            },
            class: MissClass::Err,
        },
    }
}

/// 落遥测：按分类 level 计 resolve/hit/miss/error/upstream。
///
/// 计数口径（F05，**P1-5 起为唯一判据**）：
/// - `resolve`（= total + QPS 窗口）：**每客户端查询恰好一次**。未进 `resolve()` 的
///   路径（缓存快路径 / 畸形包 / 空 question）由本函数补计；进过 `resolve()` 的路径
///   由 `resolve()` 内部计（`ResolveOpts.counted=true`），本函数不再计，避免 total 双计。
/// - `hit`/`miss`：由 [`AnswerSource`] 决定（Cache→hit，Upstream/UpstreamFailed→miss），
///   因此 `total == hit + miss` 对**所有**进入本函数的查询成立（唯二例外是设计上
///   只计 total 的 `Rule` 路径与 `resolve()` 内部的本地抑制路径，见下）。
/// - `upstream`：**口径 = 每次真正发往上游的解析计 1**。判据是
///   `source == Upstream || source == UpstreamFailed`（**不再**用
///   `error_reason != Some("empty-question")` 这类字符串哨兵 —— 那个哨兵在
///   构造点被写成 `None` 而判据仍比较 `Some("empty-question")`，恒真，P1-6）。
/// **[历史归因]**   Python 是 `inc("upstream_queries", len(ups))` 按**并发上游条数**累加，本版
///   `ResolveResult` 没有上游个数口径，故不臆造：每查询最多计 1（不会高估）。
/// - `error`：**仅** `AnswerSource::UpstreamFailed | Malformed | Unsupported`（上游全失败 /
///   组包失败 / 畸形包 / 本地 NOTIMP）。NXDOMAIN / NODATA / 非 A 类型等**合法应答一律不计**；
///   也**不再**用「`rcode==0 && ancount>0` 就当好应答」的字节启发式（P1-5：那会把
///   已判 err 的结果改判 miss，掩盖真实错误）。
///
/// **已知的 total 口径例外**（计数设计使然，不是缺陷）：`Rule`（本地规则判定）与
/// resolver 内部的本地抑制路径（AAAA 关闭 / prefer_ipv4 / RFC 8020 直答）由
/// `resolve()` 计了 total，但按既有口径**不计 hit/miss**，因此这些查询下
/// `total > hit + miss`。`Rule` 路径的命中数由 resolver 的 `rule_hits` 单独观测。
///
/// **2.1.12**：额外收一个 `neg_telemetry: Option<&ServerTelemetry>`。
/// 负缓存命中是**服务端专有**观测（不在 resolver 的 `Telemetry` trait 表面上），
/// 而本函数的 `telemetry: &dyn Telemetry` 是刻意的（单测注入计数桩）。
/// 数据面的三个调用点都持有具体类型 `Arc<ServerTelemetry>`，直接 `Some(&telemetry)`；
/// 单测传 `None`（既有的 `total == hit + miss` 等口径断言逐字不变）。
#[allow(clippy::too_many_arguments)]
fn log_and_count(
    telemetry: &dyn Telemetry,
    neg_telemetry: Option<&ServerTelemetry>,
    domain: &str,
    qtype: &str,
    client_ip: Option<&str>,
    latency_ms: f64,
    upstream: &str,
    outcome: &AnswerOutcome,
) {
    // **2.1.41（QPS 回归修复）**：QPS 窗口与 `total` / `neg_telemetry` **彻底解耦**。
    //
    // 2.1.40 的唯一推进点是下面 `if neg_telemetry.is_none() && !outcome.resolved`
    // 分支里的 `count_query("resolve")`；而生产三条数据面出口（UDP 快路径 / UDP
    // miss / TCP）**全部**传 `Some(&telemetry)` ⇒ 该分支永不执行 ⇒ `qps_win`
    // 永不增长 ⇒ `/api/status.qps`、`/api/snapshot.qps`、`history[].qps` 恒 0
    // （实测 total 6 s +1209 而 qps=0.0）。这里**无条件**推进一次：
    // ① 本函数是数据面唯一落遥测出口，每个客户端查询恰好经过一次 ⇒ 不会双计；
    // ② 与 `neg_telemetry` 无关（None/Some 都推进）；
    // ③ 不碰 `total`（total 仍由 `note_data_plane_outcome` 从 `Σ client_rcode` 派生）。
    // >>> 245 P2-6 data-plane-gate BEGIN
    // **2.1.45（P2-6 / REV247 P2-2）**：整段记账与 `/api/reset` 的清零**互斥**。
    // 语义（明确）：reset 冻结期内到达的查询**不计入**任何计数器（不是"算进旧代"）。
    // 没有这道屏障时，一条查询的 `total`（`note_data_plane_outcome`）与分类
    // （`count_query`）可能被 reset 分到清空的两侧 ⇒ `policy/rule > total` 或
    // `total` 少计（REV247 的并发反例）。
    let _reset_gate = neg_telemetry.map(|t| t.reset_read_gate());
    // <<< 245 P2-6 data-plane-gate END
    telemetry.note_client_query();
    let log = classify_miss(
        outcome.is_hit,
        outcome.source,
        &outcome.resp,
        qtype,
        outcome.error_reason.as_deref(),
    );
    // **A7 / 2.1.12**：负缓存命中的**唯一判定点**（数据面出口）。
    //
    // 放在这里而不是 `count_wire`：UDP 快路径 / UDP miss 路径 / TCP 单连接
    // **三条出口都必经本函数**（`log_and_count` 是数据面唯一的落遥测出口），
    // 而 `count_wire` 只管字节数。判据见 [`count_negative_cache_hit`]。
    if let Some(st) = neg_telemetry {
        count_negative_cache_hit(st, outcome);
        // **2.1.18（修复项 2）**：三类**同点**观测一次落账 —— 此前是三次独立调用
        // （`note_client_rcode` / `note_servfail` / `count_cache_skipped_private`），
        // 每次各自加锁 ⇒ 读者有窗口看到
        // 「`client_rcode[2]` 已 +1 而 `servfail_total` 还没 +1」的中间态，
        // 那正好破坏 `client_rcode["2"] == servfail_total` 这条硬等式
        // （与 2.1.17 交付报告 E5 的 ±1 同型）。现在由遥测侧在**一把锁内**完成，
        // 判据/口径**逐字不变**（下面对每类的语义说明仍然有效）。
        //
        // **2.1.16（修复项 8）**：**实际发往客户端的 rcode 分布**（服务端侧自证口径）。
        //
        // 打点位置与 `servfail_total` 的**完全相同**（同一函数、同一处），因此
        // `client_rcode[2] == servfail_total` 是硬等式而不是"应该相等"。
        //
        // 这条计数的用途正是消除 2.1.15 "客户端 2 个 SERVFAIL、服务端 0"的口径缺口：
        // 客户端脚本把"超时/无应答"并入 SERVFAIL 时，服务端的
        // `client_rcode["2"]` 仍为 0 —— 于是**在服务端侧就能自证**那 2 次不是 rcode=2，
        // 而是被丢弃/无应答（`udp_dropped`、TCP 缓冲超限、`send_to` 失败）。
        // 反之若 `client_rcode["2"] > 0` 而 `servfail_total == 0`，才是真的漏计。
        //
        // **2.1.15（P1 低频 SERVFAIL）**：`servfail_total` + 原因维度的**唯一打点**。
        //
        // 为什么放在这里：`log_and_count` 是数据面（UDP 快路径 / UDP miss / TCP）
        // **唯一**的落遥测出口，而 SERVFAIL 的产出点分布在 `resolve()` 与
        // `resolve_guarded` 两处 —— 只在"出口"打点才能保证
        // `servfail_total == sum(servfail_reasons)` 且不存在漏计/双计。
        // 判据 = **真正发给客户端的报文 rcode == 2**（见 `servfail_reason_of`），
        // 与 `errors`（内部错误口径）刻意分开：上一轮两轮压测出现 0~4 个客户端
        // SERVFAIL 而 journal 无任何 ERROR，正是因为两者此前没有各自的口径。
        //
        // **2.1.17（修复项 3）**：**设计行为可观测** —— 私有/保留地址答案被
        // rebind 防护丢弃的条数（这些结果**不入缓存**，因此同键重查恒 miss）。
        //
        // 为什么放在这个唯一出口：与 `servfail_total` / `client_rcode` 同点，
        // 三个数据面出口（UDP 快路径 / UDP miss / TCP）与手动查询全部经此，
        // 不存在"漏计某条出口"的可能。`n == 0` 时函数内部 no-op。
        //
        // 审计提示（2.1.16 的真实误判）：若 `cache_skipped_private_total > 0`
        // 而 `cache.entries == 0` 或某域名同键重查恒 miss，**先看本计数** ——
        // 非零即说明"缓存不写私网答案"这条设计正在生效，不是缓存缺陷。
        let rcode = if outcome.resp.len() >= 12 {
            Some(outcome.resp[3] & 0x0F)
        } else {
            None
        };
        st.note_data_plane_outcome(
            rcode,
            servfail_reason_of(outcome),
            outcome.private_answers_filtered,
        );
    }
    // ---- **2.1.18（修复项 9）：`total` 的唯一自增点已下移到上面那次
    //      `note_data_plane_outcome`** ----
    //
    // 旧实现（2.1.17 及以前）在这里按 `!outcome.resolved` 补计 `total`，
    // 并由 `resolver::resolve()` 的入口计另一半 —— 两处都**只**看"是否进入解析引擎"，
    // 而**不看是否真的构造出了应答**。于是 `total` 与 `Σ client_rcode` 之间长期存在
    // 一个不可观测的差额（部署实例实测 `total = Σrcode + 256`：控制面 `/api/query`、
    // 启动预热等 `resolve()` 调用计了 `total` 却没有任何客户端应答）。
    //
    // 删除这两处后：`total` 与 `client_rcode` 由**同一次** `note_data_plane_outcome`
    // 在**同一分支**里各 +1 ⇒ `counters.total == Σ counters.client_rcode` 恒成立；
    // 出口登记但没有可发送报文的那些查询落到 `counters.no_response_total`（可对账）。
    //
    // 注意：`outcome.resolved` 字段**仍然保留**（它是 `resolve()` 是否参与的诊断信息，
    // 也是 `count_negative_cache_hit` 等其它判据的输入），只是不再驱动 `total`。
    //
    // **桩/外部 Telemetry 路径**：`neg_telemetry = None` 时没有 `ServerTelemetry`
    // （无法计 rcode），此时仍按旧契约把"这条查询进过出口"记到 trait 的 `resolve`
    // 类别上 —— 生产三条出口**全部**传 `Some(&telemetry)`，因此真实读数只受上面那次
    // `note_data_plane_outcome` 影响（`total` 是 `Σ client_rcode` 的派生量，
    // 且 `inc_n("total")` 已是 no-op ⇒ 这条路不可能造成双计）。
    //
    // **2.1.41**：本分支**不再推进 QPS**（`count_query("resolve")` 与 QPS 窗口已解耦）；
    // QPS 由函数入口那次无条件的 `note_client_query()` 统一推进，故 None/Some 两条
    // 路径都只推进一次、且与 `neg_telemetry` 无关。保留本行只为"外部 Telemetry 桩"
    // 的 `resolve` 类别语义（生产 no-op）。
    if neg_telemetry.is_none() && !outcome.resolved {
        telemetry.count_query("resolve");
    }
    // 分类 → hit/miss/error。**只看显式枚举，不读应答字节**（P1-5）。
    // >>> 242B BEGIN P1-6-count >>> //
    match log.class {
        // **2.1.42-B（P1-6）**：本地规则直答（block / forceIp / no-upstream）
        // 单独计 `rule`，**不计** hit/miss/error/upstream。恢复硬等式：
        // `hit + miss + policy_filtered_total + rule == total`。
        MissClass::Rule => {
            telemetry.count_query("rule");
        }
        // **2.1.40**：本地策略应答单独计数，**不计** hit/miss/error/upstream
        // <<< 242B END P1-6-count <<< //
        // （2.1.39 及以前它落到 MissClass::Miss，污染 hit_rate 的分母）。
        MissClass::PolicyFiltered => {
            telemetry.count_query("policy_filtered");
        }
        MissClass::Miss => {
            if outcome.is_hit {
                telemetry.count_query("hit");
            } else {
                telemetry.count_query("miss");
            }
        }
        MissClass::Err => {
            if outcome.is_hit {
                telemetry.count_query("hit");
            } else {
                telemetry.count_query("miss");
            }
            telemetry.count_query("error");
        }
    }
    // **2.1.29**：未知 qtype 透传计数（成功 + 失败都算"走了透传路径"）。
    // 与 `upstream` 口径的区别：`upstream` 是"发过上游"的通用计数，本键只数
    // "因为 qtype 未知而原样透传"的查询（幂等、单调，供审计区分透传与受理类型）。
    if matches!(
        outcome.source,
        AnswerSource::Passthrough | AnswerSource::PassthroughFailed
    ) {
        telemetry.count_query("passthrough_qtype");
    }
    // upstream_queries：仅当**确实有包发往上游**才计（P1-6：显式枚举判据）。
    // `Malformed`（畸形包 / 空 question / 未组包）与 `Rule`（本地判定）都**没发上游**。
    //
    // **2.1.41（字段体检修复）**：本地规则直答（block / forceIp）在本移植版按
    // `MissClass::Miss` 计（保持 `total == hit + miss` 既有口径），但它们**根本没发上游**；
    // 2.1.40 及以前仅凭 `source == Upstream` 就把它们计进 `upstream_queries`，导致
    // 该计数比物理上游请求多出全部 block/forceIp 条数（实测 240/圈）。结构化判据：
    // `res.rule.is_some()` **且** `up_name` 为空 —— block/forceIp 的 `ResolveResult`
    // 从不写 `up_name`，而 allow/group 真正走上游时 `up_name` 必为获胜上游名。
    let local_rule_answer = outcome.rule.is_some() && outcome.up_name.is_empty();
    let sent_upstream = matches!(
        outcome.source,
        AnswerSource::Upstream
            | AnswerSource::UpstreamFailed
            | AnswerSource::Passthrough
            | AnswerSource::PassthroughFailed
    );
    if !outcome.is_hit && log.class != MissClass::Rule && sent_upstream && !local_rule_answer {
        telemetry.count_query("upstream");
    }
    // ---- 规则命中 → `level="rule"` 事件（缺陷 C）----
    // 事件级别/文案取自 resolver 侧冒泡上来的 [`RuleHit`]（对齐 v1.9.162 的
    // `tel.log(d, qtype, "rule", msg, ..., upstream=<规则/白名单/分流规则>, rule=<标签>)`）。
    // **计数口径完全不变**：hit/miss/error/upstream 仍由上面的 `log.class` 决定
    // （block/forceIp/allow/group 命中照旧算 miss，`no-upstream` 照旧不计 hit/miss），
    // 因此 `total == hit + miss` 不变量不受影响。
    // 真解析失败（`MissClass::Err`）优先记 err：允许规则命中后上游仍失败时保留失败证据。
    // answer 展示值：规则自带 answer（forceIp 的强制 IP）优先，否则回退分类得到的
    // 可读值（如屏蔽 → `NXDOMAIN`），保证事件里的 answer 非空、排障可用。
    let (level, msg, answer, upstream): (&str, String, String, &str) = match &outcome.rule {
        Some(rh) if log.class != MissClass::Err => {
            let answer = if rh.answer.is_empty() {
                log.answer.clone()
            } else {
                rh.answer.clone()
            };
            ("rule", rh.msg.clone(), answer, rh.upstream.as_str())
        }
        _ => (
            log.level,
            log.msg.to_string(),
            log.answer.clone(),
            // 非规则路径：**优先用获胜上游名** —— `ResolveResult::up_name` 现在是
            // **单一**名字（此前是候选列表 `"lan235 / lan235tcp / alidoh"`，控制台
            // 看不出谁真正应答）。拿不到（未进解析引擎/本地早退）才回退调用方兜底值，
            // 调用方也没给 → **按 `outcome.source` 合成可读标签**（2.1.19 修复项 11：
            // 不再让 AAAA / other 这类路径显示 `?`）。事件 `upstream` 永不为空串。
            event_upstream(outcome.up_name.as_ref(), upstream, outcome.source),
        ),
    };
    telemetry.log(
        domain,
        qtype,
        level,
        &msg,
        latency_ms,
        client_ip,
        upstream,
        &answer,
        outcome.rule.as_ref().map(|r| r.label.as_str()),
    );
}

/* ======================= UDP 数据面 ======================= */

/// UDP 收包主循环。
async fn udp_loop(
    sock: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
    telemetry: Arc<ServerTelemetry>,
    slots: Arc<Semaphore>,
    drop_cnt: Arc<AtomicU64>,
    stop: Arc<Stop>,
    // **2.1.16（功能 7）**：本循环**自己的**停机标志（`rebind` 只停被替换的地址）。
    own: Arc<Stop>,
) {
    let mut buf = vec![0u8; UDP_RECV_BUF];
    // 复用缓冲：对端 IP 与域名每包重写，避免每包 `String` 分配（F24）。
    let mut client_scratch = String::with_capacity(48);
    let mut dom_scratch = String::with_capacity(256);
    let mut backoff = ErrBackoff::default();
    // 在途 miss 任务：停机时先等宽限，再 `shutdown()` 全部 abort（socket 随之释放）。
    let mut misses: JoinSet<()> = JoinSet::new();
    loop {
        if stop.requested() || own.requested() {
            break;
        }
        // `recv_from` 是取消安全的：被停机分支取消不会丢半包。
        let recv = tokio::select! {
            biased;
            _ = stop.wait() => break,
            _ = own.wait() => break,
            r = sock.recv_from(&mut buf) => r,
        };
        let (n, peer) = match recv {
            Ok(v) => {
                backoff.on_ok();
                v
            }
            Err(e) => {
                match backoff_step(&mut backoff, "UDP recv_from", &e) {
                    OnError::Fatal => break, // 优雅停机（不 panic、不 exit；由上层决定重启）
                    OnError::Backoff(ms) => {
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                        continue;
                    }
                }
            }
        };
        let t0 = std::time::Instant::now();
        fill_client(&mut client_scratch, peer);
        // 借用切片（F24）：命中路径不再 `buf[..n].to_vec()` 拷贝 ≤64KB。
        // 仅 miss 路径需要 `'static` 数据给 spawn 的任务，才在下面显式拷贝一次。
        let data = &buf[..n];
        // P1-3：这里原本有 `eprintln!("DEBUG recv: …")`（每 500 包一条，**绕过日志
        // 级别**、直接写 stderr，生产环境无法关闭）。已删除：接收量本身由
        // `note_data_plane` 的 top_clients/top_domains 与 `/api/status` 观测，
        // 采样日志统一走 [`rate_limited_debug`]（debug 级 + 每 1000 包一条）。
        rate_limited_debug("udp_recv", n as u64);
        // 数据面遥测：记录对端 IP + 域名 + qtype 频次（top_clients/top_domains/qtype_dist）。
        let (dom, qt) = extract_qname_into(data, &mut dom_scratch).unwrap_or(("", "other"));
        // **2.1.24（热路径分配）**：`dom` 由 `extract_qname_into` **逐标签小写**产出，
        // 因此直接走"已归一化"入口 —— 不再每包复制一份小写字符串（见该入口的文档）。
        telemetry.note_data_plane_normalized(Some(client_scratch.as_str()), dom, qt);
        // 回收已完成的 miss 任务：`JoinSet` 在 `join_next()` 之前会**保留每个已结束任务的
        // 条目**（AbortHandle/Id 槽位），高 QPS 下单轮不回收即无界增长。
        // 压测实测（24 worker / 180s / 约 100 万查询）：不回收时 90s 内 RSS +690MB、
        // P99 从 13.9ms 劣化到 25ms。TCP 路径一直有此回收，UDP 路径此前漏了。
        while misses.try_join_next().is_some() {}
        // 热路径：仅缓存命中（`answer_fast_ex` 不上游、非阻塞）才内联回发，避免阻塞整个 UDP 监听。
        // miss 一律 try_acquire 信号量后 spawn 全量解析。
        //
        // **2.1.44（UDP FastKind）**：本路径此前调 `answer_fast`（**丢弃 `FastKind`**）
        // 并硬编码 `is_hit: true, source: Cache` —— 于是 `ipv6=false` / `prefer_ipv4` 的
        // 本地策略应答（`FastKind::PolicyFiltered`）在 UDP 上被记成缓存命中：每次
        // `hit +1`、`negative_hits +1`，而 `policy_filtered_total` 恒 0（TCP 同查询却正确）。
        // 现在改用 `answer_fast_ex` 并把来源透传，**与 `answer_wire_ex`（TCP/完整路径）
        // 逐字段同口径**：策略应答只计 `policy_filtered_total`，不计 hit / 负缓存命中。
        match resolver.answer_fast_ex(data) {
            Some((resp, kind)) => {
                let policy = kind == FastKind::PolicyFiltered;
                // 控制台「实时查询日志」：内核/用户态缓存命中一行（level=hit）。
                // 计数下沉到 `log_and_count`（hit + resolve，口径与 TCP 一致）。
                let outcome = AnswerOutcome {
                    resp,
                    // 策略应答既没缓存直答、也没发上游：不得计 hit / 负缓存命中。
                    is_hit: !policy,
                    // 2.1.12：UDP 快路径 = 缓存直答（负缓存计数的唯一判据之一）。
                    is_cache_direct: !policy,
                    resolved: false,
                    source: if policy {
                        AnswerSource::PolicyFiltered
                    } else {
                        AnswerSource::Cache
                    },
                    error_reason: None,
                    // 快路径命中不产生规则事件（block 命中已在 `answer_fast_ex` 内提前返回
                    // None 降级到完整路径；allow/group 不影响缓存快路径）。
                    rule: None,
                    // 事件 `upstream` 列：缓存直答（与 `answer_wire_ex` 快路径同一文案）；
                    // 策略应答留空，由 `event_upstream` 按来源合成可读标签。
                    up_name: if policy {
                        Cow::Borrowed("")
                    } else {
                        Cow::Borrowed(CACHE_DIRECT_UP_NAME)
                    },
                    servfail_reason: None,
                    // 2.1.17（修复项 3）：缓存快路径不经过答案过滤（过滤只发生在解析路径）。
                    private_answers_filtered: 0,
                };
                log_and_count(
                    &*telemetry,
                    Some(&telemetry),
                    dom,
                    qt,
                    Some(client_scratch.as_str()),
                    elapsed_ms(t0),
                    "",
                    &outcome,
                );
                // A7：客户端字节数（收 = 收到的数据报，发 = 实际回发的应答）。
                count_wire(&telemetry, n as u64, outcome.resp.len() as u64);
                if t0.elapsed() > SLOW_HIT_WARN {
                    tracing::debug!("UDP 快路径耗时偏高（{}ms）", elapsed_ms(t0));
                }
                if sock.send_to(&outcome.resp, peer).await.is_err() {
                    // 客户端已断开，静默忽略。
                }
            }
            None => match slots.clone().try_acquire_owned() {
                Ok(perm) => {
                    spawn_miss(
                        &mut misses,
                        resolver.clone(),
                        sock.clone(),
                        telemetry.clone(),
                        data.to_vec(), // 唯一一次拷贝（spawn 需要 'static）
                        peer,
                        dom.to_string(),
                        qt,
                        perm,
                    );
                }
                Err(_) => {
                    // **闸门拒绝/丢包**（P0-5）：UDP miss 槽位耗尽 → 直接丢这条报文
                    // （DNS 客户端会重试）。旧实现只自增一个内部 `AtomicU64`，
                    // `/api/status.counters` 与 `/metrics` 都看不到，运维无法判断
                    // 「客户端超时」是内核丢包还是应用闸门丢包 —— 这正是 2.1.12
                    // 把槽位从 1024 静默降到 32 却没人发现的原因。
                    // **2.1.43-A（P2：`udp_dropped` 双源）**：`drop_cnt` **就是**
                    // 遥测的那个原子（`DnsServer::start_multi_workers` 用
                    // `telemetry.udp_dropped_handle()` 构造），因此这里只自增**一次**。
                    // 2.1.42 的 `drop_cnt.fetch_add` + `telemetry.inc_n` 是**两个**
                    // 原子各 +1（双计 + 可分叉），现在只剩这一个写点。
                    drop_cnt.fetch_add(1, Ordering::Relaxed);
                }
            },
        }
    }
    // 停机：给在途解析任务 2s 宽限，用尽即 abort（abort 后 `Arc<UdpSocket>` drop → close）。
    let _ = timeout(SHUTDOWN_UDP_DRAIN, misses.shutdown()).await;
}

/// 慢快路径告警阈值（仅 debug 日志，不影响回包）。
const SLOW_HIT_WARN: Duration = Duration::from_millis(50);

/// UDP miss 路径：有界信号量内 spawn 全量解析（panic 隔离 → SERVFAIL）。
///
/// 任务注册进 `misses`（JoinSet）而非裸 `tokio::spawn`：停机时能 abort，
/// 不会像旧实现那样「join 超时 → handle drop → 任务 detach → socket 不释放」。
#[allow(clippy::too_many_arguments)]
fn spawn_miss(
    misses: &mut JoinSet<()>,
    resolver: Arc<Resolver>,
    sock: Arc<UdpSocket>,
    telemetry: Arc<ServerTelemetry>,
    data: Vec<u8>,
    peer: SocketAddr,
    dom: String,
    qt: &'static str,
    perm: tokio::sync::OwnedSemaphorePermit,
) {
    misses.spawn(async move {
        // panic 隔离：单包解析 panic → SERVFAIL，不崩监听任务。
        let fut = async {
            let t0 = std::time::Instant::now();
            let outcome = resolve_guarded(&resolver, &data).await;
            log_and_count(
                &*telemetry,
                Some(&telemetry),
                &dom,
                qt,
                Some(&client_ip_text(peer)),
                elapsed_ms(t0),
                "",
                &outcome,
            );
            // A7：UDP miss 路径客户端字节数。
            count_wire(&telemetry, data.len() as u64, outcome.resp.len() as u64);
            let _ = sock.send_to(&outcome.resp, peer).await;
        };
        let _ = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(fut)).await;
        drop(perm);
    });
}

/// 带 panic 隔离的完整解析：panic / `None` → **FORMERR**（fail-closed，绝不退出数据面）。
///
/// P0-4：旧实现把「未进解析引擎」的路径统一兜底成 **SERVFAIL(2)**，实测 11 例畸形包
/// （长度不足 / question 截断 / qclass=0…）「该回 FORMERR 却回 SERVFAIL」。
/// 现在畸形输入由 [`answer_wire_ex`] → [`malformed_outcome`] 直接产出 FORMERR，
/// 本层的兜底分支同样回 FORMERR（真正的 SERVFAIL 只留给「上游失败 / 组包失败」）。
///
/// P1-5：`resolved=false`（total 由 [`log_and_count`] 补计）—— 旧实现这几条路径也置
/// `resolved=true`，于是只计 miss 不计 total，破坏 `total == hit + miss`。
async fn resolve_guarded(resolver: &Arc<Resolver>, raw: &[u8]) -> AnswerOutcome {
    let fut = async { answer_wire_ex(resolver, raw).await };
    match futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(fut)).await {
        Ok(Some(o)) if !o.resp.is_empty() => o,
        Ok(Some(mut o)) => {
            // 走到这里说明 `resolve()` 已跑过（total 已由它代计），只是**组包失败**：
            // 计 error（P1-5 明确把「组包失败」列为 error 判据），且上游确实被问过。
            o.resp = build_error_response(raw, RCODE_SERVFAIL)
                .or_else(|| build_error_response_short(raw, RCODE_SERVFAIL))
                .unwrap_or_default();
            o.is_hit = false;
            o.is_cache_direct = false;
            o.source = AnswerSource::UpstreamFailed;
            o.error_reason = Some("encode-failed".to_string());
            // **2.1.15（P1）**：结构化归因（组包失败）。
            o.servfail_reason = Some(ebpdns_resolver::types::ServfailReason::EncodeFailed);
            o
        }
        Ok(None) => malformed_outcome(raw, "wire-parse-failed"),
        Err(_) => {
            // panic 隔离：`resolved` 保守置 true（无法判定 `resolve()` 是否已计过 total，
            // 宁可少计一次 total 也不双计）；`source=Malformed` 保证计 error、不计上游。
            let mut o = malformed_outcome(raw, "panic");
            o.resolved = true;
            // **2.1.15（P1）**：结构化归因（panic 隔离，fail-closed）。
            o.servfail_reason = Some(ebpdns_resolver::types::ServfailReason::Panic);
            o
        }
    }
}

/* ======================= 热路径日志限流（P1-3） ======================= */

/// 采样/限流窗口：每 `LOG_SAMPLE_EVERY` 次调用放行一条日志。
///
/// P1-3：旧实现在热路径上写了三类**不限流**的日志 —— `eprintln!("DEBUG recv…")`
/// （每 500 包，绕过日志级别）、`tracing::info!("parse_sample…")`（每 1000 包）、
/// 每个 <12 字节的包一条 `warn!`（畸形包洪水可刷爆磁盘）。现在统一走 `tracing`
/// 且**按计数采样**，并且 debug 级不进生产 INFO 日志。
const LOG_SAMPLE_EVERY: u64 = 1000;

/// 采样计数器（每个日志点一个），`false` = 本次不放行。
fn sample_hit(counter: &AtomicU64, every: u64) -> bool {
    let n = counter.fetch_add(1, Ordering::Relaxed);
    n.is_multiple_of(every)
}

/// 限流 `warn`：每 [`LOG_SAMPLE_EVERY`] 次调用放行一条（畸形包洪水下不再刷日志）。
fn rate_limited_warn(msg: &'static str, value: u64) {
    static SHORT_PKT: AtomicU64 = AtomicU64::new(0);
    if sample_hit(&SHORT_PKT, LOG_SAMPLE_EVERY) {
        tracing::warn!(value, "{}（本条为每 {} 次采样）", msg, LOG_SAMPLE_EVERY);
    }
}

/// 限流 `debug`：热路径采样日志（默认日志级别下**不输出**，排障时才开 debug）。
fn rate_limited_debug(tag: &'static str, value: u64) {
    static PARSE_SAMPLE: AtomicU64 = AtomicU64::new(0);
    if sample_hit(&PARSE_SAMPLE, LOG_SAMPLE_EVERY) {
        tracing::debug!(tag, value, "热路径采样");
    }
}

/// **A7**：数据面**客户端侧**字节计数。
///
/// 调用方是唯一的三个客户端收发出口（UDP 快路径 / UDP miss 路径 / TCP 单连接），
/// 因此这里就是 `counters.bytes_in` / `bytes_out` 的**唯一入口**：2.1.8 的
/// `ServerTelemetry::inc_n` 分支存在但全代码库**无调用点** → 两个计数器恒为 0，
/// `/metrics` 也完全没有它们（现已补 `ebpdns_bytes_in_total` / `_out_total`）。
///
/// 口径：
/// - `wire_in`  = 收到的 DNS **报文体**字节数（TCP 不含 2B 长度前缀；UDP 一个数据报）；
/// - `wire_out` = 实际**回发上线**的字节数（TCP 含 2B 长度前缀，与 `write_all` 一致）。
/// 只计真实数据面客户端流量，**不含**控制面 `/api/query`。
///
/// **2.1.12 起不再顺带记负缓存命中**：负缓存判据已下移到
/// [`count_negative_cache_hit`]（与「查询来自 UDP/TCP/控制面」无关）。旧实现把
/// `count_neg_hit()` 埋在这里，导致 `/api/query`（控制面）完全不计 —— 实测
/// 3 次控制面命中时 `cache_direct` +1、`neg_hits` 恒 Δ0。
///
/// 取具体类型 `&ServerTelemetry`（而非 `&dyn Telemetry`）：这些计数是**服务端专有**
/// 观测，不污染 resolver 的 `Telemetry` trait 表面；也因此**不需要**改动
/// `ebpdns-resolver/**`（该目录由另一代理负责）。
///
/// 不做 I/O、不持锁（仅原子自增），可安全放在热路径。
fn count_wire(telemetry: &ServerTelemetry, wire_in: u64, wire_out: u64) {
    if wire_in > 0 {
        telemetry.inc_n("bytes_in", wire_in);
    }
    if wire_out > 0 {
        telemetry.inc_n("bytes_out", wire_out);
    }
}

/// **2.1.12**：负缓存命中计数的**唯一判定点**（口径修正，见 2.1.11 遗留问题）。
///
/// 语义：`ebpdns_cache_negative_hits_total` = 「**缓存直答**里有多少条是负应答」，
/// 因此判据是 `outcome.is_cache_direct && is_negative_answer(resp)`。
///
/// 为什么必须集中在这里（而不是埋在 `dns.rs::count_wire` 的数据面出口）：
/// - 旧实现只在 **UDP 快路径 + TCP** 调用 `count_wire`，`/api/query`（控制面）**完全不计**
///   → 同一个缓存命中，走数据面计、走控制面不计，指标随"谁在查"而变；
/// - 旧判据用 `is_hit`：`resolved=true && is_hit=true`（`answer_fast` 未命中、
///   `resolve()` 内部二次命中）这条路径也会再计一次，同一个客户端查询被计两次。
///   现在由调用方传入 `resolved`（该路径的 hit 已由 `resolve()` 代计），
///   判据收窄为「**本条应答由缓存直答产生且尚未被计数**」。
///
/// 三个出口共用同一个函数（**路径无关**）：
/// - 数据面 UDP/TCP：`log_and_count` 里调用（UDP 快路径 / miss 路径 / TCP 都过这里）；
/// - 控制面 `/api/query`：`api.rs::query` 调用（补上原先完全缺失的路径）。
///
/// 与 `cache_direct` 口径自洽：`cache_direct`（=`/api/status.counters.hit`）
/// 只在「用户态缓存直答」时 +1，本计数是其**子集**，
/// 因此 `ebpdns_negcache_hit_ratio` 恒在 `0..=1`。
///
/// 纯计数、不 I/O、不持锁（仅一次原子自增），可放在热路径。
fn count_negative_cache_hit(telemetry: &ServerTelemetry, outcome: &AnswerOutcome) {
    // 半支短路：非缓存直答一律不读应答字节（热路径零额外开销），
    // 之后与 [`count_negative_wire`] 共用**同一个**负应答判据。
    if outcome.is_cache_direct {
        count_negative_wire(telemetry, &outcome.resp);
    }
}

/// **2.1.12**：`&[u8]` 入口的同一判定（控制面 `/api/query` 用）。
///
/// 控制面**没有** `AnswerOutcome`（它走 `resolver.resolve()` + JSON 渲染，不组线格式
/// 应答字节，见 `api.rs::query`）。它把「这次是缓存直答」的事实与**编码后的线格式
/// 应答**一起传进来，从而与数据面共用同一个判据 —— 不再另写一份
/// `rcode==3 || answers.is_empty()` 的判据（那正是旧实现覆盖不全的成因）。
///
/// 判据 `is_negative_answer(resp)` 与数据面**逐字节同源**。
pub fn count_negative_wire(telemetry: &ServerTelemetry, resp: &[u8]) {
    if is_negative_answer(resp) {
        telemetry.count_neg_hit();
    }
}

/// 毫秒耗时（单调钟；`as_secs_f64` 不会 panic）。
fn elapsed_ms(t0: std::time::Instant) -> f64 {
    t0.elapsed().as_secs_f64() * 1000.0
}

/// **2.1.15（P1 低频 SERVFAIL）**：本应答是否为 SERVFAIL（`rcode == 2`）。
///
/// 判据取**真正发给客户端的报文**（`ResponseInfo::parse` 读 header 低 4 位），
/// 而不是中间态的 `ResolveResult.rcode` —— 这样"客户端看到的 SERVFAIL"与
/// `servfail_total` 是同一件事，不会再出现"客户端 4 个 SERVFAIL、服务端 0 条 ERROR"
/// 这种无法对账的观测缺口（正是上一轮两轮压测的结论）。
fn servfail_reason_of(outcome: &AnswerOutcome) -> Option<&'static str> {
    if outcome.resp.len() < 12 || ResponseInfo::parse(&outcome.resp).rcode != RCODE_SERVFAIL {
        return None;
    }
    // 中间态已有结构化归因（`resolve()` 的三处 SERVFAIL 出口）→ 直接用。
    if let Some(r) = outcome.servfail_reason {
        return Some(r.as_str());
    }
    // 兜底：中间态未标记（`no-upstream` 等），按来源/原因文案归因。
    Some(match outcome.source {
        AnswerSource::Malformed => "panic",
        // 上游路径：`error_reason` 为 `encode-failed` 才是真的组包失败；其余（含
        // 上游自己回 SERVFAIL、无有效票）都归 `upstream_no_answer`
        // （超时子集由 `resolve()` 的结构化归因给出，见上）。
        AnswerSource::UpstreamFailed | AnswerSource::Upstream => {
            match outcome.error_reason.as_deref() {
                Some("encode-failed") | Some("wire-parse-failed") => "encode_failed",
                _ => "upstream_no_answer",
            }
        }
        // **2.1.29**：透传路径 —— 成功时上游若回 SERVFAIL，如实按 `upstream_no_answer`
        // 归因；失败时 `servfail_reason` 已由 resolver 结构化给出（超时/无应答）。
        AnswerSource::PassthroughFailed => "upstream_no_answer",
        AnswerSource::Passthrough => "upstream_no_answer",
        // >>> 242B BEGIN P1-6-servfail >>> //
        AnswerSource::Rule | AnswerSource::RuleLocal | AnswerSource::Cache => {
            match outcome.error_reason.as_deref() {
                // <<< 242B END P1-6-servfail <<< //
                Some("panic") => "panic",
                Some("encode-failed") | Some("wire-parse-failed") | None => "encode_failed",
                _ => "no_upstream",
            }
        }
        // **2.1.19（修复项 5-④）**：NOTIMP 类本地应答不是 panic，也不是组包失败 ——
        // 归 `no_upstream`（"没有可用的上游能处理它"），不给 panic 这种吓人的归因。
        AnswerSource::Unsupported => "no_upstream",
        // 本地策略应答不是 SERVFAIL（本分支不可达，穷举需要）。
        AnswerSource::PolicyFiltered => "no_upstream",
    })
}

/// **A7**：判断一条线格式应答是否为**负应答**（NXDOMAIN 或 NODATA）。
///
/// 纯函数、只读字节、越界安全（畸形包一律 `false`，绝不 panic）：
/// - 长度 < 12 → `false`；
/// - rcode（flags 低 4 位）== 3（NXDOMAIN）→ `true`；
/// - ANCOUNT == 0（NODATA / 空答案段）→ `true`；
/// - 其余 → `false`。
fn is_negative_answer(resp: &[u8]) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let rcode = resp[3] & 0x0F;
    if rcode == 3 {
        return true;
    }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    ancount == 0
}

/// 对端 IP 文本（仅 miss/err 日志路径调用；热路径走复用缓冲）。
fn client_ip_text(peer: SocketAddr) -> String {
    peer.ip().to_string()
}

/// 复用缓冲写入对端 IP，避免每包一次 `String` 分配。
fn fill_client(buf: &mut String, peer: SocketAddr) {
    use std::fmt::Write;
    buf.clear();
    let _ = write!(buf, "{}", peer.ip());
}

/* ======================= TCP 数据面 ======================= */

/// TCP accept 循环（backlog 由 OS 维持；连接槽信号量限流）。
async fn tcp_accept_loop(
    listener: TcpListener,
    resolver: Arc<Resolver>,
    telemetry: Arc<ServerTelemetry>,
    slots: Arc<Semaphore>,
    stop: Arc<Stop>,
    // **2.1.16（功能 7）**：本循环自己的停机标志（`rebind` 只停被替换的地址）。
    own: Arc<Stop>,
) {
    // JoinSet 持有在途连接任务：停机时统一 abort，保证 socket/fd 及时释放。
    let mut conns: JoinSet<()> = JoinSet::new();
    let mut backoff = ErrBackoff::default();
    loop {
        if stop.requested() || own.requested() {
            break;
        }
        let accept_fut = listener.accept();
        tokio::pin!(accept_fut);
        let accepted = tokio::select! {
            _ = stop.wait() => break,
            _ = own.wait() => break,
            // 回收已结束的连接任务（避免 JoinSet 无界增长）。
            Some(_) = conns.join_next(), if !conns.is_empty() => continue,
            r = &mut accept_fut => r,
        };
        let (stream, peer) = match accepted {
            Ok(v) => {
                backoff.on_ok();
                v
            }
            Err(e) => match backoff_step(&mut backoff, "TCP accept", &e) {
                OnError::Fatal => break,
                OnError::Backoff(ms) => {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    continue;
                }
            },
        };
        match slots.clone().try_acquire_owned() {
            Ok(perm) => {
                let r = resolver.clone();
                let t = telemetry.clone();
                conns.spawn(async move {
                    let _ = handle_tcp_conn(r, t, peer, stream).await;
                    drop(perm);
                });
            }
            Err(_) => {
                // 槽满：关闭新连接（对齐 server.py _conn_slots 超时即拒）。
                tracing::debug!("TCP 连接槽已满(256), 拒绝新连接");
            }
        }
    }
    // 停机：abort 剩余连接任务（30s 连接寿命不该拖住进程退出）。
    conns.shutdown().await;
}

/// 处理单条 TCP 连接：30s 总寿命、1MB 缓冲上限、按偏移推进的粘包批量处理。
async fn handle_tcp_conn(
    resolver: Arc<Resolver>,
    telemetry: Arc<ServerTelemetry>,
    peer: SocketAddr,
    mut stream: TcpStream,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut client_scratch = String::with_capacity(48);
    let mut dom_scratch = String::with_capacity(256);
    fill_client(&mut client_scratch, peer);
    let deadline = tokio::time::Instant::now() + TCP_CONN_DEADLINE;
    loop {
        if tokio::time::Instant::now() > deadline {
            break;
        }
        // 缓冲上限 1MB，超限先断开（在读出请求前判定，防恶意无帧边界投喂）。
        if buf.len() > TCP_BUF_LIMIT {
            tracing::warn!("TCP 客户端缓冲超限({} B), 断开", buf.len());
            break;
        }
        // 单次读限时 5s（对齐 settimeout(5)）。
        let read_fut = stream.read(&mut chunk);
        match timeout(TCP_READ_TIMEOUT, read_fut).await {
            Ok(Ok(0)) => break, // 对端关闭
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => return Err(e),
            Err(_) => break, // 读超时
        }
        // 批量处理缓冲内所有完整帧（按偏移推进：无 `buf = rest` 的 O(n²) 剩余拷贝）。
        let mut pos = 0usize;
        // **2.1.24**：`loop { let Some(x) = … else { break } … }` 触 `clippy::while_let_loop`；
        // 改成 `while let`：判据完全等价（"半包/无帧头"仍是本循环的正常出口）。
        // 帧长是 u16 大端，`next_frame_len` 已保证 ≤65535 且不超出缓冲。
        while let Some(frame_len) = next_frame_len(&buf[pos..]) {
            let data = &buf[pos + 2..pos + 2 + frame_len];
            pos += 2 + frame_len;
            // 数据面遥测：记录对端 IP + 域名 + qtype 频次。
            let (dom, qt) = extract_qname_into(data, &mut dom_scratch).unwrap_or(("", "other"));
            // 同 UDP 路径：`dom` 已是小写 ⇒ 走零分配入口（**2.1.24**）。
            telemetry.note_data_plane_normalized(Some(client_scratch.as_str()), dom, qt);
            let t0 = std::time::Instant::now();
            let outcome = resolve_guarded(&resolver, data).await;
            // A7：先组包再记账 —— `wire_out` 必须是**实际写上线**的字节数
            // （含 2B 长度前缀）。组包失败（理论上不可达）则不记账并断开。
            let frame = match tcp_frame(&outcome.resp) {
                Ok(f) => f,
                // 响应超 65535（不可能的正常路径），断开而非发非法帧。
                Err(_) => return Ok(()),
            };
            count_wire(&telemetry, frame_len as u64, frame.len() as u64);
            // 与 UDP 同一口径（同一 `log_and_count`）。
            log_and_count(
                &*telemetry,
                Some(&telemetry),
                dom,
                qt,
                Some(client_scratch.as_str()),
                elapsed_ms(t0),
                "",
                &outcome,
            );
            if tokio::time::timeout(TCP_READ_TIMEOUT, stream.write_all(&frame))
                .await
                .is_err()
            {
                return Ok(()); // 连接已坏，断开。
            }
        }
        if pos > 0 {
            // 只搬一次剩余半包（≤4096 字节）到缓冲头部。
            buf.drain(..pos);
        }
    }
    Ok(())
}

/// 帧游标：返回本条帧的 payload 长度（不含 2 字节长度前缀）；无完整帧返回 None。
///
/// 与 `ebpdns_proto::tcp::parse_tcp_frame` 的区别：**不复制剩余缓冲**，调用方按
/// 返回长度推进偏移即可（旧实现每帧 `data[2+len..].to_vec()`，1MB 流水线 ≈ O(n²)）。
fn next_frame_len(data: &[u8]) -> Option<usize> {
    if data.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + len {
        return None;
    }
    Some(len)
}

/* ======================= 测试 ======================= */

#[cfg(test)]
mod tests {
    use super::*;

    fn be16(v: u16) -> [u8; 2] {
        v.to_be_bytes()
    }

    /// 组装查询报文（1 个 question）。
    fn query_packet(name: &str, qtype: u16) -> Vec<u8> {
        query_packet_qclass(name, qtype, 1)
    }

    /// 组装查询报文（显式 qclass，用于 P0-4 的非法 class 回归）。
    fn query_packet_qclass(name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let nbytes = ebpdns_proto::name::encode_name(name).expect("encode");
        let mut p = vec![0u8; 12];
        p[0..2].copy_from_slice(&0x1234u16.to_be_bytes());
        p[2] = 0x01; // RD
        p[5] = 1; // qdcount
        p.extend_from_slice(&nbytes);
        p.extend_from_slice(&be16(qtype));
        p.extend_from_slice(&be16(qclass));
        p
    }

    /// 报文头 rcode（低 4 位）。
    fn rcode_of(resp: &[u8]) -> u8 {
        resp[3] & 0x0F
    }

    /// 报文头 ancount。
    fn ancount_of(resp: &[u8]) -> u16 {
        u16::from_be_bytes([resp[6], resp[7]])
    }

    /// 组装应答报文：1 个 question + `answers` 条 RR。
    /// `answers` 元素 = (owner_name_len_octets, rtype, rdlen, rdata)；
    /// owner 用单字节长度 + 标签 + 0 的未压缩形式（`own` 为空 → 单字节 0 表示根）。
    fn response_packet(
        name: &str,
        qtype: u16,
        rcode: u8,
        answers: &[(&str, u16, u16, Vec<u8>)],
    ) -> Vec<u8> {
        let q = query_packet(name, qtype);
        let mut p = q.clone();
        p[2] = 0x81; // QR + RD
        p[3] = 0x80 | (rcode & 0x0F); // RA + rcode
        p[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (own, rtype, rdlen, rdata) in answers {
            let ob = ebpdns_proto::name::encode_name(own).expect("encode owner");
            p.extend_from_slice(&ob);
            p.extend_from_slice(&be16(*rtype));
            p.extend_from_slice(&be16(1)); // class IN
            p.extend_from_slice(&0x0000_00B4u32.to_be_bytes()); // ttl 180
            p.extend_from_slice(&be16(*rdlen));
            p.extend_from_slice(rdata);
        }
        p
    }

    /// 改头部字段（qdcount / ancount），用于制造声明计数 > 实际段的畸形报文。
    fn patch_counts(pkt: &mut [u8], qd: u16, an: u16) {
        pkt[4..6].copy_from_slice(&qd.to_be_bytes());
        pkt[6..8].copy_from_slice(&an.to_be_bytes());
    }

    /* ---------- first_answer ---------- */

    #[test]
    fn first_answer_a_record() {
        let resp = response_packet(
            "a.example.",
            1,
            0,
            &[("a.example.", 1, 4, vec![1, 2, 3, 4])],
        );
        assert_eq!(first_answer(&resp).as_deref(), Some("1.2.3.4"));
    }

    #[test]
    fn first_answer_aaaa_record() {
        let mut rd = vec![0u8; 16];
        rd[0] = 0x20;
        rd[1] = 0x01;
        rd[2] = 0x0d;
        rd[3] = 0xb8;
        rd[15] = 1; // ::1 结尾
        let resp = response_packet("aaaa.example.", 28, 0, &[("aaaa.example.", 28, 16, rd)]);
        // 2001:db8::1（段内前导零压缩；IPv6 内嵌 IPv4 不做点分表示）。
        assert_eq!(first_answer(&resp).as_deref(), Some("2001:db8::1"));
    }

    #[test]
    fn first_answer_aaaa_keeps_byte_order_and_shortens_segments() {
        // 非零段的顺序不得颠倒：0102:0304:...:0f10。
        let mut rd = Vec::new();
        for i in 0..8u8 {
            rd.push(i * 2 + 1);
            rd.push(i * 2 + 2);
        }
        let resp = response_packet("v6.example.", 28, 0, &[("v6.example.", 28, 16, rd)]);
        assert_eq!(
            first_answer(&resp).as_deref(),
            Some("102:304:506:708:90a:b0c:d0e:f10")
        );
        // 全零 → "::"。
        let resp0 = response_packet(
            "z.example.",
            28,
            0,
            &[("z.example.", 28, 16, vec![0u8; 16])],
        );
        assert_eq!(first_answer(&resp0).as_deref(), Some("::"));
    }

    /// RFC 5952 §4.1/§4.2 零压缩向量。
    ///
    /// **[历史归因]** 期望值由参考实现 `socket.inet_ntop(AF_INET6, …)` 逐字节生成（Python 3，
    /// 见 v1.9.162 `dnsmsg.py` 的 IPv6 rdata 文本化口径），覆盖：最长段优先、
    /// **等长取最靠前**、单零组不压缩、前导/尾随/中间零段、无零段原样输出。
    #[test]
    fn format_ipv6_rfc5952_vectors() {
        fn v(hexs: &str) -> String {
            let mut b = Vec::new();
            let cs: Vec<char> = hexs.chars().collect();
            for p in cs.chunks(2) {
                let s: String = p.iter().collect();
                b.push(u8::from_str_radix(&s, 16).expect("hex"));
            }
            format_ipv6(&b)
        }
        // inet_ntop 实测输出（逐条对照）。
        for (hexs, want) in [
            ("20010db8000000000000000000000001", "2001:db8::1"),
            ("00000000000000000000000000000000", "::"),
            (
                "0102030405060708090a0b0c0d0e0f10",
                "102:304:506:708:90a:b0c:d0e:f10",
            ),
            ("00000000000000000000000000000001", "::1"),
            ("00010000000000000000000000000000", "1::"),
            ("00000001000000000002000000000000", "0:1:0:0:2::"),
            ("00010002000300040005000600070008", "1:2:3:4:5:6:7:8"),
            ("20010db8000000000001000000000001", "2001:db8::1:0:0:1"),
            ("00000000000000010000000000000002", "::1:0:0:0:2"),
            ("ffff0000000000000000000000000000", "ffff::"),
            ("0000ffff00000000000000000000ffff", "0:ffff::ffff"),
            ("20010db8000000000000000000000000", "2001:db8::"),
            ("0000000000000000000000000000abcd", "::abcd"),
        ] {
            assert_eq!(v(hexs), want, "format_ipv6({hexs})");
        }
        // 单零组不得压缩（1:0:2… 不能变成 1::2）。
        assert_eq!(
            format_ipv6(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            "1:0:2::"
        );
    }

    #[test]
    fn first_answer_skips_non_address_and_finds_later_a() {
        // 首条 CNAME，第二条 A → 命中第二条。
        let resp = response_packet(
            "c.example.",
            1,
            0,
            &[
                ("c.example.", 5, 4, vec![0x01, b'x', 0x00, 0x00]),
                ("c.example.", 1, 4, vec![9, 9, 9, 9]),
            ],
        );
        assert_eq!(first_answer(&resp).as_deref(), Some("9.9.9.9"));
    }

    #[test]
    fn first_answer_non_address_only_is_none() {
        let txt = b"\x03abc".to_vec();
        let resp = response_packet(
            "t.example.",
            16,
            0,
            &[("t.example.", 16, txt.len() as u16, txt)],
        );
        // 非 A/AAAA 类型：first_answer 不返回地址，但 ResponseInfo 给出类型提示。
        assert_eq!(first_answer(&resp), None);
        let info = ResponseInfo::parse(&resp);
        assert_eq!(info.rcode, 0);
        assert_eq!(info.first_type(&resp), Some(16u16));
        let hint: Option<&str> = info.hint(&resp);
        assert_eq!(hint, Some("TXT"));
    }

    #[test]
    fn first_answer_nxdomain_is_none_with_hint() {
        let resp = response_packet("nx.example.", 1, 3, &[]);
        assert_eq!(first_answer(&resp), None);
        let info = ResponseInfo::parse(&resp);
        assert_eq!(info.rcode, 3);
        let hint: Option<&str> = info.hint(&resp);
        assert_eq!(hint, Some("NXDOMAIN"));
    }

    #[test]
    fn first_answer_empty_answer_section_is_nodata() {
        // NODATA：NOERROR 且 answer 段为空。
        let resp = response_packet("nodata.example.", 1, 0, &[]);
        assert_eq!(first_answer(&resp), None);
        let info = ResponseInfo::parse(&resp);
        assert_eq!(info.rcode, 0);
        assert_eq!(info.first_type(&resp), None);
        // NODATA 由调用方（classify_miss）用 qtype 补文案：hint 返回 None。
        let hint: Option<&str> = info.hint(&resp);
        assert_eq!(hint, None);
    }

    #[test]
    fn first_answer_malformed_never_panics() {
        // 空 / 截断 / 头部声明 ancount 但无 answer 段 / rdlen 越界。
        assert_eq!(first_answer(&[]), None);
        assert_eq!(first_answer(&[0u8; 8]), None);
        let mut bogus = response_packet(
            "b.example.",
            1,
            0,
            &[("b.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        bogus[6..8].copy_from_slice(&5u16.to_be_bytes()); // ancount=5 但只有 1 条
                                                          // **[历史归因]** 头部声明数与实存 RR 数不符时的口径（fail-safe，与 Python `inet_ntop` 无关的
                                                          // 纯健壮性约定）：**不越界、不 panic**，并返回**已成功解析到的**首条 A/AAAA。
                                                          // 声明数偏大不改变已解析记录的可信度；丢弃它只会让控制台「解析值IP」/`/api/query`
                                                          // 在畸形报文上显示空值。answer 段真的读不出 RR（截断/rdlen 越界）才返回 None。
        assert_eq!(first_answer(&bogus).as_deref(), Some("1.1.1.1"));
        let mut bad_len = response_packet(
            "d.example.",
            1,
            0,
            &[("d.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        let n = bad_len.len();
        bad_len[n - 6..n - 4].copy_from_slice(&99u16.to_be_bytes()); // rdlen=99 > 剩余
        assert_eq!(first_answer(&bad_len), None);
        // 声明 5 条 + 第 1 条 rdata 越界（读不出任何 RR）→ None，且不 panic。
        let mut bogus2 = bogus.clone();
        let m = bogus2.len();
        bogus2[m - 6..m - 4].copy_from_slice(&99u16.to_be_bytes());
        assert_eq!(first_answer(&bogus2), None);
        // ResponseInfo 也不 panic。
        let _ = ResponseInfo::parse(&bad_len);
        let _ = ResponseInfo::parse(&bogus);
    }

    #[test]
    fn first_answer_declared_counts_beyond_buffer() {
        // qdcount>实际 question / ancount>实际 answer：不得越界读、不得 panic。
        let base = response_packet(
            "q.example.",
            1,
            0,
            &[("q.example.", 1, 4, vec![8, 8, 8, 8])],
        );
        assert_eq!(first_answer(&base).as_deref(), Some("8.8.8.8"));
        let mut many_q = base.clone();
        patch_counts(&mut many_q, 3, 1);
        // qd 声明 3 条、实存 1 条：**answer 段偏移不可知**（第 2 条 question 起就越界），
        // 无法可靠定位 RR → None。这与下面 an 声明偏大的情形不对称，是有意为之。
        assert_eq!(first_answer(&many_q), None);
        assert_eq!(first_answer_type(&many_q), None);
        let mut many_an = base.clone();
        patch_counts(&mut many_an, 1, 9);
        // an 声明 9 条、实存 1 条：question 偏移可定、首条 RR 在界内 → fail-safe
        // 返回该答案（不因声明数偏大而丢弃已解析结果）。
        assert_eq!(first_answer(&many_an).as_deref(), Some("8.8.8.8"));
        // 只剩 5 字节（不够 owner+10 字节 RR 头）。
        assert_eq!(first_answer(&base[..17]), None);
        assert_eq!(first_answer_type(&base[..17]), None);
        // Protocol 层也不 panic。
        let _ = ResponseInfo::parse(&many_an);
    }

    #[test]
    fn first_answer_truncated_ipv6_rdata_is_none() {
        // AAAA 但 rdlen=4（畸形）：不得读越界，直接跳过/失败。
        let resp = response_packet(
            "x.example.",
            28,
            0,
            &[("x.example.", 28, 4, vec![1, 2, 3, 4])],
        );
        assert_eq!(first_answer(&resp), None);
    }

    #[test]
    fn first_answer_follows_compression_pointer_in_question() {
        // question 名在 offset 12，answer owner 用压缩指针指回它（RFC 1035 压缩）。
        let mut p = vec![0u8; 12];
        p[2] = 0x81; // QR + RD
        p[3] = 0x80; // RA + rcode=0
        p[5] = 1; // qd=1
        let nb = ebpdns_proto::name::encode_name("q.example.").expect("encode");
        p.extend_from_slice(&nb);
        let q_off = p.len(); // question 里 name 起点
        p.extend_from_slice(&be16(1));
        p.extend_from_slice(&be16(1));
        p[6..8].copy_from_slice(&1u16.to_be_bytes()); // an=1
                                                      // answer owner：压缩指针指向 q_off（name 起点）。
        p.push(0xC0);
        p.push(q_off as u8);
        p.extend_from_slice(&be16(1));
        p.extend_from_slice(&be16(1));
        p.extend_from_slice(&0x0000_00B4u32.to_be_bytes());
        p.extend_from_slice(&be16(4));
        p.extend_from_slice(&[7, 7, 7, 7]);
        assert_eq!(first_answer(&p).as_deref(), Some("7.7.7.7"));
        assert_eq!(first_answer_type(&p), Some(1));
        // 压缩指针越界（指向报文之外）→ 不 panic（安全失败）。
        let name_off = 12usize;
        let ptr_pos = name_off + nb.len() + 4;
        let mut bad = p.clone();
        bad[ptr_pos] = 0xC0;
        bad[ptr_pos + 1] = 0xFF; // 指向 255（越界）
        let _ = first_answer(&bad);
        let _ = ResponseInfo::parse(&bad);
    }

    /* ---------- extract_qname_into（复用缓冲的借用解码） ---------- */

    /// **2.1.24（性能证据）**：`extract_qname_into` 的**每包**成本（3 标签查询）。
    ///
    /// 改前：每个标签一次 `String` 分配（`str::to_ascii_lowercase()` 生成临时串再
    /// `push_str`）⇒ 一个 3 标签查询 = 3 次堆分配。
    /// 改后：逐字符 `char::to_ascii_lowercase` 直接 `extend` 进复用缓冲 ⇒ **零分配**。
    ///
    /// 本用例给出改后的**绝对成本**（ns/包），并顺带把"小写化口径"钉死成回归断言。
    #[test]
    #[ignore = "性能测量（手动）：cargo test --release -p ebpdns-server --lib perf224 -- --ignored --nocapture"]
    fn perf224_extract_qname_cost() {
        let pkt = query_packet("WwW.ExAmPlE.CoM", 1);
        let mut scratch = String::with_capacity(256);
        for _ in 0..10_000 {
            let _ = extract_qname_into(&pkt, &mut scratch);
        }
        let n: u32 = 1_000_000;
        let t0 = std::time::Instant::now();
        let mut acc = 0usize;
        for _ in 0..n {
            let (d, q) = extract_qname_into(&pkt, &mut scratch).expect("valid qname");
            acc += d.len() + q.len();
        }
        let el = t0.elapsed();
        println!(
            "perf224 extract_qname_into: {:.1} ns/packet (n={n}, labels=3, acc={acc})",
            el.as_nanos() as f64 / n as f64
        );
        // 行为回归：删掉每标签分配后，小写化与 qtype 口径必须逐位不变。
        let (d, q) = extract_qname_into(&pkt, &mut scratch).expect("valid qname");
        assert_eq!(d, "www.example.com", "0x20 随机大小写必须仍被小写化");
        assert_eq!(q, "A");
    }

    #[test]
    fn extract_qname_lowercases_and_reads_qtype() {
        let mut scratch = String::new();
        // DNS 0x20 随机大小写：解码后必须小写（否则 top_domains 被拆成多键）。
        let q = query_packet("WwW.Example.COM.", 28);
        let (d, qt) = extract_qname_into(&q, &mut scratch).expect("decode");
        assert_eq!(d, "www.example.com");
        assert_eq!(qt, "AAAA");
        // 复用同一缓冲：第二次解码覆盖旧内容，不残留。
        let mut scratch2 = String::new();
        let q2 = query_packet("a.io.", 15);
        let (d2, qt2) = extract_qname_into(&q2, &mut scratch2).expect("decode");
        assert_eq!(d2, "a.io");
        assert_eq!(qt2, "MX");
        assert!(!scratch2.contains("example"));
    }

    #[test]
    fn extract_qname_handles_compression_and_malformed() {
        let mut scratch = String::new();
        // 头部 12 字节 + 压缩指针指向自身之前的偏移（12）→ 标签在 offset 12 处，合法。
        // 这里直接用未压缩包 + 指针自引用（ptr >= pos 必须被拒）。
        let mut evil = vec![0u8; 12];
        evil[5] = 1;
        evil.extend_from_slice(&[0xC0, 0x0C]); // 指向自己（pos=12）→ 拒绝
        evil.extend_from_slice(&be16(1));
        evil.extend_from_slice(&be16(1));
        assert_eq!(extract_qname_into(&evil, &mut scratch), None);
        // 畸形/截断一律 None，且不 panic。
        assert_eq!(extract_qname_into(&[], &mut scratch), None);
        assert_eq!(extract_qname_into(&[0u8; 11], &mut scratch), None);
        let mut trunc = query_packet("t.example.", 1);
        trunc.truncate(trunc.len() - 1); // 截断 qclass
        assert_eq!(extract_qname_into(&trunc, &mut scratch), None);
        // 标签长度越界（声明 5 字节但只有 2 字节）。
        let mut bad = vec![0u8; 12];
        bad[5] = 1;
        bad.extend_from_slice(&[5, b'a', b'b']);
        bad.extend_from_slice(&be16(1));
        bad.extend_from_slice(&be16(1));
        assert_eq!(extract_qname_into(&bad, &mut scratch), None);
    }

    /// **2.1.49（AUD-16）**：控制字符 qname 不得进入日志/遥测提取器。
    /// 旧实现会返回 `"bad\nname"`，`tracing` 一行变两行（日志注入）。
    #[test]
    fn m249_extract_qname_rejects_control_characters() {
        for name in ["bad\nname.test", "bad\rname.test", "bad\u{1b}name.test"] {
            let pkt = query_packet(name, 1);
            let mut scratch = String::new();
            assert_eq!(
                extract_qname_into(&pkt, &mut scratch),
                None,
                "qname 含控制字符必须拒绝，name={name:?}"
            );
        }
        // 普通 Unicode 标签不受影响（不能被“全非 ASCII 拒绝”误伤）。
        // `query_packet` 走生产 `encode_name`（IDNA）⇒ Unicode 标签变 punycode，
        // 这里断言的是“没有被控制字符门禁误杀”，不是原始码点。
        let pkt = query_packet("bücher.example", 1);
        let mut scratch = String::new();
        assert_eq!(
            extract_qname_into(&pkt, &mut scratch).map(|(d, _)| d),
            Some("xn--bcher-kva.example")
        );
    }

    /* ---------- skip_name ---------- */

    #[test]
    fn skip_name_boundaries() {
        // 根
        assert_eq!(skip_name(&[0], 0), Some(1));
        // 单标签 a + 根 → 3 字节
        assert_eq!(skip_name(&[1, b'a', 0], 0), Some(3));
        // 压缩指针占 2 字节
        assert_eq!(skip_name(&[0xC0, 0x00], 0), Some(2));
        // 空输入 / offset 越界
        assert_eq!(skip_name(&[], 0), None);
        assert_eq!(skip_name(&[1, b'a', 0], 5), None);
        // 非法标签长度（>63 且非指针）
        assert_eq!(skip_name(&[64, 0], 0), None);
        assert_eq!(skip_name(&[0xFF], 0), Some(2)); // 0xFF & 0xC0 == 0xC0 → 指针
                                                    // 标签声明超过缓冲（截断）→ None
        assert_eq!(skip_name(&[5, b'a'], 0), None);
        // 连续标签
        assert_eq!(skip_name(&[1, b'a', 1, b'b', 0], 0), Some(5));
    }

    /* ---------- 计数口径分类（F05/F06） ---------- */

    /// 计数口径测试桩：只记录 `count_query` 的分类，其余 trait 方法空实现。
    ///
    /// 与 `ebpdns_resolver::telemetry::Telemetry`（当前定义：`count_query`/`count_top`/
    /// `inc`/`inc_rule`/`push_latency`/`log`，全部带默认实现）**逐符号对齐**：
    /// 这里把 5 个非 `log` 方法全部显式列出（签名照抄 trait），避免依赖默认实现时
    /// 因 trait 演进出现签名不匹配。
    /// 一条落下的日志事件快照：`(level, msg, upstream, answer, rule)`。
    ///
    /// **2.1.24**：抽成 type alias（`clippy::type_complexity` 上限 250；原来那个
    /// 五元组嵌套 `Mutex<Vec<…>>` 直接超了）。
    type LogRow = (String, String, String, String, Option<String>);

    struct ClassifyCounts {
        hit: AtomicU64,
        miss: AtomicU64,
        error: AtomicU64,
        upstream: AtomicU64,
        rule: AtomicU64,
        resolve: AtomicU64,
        /// **2.1.29**：未知 qtype 透传计数（`count_query("passthrough_qtype")`）。
        passthrough: AtomicU64,
        /// **2.1.40**：本地策略短路计数（`count_query("policy_filtered")`）。
        policy: AtomicU64,
        logs: parking_lot::Mutex<Vec<LogRow>>,
    }

    impl ClassifyCounts {
        fn new() -> Self {
            Self {
                hit: AtomicU64::new(0),
                miss: AtomicU64::new(0),
                error: AtomicU64::new(0),
                upstream: AtomicU64::new(0),
                rule: AtomicU64::new(0),
                resolve: AtomicU64::new(0),
                passthrough: AtomicU64::new(0),
                policy: AtomicU64::new(0),
                logs: parking_lot::Mutex::new(Vec::new()),
            }
        }

        /// 已落下的日志事件快照（按写入顺序）。
        fn logs(&self) -> Vec<(String, String, String, String, Option<String>)> {
            self.logs.lock().clone()
        }
    }

    impl Telemetry for ClassifyCounts {
        fn count_query(&self, cat: &str) {
            let c: &AtomicU64 = match cat {
                "resolve" => &self.resolve,
                "hit" => &self.hit,
                "miss" => &self.miss,
                "error" => &self.error,
                "upstream" => &self.upstream,
                "rule" => &self.rule,
                "passthrough_qtype" => &self.passthrough,
                "policy_filtered" => &self.policy,
                _ => return,
            };
            c.fetch_add(1, Ordering::Relaxed);
        }

        fn count_top(&self, _domain: &str, _client: Option<&str>) {}

        fn inc(&self, _key: &str) {}

        fn inc_rule(&self, _key: &str) {}

        fn push_latency(&self, _ms: f64) {}

        // 参数表与 trait 定义逐字对齐：domain/qtype/hit/msg/latency_ms/client_ip/
        // upstream/answer/rule（9 个）。事件内容落进 `logs` 供断言。
        fn log(
            &self,
            _domain: &str,
            _qtype: &str,
            hit: &str,
            msg: &str,
            _latency_ms: f64,
            _client_ip: Option<&str>,
            upstream: &str,
            answer: &str,
            rule: Option<&str>,
        ) {
            self.logs.lock().push((
                hit.to_string(),
                msg.to_string(),
                upstream.to_string(),
                answer.to_string(),
                rule.map(str::to_string),
            ));
        }
    }

    /// 构造一次应答结果（`f64` 显式标注，避免整数字面量类型推断歧义）。
    ///
    /// `is_cache_direct` 由 `is_hit && !resolved` 推导，与生产路径**逐点一致**：
    /// 只有「缓存直答且未经 `resolve()`」才为真（`finish_outcome` 的
    /// `resolved=true` 分支、畸形包分支都为假）。
    ///
    /// `source`（P1-5/P1-6 的唯一计数判据）按与 `finish_outcome` /
    /// `resolve_guarded` **同一规则**推导：
    /// 命中 → `Cache`；`no-upstream` → `Rule`；未进解析引擎 → `Malformed`；
    /// 其余有错误原因 → `UpstreamFailed`；无错误原因 → `Upstream`。
    fn outcome(resp: Vec<u8>, is_hit: bool, resolved: bool, reason: Option<&str>) -> AnswerOutcome {
        let source = if is_hit {
            AnswerSource::Cache
        } else if reason == Some(ebpdns_resolver::types::REASON_POLICY_FILTERED) {
            AnswerSource::PolicyFiltered
        } else if reason == Some("no-upstream") {
            AnswerSource::Rule
        } else if !resolved {
            AnswerSource::Malformed
        } else if reason.is_some() {
            AnswerSource::UpstreamFailed
        } else {
            AnswerSource::Upstream
        };
        AnswerOutcome {
            resp,
            is_hit,
            is_cache_direct: is_hit && !resolved,
            resolved,
            source,
            error_reason: reason.map(|s| s.to_string()),
            rule: None,
            up_name: Cow::Borrowed(""),
            // 2.1.15：测试构造点默认不带 SERVFAIL 归因（需要时用
            // `outcome_servfail` 显式给出，避免 20+ 处既有断言被无关字段扰动）。
            servfail_reason: None,
            // 2.1.17（修复项 3）：测试构造点默认无答案过滤（需要时用
            // `outcome_private_filtered` 显式给出）。
            private_answers_filtered: 0,
        }
    }

    /// **2.1.17（修复项 3）**：构造一次"私网答案被丢弃"的应答
    /// （`private_answers_filtered = n`），用于钉死
    /// `counters.cache_skipped_private_total` 的数据面打点。
    fn outcome_private_filtered(n: u32) -> AnswerOutcome {
        AnswerOutcome {
            resp: response_packet("priv.example.", 1, 0, &[]),
            resolved: true,
            source: AnswerSource::Upstream,
            private_answers_filtered: n,
            ..AnswerOutcome::default()
        }
    }

    /// **2.1.15**：构造一次 SERVFAIL 应答（`rcode=2` + 显式结构化归因）。
    fn outcome_servfail(reason: ebpdns_resolver::types::ServfailReason) -> AnswerOutcome {
        AnswerOutcome {
            resp: response_packet("sf.example.", 1, 2, &[]),
            resolved: true,
            source: AnswerSource::UpstreamFailed,
            error_reason: Some("no-answer".to_string()),
            servfail_reason: Some(reason),
            ..AnswerOutcome::default()
        }
    }

    /// **2.1.16（修复项 8）：注入式对照 —— "客户端 `rcode==2` 的应答数"与
    /// `servfail_total` 必须**一一对应**。**
    ///
    /// 这条测试就是缺陷 8 的判据本体：2.1.15 两轮压测出现「客户端 2 个 SERVFAIL、
    /// `servfail_total` 恒 0、journal 无 ERROR」。判据被定死为
    /// **"真正发给客户端的报文 `rcode == 2`"**（[`servfail_reason_of`] 从应答字节读取，
    /// 不信任中间态 `ResolveResult.rcode`），因此本测试从**客户端视角**数：
    /// 把 N 条应答按 `resp[3] & 0x0F == 2` 分类，再与 `servfail_total` 比对。
    ///
    /// 覆盖 2.1.15 实测的三个出口（全部走同一 `log_and_count`）：
    /// - **UDP 快路径**语义（`is_hit=true` / `resolved=false` / `source=Cache`）；
    /// - **UDP miss** 语义（`resolved=true` / `source=UpstreamFailed`）；
    /// - **TCP** 语义（与 miss 同口径，单连接内逐帧调用）。
    ///
    /// 2.1.15 二进制上的**注入式实测**（可控 SERVFAIL 上游，见
    /// `scripts/f216-item8-inject-servfail.sh`）：UDP 25/25、TCP 20/20、
    /// 并发 UDP 32×20=640/640 —— 用户态出口无漏计；
    /// 真正的漏计口在**绕过用户态**的内核直答路径，已由
    /// 解析器负缓存路径的 rcode 门禁（`resolve.rs`）。
    #[test]
    fn s8_client_servfail_rcode_matches_servfail_total() {
        let t = ServerTelemetry::new();
        const N: usize = 7;

        // ---- 出口 1：UDP 快路径（缓存直答语义）----
        for i in 0..N {
            let mut o = outcome_servfail(ebpdns_resolver::types::ServfailReason::UpstreamTimeout);
            o.is_hit = true;
            o.is_cache_direct = true;
            o.resolved = false;
            o.source = AnswerSource::Cache;
            o.servfail_reason = None; // 快路径不标记 → 走 `servfail_reason_of` 兜底归因
            log_and_count(
                &t,
                Some(&t),
                &format!("s{i}.fast.example"),
                "A",
                None::<&str>,
                0.3,
                "",
                &o,
            );
            // 客户端视角：这条报文确实带 rcode==2。
            assert_eq!(
                o.resp[3] & 0x0F,
                RCODE_SERVFAIL,
                "构造的应答必须是 SERVFAIL"
            );
        }
        assert_eq!(
            t.servfail_total(),
            N as u64,
            "UDP 快路径出口：{N} 条客户端 SERVFAIL 必须对应 {N} 次计数"
        );

        // ---- 出口 2：UDP miss（完整解析路径）----
        for i in 0..N {
            log_and_count(
                &t,
                Some(&t),
                &format!("s{i}.miss.example"),
                "A",
                None::<&str>,
                1.0,
                "up1",
                &outcome_servfail(ebpdns_resolver::types::ServfailReason::UpstreamNoAnswer),
            );
        }
        assert_eq!(
            t.servfail_total(),
            2 * N as u64,
            "UDP miss 出口：累计必须等于客户端可见 SERVFAIL 总数"
        );

        // ---- 出口 3：TCP（与 miss 同口径）----
        for i in 0..N {
            log_and_count(
                &t,
                Some(&t),
                &format!("s{i}.tcp.example"),
                "A",
                None::<&str>,
                1.5,
                "up1",
                &outcome_servfail(ebpdns_resolver::types::ServfailReason::UpstreamTimeout),
            );
        }
        assert_eq!(
            t.servfail_total(),
            3 * N as u64,
            "三段出口累计必须一一对应（漏一条即失败）"
        );

        // ---- 不变式：`servfail_total == sum(servfail_reasons)` ----
        let reasons = t.servfail_reasons();
        assert_eq!(
            sum_of_reasons(&reasons),
            t.servfail_total(),
            "原因维度之和必须等于总数：{reasons:?}"
        );
        // 三段出口的归因分布：timeout = N(快路径兜底 encode_failed? 不) —— 只断言
        // 非零档位存在，具体分档由 `servfail_reason_of` 的既有单测界定。
        assert!(
            reasons["upstream_no_answer"].as_u64().unwrap() >= N as u64,
            "miss 段必须归到 upstream_no_answer：{reasons:?}"
        );

        // ---- 反向判据：非 SERVFAIL 的一条都不能多计 ----
        let before = t.servfail_total();
        for rc in [
            ebpdns_proto::constants::RCODE_NOERROR,
            ebpdns_proto::constants::RCODE_NXDOMAIN,
            RCODE_FORMERR,
            RCODE_NOTIMP,
        ] {
            let o = AnswerOutcome {
                resp: response_packet("ok.example.", 1, rc, &[]),
                resolved: true,
                source: AnswerSource::Upstream,
                ..AnswerOutcome::default()
            };
            log_and_count(
                &t,
                Some(&t),
                "ok.example",
                "A",
                None::<&str>,
                0.2,
                "up1",
                &o,
            );
        }
        assert_eq!(
            t.servfail_total(),
            before,
            "rcode != 2 的应答绝不增加 servfail_total（口径 = 客户端实际看到的应答码）"
        );
    }

    /// **2.1.15（P1）**：`servfail_total` 与原因维度的**唯一出口**打点验证。    ///
    /// 三条断言：
    /// 1. `rcode == 2` 的应答 → `servfail_total` +1 且落到对应原因档；
    /// 2. 非 SERVFAIL（NOERROR / NXDOMAIN / FORMERR）→ 两个计数器都不动；
    /// 3. `servfail_total == sum(servfail_reasons)` 不变式（含 5 档各打一次）。
    #[test]
    fn servfail_total_is_counted_once_at_the_single_exit() {
        let t = ServerTelemetry::new();
        // 1) 每档各一次。
        for r in [
            ebpdns_resolver::types::ServfailReason::UpstreamTimeout,
            ebpdns_resolver::types::ServfailReason::UpstreamNoAnswer,
            ebpdns_resolver::types::ServfailReason::NoUpstream,
            ebpdns_resolver::types::ServfailReason::EncodeFailed,
            ebpdns_resolver::types::ServfailReason::Panic,
        ] {
            log_and_count(
                &t,
                Some(&t),
                "sf.example",
                "A",
                None::<&str>,
                1.0,
                "",
                &outcome_servfail(r),
            );
        }
        assert_eq!(t.servfail_total(), 5, "5 档各一次 → 总数 5");
        let reasons = t.servfail_reasons();
        for k in crate::telemetry::SERVFAIL_REASONS {
            assert_eq!(reasons[k], serde_json::json!(1), "{k} 应为 1：{reasons:?}");
        }
        // 3) 不变式：总数 == 各档之和。
        assert_eq!(
            sum_of_reasons(&reasons),
            t.servfail_total(),
            "total 必须等于各档之和"
        );
        // 2) 非 SERVFAIL 不动计数：NOERROR / NXDOMAIN / FORMERR 各一次。
        for rc in [0u8, 3, 1] {
            log_and_count(
                &t,
                Some(&t),
                "ok.example",
                "A",
                None::<&str>,
                0.5,
                "",
                &outcome(
                    response_packet("ok.example.", 1, rc, &[]),
                    false,
                    true,
                    None,
                ),
            );
        }
        assert_eq!(t.servfail_total(), 5, "只有 rcode==2 计 SERVFAIL");
        // reset 归零（与 udp_dropped 同口径）。
        t.reset();
        assert_eq!(t.servfail_total(), 0);
        assert_eq!(sum_of_reasons(&t.servfail_reasons()), 0);
    }

    /// 原因维度快照求和（不变式用）。
    fn sum_of_reasons(v: &serde_json::Value) -> u64 {
        v.as_object()
            .map(|m| m.values().filter_map(|x| x.as_u64()).sum())
            .unwrap_or(0)
    }

    /// 构造一次「命中规则」的应答结果（供 `level="rule"` 事件测试）。
    // >>> 242B BEGIN T-dns-helper >>> //
    fn outcome_rule(
        resp: Vec<u8>,
        is_hit: bool,
        resolved: bool,
        reason: Option<&str>,
        rule: RuleHit,
    ) -> AnswerOutcome {
        // **2.1.42-B（P1-6）**：正常 block/forceIp 的 `ResolveResult` 带 rule、不带
        // up_name ⇒ `finish_outcome` 会判 `RuleLocal`。测试直接构造 outcome 时按同一
        // 结构化判据补上来源（reason=Some 的"规则命中后上游失败"仍保留原来源）。
        let mut o = outcome(resp, is_hit, resolved, reason);
        o.rule = Some(rule);
        if o.source == AnswerSource::Upstream {
            o.source = AnswerSource::RuleLocal;
        }
        o
    }
    // <<< 242B END T-dns-helper <<< //

    #[test]
    fn classify_nxdomain_is_miss_not_error() {
        let resp = response_packet("nx.example.", 1, 3, &[]);
        let log = classify_miss(false, AnswerSource::Upstream, &resp, "A", None);
        assert_eq!(log.class, MissClass::Miss);
        assert_eq!(log.level, "miss");
        assert_eq!(log.answer, "NXDOMAIN");
    }

    #[test]
    fn classify_non_address_answer_is_miss_with_type_hint() {
        let mx = vec![0u8, 10, 1, b'm', 0];
        let resp = response_packet(
            "m.example.",
            15,
            0,
            &[("m.example.", 15, mx.len() as u16, mx)],
        );
        let log = classify_miss(false, AnswerSource::Upstream, &resp, "MX", None);
        assert_eq!(log.class, MissClass::Miss);
        assert_eq!(log.level, "miss");
        assert_eq!(log.answer, "MX");
        // CNAME-only（无地址记录）同样不判 err。
        let cn = vec![0x01, b'x', 0x00, 0x00];
        let resp2 = response_packet("c.example.", 5, 0, &[("c.example.", 5, 4, cn)]);
        let log2 = classify_miss(false, AnswerSource::Upstream, &resp2, "CNAME", None);
        assert_eq!(log2.class, MissClass::Miss);
        assert_eq!(log2.answer, "CNAME");
    }

    #[test]
    fn classify_nodata_and_servfail() {
        // NODATA：合法应答 → miss，answer 填 qtype(NODATA)。
        let nodata = response_packet("n.example.", 1, 0, &[]);
        let log = classify_miss(false, AnswerSource::Upstream, &nodata, "A", None);
        assert_eq!(log.class, MissClass::Miss);
        assert_eq!(log.level, "miss");
        assert_eq!(log.answer, "A(NODATA)");
        // SERVFAIL（上游全失败）：`finish_outcome` 把 rcode=2 归为 UpstreamFailed → err。
        let sf = response_packet("s.example.", 1, 2, &[]);
        let log = classify_miss(false, AnswerSource::UpstreamFailed, &sf, "A", None);
        assert_eq!(log.class, MissClass::Err);
        assert_eq!(log.level, "err");
        // 上游全失败（resolve 报 no-answer）→ err。
        let log = classify_miss(
            false,
            AnswerSource::UpstreamFailed,
            &sf,
            "A",
            Some("no-answer"),
        );
        assert_eq!(log.class, MissClass::Err);
        // 无可用上游 → rule（未发上游），不算 err。
        let log = classify_miss(false, AnswerSource::Rule, &sf, "A", Some("no-upstream"));
        assert_eq!(log.class, MissClass::Rule);
        assert_eq!(log.level, "rule");
        // 畸形包 → err，answer 用可读原因（P1-5：不再被字节启发式改判 miss）。
        let log = classify_miss(
            false,
            AnswerSource::Malformed,
            &sf,
            "A",
            Some("short-packet"),
        );
        assert_eq!(log.class, MissClass::Err);
        assert_eq!(log.answer, "short-packet");
    }

    /// P1-5 回归（原缺陷）：**已判 err 的结果不得因「应答字节看起来正常」被改判 miss**。
    ///
    /// 旧实现在 `classify_miss` 末尾有 `rcode == 0 && ancount > 0 → miss` 的兜底，
    /// 于是一条 **NOERROR 带 A 记录但上游随后失败**（如组包失败 / 上游中断）的查询
    /// 会被记成 miss，`errors` 计数器永远看不到它。
    #[test]
    fn classify_error_is_not_masked_by_good_looking_bytes() {
        // 应答字节完全正常（NOERROR + 1 条 A）。
        let good = response_packet(
            "g.example.",
            1,
            0,
            &[("g.example.", 1, 4, vec![9, 9, 9, 9])],
        );
        let log = classify_miss(
            false,
            AnswerSource::UpstreamFailed,
            &good,
            "A",
            Some("encode-failed"),
        );
        assert_eq!(
            log.class,
            MissClass::Err,
            "上游/组包失败必须记 err，不能被 rcode/ancount 启发式改判 miss"
        );
    }

    #[test]
    fn classify_cache_hit_including_negative_is_hit() {
        let ans = response_packet(
            "h.example.",
            1,
            0,
            &[("h.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        let log = classify_miss(true, AnswerSource::Cache, &ans, "A", None);
        assert_eq!(log.level, "hit");
        assert_eq!(log.answer, "1.1.1.1");
        // 缓存 NXDOMAIN 命中：旧实现判 err（answer 空），现在必须是 hit。
        let nx = response_packet("nx.example.", 1, 3, &[]);
        let log = classify_miss(true, AnswerSource::Cache, &nx, "A", None);
        assert_eq!(log.level, "hit");
        assert_eq!(log.answer, "NXDOMAIN");
    }

    #[test]
    fn log_and_count_total_equals_hit_plus_miss_and_no_double_total() {
        let t = ClassifyCounts::new();
        // 快路径命中：resolved=false → 本函数补计 resolve；hit=1。
        let ans = response_packet(
            "h.example.",
            1,
            0,
            &[("h.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        log_and_count(
            &t,
            None,
            "h.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome(ans, true, false, None),
        );
        // resolve 路径命中（answer_wire 内部二次命中）：resolved=true → 不补计 total，hit=1。
        let nx = response_packet("nx.example.", 1, 3, &[]);
        log_and_count(
            &t,
            None,
            "nx.example",
            "A",
            None::<&str>,
            2.0_f64,
            "",
            &outcome(nx, true, true, None),
        );
        // miss：`resolved=true` 表示 resolve() 内部已 count_query("resolve")，本函数不再计。
        let resp = response_packet(
            "m.example.",
            1,
            0,
            &[("m.example.", 1, 4, vec![2, 2, 2, 2])],
        );
        log_and_count(
            &t,
            None,
            "m.example",
            "A",
            None::<&str>,
            3.0_f64,
            "",
            &outcome(resp, false, true, None),
        );
        // 真失败：miss + error + upstream。
        let sf = response_packet("s.example.", 1, 2, &[]);
        log_and_count(
            &t,
            None,
            "s.example",
            "A",
            None::<&str>,
            4.0_f64,
            "",
            &outcome(sf, false, true, Some("no-answer")),
        );
        // 规则路径：不计 hit/miss/error/upstream。
        let sf2 = response_packet("r.example.", 1, 2, &[]);
        log_and_count(
            &t,
            None,
            "r.example",
            "A",
            None::<&str>,
            5.0_f64,
            "",
            &outcome(sf2, false, true, Some("no-upstream")),
        );
        let g = |a: &AtomicU64| -> u64 { a.load(Ordering::Relaxed) };
        assert_eq!(g(&t.resolve), 1, "只有快路径补计 total(resolve)");
        assert_eq!(g(&t.hit), 2);
        assert_eq!(g(&t.miss), 2, "真 miss + SERVFAIL 都计 miss");
        assert_eq!(g(&t.error), 1, "只有 SERVFAIL 计 error");
        assert_eq!(g(&t.upstream), 2, "miss 与 err 各计 1 次 upstream");
        // >>> 242B BEGIN T-rule-noupstream >>> //
        // **2.1.42-B（P1-6）**：no-upstream 也是 Rule 本地判定 ⇒ rule=1。
        assert_eq!(g(&t.rule), 1, "no-upstream 计入 rule");
        // hit + miss == 2 + 2
        // <<< 242B END T-rule-noupstream <<< //；resolve(1) 只覆盖快路径那一次，其余由 resolve() 内部计。
        assert_eq!(g(&t.hit) + g(&t.miss), 4);
    }

    /// **2.1.41（QPS 回归）**：**真实数据面出口**（`neg_telemetry=Some`）每发一次
    /// 就必须让 `qps()` +1；策略/规则/畸形包同样计入（它们都是客户端查询），
    /// 且 `total` 仍只由 `note_data_plane_outcome` 的 rcode 派生（不双计）。
    #[test]
    fn real_exit_advances_qps_once_per_query_independent_of_neg_telemetry() {
        use ebpdns_resolver::types::REASON_POLICY_FILTERED;

        let tel = ServerTelemetry::new();
        let ok = response_packet(
            "q.example.",
            1,
            0,
            &[("q.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        // ① 3 次真实出口（Some）⇒ qps == 3，total 同步 == 3。
        for _ in 0..3 {
            log_and_count(
                &tel,
                Some(&tel),
                "q.example",
                "A",
                None::<&str>,
                0.1_f64,
                "",
                &outcome(ok.clone(), true, false, None),
            );
        }
        assert_eq!(tel.qps(), 3.0, "3 次真实出口必须让 qps == 3");
        assert_eq!(tel.counters()["total"], serde_json::json!(3));
        assert_eq!(tel.counters()["hit"], serde_json::json!(3));
        // ② `neg_telemetry=None`（外部桩路径）也必须推进，且只推进一次。
        log_and_count(
            &tel,
            None,
            "q.example",
            "A",
            None::<&str>,
            0.1_f64,
            "",
            &outcome(ok.clone(), true, false, None),
        );
        assert_eq!(tel.qps(), 4.0, "QPS 必须与 neg_telemetry 无关");
        // ③ policy_filtered 是客户端查询 ⇒ 计入 QPS；不计 hit/miss。
        let policy = response_packet("p.example.", 28, 0, &[]);
        log_and_count(
            &tel,
            Some(&tel),
            "p.example",
            "AAAA",
            None::<&str>,
            0.2_f64,
            "",
            &outcome(policy, false, true, Some(REASON_POLICY_FILTERED)),
        );
        assert_eq!(tel.qps(), 5.0, "policy_filtered 必须计入 QPS");
        assert_eq!(
            tel.counters()["policy_filtered_total"],
            serde_json::json!(1)
        );
        // ④ 规则直答（block）也是客户端查询 ⇒ 计入 QPS；不计 hit/miss/upstream。
        let nx = response_packet("b.example.", 1, 3, &[]);
        log_and_count(
            &tel,
            Some(&tel),
            "b.example",
            "A",
            None::<&str>,
            0.2_f64,
            "",
            &outcome_rule(
                nx,
                false,
                true,
                None,
                RuleHit {
                    label: "屏蔽 b.example".to_string(),
                    msg: "规则屏蔽 → NXDOMAIN".to_string(),
                    answer: String::new(),
                    upstream: "规则屏蔽".to_string(),
                },
            ),
        );
        assert_eq!(tel.qps(), 6.0, "规则直答必须计入 QPS");
        assert_eq!(tel.counters()["upstream_queries"], serde_json::json!(0));
        // ⑤ 畸形包（FORMERR）也到达了出口 ⇒ 计入 QPS。
        log_and_count(
            &tel,
            Some(&tel),
            "",
            "other",
            None::<&str>,
            0.0_f64,
            "",
            &outcome(vec![0u8; 4], false, false, Some("wire-parse-failed")),
        );
        assert_eq!(tel.qps(), 7.0, "畸形包（已回 FORMERR）也是客户端查询");
        // ⑥ reset 后 QPS 归 0（要求④）。
        tel.reset();
        assert_eq!(tel.qps(), 0.0, "reset 必须清空 QPS 窗口");
    }

    /// **2.1.40**：`reason="policy_filtered"` 必须映射到 `AnswerSource::PolicyFiltered`
    /// （否则 data plane 会把它当 Upstream 记 miss）。
    #[test]
    fn finish_outcome_maps_policy_filtered_reason() {
        use ebpdns_resolver::types::{ResolveResult, REASON_POLICY_FILTERED};
        let raw = query_packet("p.example.", 28);
        let res = ResolveResult {
            reason: Some(REASON_POLICY_FILTERED.to_string()),
            rcode: 0,
            empty: true,
            ..Default::default()
        };
        let out = finish_outcome(&raw, res);
        assert_eq!(out.source, AnswerSource::PolicyFiltered);
    }

    /// **2.1.40**：本地策略应答只计 `policy_filtered_total`，
    /// **不得**计 miss/hit/upstream/error（2.1.39 的 miss 污染回归）。
    #[test]
    fn policy_filtered_is_not_counted_as_miss() {
        use ebpdns_resolver::types::REASON_POLICY_FILTERED;
        let c = ClassifyCounts::new();
        let resp = response_packet("p.example.", 1, 0, &[]);
        log_and_count(
            &c,
            None,
            "p.example",
            "AAAA",
            None,
            0.2_f64,
            "",
            &outcome(resp, false, true, Some(REASON_POLICY_FILTERED)),
        );
        assert_eq!(c.hit.load(Ordering::Relaxed), 0, "不得计 hit");
        assert_eq!(c.miss.load(Ordering::Relaxed), 0, "不得计 miss");
        assert_eq!(c.upstream.load(Ordering::Relaxed), 0, "不得计 upstream");
        assert_eq!(c.error.load(Ordering::Relaxed), 0, "不得计 error");
        assert_eq!(c.policy.load(Ordering::Relaxed), 1, "只计 policy_filtered");
        let logs = c.logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "policy", "事件 level 必须单列，不再冒充 miss");
        assert_eq!(logs[0].1, "本地策略应答(未发上游)");
    }

    #[test]
    fn log_and_count_malformed_never_counts_upstream() {
        let t = ClassifyCounts::new();
        // 畸形包（未进 resolve）→ err，但不发上游 → 不计 upstream。
        log_and_count(
            &t,
            None,
            "",
            "other",
            None::<&str>,
            0.0_f64,
            "",
            &outcome(vec![0u8; 4], false, false, Some("wire-parse-failed")),
        );
        assert_eq!(t.error.load(Ordering::Relaxed), 1);
        assert_eq!(t.upstream.load(Ordering::Relaxed), 0);
        assert_eq!(t.resolve.load(Ordering::Relaxed), 1);
    }

    /// 构造一次「带获胜上游名」的应答结果（供事件 `upstream` 列测试）。
    fn outcome_up(
        resp: Vec<u8>,
        is_hit: bool,
        resolved: bool,
        reason: Option<&str>,
        up: &str,
    ) -> AnswerOutcome {
        AnswerOutcome {
            up_name: Cow::Owned(up.to_string()),
            ..outcome(resp, is_hit, resolved, reason)
        }
    }

    /// **2.1.25（B9）同进程微基准**：事件 `upstream` 列的固定文案 ——
    /// A：`"缓存直答".to_string()`（每命中一次一次堆分配 + memcpy）；
    /// B：`Cow::Borrowed(CACHE_DIRECT_UP_NAME)`（零分配）。
    ///
    /// 显式运行：`cargo test --release -p ebpdns-server --lib bench_up_name -- --ignored --nocapture`
    #[test]
    #[ignore = "微基准：需显式 --ignored --nocapture 运行"]
    fn bench_up_name_allocating_vs_cow() {
        use std::time::Instant;
        let n = 500_000;
        let t0 = Instant::now();
        for _ in 0..n {
            let s: String = std::hint::black_box("缓存直答").to_string();
            std::hint::black_box(s.as_ptr());
        }
        let a = t0.elapsed().as_nanos() as f64 / n as f64;
        let t1 = Instant::now();
        for _ in 0..n {
            let c: Cow<'static, str> = std::hint::black_box(Cow::Borrowed(CACHE_DIRECT_UP_NAME));
            std::hint::black_box(c.as_ref().as_ptr());
        }
        let b = t1.elapsed().as_nanos() as f64 / n as f64;
        // 语义等价（同一串字节），只允许"分配次数"不同。
        assert_eq!(Cow::Borrowed(CACHE_DIRECT_UP_NAME).as_ref(), "缓存直答");
        println!(
            "\n[B9/up_name] iters={n}\n  A String::to_string : {a:.2} ns/次\n  B Cow::Borrowed     : {b:.2} ns/次\n  saved = {:.2} ns/次（每次缓存命中）",
            a - b
        );
    }

    /// 缺陷（P0）：hit/miss/err 事件的 `upstream` 列此前写**候选上游列表**
    /// （`"lan235 / lan235tcp"`）。现在写**单一获胜上游**：上游解析 → 上游 id；
    /// 缓存直答 → `缓存直答`；serve-stale → `serve-stale`；未发上游 → `无上游`；
    /// 规则路径仍用 [`RuleHit::upstream`] 文案。
    #[test]
    fn non_rule_events_carry_winning_upstream() {
        let t = ClassifyCounts::new();
        // 缓存直答（快路径命中）。
        let ans = response_packet(
            "h.example.",
            1,
            0,
            &[("h.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        log_and_count(
            &t,
            None,
            "h.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome_up(ans.clone(), true, false, None, "缓存直答"),
        );
        // 上游解析 miss（获胜上游 u2 —— 单一名字，不再是候选列表）。
        let resp = response_packet(
            "m.example.",
            1,
            0,
            &[("m.example.", 1, 4, vec![2, 2, 2, 2])],
        );
        log_and_count(
            &t,
            None,
            "m.example",
            "A",
            None::<&str>,
            2.0_f64,
            "",
            &outcome_up(resp, false, true, None, "lan235tcp"),
        );
        // NXDOMAIN 负应答（上游 id）。
        let nx = response_packet("nx.example.", 1, 3, &[]);
        log_and_count(
            &t,
            None,
            "nx.example",
            "A",
            None::<&str>,
            3.0_f64,
            "",
            &outcome_up(nx, false, true, None, "alidoh"),
        );
        // serve-stale 窗口直答。
        log_and_count(
            &t,
            None,
            "st.example",
            "A",
            None::<&str>,
            4.0_f64,
            "",
            &outcome_up(ans, true, false, None, "serve-stale"),
        );
        let logs = t.logs();
        assert_eq!(logs.len(), 4);
        assert_eq!(
            (logs[0].0.as_str(), logs[0].2.as_str()),
            ("hit", "缓存直答")
        );
        assert_eq!(
            (logs[1].0.as_str(), logs[1].2.as_str()),
            ("miss", "lan235tcp")
        );
        assert_eq!((logs[2].0.as_str(), logs[2].2.as_str()), ("miss", "alidoh"));
        assert_eq!(
            (logs[3].0.as_str(), logs[3].2.as_str()),
            ("hit", "serve-stale")
        );
        // 四条事件的 `upstream` 都必须是**单一**名字（不含候选列表分隔符）。
        for (level, _, up, _, _) in &logs {
            assert!(
                !up.contains(" / "),
                "{level} 事件的 upstream 必须是单一上游名，实际 = {up:?}"
            );
            assert!(!up.is_empty(), "{level} 事件的 upstream 不得为空串");
        }
    }

    /// 缺陷（P0）①：结果**带** `up_name`（单一获胜上游）时，事件 `upstream` 用它，
    /// 且**优先于**调用方传入的兜底值（即便兜底值是旧的候选列表形态）。
    #[test]
    fn event_upstream_prefers_single_winning_up_name() {
        let t = ClassifyCounts::new();
        let resp = response_packet(
            "w.example.",
            1,
            0,
            &[("w.example.", 1, 4, vec![3, 3, 3, 3])],
        );
        log_and_count(
            &t,
            None,
            "w.example",
            "A",
            None::<&str>,
            1.0_f64,
            // 旧形态的候选列表兜底值：必须被 up_name 覆盖。
            "lan235 / lan235tcp / alidoh",
            &outcome_up(resp, false, true, None, "alidoh"),
        );
        let logs = t.logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].0, "miss");
        assert_eq!(logs[0].2, "alidoh", "有 up_name → 写单一获胜上游名");
    }

    /// 缺陷（P0）②：结果**无** `up_name`（未进解析引擎：畸形包 / 空 question）时，
    /// 事件 `upstream` 回退：先调用方兜底值，调用方也没给（数据面传空串）→ `"?"`。
    /// **绝不写空串**。
    #[test]
    fn event_upstream_falls_back_when_up_name_missing() {
        let t = ClassifyCounts::new();
        // ①调用方给了兜底值 → 用兜底值。
        log_and_count(
            &t,
            None,
            "s.example",
            "A",
            None::<&str>,
            1.0_f64,
            "caller-fallback",
            &outcome(
                response_packet("s.example.", 1, 2, &[]),
                false,
                true,
                Some("no-answer"),
            ),
        );
        // ②调用方也没给（数据面一律传空串）→ **按来源合成**（2.1.19 修复项 11）。
        log_and_count(
            &t,
            None,
            "",
            "other",
            None::<&str>,
            0.0_f64,
            "",
            &outcome(vec![0u8; 4], false, false, Some("wire-parse-failed")),
        );
        let logs = t.logs();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].0, "err");
        assert_eq!(
            logs[0].2, "caller-fallback",
            "无 up_name → 回退调用方兜底值"
        );
        assert_eq!(logs[1].0, "err");
        assert_eq!(
            logs[1].2, "本地判定（未发上游）",
            "无 up_name 且无兜底值 → **按 AnswerSource 合成可读标签**（不是 `?`）"
        );
        assert!(!logs[1].2.is_empty(), "事件 upstream 永不为空串");
        assert_ne!(logs[1].2, UPSTREAM_UNKNOWN, "正常路径不得出现 `?`");
    }

    /// **2.1.18（修复项 11）**：**每一个 `AnswerSource` 都有可读标签**，
    /// 且**正常数据面路径永远不出现 `?`**（用户实测：AAAA / other 类型满屏 `?`）。
    ///
    /// 覆盖 A/AAAA/CNAME/MX/TXT/SRV/PTR/HTTPS/other 全部 qtype × 五种来源，
    /// 断言 `event_upstream("", "", source)` 非空、非 `?`、且互不相同
    /// （相同会让日志无法区分"缓存直答"与"未发上游"）。
    ///
    /// **2.1.20（F-13）**：另有下面的 `f13_*` 用例覆盖 qtype 显示口径。
    #[test]
    fn f13_qtype_log_label_keeps_common_types_distinct() {
        for (code, name) in [
            (12u16, "PTR"),
            (33, "SRV"),
            (257, "CAA"),
            (65, "HTTPS"),
            (64, "SVCB"),
            (43, "DS"),
            (44, "SSHFP"),
            (48, "DNSKEY"),
            (52, "TLSA"),
            (59, "CDS"),
            (60, "CDNSKEY"),
            (35, "NAPTR"),
            (256, "URI"),
            (15, "MX"),
            (16, "TXT"),
            (6, "SOA"),
            (2, "NS"),
            (5, "CNAME"),
        ] {
            assert_eq!(
                qtype_log_label(code),
                name,
                "qtype {code} 必须显示为 `{name}`（不得塌缩成 other）"
            );
        }
        // **2.1.29**：受理名单里的**每一个** qtype 都必须有展示名（不得落 `other`）。
        for (code, name) in ebpdns_proto::constants::SUPPORTED_QTYPES {
            assert_eq!(
                qtype_log_label(*code),
                *name,
                "受理类型 {code} 的日志展示名必须与 SUPPORTED_QTYPES 一致"
            );
        }
        // A/AAAA 仍正确。
        assert_eq!(qtype_log_label(1), "A");
        assert_eq!(qtype_log_label(28), "AAAA");
        // 真的未知码才落 `other`（保持既有兜底，不引入 panic）。
        assert_eq!(qtype_log_label(65280), "other");
        assert_eq!(qtype_log_label(0), "other");
        // 四个点名类型**互不相同**（塌缩的判据）。
        let four: std::collections::HashSet<&str> = [12u16, 33, 257, 65]
            .iter()
            .map(|c| qtype_log_label(*c))
            .collect();
        assert_eq!(four.len(), 4, "PTR/SRV/CAA/HTTPS 必须两两可区分：{four:?}");
    }

    /// **[历史归因]** 每个 `AnswerSource` 变体都必须有可读的"来源上游"标签。
    #[test]
    fn every_answer_source_has_a_readable_upstream_label() {
        use AnswerSource::*;
        // **2.1.19（修复项 5-④）**：`Unsupported` 一并纳入 —— 本数组必须**穷举**
        // 全部变体，否则"新增来源没有标签"会静默溜过（编译器不会提醒这里的遗漏）。
        let sources = [
            Cache,
            // >>> 242B BEGIN T-dns-exhaustive >>> //
            Rule,
            RuleLocal,
            Upstream,
            UpstreamFailed,
            // <<< 242B END T-dns-exhaustive <<< //
            Malformed,
            Unsupported,
            // **2.1.40**：本地策略短路（AAAA 屏蔽 / IPv6 关闭）。
            PolicyFiltered,
            // **2.1.29**：未知 qtype 透传（成功/失败）也必须各有可读标签，
            // 且与 `Unsupported`（"类型/opcode 不支持"）**不同**。
            Passthrough,
            PassthroughFailed,
        ];
        let qtypes = [
            "A",
            "AAAA",
            "CNAME",
            "MX",
            "TXT",
            "SRV",
            "PTR",
            "HTTPS",
            "other",
            "TYPE65280",
        ];
        let mut seen = Vec::new();
        for src in sources {
            let label = event_upstream("", "", src);
            assert!(!label.is_empty(), "{src:?} 的标签不得为空");
            assert_ne!(label, UPSTREAM_UNKNOWN, "{src:?} 不得回退到 `?`");
            assert!(
                !seen.contains(&label),
                "不同来源必须有不同的可读标签（{src:?} 与已有标签重复: {label}）"
            );
            seen.push(label);
            // qtype 不参与标签合成（标签只由来源决定），但这里逐一走一遍以钉死
            // "任何 qtype 都不会因为类型不同而落到 `?`"。
            for q in qtypes {
                let l2 = event_upstream("", "", src);
                assert_ne!(l2, UPSTREAM_UNKNOWN, "{src:?}/{q} 不得为 `?`");
            }
        }
        // 有一档获胜上游名时**必须**用它（哪怕来源是 Malformed）。
        for q in qtypes {
            assert_eq!(
                event_upstream("up1", "", Malformed),
                "up1",
                "{q}: 有获胜上游名时必须优先展示它"
            );
        }
        // 规则路径的兜底文案来自 `RuleHit::upstream`（不经过本函数）。
        assert_eq!(event_upstream("", "规则屏蔽", Rule), "规则屏蔽");

        // **2.1.19（修复项 5-④）**：显式断言**每个变体**都出现在上面的数组里 ——
        // 新增变体时本 match 会编译失败（"非穷举模式"），因此"忘记加进数组"
        // 从"静默漏测"变成"编译错误"。
        for src in sources {
            let _used = match src {
                Cache => "缓存直答",
                // >>> 242B BEGIN T-dns-exhaustive2 >>> //
                Rule => "本地判定（规则）",
                RuleLocal => "本地规则直答（未发上游）",
                Upstream => "上游（未记录上游名）",
                // <<< 242B END T-dns-exhaustive2 <<< //
                UpstreamFailed => "上游失败（无获胜上游）",
                Malformed => "本地判定（未发上游）",
                Unsupported => "本地应答（类型/opcode 不支持）",
                PolicyFiltered => "本地策略应答（未发上游）",
                Passthrough => "上游（类型未知→透传）",
                PassthroughFailed => "上游失败（类型未知→透传）",
            };
        }
        // 四类"非上游"本地标签两两不同（缓存/规则/畸形/不支持）。
        let locals = [
            event_upstream("", "", Cache),
            event_upstream("", "", Rule),
            event_upstream("", "", Malformed),
            event_upstream("", "", Unsupported),
        ];
        for (i, a) in locals.iter().enumerate() {
            for (j, b) in locals.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "四类本地标签必须互不相同：{locals:?}");
                }
            }
        }
        // **2.1.29**：透传标签必须与"不支持"标签不同（否则日志分不出两者）。
        assert_ne!(
            event_upstream("", "", Passthrough),
            event_upstream("", "", Unsupported),
            "透传与 NOTIMP 必须可区分"
        );
    }

    /* ---------- 缺陷 C：规则命中落 level="rule" 事件 ---------- */

    /// 规则屏蔽（NXDOMAIN）→ 事件 level=rule、带 rule 标签与 msg 文案，
    /// 且 **hit/miss/error/upstream 口径完全不变**（屏蔽仍按 miss 计）。
    #[test]
    fn rule_block_logs_level_rule_without_changing_counts() {
        let t = ClassifyCounts::new();
        let nx = response_packet("ads.blocked.test.", 1, 3, &[]);
        log_and_count(
            &t,
            None,
            "ads.blocked.test",
            "A",
            Some("192.168.0.9"),
            1.5_f64,
            "",
            &outcome_rule(
                nx,
                false,
                true,
                None,
                RuleHit {
                    label: "屏蔽 *.ads.blocked.test".to_string(),
                    msg: "规则屏蔽 → NXDOMAIN".to_string(),
                    answer: String::new(),
                    upstream: "规则屏蔽".to_string(),
                },
            ),
        );
        let logs = t.logs();
        assert_eq!(logs.len(), 1, "规则路径只落一条事件（不与 miss 重复）");
        assert_eq!(logs[0].0, "rule", "level 必须是 rule");
        assert_eq!(logs[0].1, "规则屏蔽 → NXDOMAIN");
        assert_eq!(logs[0].2, "规则屏蔽");
        assert_eq!(logs[0].3, "NXDOMAIN", "answer 回退到可读的 NXDOMAIN");
        assert_eq!(logs[0].4.as_deref(), Some("屏蔽 *.ads.blocked.test"));
        // >>> 242B BEGIN T-dns-block >>> //
        // **2.1.42-B（P1-6）**：block 是本地规则直答 ⇒ 只计 `rule`，**不再计 miss**
        // （`rule_hits` 与 `miss` 因此不重叠）。
        let g = |a: &AtomicU64| -> u64 { a.load(Ordering::Relaxed) };
        assert_eq!(g(&t.rule), 1, "block 必须计入 rule");
        assert_eq!(g(&t.miss), 0, "block 不得计入 miss");
        assert_eq!(g(&t.hit), 0);
        assert_eq!(g(&t.error), 0);
        // <<< 242B END T-dns-block <<< //
        assert_eq!(g(&t.resolve), 0, "resolved=true → resolve() 内部已计 total");
        // `upstream_queries` 口径：**只数真正发过上游的查询**。
        // **2.1.41**：规则屏蔽（block）在本移植版按 `MissClass::Miss` 计（保证
        // `total == hit + miss` 不变量），但它**没有发上游** —— 2.1.40 及以前仅凭
        // `source == Upstream` 就把这条计进 `upstream_queries`，导致该字段比
        // 物理上游请求多出全部 block/forceIp 条数。现在用
        // `rule.is_some() && up_name.is_empty()` 排除本地规则直答。
        // **[历史归因]** 这一步同时把与 Python v1.9.162 的已知差异修正回
        // Python 口径（Python 的 block 分支在 `_query_parallel` 之前 return，
        // `inc("upstream_queries", …)` 不执行 ⇒ 计 0）。
        assert_eq!(
            g(&t.upstream),
            0,
            "规则屏蔽未发上游 ⇒ 不得计 upstream_queries"
        );
    }

    /// forceIp 命中：answer 用规则强制 IP，msg/upstream 对齐 v1.9.162。
    #[test]
    fn rule_forceip_logs_rule_ip_as_answer() {
        let t = ClassifyCounts::new();
        let ok = response_packet("f.test.", 1, 0, &[("f.test.", 1, 4, vec![1, 2, 3, 4])]);
        log_and_count(
            &t,
            None,
            "f.test",
            "A",
            None::<&str>,
            0.8_f64,
            "",
            &outcome_rule(
                ok,
                false,
                true,
                None,
                RuleHit {
                    label: "强制IP *.f.test".to_string(),
                    msg: "分流规则 → 1.2.3.4".to_string(),
                    answer: "1.2.3.4".to_string(),
                    upstream: "分流规则".to_string(),
                },
            ),
        );
        let logs = t.logs();
        assert_eq!(logs[0].0, "rule");
        assert_eq!(logs[0].1, "分流规则 → 1.2.3.4");
        assert_eq!(logs[0].2, "分流规则");
        assert_eq!(logs[0].3, "1.2.3.4", "规则自带 answer 优先于分类值");
        assert_eq!(logs[0].4.as_deref(), Some("强制IP *.f.test"));
        // >>> 242B BEGIN T-dns-forceip >>> //
        // **2.1.42-B（P1-6）**：forceIp 是本地规则直答 ⇒ 计 rule，不计 miss。
        assert_eq!(t.miss.load(Ordering::Relaxed), 0, "forceIp 不得计 miss");
        assert_eq!(t.rule.load(Ordering::Relaxed), 1, "forceIp 计入 rule");
        // <<< 242B END T-dns-forceip <<< //
    }

    /// 命中但上游真失败（SERVFAIL）→ 保留 err 证据（不被 rule 覆盖），
    /// 规则命中计数已由 resolver 侧全量完成，与事件级别无关。
    #[test]
    fn rule_hit_with_upstream_error_still_logs_err() {
        let t = ClassifyCounts::new();
        let sf = response_packet("g.test.", 1, 2, &[]);
        log_and_count(
            &t,
            None,
            "g.test",
            "A",
            None::<&str>,
            9.0_f64,
            "",
            &outcome_rule(
                sf,
                false,
                true,
                Some("no-answer"),
                RuleHit {
                    label: "国内 *.g.test".to_string(),
                    msg: "分流规则 → 「domestic」组".to_string(),
                    answer: String::new(),
                    upstream: "分流规则".to_string(),
                },
            ),
        );
        let logs = t.logs();
        assert_eq!(logs[0].0, "err");
        assert_eq!(logs[0].4.as_deref(), Some("国内 *.g.test"));
    }

    /// 端到端（数据面 → 遥测）：block 规则命中 → `rule_hits.block` 全量计数 +
    /// `level="rule"` 事件 + `total == hit + miss` 口径不变。
    #[tokio::test]
    async fn blocked_query_end_to_end_counts_rule_hit_and_emits_rule_event() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;

        let tel = Arc::new(ServerTelemetry::new());
        let rule = ebpdns_rules::rule_from_json(
            serde_json::json!({"match": "*.blocked.test", "action": "block"})
                .as_object()
                .cloned()
                .expect("object"),
            ebpdns_rules::RuleSource::Local,
        )
        .expect("block 规则构造");
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![rule], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_, _, _| Vec::new())),
        );
        let raw = query_packet("ads.blocked.test.", 1);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        // 数据面口径：`answer_wire_ex` 只产出 `AnswerOutcome`，`level="rule"` 事件由
        // 调用方（UDP/TCP 循环）经 `log_and_count` 落遥测 —— 单测必须补这一步，
        // 否则遥测环里没有任何事件（此前直接断言事件存在 → 必然失败）。
        log_and_count(
            &*tel,
            Some(&tel),
            "ads.blocked.test",
            "A",
            None::<&str>,
            0.5_f64,
            "",
            &out,
        );
        assert_eq!(out.resp[3] & 0x0F, 3, "规则屏蔽应答 NXDOMAIN");
        // 缺陷 A：rule_hits 全量计数（不受事件采样影响）。
        assert_eq!(
            tel.rule_hits().get("block"),
            Some(&serde_json::json!(1)),
            "rule_hits.block"
        );
        // 缺陷 C：`level="rule"` 事件的**内容**断言见本用例末尾 ——
        // **2.1.43-A 起 `rule` 事件与 `hit`/`miss` 同档采样（10%）**，因此
        // "这一次调用一定把事件留在环里"不再成立；下面的计数断言与采样无关，
        // 仍逐字保留在原位置。
        // >>> 242B BEGIN T-dns-e2e >>> //
        // **2.1.42-B（P1-6）**：block 走 `AnswerSource::RuleLocal` ⇒
        // total=1 / miss=0 / rule=1 / hit=0，且
        // `hit + miss + policy_filtered + rule == total`。
        let c = tel.counters();
        assert_eq!(c["total"], serde_json::json!(1));
        assert_eq!(c["hit"], serde_json::json!(0));
        assert_eq!(c["miss"], serde_json::json!(0), "block 不得再计 miss");
        assert_eq!(c["rule"], serde_json::json!(1), "block 必须计 rule");
        assert_eq!(c["policy_filtered_total"], serde_json::json!(0));
        assert_eq!(
            c["total"].as_u64().unwrap(),
            c["hit"].as_u64().unwrap()
                + c["miss"].as_u64().unwrap()
                + c["policy_filtered_total"].as_u64().unwrap()
                + c["rule"].as_u64().unwrap(),
            "硬等式：hit+miss+policy_filtered+rule == total"
        );
        // <<< 242B END T-dns-e2e <<< //
        // 第二次同域名查询（屏蔽结果不入缓存 → 仍走完整规则路径）→ 计数继续累加。
        let out2 = answer_wire_ex(&resolver, &raw).await.expect("应答2");
        log_and_count(
            &*tel,
            Some(&tel),
            "ads.blocked.test",
            "A",
            None::<&str>,
            0.4_f64,
            "",
            &out2,
        );
        assert_eq!(out2.resp[3] & 0x0F, 3);
        assert_eq!(tel.rule_hits().get("block"), Some(&serde_json::json!(2)));

        // 缺陷 C：`level="rule"` 事件，带 rule 标签 + v1.9.162 文案。
        //
        // **2.1.43-A**：`rule` 现在与 `hit`/`miss` 同档采样（10%），所以单次调用
        // 可能不采到 —— 事件**内容**仍必须正确，故重放同一数据面路径直到采到
        // （p=0.1，300 次全不中的概率 ≈ 6e-15，等价于确定性）。上面全部计数断言
        // 都在重放**之前**，不受影响。
        let is_rule = |e: &serde_json::Value| {
            e.get("level").and_then(serde_json::Value::as_str) == Some("rule")
        };
        let mut rule_ev = tel.events_snapshot().into_iter().find(|e| is_rule(e));
        let mut tries = 0;
        while rule_ev.is_none() && tries < 300 {
            tries += 1;
            let out = answer_wire_ex(&resolver, &raw).await.expect("应答(重放)");
            log_and_count(
                &*tel,
                Some(&tel),
                "ads.blocked.test",
                "A",
                None::<&str>,
                0.5_f64,
                "",
                &out,
            );
            rule_ev = tel.events_snapshot().into_iter().find(|e| is_rule(e));
        }
        let rule_ev = rule_ev.expect("必须有一条 level=rule 事件（300 次重放仍未采样）");
        assert_eq!(
            rule_ev.get("msg").and_then(serde_json::Value::as_str),
            Some("规则屏蔽 → NXDOMAIN")
        );
        assert_eq!(
            rule_ev.get("rule").and_then(serde_json::Value::as_str),
            Some("屏蔽 *.blocked.test")
        );
        assert_eq!(
            rule_ev.get("upstream").and_then(serde_json::Value::as_str),
            Some("规则屏蔽")
        );
    }

    /* ---------- P0-4：qtype / qclass / 畸形报文 受理判定 ---------- */
    // >>> 242B BEGIN T-dns-equation >>> //
    /// **2.1.42-B（P1-6）硬等式回归**：100 次缓存命中 + 100 次 block ⇒
    /// `hit=100, miss=0, policy_filtered=0, rule=100, total=200`，
    /// `hit_rate=100%`，且 `hit + miss + policy_filtered + rule == total`。
    #[tokio::test]
    async fn p1_6_hundred_cache_hits_plus_hundred_blocks_satisfy_equation() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};

        let tel = Arc::new(ServerTelemetry::new());
        let rule = ebpdns_rules::rule_from_json(
            serde_json::json!({"match": "*.blocked.test", "action": "block"})
                .as_object()
                .cloned()
                .expect("object"),
            ebpdns_rules::RuleSource::Local,
        )
        .expect("block 规则构造");
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![rule], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_q, qt, _d| {
                if qt == "A" {
                    vec![UpstreamAnswer::ok(
                        "u1",
                        0,
                        vec![ResolveAnswer::new("1.2.3.4", 300.0, 1)],
                        vec![],
                    )]
                } else {
                    Vec::new()
                }
            })),
        );
        // 预热：一次 A 查询把缓存填上（这次 miss 随后被 reset 清掉）。
        let a_raw = query_packet("cache.hit.test.", 1);
        let _ = answer_wire_ex(&resolver, &a_raw).await.expect("预热应答");
        tel.reset();
        // 100 次缓存直答。
        for _ in 0..100 {
            let out = answer_wire_ex(&resolver, &a_raw).await.expect("缓存应答");
            assert!(out.is_hit, "前置：第二次起必须是缓存命中");
            log_and_count(
                &*tel,
                Some(&tel),
                "cache.hit.test",
                "A",
                None,
                0.1,
                "",
                &out,
            );
        }
        // 100 次 block（本地规则直答）。
        let b_raw = query_packet("ads.blocked.test.", 1);
        for _ in 0..100 {
            let out = answer_wire_ex(&resolver, &b_raw).await.expect("屏蔽应答");
            assert_eq!(rcode_of(&out.resp), 3, "block 必须 NXDOMAIN");
            assert_eq!(out.source, AnswerSource::RuleLocal);
            log_and_count(
                &*tel,
                Some(&tel),
                "ads.blocked.test",
                "A",
                None,
                0.1,
                "",
                &out,
            );
        }
        let c = tel.counters();
        assert_eq!(c["hit"], serde_json::json!(100));
        assert_eq!(c["miss"], serde_json::json!(0), "block 不得再摊薄 miss");
        assert_eq!(c["policy_filtered_total"], serde_json::json!(0));
        assert_eq!(c["rule"], serde_json::json!(100));
        assert_eq!(c["total"], serde_json::json!(200));
        assert_eq!(tel.hit_rate_pct(), 100.0, "hit_rate 必须是 100%");
        assert_eq!(
            c["total"].as_u64().unwrap(),
            c["hit"].as_u64().unwrap()
                + c["miss"].as_u64().unwrap()
                + c["policy_filtered_total"].as_u64().unwrap()
                + c["rule"].as_u64().unwrap(),
            "硬等式必须成立: {c:?}"
        );
        // `rule_hits` 与 `miss` 不重叠：100 条 block 全在 rule_hits.block，miss 为 0。
        assert_eq!(tel.rule_hits().get("block"), Some(&serde_json::json!(100)));
    }
    // <<< 242B END T-dns-equation <<< //

    /// 构造一个「只回 A 记录」的脚本化 resolver（缓存会被真实填充）。
    async fn resolver_with_a_record(
        tel: Arc<ServerTelemetry>,
        value: &'static str,
    ) -> Arc<Resolver> {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};

        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
        Resolver::new(
            cfg,
            tel,
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_q, qt, _d| {
                if qt == "A" {
                    vec![UpstreamAnswer::ok(
                        "u1",
                        0,
                        vec![ResolveAnswer::new(value, 300.0, 1)],
                        vec![],
                    )]
                } else {
                    Vec::new()
                }
            })),
        )
    }

    /// **P0-4 回归（核心缺陷）**：必须拒绝的 qtype 一定要回 `NOTIMP`，且
    /// **绝不能**命中同名域名的 A 缓存（旧实现 `_ => "A"` 会把 AXFR 当成 A 查询，
    /// 客户端因此拿到一条 A 记录）。
    ///
    /// **2.1.29**：HTTPS 已转为**受理**、TYPE65280 已转为**透传**（两者从本表移出，
    /// 分别由 `new_types_are_supported_and_cacheable` /
    /// `unknown_qtype_passthrough_is_not_cached_and_keeps_raw_qtype` 覆盖）；
    /// 本表只剩"必须拒绝"的区传送/元查询/保留码/DNSSEC 语义类型。
    #[tokio::test]
    async fn rejected_qtypes_answer_notimp_and_never_hit_a_cache() {
        for (qtype, label) in [
            (10u16, "NULL"),
            (41, "OPT"),
            (46, "RRSIG"),
            (47, "NSEC"),
            (50, "NSEC3"),
            (51, "NSEC3PARAM"),
            (249, "TKEY"),
            (250, "TSIG"),
            (251, "IXFR"),
            (252, "AXFR"),
            (255, "ANY"),
            (0, "TYPE0"),
        ] {
            let tel = Arc::new(ServerTelemetry::new());
            let resolver = resolver_with_a_record(tel.clone(), "1.2.3.4").await;
            // 先用 A 查询把 "cached.test" 的 A 记录写进缓存。
            let a_raw = query_packet("cached.test.", 1);
            let a_out = answer_wire_ex(&resolver, &a_raw).await.expect("A 应答");
            assert_eq!(rcode_of(&a_out.resp), 0, "A 查询应 NOERROR");
            assert_eq!(first_answer(&a_out.resp).as_deref(), Some("1.2.3.4"));

            // 再查一个不受支持的 qtype：必须 NOTIMP、ancount=0、不计上游。
            let raw = query_packet("cached.test.", qtype);
            let out = answer_wire_ex(&resolver, &raw)
                .await
                .unwrap_or_else(|| panic!("{label} 必须有应答（不得返回 None）"));
            assert_eq!(
                rcode_of(&out.resp),
                4,
                "{label} 必须回 NOTIMP(4)，实际 rcode={}",
                rcode_of(&out.resp)
            );
            assert_eq!(ancount_of(&out.resp), 0, "{label} 不得带任何 answer");
            // **2.1.19（修复项 5-④）**：显式的 `Unsupported` 来源（2.1.18 与畸形报文
            // 共用 `Malformed` ⇒ 事件文案相同，分不出"不支持"与"坏了"）。
            assert_eq!(
                out.source,
                AnswerSource::Unsupported,
                "{label} 必须是显式的『本地应答·内容不支持』来源"
            );
            // 事件「上游解析」列必须是**显式语义标签**，且与会话「畸形报文」的标签不同。
            let up_label = event_upstream("", "", out.source);
            assert_eq!(
                up_label, "本地应答（类型/opcode 不支持）",
                "{label}: 上游列标签"
            );
            assert_ne!(
                up_label,
                event_upstream("", "", AnswerSource::Malformed),
                "{label}: 必须与『畸形报文』的标签不同（否则日志无法区分）"
            );
            assert!(!out.is_hit, "{label} 不得被当成缓存命中");
            // 用**增量**断言：上面的 A 查询已经让 `resolve()` 计过一次 total，
            // 因此只能比较 `log_and_count` 这次带来的变化（口径见 `log_and_count` 文档）。
            let before_total = tel.counters()["total"].as_u64().unwrap_or(0);
            let before_hit = tel.counters()["hit"].as_u64().unwrap_or(0);
            let before_miss = tel.counters()["miss"].as_u64().unwrap_or(0);
            // **2.1.18（修复项 9）**：传 `Some(&tel)`（与生产三条数据面出口一致）——
            // `total` 现在只由唯一出口 `note_data_plane_outcome` 推进（= Σ client_rcode）。
            log_and_count(
                &*tel,
                Some(&tel),
                "cached.test",
                label,
                None::<&str>,
                0.1,
                "",
                &out,
            );
            let c = tel.counters();
            assert_eq!(
                c["upstream_queries"],
                serde_json::json!(0),
                "{label} 未发上游"
            );
            assert_eq!(c["errors"], serde_json::json!(1), "{label} 计 error");
            assert_eq!(
                c["miss"].as_u64().unwrap_or(0) - before_miss,
                1,
                "{label} 计 miss（+1）"
            );
            assert_eq!(
                c["total"].as_u64().unwrap_or(0) - before_total,
                1,
                "{label} 计 total（+1，未进解析引擎 → 由本层补计）"
            );
            assert_eq!(
                c["hit"].as_u64().unwrap_or(0) - before_hit,
                0,
                "{label} 不得计 hit"
            );
        }
    }

    /// **2.1.29**：未知 qtype（TYPE65280）**透传** —— 原始 `u16` 发上游、上游报文
    /// 原样回传（只改头）、**不缓存**（第二次仍走上游）。
    #[tokio::test]
    async fn unknown_qtype_passthrough_is_not_cached_and_keeps_raw_qtype() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::UpstreamAnswer;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let tel = Arc::new(ServerTelemetry::new());
        // 夹具上游：返回一条 TYPE65280 的"答案"（rdata 是任意 4 字节，透传不解析）。
        let upstream = response_packet(
            "passthru.test.",
            65280,
            0,
            &[("passthru.test.", 65280, 4, vec![0xde, 0xad, 0xbe, 0xef])],
        );
        let seen_qtypes: Arc<parking_lot::Mutex<Vec<String>>> =
            Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen = seen_qtypes.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let upstream_for_closure = upstream.clone();
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_q, qt, _d| {
                seen.lock().push(qt.to_string());
                calls2.fetch_add(1, AtomicOrdering::Relaxed);
                vec![UpstreamAnswer {
                    up_name: "u1".to_string(),
                    rcode: Some(0),
                    raw: Some(upstream_for_closure.clone()),
                    lat: 3.0,
                    ..Default::default()
                }]
            })),
        );

        let raw = query_packet("passthru.test.", 65280);
        let out = answer_wire_ex(&resolver, &raw).await.expect("透传应答");
        // 上游收到的 qtype 必须是**原始 65280**（不是 A！）。
        {
            let seen = seen_qtypes.lock();
            assert_eq!(seen.len(), 1, "应恰好一次上游查询");
            assert_eq!(
                seen[0], "TYPE65280",
                "上游必须收到原始 qtype（P0-4 底线：绝不降级成 A）"
            );
        }
        assert_eq!(rcode_of(&out.resp), 0, "透传应回上游的 NOERROR");
        assert_eq!(out.source, AnswerSource::Passthrough);
        assert!(!out.is_hit);
        // 只改头：ID/flags 按数据面口径，answer 段逐字节保留。
        assert_eq!(&out.resp[..2], &raw[..2], "ID 必须回显客户端");
        assert_eq!(
            &out.resp[12..],
            &upstream[12..],
            "question/answer 段必须原样回传（不解析、不重编码）"
        );

        log_and_count(
            &*tel,
            Some(&tel),
            "passthru.test",
            "other",
            None::<&str>,
            0.2_f64,
            "",
            &out,
        );
        let c = tel.counters();
        assert_eq!(c["passthrough_qtype_total"], serde_json::json!(1));
        assert_eq!(c["upstream_queries"], serde_json::json!(1));
        assert_eq!(c["errors"], serde_json::json!(0), "透传成功不计 error");
        assert_eq!(c["miss"], serde_json::json!(1));

        // 第二次查询：**不得**命中缓存（透传不缓存）→ 仍走上游。
        let out2 = answer_wire_ex(&resolver, &raw).await.expect("透传应答2");
        assert!(!out2.is_hit, "透传结果不得进缓存");
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 2, "第二次仍必须发上游");
        log_and_count(
            &*tel,
            Some(&tel),
            "passthru.test",
            "other",
            None::<&str>,
            0.2_f64,
            "",
            &out2,
        );
        let c = tel.counters();
        assert_eq!(c["passthrough_qtype_total"], serde_json::json!(2));
        assert_eq!(c["upstream_queries"], serde_json::json!(2));
        assert_eq!(c["hit"], serde_json::json!(0), "透传没有缓存命中");
    }

    /// **2.1.29**：透传失败（全部上游超时）→ SERVFAIL + `servfail_reasons.timeout`
    /// + `passthrough_qtype_total`，且计 miss/error/upstream（与 `UpstreamFailed` 同口径）。
    #[tokio::test]
    async fn unknown_qtype_passthrough_timeout_is_servfail_and_counted() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::UpstreamAnswer;

        let tel = Arc::new(ServerTelemetry::new());
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_q, _qt, _d| {
                vec![UpstreamAnswer::fail("u1")]
            })),
        );
        let raw = query_packet("fail.test.", 65280);
        let out = answer_wire_ex(&resolver, &raw)
            .await
            .expect("必须有 SERVFAIL 应答");
        assert_eq!(rcode_of(&out.resp), 2, "透传失败必须回 SERVFAIL");
        assert_eq!(out.source, AnswerSource::PassthroughFailed);
        log_and_count(
            &*tel,
            Some(&tel),
            "fail.test",
            "other",
            None::<&str>,
            1.5_f64,
            "",
            &out,
        );
        let c = tel.counters();
        assert_eq!(c["passthrough_qtype_total"], serde_json::json!(1));
        assert_eq!(c["upstream_queries"], serde_json::json!(1));
        assert_eq!(c["errors"], serde_json::json!(1));
        assert_eq!(c["miss"], serde_json::json!(1));
        assert_eq!(c["servfail_total"], serde_json::json!(1));
        assert_eq!(
            c["servfail_reasons"]["upstream_timeout"],
            serde_json::json!(1),
            "超时必须归因到 upstream_timeout"
        );
    }

    /// **2.1.29**：未知 qtype **不得绕过 block 规则** —— 规则优先判决，
    /// 命中屏蔽时回 NXDOMAIN、绝不发上游、且**不计**透传计数。
    #[tokio::test]
    async fn unknown_qtype_passthrough_still_honors_block_rule() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let tel = Arc::new(ServerTelemetry::new());
        let rule = ebpdns_rules::rule_from_json(
            serde_json::json!({"match": "*.blocked.test", "action": "block"})
                .as_object()
                .cloned()
                .expect("object"),
            ebpdns_rules::RuleSource::Local,
        )
        .expect("block 规则构造");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = calls.clone();
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![rule], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(move |_q, _qt, _d| {
                calls2.fetch_add(1, AtomicOrdering::Relaxed);
                Vec::new()
            })),
        );
        let raw = query_packet("ads.blocked.test.", 65280);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 3, "屏蔽必须 NXDOMAIN（不得透传）");
        assert_eq!(calls.load(AtomicOrdering::Relaxed), 0, "屏蔽不得发上游");
        log_and_count(
            &*tel,
            Some(&tel),
            "ads.blocked.test",
            "other",
            None::<&str>,
            0.3_f64,
            "",
            &out,
        );
        let c = tel.counters();
        assert_eq!(
            c["passthrough_qtype_total"],
            serde_json::json!(0),
            "被屏蔽的查询不是透传"
        );
        // 与既有 block 口径**逐字一致**：屏蔽仍走 `MissClass::Miss`（计 miss），
        // 但**没有发上游** ⇒ `upstream_queries` 不得 +1（2.1.41 修复：此前这里
        // 会多计 1，物理上游调用数却是 0）。
        assert_eq!(c["upstream_queries"], serde_json::json!(0));
        // 规则事件（level=rule）必须存在，且 rule 标签正确。
        //
        // **2.1.43-A**：`rule` 已与 `hit`/`miss` 同档采样（10%）⇒ 单次调用可能不采到，
        // 故重放同一路径直到采到（300 次全不中 ≈ 6e-15）。上面的计数断言在重放之前。
        let is_rule = |e: &serde_json::Value| {
            e.get("level").and_then(serde_json::Value::as_str) == Some("rule")
        };
        let mut ev = tel.events_snapshot().into_iter().find(|e| is_rule(e));
        let mut tries = 0;
        while ev.is_none() && tries < 300 {
            tries += 1;
            let out2 = answer_wire_ex(&resolver, &raw).await.expect("应答(重放)");
            log_and_count(
                &*tel,
                Some(&tel),
                "ads.blocked.test",
                "other",
                None::<&str>,
                0.3_f64,
                "",
                &out2,
            );
            ev = tel.events_snapshot().into_iter().find(|e| is_rule(e));
        }
        let ev = ev.expect("必须有一条 level=rule 事件（300 次重放仍未采样）");
        assert_eq!(
            ev.get("upstream").and_then(serde_json::Value::as_str),
            Some("规则屏蔽")
        );
    }

    /// **2.1.29（Tier-1 回归）**：`HTTPS` 已转为**受理类型** —— 解析、编码、**可缓存**。
    #[tokio::test]
    async fn https_is_supported_encoded_and_cacheable() {
        use ebpdns_resolver::clock::MockClock;
        use ebpdns_resolver::config::{ResolverConfig, UpstreamCfg};
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::types::{ResolveAnswer, UpstreamAnswer};

        let tel = Arc::new(ServerTelemetry::new());
        let cfg = ResolverConfig::test_default(vec![UpstreamCfg::test_up("u1")], vec![], 1);
        let resolver = Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(MockClock::new(1_700_000_000.0)),
            Arc::new(ScriptedQuerier::new(|_q, qt, _d| {
                if qt == "HTTPS" {
                    vec![UpstreamAnswer::ok(
                        "u1",
                        0,
                        vec![ResolveAnswer::new("1 . alpn=h2,h3", 300.0, 65)],
                        vec![],
                    )]
                } else {
                    Vec::new()
                }
            })),
        );
        let raw = query_packet("svc.test.", 65);
        let out = answer_wire_ex(&resolver, &raw).await.expect("HTTPS 应答");
        assert_eq!(rcode_of(&out.resp), 0, "HTTPS 查询必须 NOERROR");
        assert_eq!(ancount_of(&out.resp), 1, "必须带一条 HTTPS 答案");
        assert!(!out.is_hit);
        // 应答 RDATA 必须能被 proto 解析回 SVCB（不是 hex/Other）。
        let parsed = ebpdns_proto::message::parse_message(&out.resp).expect("解析应答");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].rtype, 65);
        assert_eq!(parsed.answers[0].rdata.as_display(), "1 . alpn=h2,h3");
        // 第二次必须命中缓存，且报文逐字节一致（TTL 以 300→300 不衰减的同一秒内）。
        let out2 = answer_wire_ex(&resolver, &raw).await.expect("HTTPS 应答2");
        assert!(out2.is_hit, "HTTPS 必须可缓存");
        assert_eq!(out2.resp, out.resp, "缓存直答报文必须与首次一致");
        log_and_count(
            &*tel,
            Some(&tel),
            "svc.test",
            "HTTPS",
            None::<&str>,
            0.1_f64,
            "",
            &out2,
        );
        let c = tel.counters();
        assert_eq!(c["hit"], serde_json::json!(1), "第二次必须计 hit");
        assert_eq!(c["passthrough_qtype_total"], serde_json::json!(0));
    }

    /// **2.1.29**：透传回传时 **question 段必须回显客户端原始字节** —— 上游若开启
    /// 0x20（出厂默认 `dnssec_0x20=true`）其响应 question 是随机大小写，原样转发会让
    /// 做 0x20 校验的严格客户端拒收。ID/flags 仍按既有口径改写。
    #[test]
    fn passthrough_relay_echoes_client_question_bytes() {
        let client = query_packet("MiXeD.Example.", 65280);
        let mut upstream = query_packet("mIxEd.eXaMpLe.", 65280); // 模拟 0x20 响应
        upstream[2] = 0x81; // QR
        upstream[3] = 0x80; // RA, rcode=0
        let out = relay_upstream_response(&client, upstream);
        let qlen = question_edns_info(&client)
            .qbytes
            .expect("client qbytes")
            .len();
        assert_eq!(
            &out[12..12 + qlen],
            &client[12..12 + qlen],
            "question 必须回显客户端原始字节（不得泄漏上游 0x20 大小写）"
        );
        assert_eq!(&out[..2], &client[..2], "ID 必须回显客户端");
        assert_eq!(out[3] & 0x0F, 0, "rcode 取上游");
        assert_ne!(out[3] & 0x80, 0, "RA 必须置位");
        assert_ne!(out[2] & 0x80, 0, "QR 必须置位");

        // 上游 question 段长度不同（畸形/串包）⇒ **不覆盖**（防御性，绝不越界写）。
        let mut wrong = query_packet("otherlong.example.", 65280);
        wrong[2] = 0x81;
        wrong[3] = 0x80;
        let before = wrong[12..].to_vec();
        let out2 = relay_upstream_response(&client, wrong);
        assert_eq!(&out2[12..], &before[..], "长度不匹配时不得改写 question");
    }

    /// **P0-4 回归**：非法 qclass（0）→ `FORMERR`；非 IN 的合法 class → `NOTIMP`。
    #[tokio::test]
    async fn bad_qclass_answers_formerr_or_notimp() {
        let tel = Arc::new(ServerTelemetry::new());
        let resolver = resolver_with_a_record(tel, "1.2.3.4").await;
        // qclass=0（非法）→ FORMERR。
        let raw = query_packet_qclass("cls.test.", 1, 0);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "qclass=0 必须 FORMERR(1)");
        assert_eq!(out.source, AnswerSource::Malformed);
        // qclass=3（CH）→ NOTIMP（本服务只提供 IN）。
        let raw = query_packet_qclass("cls.test.", 1, 3);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 4, "qclass=CH 必须 NOTIMP(4)");
        assert_eq!(
            out.source,
            AnswerSource::Unsupported,
            "NOTIMP 必须是显式的『内容不支持』来源（2.1.19 修复项 5-④）"
        );
    }

    /// **P0-4 回归**：截断/畸形报文必须回 `FORMERR`（旧实现返回 `None` →
    /// 数据面兜底 **SERVFAIL**，实测 11 例畸形包全部命中这条路径）。
    #[tokio::test]
    async fn malformed_packets_answer_formerr_not_servfail() {
        let tel = Arc::new(ServerTelemetry::new());
        let resolver = resolver_with_a_record(tel.clone(), "1.2.3.4").await;
        // ① 长度不足 12 字节（截断包）：仍要给出可发送的 12 字节最小头。
        for n in [0usize, 1, 4, 11] {
            let raw = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01]
                .into_iter()
                .take(n)
                .collect::<Vec<u8>>();
            let out = answer_wire_ex(&resolver, &raw).await.expect("必须应答");
            assert_eq!(out.resp.len(), 12, "截断包应回 12 字节最小头（n={n}）");
            assert_eq!(rcode_of(&out.resp), 1, "截断包必须 FORMERR（n={n}）");
            assert_eq!(out.source, AnswerSource::Malformed);
            let want_qid: [u8; 2] = if n >= 2 { [0x12, 0x34] } else { [0, 0] };
            assert_eq!(&out.resp[0..2], &want_qid[..], "qid 尽力回显（n={n}）");
        }
        // ② 头部声明 qd=1 但 question 段缺失（12 字节头 + 无 question）。
        let mut raw = query_packet("trunc.test.", 1);
        raw.truncate(12);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "question 缺失必须 FORMERR");
        assert_eq!(out.source, AnswerSource::Malformed);
        // ③ question 少了 qclass 末字节（parse_message 判截断）。
        let mut raw = query_packet("trunc.test.", 1);
        raw.truncate(raw.len() - 1);
        let out = answer_wire_ex(&resolver, &raw).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "qclass 截断必须 FORMERR");
        // ④ 畸形包的口径：error + miss + total 各 1，**不计上游**。
        // **2.1.18（修复项 9）**：同上，走真实出口（这条 FORMERR 应答 ⇒ total +1）。
        log_and_count(&*tel, Some(&tel), "", "A", None::<&str>, 0.0, "", &out);
        let c = tel.counters();
        assert_eq!(c["errors"], serde_json::json!(1));
        assert_eq!(c["upstream_queries"], serde_json::json!(0));
        assert_eq!(c["total"], serde_json::json!(1));
        assert_eq!(c["hit"], serde_json::json!(0));
        assert_eq!(c["miss"], serde_json::json!(1));
    }

    /// **2.1.21（DEF-220-04）**：**本机应答的 `qdcount` 矩阵** —— 所有"无法解析出
    /// question 段"的畸形包与所有正常形状的本地错误应答，都必须落在**同一条**策略上：
    ///
    /// * question 段**可解析** ⇒ `qd=1`（回显问题段）；
    /// * question 段**不可解析** ⇒ `qd=0`（12 字节头）。
    ///
    /// 缺陷背景（AUDIT-220 B 节 DEF-220-04 实测）：2.1.20 的 QR=1 / opcode≠0 走
    /// `simple_outcome`（可解析时 `qd=1`），而 70 字节 label / 空 question 走
    /// `malformed_outcome` 里的**另一条** `build_error_response_short` 兜底（`qd=0`）
    /// ⇒ 同一类畸形出现 `qd=1,len=25` 与 `qd=0,len=12` 两套形状，上一轮 A-09 的
    /// "qdcount=0"验收条款**只对一半路径成立**。现在两者共用同一个构造器。
    #[tokio::test]
    async fn formerr_qdcount_matrix_is_consistent() {
        fn qd_of(p: &[u8]) -> u16 {
            u16::from_be_bytes([p[4], p[5]])
        }
        let tel = Arc::new(ServerTelemetry::new());
        let resolver = resolver_with_a_record(tel, "1.2.3.4").await;

        // ① question 段**不可解析**：70 字节 label（长度字节 0x46 = 70 > 63，
        //    `question_edns_info` 因而返回 `qbytes=None`）→ FORMERR + qd=0 + 12 字节。
        let mut bad_label = query_packet("x.test.", 1);
        bad_label[12] = 70;
        let out = answer_wire_ex(&resolver, &bad_label).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "70 字节 label → FORMERR");
        assert_eq!(
            out.resp.len(),
            12,
            "不可解析 ⇒ 12 字节头（实际 {}）",
            out.resp.len()
        );
        assert_eq!(qd_of(&out.resp), 0, "不可解析 ⇒ qdcount=0");

        // ② qdcount=0（声明没有任何 question）→ FORMERR + qd=0 + 12 字节。
        let mut empty_q = query_packet("x.test.", 1);
        empty_q[4] = 0;
        empty_q[5] = 0;
        empty_q.truncate(12);
        let out = answer_wire_ex(&resolver, &empty_q).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "qdcount=0 → FORMERR");
        assert_eq!(out.resp.len(), 12, "无 question ⇒ 12 字节头");
        assert_eq!(qd_of(&out.resp), 0, "无 question ⇒ qdcount=0");

        // ③ 长度不足 12 字节 → FORMERR + qd=0 + 12 字节（`build_error_response_short`）。
        let out = answer_wire_ex(&resolver, &[0u8, 1, 2, 3])
            .await
            .expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "短包 → FORMERR");
        assert_eq!(out.resp.len(), 12, "短包 ⇒ 12 字节头");
        assert_eq!(qd_of(&out.resp), 0, "短包 ⇒ qdcount=0");

        // ④ `QR=1`（响应包）：question 段**可解析** ⇒ FORMERR + **qd=1**（回显问题段）。
        let mut qr = query_packet("qr221.test.", 1);
        qr[2] |= 0x80;
        let out = answer_wire_ex(&resolver, &qr).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "QR=1 → FORMERR");
        assert_eq!(qd_of(&out.resp), 1, "可解析的 question ⇒ qdcount=1（回显）");
        assert!(out.resp.len() > 12, "回显问题段 ⇒ 长度 > 12");

        // ⑤ `opcode=2`（本服务不支持）：与 ④ **同一个构造器** ⇒ NOTIMP + **qd=1**。
        //    改前这一支走 `simple_outcome`、而 70 字节 label 走另一支 ⇒ 两套形状。
        let mut op = query_packet("op221.test.", 1);
        op[2] = (op[2] & 0x87) | (2 << 3); // opcode=2，清 QR
        let out = answer_wire_ex(&resolver, &op).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 4, "opcode=2 → NOTIMP");
        assert_eq!(
            qd_of(&out.resp),
            1,
            "opcode≠0 也必须与其它本地应答同形状（可解析 ⇒ qd=1）"
        );

        // ⑥ 不变式：**任何**输入都产出 ≥12 字节、且 qd 与实际 question 段自洽
        //    （"声明的段数 = 报文里真实有的段数"）。
        for pkt in [&bad_label, &empty_q, &qr, &op] {
            let out = answer_wire_ex(&resolver, pkt).await.expect("应答");
            assert!(out.resp.len() >= 12, "畸形包必须有可发送应答");
            let qd = qd_of(&out.resp);
            assert!(qd <= 1, "本地应答不得声明多于 1 个 question（实际 {qd}）");
        }
    }

    /// **P0-4**：查询包置 QR（这是响应包）/ opcode≠0 → 不解析、不计上游。
    #[tokio::test]
    async fn response_packet_and_nonzero_opcode_are_rejected() {
        let tel = Arc::new(ServerTelemetry::new());
        let resolver = resolver_with_a_record(tel, "1.2.3.4").await;
        let mut qr = query_packet("qr.test.", 1);
        qr[2] |= 0x80; // QR=1
        let out = answer_wire_ex(&resolver, &qr).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 1, "置 QR 的「查询」→ FORMERR");
        let mut iq = query_packet("iq.test.", 1);
        iq[2] |= 0x08; // opcode=1 (IQUERY)
        let out = answer_wire_ex(&resolver, &iq).await.expect("应答");
        assert_eq!(rcode_of(&out.resp), 4, "opcode≠0 → NOTIMP");
    }

    /// **P0-5 回归门禁**：UDP miss 闸门总槽位**永不低于 1024**。
    ///
    /// 2.1.13 的缺陷正是「`workers` 被固定成 1 + 每 worker 32 槽」⇒ 总槽位 32，
    /// 256 并发下丢包回归（客户端 6s 超时），而当时的 `/api/status` 与 `/metrics`
    /// 看不到任何丢包计数。本测试同时锁住「槽位下限」与「随 CPU 单调不减」。
    #[test]
    fn udp_slots_never_below_floor() {
        for cpus in [1usize, 2, 4, 8, 16, 64, 256] {
            let n = udp_slot_total(cpus);
            assert!(
                n >= UDP_MISS_SLOTS_MIN,
                "cpus={cpus} 时闸门只有 {n} 槽（下限 {UDP_MISS_SLOTS_MIN}）"
            );
            assert!(n >= udp_slot_total(cpus.saturating_sub(1).max(1)));
        }
        assert_eq!(
            udp_slot_total(0),
            UDP_MISS_SLOTS_MIN,
            "非法 CPU 数也要给下限"
        );
        assert_eq!(udp_slot_total(8), 1024);
        assert_eq!(udp_slot_total(32), 2048);
    }

    /// **P0-5 回归**：闸门拒绝必须**同时**进内部计数与 `udp_dropped` 计数器
    /// （`/api/status.counters` + `/metrics` 的共同来源）。
    #[test]
    fn udp_dropped_is_exposed_in_counters() {
        let t = ServerTelemetry::new();
        assert_eq!(t.counters()["udp_dropped"], serde_json::json!(0));
        t.inc_n("udp_dropped", 3);
        assert_eq!(t.udp_dropped(), 3);
        assert_eq!(t.counters()["udp_dropped"], serde_json::json!(3));
        // reset 一并归零（否则「清空」后运维仍看到旧丢包数）。
        t.reset();
        assert_eq!(t.udp_dropped(), 0);
    }

    /// **P1-5 回归**：`total == hit + miss` 不变量（对所有由本层补计 total 的路径）。
    ///
    /// 覆盖：缓存直答 hit、上游 miss、上游失败 err、畸形包 err。
    /// （`Rule` 与 resolver 内部抑制路径由 `resolve()` 计 total 且按既有口径不计
    /// hit/miss，是**已文档化的例外**，见 [`log_and_count`] 的说明。）
    #[test]
    fn total_equals_hit_plus_miss_invariant_for_all_paths() {
        let t = ClassifyCounts::new();
        let ans = response_packet(
            "i1.example.",
            1,
            0,
            &[("i1.example.", 1, 4, vec![1, 1, 1, 1])],
        );
        let nodata = response_packet("i2.example.", 1, 0, &[]);
        let sf = response_packet("i3.example.", 1, 2, &[]);
        let cases: Vec<AnswerOutcome> = vec![
            // ① 快路径缓存命中（resolved=false → 本层补计 total）。
            outcome(ans.clone(), true, false, None),
            // ② 上游 miss：`resolve()` 路径本来由它代计 total（resolved=true），这里把
            //    `resolved` 置回 false，专门验证「本层补计 total 时 hit+miss 也同步 +1」。
            {
                let mut o = outcome(nodata.clone(), false, true, None);
                o.resolved = false;
                o
            },
            // ③ 上游失败 → err（同上，验证 err 路径也计 miss + total）。
            {
                let mut o = outcome(sf.clone(), false, true, Some("no-answer"));
                o.resolved = false;
                o
            },
            // ④ 畸形包 → err（本来就未进解析引擎，total 由本层计）。
            outcome(vec![0u8; 4], false, false, Some("wire-parse-failed")),
        ];
        for (i, o) in cases.iter().enumerate() {
            log_and_count(&t, None, "i.example", "A", None::<&str>, 1.0, "", o);
            let g = |a: &AtomicU64| -> u64 { a.load(Ordering::Relaxed) };
            // `ClassifyCounts::resolve` 就是本层的 total 计数器（与生产口径一致：
            // `resolve` 类别 = total/QPS 窗口，见 `log_and_count` 文档）。
            assert_eq!(
                g(&t.resolve),
                g(&t.hit) + g(&t.miss),
                "第 {i} 条后 total(resolve) 必须等于 hit + miss"
            );
        }
        // err 计数只来自「上游失败 / 畸形包」两类（P1-5：合法应答一律不计 error）。
        assert_eq!(t.error.load(Ordering::Relaxed), 2);
        // upstream 来自「上游 miss（②）」与「上游失败（③）」两条 ——
        // 畸形包（④）与缓存直答（①）一律不计上游（P1-5/P1-6 的显式枚举判据）。
        assert_eq!(
            t.upstream.load(Ordering::Relaxed),
            2,
            "只有 Upstream/UpstreamFailed 计 upstream"
        );
    }

    /* ---------- 错误退避（F25） ---------- */
    #[test]
    fn err_backoff_is_monotonic_capped_and_reset() {
        let mut b = ErrBackoff::default();
        assert_eq!(b.consecutive(), 0);
        let mut prev = 0u64;
        for i in 1..ERR_FATAL_AFTER {
            match b.on_err() {
                OnError::Backoff(ms) => {
                    assert!(ms >= prev, "退避应单调不减: {ms} < {prev}");
                    assert!(ms <= ERR_BACKOFF_MAX_MS, "退避不得超过上限: {ms}");
                    prev = ms;
                }
                OnError::Fatal => panic!("第 {i} 次不该判致命"),
            }
        }
        // 首次为 10ms、逐步翻倍、封顶 1000ms。
        let mut b2 = ErrBackoff::default();
        assert_eq!(b2.on_err(), OnError::Backoff(10));
        assert_eq!(b2.on_err(), OnError::Backoff(20));
        assert_eq!(b2.on_err(), OnError::Backoff(40));
        for _ in 0..20 {
            let _ = b2.on_err();
        }
        assert_eq!(b2.on_err(), OnError::Fatal);
        // **[历史归因]** 阈值与 Python `_recv_errs >= 20` 对齐。
        assert_eq!(ERR_FATAL_AFTER, 20);
        // 一次成功即清零。
        let mut b3 = ErrBackoff::default();
        let _ = b3.on_err();
        let _ = b3.on_err();
        b3.on_ok();
        assert_eq!(b3.consecutive(), 0);
        assert_eq!(b3.on_err(), OnError::Backoff(10));
    }

    /* ---------- TCP 帧游标（F24） ---------- */

    /// 组 TCP 帧（2 字节大端长度 + payload）。
    fn tcp_wire(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u16).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn next_frame_len_rejects_incomplete() {
        assert_eq!(next_frame_len(&[]), None);
        assert_eq!(next_frame_len(&[0]), None);
        assert_eq!(next_frame_len(&[0, 5, 1, 2]), None, "半包必须等续");
        // 声明长度 0 是合法空帧（不吞字节、不死循环）。
        assert_eq!(next_frame_len(&[0, 0]), Some(0));
    }

    #[test]
    fn tcp_cursor_handles_coalesced_frames() {
        let p1 = vec![1u8; 12];
        let p2 = vec![2u8; 20];
        let p3 = vec![3u8; 4];
        let mut buf = tcp_wire(&p1);
        buf.extend(tcp_wire(&p2));
        buf.extend(tcp_wire(&p3));
        let mut pos = 0usize;
        let mut seen = Vec::new();
        while let Some(len) = next_frame_len(&buf[pos..]) {
            seen.push(buf[pos + 2..pos + 2 + len].to_vec());
            pos += 2 + len;
        }
        assert_eq!(pos, buf.len(), "三帧应被完整消费");
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0], p1);
        assert_eq!(seen[1], p2);
        assert_eq!(seen[2], p3);
    }

    #[test]
    fn tcp_cursor_partial_then_continuation() {
        // 第 1 帧完整 + 第 2 帧半包：只消费第 1 帧，剩余字节保留在缓冲里。
        let p1 = vec![7u8; 8];
        let p2 = vec![9u8; 30];
        let mut buf = tcp_wire(&p1);
        buf.extend(tcp_wire(&p2));
        buf.truncate(buf.len() - 10); // 去掉第 2 帧尾部 10 字节
        let mut pos = 0usize;
        let mut seen = Vec::new();
        while let Some(len) = next_frame_len(&buf[pos..]) {
            seen.push(buf[pos + 2..pos + 2 + len].to_vec());
            pos += 2 + len;
        }
        assert_eq!(seen, vec![p1.clone()]);
        let want_rest = tcp_wire(&p2);
        let want_rest = &want_rest[..want_rest.len() - 10];
        assert_eq!(&buf[pos..], want_rest, "半包字节原样保留");
        // 续上剩余字节后可完整解析。
        let mut rest = buf[pos..].to_vec();
        rest.extend_from_slice(&tcp_wire(&p2)[22..]);
        assert_eq!(next_frame_len(&rest), Some(p2.len()));
        assert_eq!(&rest[2..2 + p2.len()], &p2[..]);
    }

    #[test]
    fn tcp_cursor_long_frame_alignment() {
        // 超长帧（接近 64KB）与后续小帧在同一缓冲中，偏移推进不得错位。
        let big = vec![0xAAu8; 60000];
        let small = vec![0x55u8; 12];
        let mut buf = tcp_wire(&big);
        buf.extend(tcp_wire(&small));
        let mut pos = 0usize;
        let mut lens = Vec::new();
        while let Some(len) = next_frame_len(&buf[pos..]) {
            lens.push(len);
            pos += 2 + len;
        }
        assert_eq!(lens, vec![60000, 12]);
        assert_eq!(pos, buf.len());
        // 1MB 上限判定：缓冲超限即断开（不试图解析）。
        // **2.1.24**：改成**编译期**断言（运行期 `assert!(常量 == 常量)` 会被
        // `clippy::assertions_on_constants` 判为恒真；编译期断言更强，且不产生代码）。
        const _: () = assert!(TCP_BUF_LIMIT == 1 << 20);
    }

    /* ---------- F32: IPv4 + IPv6 同端口双栈监听 ---------- */

    /// 取一个空闲端口（绑定回环 `:0` 后读回端口号并释放）。
    fn free_port() -> u16 {
        let s = std::net::TcpListener::bind("127.0.0.1:0").expect("probe port");
        s.local_addr().expect("local_addr").port()
    }

    /// 本机是否有可用 IPv6（`[::1]` 可绑）：没有就跳过相关测试，不误报失败。
    fn have_v6() -> bool {
        std::net::UdpSocket::bind("[::1]:0").is_ok()
    }

    /// `/proc/sys/net/ipv6/bindv6only == 0`（Linux 默认：`[::]` 是双栈 socket）。
    #[cfg(target_os = "linux")]
    fn kernel_dual_stack_default() -> bool {
        std::fs::read_to_string("/proc/sys/net/ipv6/bindv6only")
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    fn kernel_dual_stack_default() -> bool {
        false
    }

    /// v6only 决策：**IPv4 与 IPv6 同时出现**时才需要 v6only。
    #[test]
    fn v6only_requested_only_when_both_families_present() {
        let v4: SocketAddr = "0.0.0.0:53".parse().unwrap();
        let v6: SocketAddr = "[::]:53".parse().unwrap();
        assert!(v6only_for(&[v4, v6]), "v4+v6 同端口 → 必须 v6only");
        assert!(
            !v6only_for(&[v6]),
            "只有 [::] 一个 socket → 保留内核双栈（历史文档用法），不得强行 v6only"
        );
        assert!(!v6only_for(&[v4]), "只有 v4 → 没有 v6 socket，开关无处可用");
        assert!(!v6only_for(&[]));
    }

    /// 关键回归：Linux 默认 `bindv6only=0` 时，**未设** `IPV6_V6ONLY` 的 `[::]:P`
    /// 会连 IPv4 的 P 端口一起占住 → 随后 `0.0.0.0:P` 直接 `EADDRINUSE`；
    /// 设了 v6only 后两者可**同时**绑定（这正是 `listen.udp` + `listen.udp6` 的前提）。
    ///
    /// 目标机 6.12 实测矩阵（`bindv6only=0`，UDP）：
    /// `v6only=0` + 双方都不开 `SO_REUSEADDR` → `EADDRINUSE`（修复前的真实故障）；
    /// `v6only=0` + 双方都开 `SO_REUSEADDR` → 两个都绑上（内核允许，但收包归属不确定，
    /// 因此本实现特意**不在 UDP 上开** `SO_REUSEADDR`，保住占用检测）；
    /// `v6only=1` → 四个 `SO_REUSEADDR` 组合下都稳定共存。
    #[test]
    fn v6only_allows_v4_and_v6_udp_on_same_port() {
        if !have_v6() {
            eprintln!("跳过：本机无可用 IPv6");
            return;
        }
        let port = free_port();
        let v6_any = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        let v4_any = SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));

        // 1) 未设 v6only 的 [::]:P（内核默认双栈）——v4 同端口随后应绑不上。
        let dual = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).expect("socket");
        dual.set_only_v6(false).expect("v6only=0");
        dual.set_nonblocking(true).expect("nonblocking");
        dual.bind(&v6_any.into()).expect("bind [::]:P (dual)");
        let v4_after_dual = bind_udp(v4_any, false);
        if kernel_dual_stack_default() {
            assert!(
                v4_after_dual.is_err(),
                "bindv6only=0 时未设 v6only 的 [::]:{port} 必须占住 IPv4 同端口（实测却绑上了）"
            );
        } else {
            eprintln!("提示：本机 bindv6only!=0，[::] 本就只占 v6，跳过互斥断言");
        }
        drop(v4_after_dual);
        drop(dual);

        // 2) v6only=1（本实现路径）：v4 + v6 同端口**同时**绑定成功。
        let v6 = bind_udp(v6_any, true).expect("v6only [::]:P 绑定成功");
        let v4 = bind_udp(v4_any, false).expect("0.0.0.0:P 与 v6only 的 [::]:P 共存");
        assert_eq!(v6.local_addr().unwrap().port(), port);
        assert_eq!(v4.local_addr().unwrap().port(), port);
        assert!(v6.local_addr().unwrap().is_ipv6());
        drop((v4, v6));
    }

    /// TCP 同理：`127.0.0.1:P` 与 `[::1]:P` 必须能同时 listen。
    #[test]
    fn v6only_allows_v4_and_v6_tcp_on_same_port() {
        if !have_v6() {
            eprintln!("跳过：本机无可用 IPv6");
            return;
        }
        let port = free_port();
        let v4 = bind_tcp(
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            true,
        )
        .expect("127.0.0.1:P listen");
        let v6 = bind_tcp(
            SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port)),
            true,
        )
        .expect("[::1]:P 与 127.0.0.1:P 同端口并存");
        assert_eq!(v4.local_addr().unwrap().port(), port);
        assert_eq!(v6.local_addr().unwrap().port(), port);
    }

    /* ============ 2.1.16（功能 1）：UDP 收包并行化 ============ */

    /// `effective_udp_workers` 的语义门禁（0=自动 / 1=旧行为 / N=显式，全部夹取）。
    ///
    /// **`raw == 1` 必须恒为 1**：这是"一键退回 2.1.15 行为"的开关，任何后续改动
    /// 让它变成其它值都会在这里失败。
    #[test]
    fn s1_effective_udp_workers_semantics() {
        // 1 = 旧行为（唯一强制单 socket 的取值，不受 cpus 影响）。
        assert_eq!(effective_udp_workers(1, 1), 1);
        assert_eq!(effective_udp_workers(1, 8), 1);
        assert_eq!(effective_udp_workers(1, 64), 1);
        // 0 = 自动：clamp(cpus, 1, UDP_WORKERS_MAX)。
        assert_eq!(
            effective_udp_workers(0, 0),
            1,
            "cpus=0（探测失败）按 1 处理"
        );
        assert_eq!(effective_udp_workers(0, 1), 1);
        assert_eq!(effective_udp_workers(0, 4), 4);
        assert_eq!(effective_udp_workers(0, 8), 8);
        assert_eq!(
            effective_udp_workers(0, 128),
            UDP_WORKERS_MAX,
            "自动档必须封顶（超过核数只增加调度开销）"
        );
        // 显式 N>1：尊重配置，夹取到 [1, 64]。
        assert_eq!(effective_udp_workers(2, 8), 2);
        assert_eq!(effective_udp_workers(16, 8), 16);
        assert_eq!(effective_udp_workers(4096, 8), 64);
    }

    /// **端口占用探测语义必须保住**（`SO_REUSEPORT` 会让"另一实例已占端口"静默通过）。
    ///
    /// 判据：同一地址已有一个**不带 REUSEPORT** 的 socket 占用时
    /// [`probe_port_free`] 必须返回 `AddrInUse`；释放后必须成功。
    #[test]
    fn s1_probe_port_free_detects_occupied_port() {
        let port = free_port();
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        // 占住端口（模拟"另一个 ebpdns 实例"）：不带 REUSEPORT 的普通 bind。
        let holder = bind_udp(addr, false).expect("占位 socket 绑定");
        let r = probe_port_free(addr, false);
        assert!(
            r.is_err(),
            "端口已被占用时预检必须报错（否则 REUSEPORT 会让重复实例静默各收一半流量）"
        );
        assert_eq!(
            r.unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse,
            "必须保留 AddrInUse 语义（运维脚本按错误码判定）"
        );
        drop(holder);
        probe_port_free(addr, false).expect("端口释放后预检必须成功");
    }

    /// 端到端：`start_multi_workers(.., 4)` 在同一地址上拉起 **4 个 REUSEPORT socket**
    /// （`ss -lunp` 会显示 4 行），且 `udp_bound` 只如实回传**一个**逻辑地址。
    ///
    /// 同时验证 **`udp_workers == 1` 与 2.1.15 等价**（只 1 个 socket）。
    #[tokio::test]
    async fn s1_reuseport_starts_n_sockets_and_legacy_starts_one() {
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;

        /// 测试基座：脚本化 querier（永不上游）+ 真钟 + 独立遥测。
        ///
        /// 注意 `Resolver::new` 自身返回 `Arc<Resolver>`（内部构造后即包装），
        /// 因此这里**不要**再套一层 `Arc::new`（会在测试编译期报类型不匹配）。
        fn mk_resolver(tel: &Arc<ServerTelemetry>) -> Arc<Resolver> {
            let q = ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| Vec::new());
            Resolver::new(
                ResolverConfig::test_default(Vec::new(), Vec::new(), 1),
                tel.clone(),
                Arc::new(RealClock::default()),
                Arc::new(q),
            )
        }

        let port = free_port();
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port));
        let tel = Arc::new(ServerTelemetry::new());

        // --- 旧行为：1 个 socket ---
        let srv1 = DnsServer::start_multi_workers(mk_resolver(&tel), tel.clone(), &[addr], &[], 1)
            .await
            .expect("legacy 单 socket 启动");
        assert_eq!(srv1.udp_bound(), &[addr]);
        assert_eq!(
            srv1.udp_sockets.len(),
            1,
            "udp_workers=1 必须与 2.1.15 逐位等价（单 socket / 单 udp_loop）"
        );
        srv1.shutdown().await;

        // --- 并行化：4 个 REUSEPORT socket ---
        let port2 = free_port();
        let addr2 = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port2));
        let srv2 = DnsServer::start_multi_workers(mk_resolver(&tel), tel.clone(), &[addr2], &[], 4)
            .await
            .expect("4 worker REUSEPORT 启动");
        assert_eq!(
            srv2.udp_sockets.len(),
            4,
            "udp_workers=4 必须拉起 4 个收包循环（每 socket 一个）"
        );
        assert_eq!(
            srv2.udp_bound(),
            &[addr2],
            "udp_bound 是**逻辑**监听地址（去重），堆叠 socket 数由 udp_handles/ss 反映"
        );
        srv2.shutdown().await;

        // --- 重复实例仍必须被发现（REUSEPORT 的运维安全网）---
        let holder = bind_udp(addr2, false).expect("占位");
        let dup =
            DnsServer::start_multi_workers(mk_resolver(&tel), tel.clone(), &[addr2], &[], 4).await;
        assert!(
            dup.is_err(),
            "端口已被别的进程占用时，多 worker 启动必须失败（绝不能 REUSEPORT 静默通过）"
        );
        drop(holder);
    }

    /* ============ 2.1.16（功能 7）：listen 热更新 ============ */

    /// **功能 7 门禁**：`rebind` 的三种语义一次钉死。
    ///
    /// 1. **成功替换**：A → {A, B} 时 A 被**保留**（keep 语义 ⇒ 改动期间 A 始终有监听，
    ///    零丢包），B 被新增；
    /// 2. **失败回滚**：目标地址被别的进程占用时必须返回 `Err`，且 `udp_bound`/`tcp_bound`
    ///    **逐位不变**（旧监听完整保留 —— "绝不裸奔"）；
    /// 3. **真正的端口切换**：{A,B} → C 时 A/B 的循环被停（`udp_bound` 只剩 C），
    ///    且新循环数 = 新地址 × `udp_workers`。
    #[tokio::test]
    async fn s7_rebind_swaps_listener_and_rolls_back_on_failure() {
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        use ebpdns_resolver::Resolver;

        fn mk(tel: &Arc<ServerTelemetry>) -> Arc<Resolver> {
            let q = ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| Vec::new());
            Resolver::new(
                ResolverConfig::test_default(Vec::new(), Vec::new(), 1),
                tel.clone(),
                Arc::new(RealClock::default()),
                Arc::new(q),
            )
        }
        fn lo(p: u16) -> SocketAddr {
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, p))
        }

        let tel = Arc::new(ServerTelemetry::new());
        let a = lo(free_port());
        let b = lo(free_port());
        let c = lo(free_port());
        let mut srv = DnsServer::start_multi_workers(mk(&tel), tel.clone(), &[a], &[a], 1)
            .await
            .expect("初始监听");
        assert_eq!(srv.udp_bound(), &[a]);
        assert_eq!(srv.tcp_bound(), &[a]);

        // ---- 1) keep + add：A 保留，新增 B ----
        srv.rebind(&[a, b], &[a, b])
            .await
            .expect("新增地址必须成功");
        assert!(srv.udp_bound().contains(&a), "keep 语义：A 必须仍在监听");
        assert!(srv.udp_bound().contains(&b), "B 必须已新增");
        assert_eq!(srv.udp_sockets.len(), 2, "两个 UDP 地址 → 两条收包循环");
        assert_eq!(srv.tcp_sockets.len(), 2, "两个 TCP 地址 → 两条 accept 循环");

        // ---- 2) 失败回滚：目标端口被别的进程占用 ⇒ Err 且监听集合不变 ----
        let holder_port = free_port();
        let holder = bind_udp(lo(holder_port), false).expect("占位 socket");
        let before_udp = srv.udp_bound().to_vec();
        let before_tcp = srv.tcp_bound().to_vec();
        let before_loops = srv.udp_sockets.len();
        let bad = srv.rebind(&[a, b, lo(holder_port)], &[a, b]).await;
        assert!(
            bad.is_err(),
            "目标端口已被占用时必须返回 Err（否则会把监听静默切到一个 bind 不上的地址）"
        );
        assert_eq!(
            srv.udp_bound(),
            before_udp.as_slice(),
            "**回滚**：失败的 rebind 之后 UDP 监听集合必须逐位不变"
        );
        assert_eq!(srv.tcp_bound(), before_tcp.as_slice(), "回滚：TCP 同样不变");
        assert_eq!(
            srv.udp_sockets.len(),
            before_loops,
            "回滚：不得留下半启动的新循环"
        );
        drop(holder);

        // ---- 3) 真替换：{a,b} → {c}（a/b 的循环必须停掉）----
        srv.rebind(&[c], &[c]).await.expect("切换到新端口必须成功");
        assert_eq!(srv.udp_bound(), &[c], "旧地址必须已被移除");
        assert_eq!(srv.tcp_bound(), &[c]);
        assert_eq!(srv.udp_sockets.len(), 1);
        assert_eq!(srv.tcp_sockets.len(), 1);
        // 缓存/在途/上游连接不受影响：rebind 只碰 socket。
        assert_eq!(srv.dropped().load(Ordering::Relaxed), 0);
        srv.shutdown().await;
    }

    /// 端到端：`start_multi` 一次拉起 v4+v6 的 UDP 与 TCP 共 4 个 socket，
    /// 全部成功监听，且 `udp_bound` / `tcp_bound` 如实回传。
    #[tokio::test]
    async fn start_multi_binds_dual_stack_and_reports_bound_addrs() {
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;

        if !have_v6() {
            eprintln!("跳过：本机无可用 IPv6");
            return;
        }
        let port = free_port();
        let addrs = vec![
            SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port)),
            SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)),
        ];
        let tel = Arc::new(ServerTelemetry::new());
        let q = ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| Vec::new());
        let resolver = Resolver::new(
            ResolverConfig::default(),
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(q),
        );
        let srv = DnsServer::start_multi_workers(resolver, tel, &addrs, &addrs, 1)
            .await
            .expect("双栈 v4+v6 UDP/TCP 同端口监听");
        assert_eq!(srv.udp_bound(), addrs.as_slice());
        assert_eq!(srv.tcp_bound(), addrs.as_slice());
        assert_eq!(srv.udp_dropped(), 0);
        srv.shutdown().await;
    }

    /* ---------- 2.1.12：负缓存命中计数的路径无关性 ---------- */

    /// **2.1.12（遗留问题 1）**：负缓存命中计数的判定点必须**唯一且路径无关**。
    ///
    /// 旧实现把 `count_neg_hit()` 埋在 `count_wire()`（只在 UDP 快路径 + TCP 被调用），
    /// 控制面 `/api/query` 完全不计 —— 同一个缓存命中，谁在查会改变指标值。
    /// 现在判据收在 [`count_negative_cache_hit`] / [`count_negative_wire`]：
    /// - 缓存直答 + NXDOMAIN/NODATA → 计 **1**；
    /// - 缓存直答 + 正应答 → 不计；
    /// - 上游解析出的 NXDOMAIN（非缓存直答）→ **不计**（语义是"缓存里答的"）；
    /// - 同一个查询重复走判定点 → 只计实际调用次数（不做语义去重，但**数据面**
    ///   每个客户端查询只会经过一次，见 `log_and_count` 的唯一出口论证）。
    #[test]
    fn negative_cache_hit_counting_is_path_independent_and_once_per_answer() {
        let t = ServerTelemetry::new();
        let nx = response_packet("nx.example.", 1, 3, &[]);
        let nodata = response_packet("nd.example.", 1, 0, &[]);
        let pos = response_packet(
            "ok.example.",
            1,
            0,
            &[("ok.example.", 1, 4, vec![1, 1, 1, 1])],
        );

        // ---- 数据面：UDP 快路径 / TCP 共用的口径（`is_cache_direct: true`）----
        let hit_nx = outcome(nx.clone(), true, false, None);
        assert!(hit_nx.is_cache_direct, "快路径命中必须是缓存直答");
        count_negative_cache_hit(&t, &hit_nx);
        assert_eq!(t.neg_hits(), 1, "数据面缓存 NXDOMAIN 命中应计 1");

        let hit_nodata = outcome(nodata.clone(), true, false, None);
        count_negative_cache_hit(&t, &hit_nodata);
        assert_eq!(t.neg_hits(), 2, "NODATA（ANCOUNT=0）同样是负应答");

        let hit_pos = outcome(pos.clone(), true, false, None);
        count_negative_cache_hit(&t, &hit_pos);
        assert_eq!(t.neg_hits(), 2, "正向缓存直答不得计入负缓存");

        // ---- 上游解析出的 NXDOMAIN：非缓存直答 → 绝不计 ----
        let miss_nx = outcome(nx.clone(), false, true, None);
        assert!(!miss_nx.is_cache_direct);
        count_negative_cache_hit(&t, &miss_nx);
        assert_eq!(t.neg_hits(), 2, "上游解析的 NXDOMAIN 不是负缓存命中");

        // `resolve()` 内部二次命中（`is_hit=true, resolved=true`）：hit 已由
        // `resolve()` 代计 → 这里**不得**再计一次负缓存命中（否则同一客户端查询计两次）。
        let second_hit = outcome(nx.clone(), true, true, None);
        assert!(
            !second_hit.is_cache_direct,
            "resolved=true 的命中不是「缓存直答出口」，不重复计数"
        );
        count_negative_cache_hit(&t, &second_hit);
        assert_eq!(t.neg_hits(), 2, "resolved 路径不得重复计负缓存");

        // ---- 控制面：`/api/query` 用同一个判据（`count_negative_wire`）----
        // 控制面没有 `AnswerOutcome`，但复用同一个 `is_negative_answer`：
        // 因此"谁在查"不再改变指标值。
        count_negative_wire(&t, &nx);
        assert_eq!(t.neg_hits(), 3, "控制面缓存 NXDOMAIN 命中应计 1");

        // ---- 与 cache_direct 口径自洽：负缓存命中恒 <= 用户态直答总数 ----
        for _ in 0..3 {
            t.inc_n("hit", 1);
        }
        assert!(
            t.neg_hits() <= t.counters()["hit"].as_u64().unwrap(),
            "neg_hits 必须是 cache_direct 的子集"
        );
        let ratio = t.neg_hit_ratio();
        assert!(
            (0.0..=1.0).contains(&ratio),
            "ratio 必须落在 0..=1: {ratio}"
        );
    }

    /// **2.1.12**：`count_negative_wire` 对畸形/超短应答必须安全（不 panic、不计）。
    #[test]
    fn negative_wire_probe_is_panic_free_on_malformed_input() {
        let t = ServerTelemetry::new();
        for bad in [
            Vec::new(),
            vec![0u8; 11],
            vec![0xFFu8; 12],
            vec![0u8; 12], // rcode=0、ancount=0 → NODATA → 计 1
        ] {
            count_negative_wire(&t, &bad);
        }
        // 只有最后一条（12 字节、rcode=0、ancount=0）算负应答。
        assert_eq!(t.neg_hits(), 1);
        // 长度 >= 12 且 rcode=3 → 负应答；rcode=0 且 ancount>0 → 正应答。
        let mut r3 = vec![0u8; 12];
        r3[3] = 0x03;
        count_negative_wire(&t, &r3);
        assert_eq!(t.neg_hits(), 2);
        let mut ok = vec![0u8; 12];
        ok[7] = 1; // ancount = 1
        count_negative_wire(&t, &ok);
        assert_eq!(t.neg_hits(), 2, "有答案段的 NOERROR 不是负应答");
    }

    /// **2.1.12**：`log_and_count` 是数据面落遥测的**唯一出口**，负缓存计数只在
    /// 传入服务端遥测时写入：
    /// - 单测的计数桩（`neg_telemetry = None`）→ 只影响 `count_query` 口径，
    ///   既有「`total == hit + miss`」等断言逐字不变；
    /// - 数据面三个出口（`Some(&telemetry)`）→ 缓存直答 + 负应答计 1。
    #[test]
    fn log_and_count_writes_neg_hit_only_when_neg_telemetry_is_given() {
        // 计数桩：未传服务端遥测 → 不写负缓存计数（也无处可写）。
        let stub = ClassifyCounts::new();
        let nx = response_packet("stub.example.", 1, 3, &[]);
        log_and_count(
            &stub,
            None,
            "stub.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome(nx.clone(), true, false, None),
        );
        assert_eq!(stub.hit.load(Ordering::Relaxed), 1, "hit 口径不变");

        // 真遥测 + 快路径形状（resolved=false）：负缓存命中 +1。
        let st = ServerTelemetry::new();
        log_and_count(
            &st,
            Some(&st),
            "real.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome(nx.clone(), true, false, None),
        );
        assert_eq!(st.neg_hits(), 1, "真遥测下缓存 NXDOMAIN 命中应计 1");
        assert_eq!(
            st.counters()["hit"],
            serde_json::json!(1),
            "hit 与 neg_hits 同源"
        );

        // 同一出口再走一次正向缓存直答：hit +1、负缓存计数不变。
        let pos = response_packet(
            "ok.example.",
            1,
            0,
            &[("ok.example.", 1, 4, vec![8, 8, 8, 8])],
        );
        log_and_count(
            &st,
            Some(&st),
            "ok.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome(pos, true, false, None),
        );
        assert_eq!(st.counters()["hit"], serde_json::json!(2));
        assert_eq!(st.neg_hits(), 1, "正向缓存直答不得计入负缓存");
    }

    /// **2.1.18（修复项 9）**：**三条数据面出口**各跑 N 次，断言
    /// `Δtotal == ΔΣ client_rcode == Δhit + Δmiss`。
    ///
    /// 为什么必须用**真实** `ServerTelemetry`（而不是本文件其它用例的计数桩）：
    /// 桩只记录 `count_query` / `log` 的**调用**，看不到"同一个计数器被两处自增"——
    /// 这正是 2.1.17 的 1460 个单测**漏掉** `total` 双计的原因。本用例直接走
    /// [`log_and_count`] + `ServerTelemetry`，任何新增的第二次 `total` 自增都会让它红。
    ///
    /// 三条出口与 `dns.rs` 的生产调用点一一对应：
    /// - **UDP 快路径（缓存直答）**：`is_hit=true, resolved=true, source=Cache`；
    /// - **UDP miss（走上游）**：`is_hit=false, resolved=true, source=Upstream`；
    /// - **畸形包 / FORMERR（error 出口）**：`resolved=false, source=Malformed`。
    #[test]
    fn s18_total_equals_sum_client_rcode_on_all_three_exits() {
        let tel = ServerTelemetry::new();
        let sum_rcode =
            |s: &crate::telemetry::CounterSnapshot| -> u64 { s.client_rcode.iter().sum() };
        let before = tel.snapshot();
        const N: u64 = 10;

        // ① UDP 快路径：缓存直答（rcode=0，有答案段）。
        let hit = outcome(
            response_packet(
                "hit.example.",
                1,
                0,
                &[("hit.example.", 1, 4, vec![10, 0, 0, 1])],
            ),
            true,
            true,
            None,
        );
        // ② UDP miss：上游解析完成（rcode=0 + 一条 A）。
        let miss = outcome(
            response_packet(
                "miss.example.",
                1,
                0,
                &[("miss.example.", 1, 4, vec![10, 0, 0, 2])],
            ),
            false,
            true,
            None,
        );
        // ③ 畸形包出口：FORMERR（`resolved=false`）。
        let bad = {
            let q = query_packet("bad.example.", 1);
            let mut pkt = q.clone();
            pkt.truncate(6); // 截断：走"合成最小头"的兜底分支
            malformed_outcome(&pkt, "truncated")
        };
        assert!(
            bad.resp.len() >= 12,
            "畸形包也必须产出可发送的 FORMERR 应答"
        );

        for _ in 0..N {
            log_and_count(&tel, Some(&tel), "hit.example", "A", None, 0.1, "", &hit);
            log_and_count(&tel, Some(&tel), "miss.example", "A", None, 0.2, "", &miss);
            log_and_count(&tel, Some(&tel), "bad.example", "A", None, 0.0, "", &bad);
        }
        let after = tel.snapshot();
        let d_total = after.total - before.total;
        let d_rcode = sum_rcode(&after) - sum_rcode(&before);
        let d_hit = after.hit - before.hit;
        let d_miss = after.miss - before.miss;
        let d_gap = after.no_response_total - before.no_response_total;

        assert_eq!(
            d_total,
            3 * N,
            "3 条出口 × N 次 ⇒ total 恰好 +30（不得双计）"
        );
        assert_eq!(d_rcode, 3 * N, "每条应答恰好一条 rcode");
        assert_eq!(
            d_total, d_rcode,
            "**硬等式**：Δtotal 必须等于 ΔΣ client_rcode（{d_total} vs {d_rcode}）"
        );
        assert_eq!(d_hit, N, "缓存直答 ⇒ hit +N");
        assert_eq!(d_miss, 2 * N, "miss + err 出口 ⇒ miss +2N");
        assert_eq!(
            d_total,
            d_hit + d_miss,
            "本用例三条出口都被分类为 hit/miss ⇒ Δtotal == Δhit + Δmiss"
        );
        assert_eq!(d_gap, 0, "本用例全部构造出了应答 ⇒ 差额项不动");
        // 同代快照内的等式（与 `api.rs` 的端点级用例同一判据）。
        let sum: u64 = after.client_rcode.iter().sum();
        assert_eq!(sum, after.total, "同代快照：Σ rcode == total");
        assert!(after.hit + after.miss <= after.total, "hit + miss <= total");
        // 三条出口的 rcode 都记到了对应槽位。
        assert_eq!(after.client_rcode[0], 2 * N, "rcode=0：hit + miss 两条出口");
        assert_eq!(after.client_rcode[1], N, "rcode=1：FORMERR 出口");
    }

    /// **2.1.18（修复项 9）**：出口登记但**无可发送报文**时，`total` 不动、
    /// `no_response_total` +1（差额项可对账）—— 与"真的构造出应答"严格分开。
    #[test]
    fn s18_exit_without_constructible_response_only_bumps_the_gap_term() {
        let tel = ServerTelemetry::new();
        let before = tel.snapshot();
        // `resp` 为空（< 12 字节）⇒ 不产生 rcode；`servfail_reason_of` 也因此返回
        // `None`（它要求 `respond >= 12 && rcode == 2`）—— 本用例正是要钉死
        // "没有应答 ⇒ 三个口径（total / client_rcode / servfail_*）都不动"。
        let empty = outcome(Vec::new(), false, true, Some("encode-failed"));
        log_and_count(&tel, Some(&tel), "e.example", "A", None, 0.0, "", &empty);
        let after = tel.snapshot();
        assert_eq!(after.total, before.total, "没有构造出应答 ⇒ total 不得增加");
        assert_eq!(
            after.no_response_total,
            before.no_response_total + 1,
            "差额项必须 +1（否则这条查询会变成静默黑洞）"
        );
        assert_eq!(
            after.client_rcode.iter().sum::<u64>(),
            before.client_rcode.iter().sum::<u64>(),
            "没有应答就没有 rcode"
        );
        assert_eq!(
            after.servfail_total, before.servfail_total,
            "没有发出 rcode=2 ⇒ **不得**计 SERVFAIL（否则 client_rcode[2] == servfail_total 被破坏）"
        );
        assert_eq!(
            after.total + after.no_response_total,
            before.total + before.no_response_total + 1,
            "恒等式：出口登记数 == total + no_response_total"
        );
    }

    /// **2.1.17（修复项 3）**：`cache_skipped_private_total` 必须在数据面**唯一出口**
    /// `log_and_count` 打点，且三处口径一致（counters / 访问器 / metrics 源）。
    ///
    /// 判据（对应 2.1.16 审计的误判本体）：
    /// 1. 未传服务端遥测（计数桩）→ 不写本计数（无副作用）；
    /// 2. 真遥测 + `private_answers_filtered = 2` → 计数 +2，且与访问器同值；
    /// 3. `private_answers_filtered = 0` 的普通应答**不得**改变本计数（防虚报）。
    #[test]
    fn log_and_count_exposes_cache_skipped_private_at_single_exit() {
        let stub = ClassifyCounts::new();
        log_and_count(
            &stub,
            None,
            "p0.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome_private_filtered(2),
        );

        let st = ServerTelemetry::new();
        assert_eq!(
            st.cache_skipped_private_total(),
            0,
            "初值必须为 0（不得有隐式初始值）"
        );
        log_and_count(
            &st,
            Some(&st),
            "p1.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome_private_filtered(2),
        );
        assert_eq!(
            st.cache_skipped_private_total(),
            2,
            "数据面唯一出口必须累加 resolver 回传的过滤条数"
        );
        assert_eq!(
            st.counters()["cache_skipped_private_total"],
            serde_json::json!(2),
            "/api/status.counters 与访问器必须同源同值"
        );

        // 0 条（公网答案）不得改变计数。
        log_and_count(
            &st,
            Some(&st),
            "pub.example",
            "A",
            None::<&str>,
            1.0_f64,
            "",
            &outcome_private_filtered(0),
        );
        assert_eq!(
            st.cache_skipped_private_total(),
            2,
            "未被过滤的应答不得虚报本计数（0 条 = no-op）"
        );
        // 与 `rebind_blocked` 是两个不同的门：数据面过滤**不得**污染控制面计数。
        assert_eq!(
            st.counters()["rebind_blocked"],
            serde_json::json!(0),
            "数据面答案过滤不得写 rebind_blocked（控制面口径）"
        );
    }

    /* ---------- 2.1.44：UDP 热路径必须保留 FastKind（与 TCP 同口径） ---------- */

    /// 2.1.44 测试基座：`ipv6` 可配、脚本化 querier（永不上游）、真钟。
    fn mk_fastkind_resolver(tel: &Arc<ServerTelemetry>, ipv6: bool) -> Arc<Resolver> {
        use ebpdns_resolver::clock::RealClock;
        use ebpdns_resolver::config::ResolverConfig;
        use ebpdns_resolver::query::ScriptedQuerier;
        let mut cfg = ResolverConfig::test_default(Vec::new(), Vec::new(), 1);
        cfg.ipv6 = ipv6;
        Resolver::new(
            cfg,
            tel.clone(),
            Arc::new(RealClock::default()),
            Arc::new(ScriptedQuerier::new(|_n: &str, _t: &str, _d: u32| {
                Vec::new()
            })),
        )
    }

    /// 直接播种一条缓存条目（键与数据面快路径同源：`ckey_normalized`）。
    fn seed_fastkind_cache(
        r: &Resolver,
        domain: &str,
        qtype: &str,
        rcode: u8,
        answers: &[(&str, u16)],
    ) {
        use ebpdns_cache::{CacheAnswer, CacheEntry, DnsCache};
        use ebpdns_resolver::clock::{Clock, RealClock};
        let now = RealClock::default().epoch();
        let ttl = 300.0_f64;
        let key = r.ckey_normalized(domain, qtype);
        let cache_answers: Vec<CacheAnswer> = answers
            .iter()
            .map(|(value, rtype)| CacheAnswer {
                value: (*value).to_string(),
                ttl,
                rtype: *rtype,
                name: None,
            })
            .collect();
        let chosen = answers
            .first()
            .map(|(value, _)| (*value).to_string())
            .unwrap_or_default();
        r.cache().put(
            key,
            CacheEntry {
                domain: domain.to_string(),
                qtype: qtype.to_string(),
                answers: cache_answers,
                chosen,
                ttl,
                rcode,
                rule_gen: r.rule_gen(),
                expires_at: now + ttl,
                seq: 0,
            },
            now,
        );
    }

    /// 发一条 UDP 查询并读回应答（2s 超时 ⇒ 超时即失败，不静默通过）。
    async fn udp_ask(addr: SocketAddr, q: &[u8]) -> Vec<u8> {
        let s = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("UDP client bind");
        s.send_to(q, addr).await.expect("UDP send");
        let mut buf = [0u8; 4096];
        let n = timeout(Duration::from_secs(2), s.recv(&mut buf))
            .await
            .expect("UDP 应答超时")
            .expect("UDP recv");
        buf[..n].to_vec()
    }

    /// 发一条 TCP 查询（2 字节长度前缀）并读回应答。
    async fn tcp_ask(addr: SocketAddr, q: &[u8]) -> Vec<u8> {
        let mut st = TcpStream::connect(addr).await.expect("TCP connect");
        let mut frame = Vec::with_capacity(q.len() + 2);
        frame.extend_from_slice(&(q.len() as u16).to_be_bytes());
        frame.extend_from_slice(q);
        st.write_all(&frame).await.expect("TCP write");
        let mut lenb = [0u8; 2];
        st.read_exact(&mut lenb).await.expect("TCP 长度前缀");
        let mut body = vec![0u8; u16::from_be_bytes(lenb) as usize];
        st.read_exact(&mut body).await.expect("TCP body");
        body
    }

    /// ① UDP `ipv6=false` + 已缓存 AAAA ⇒ 策略应答逐条计 `policy_filtered_total`，
    /// `hit` / `negative_hits` **不增**（旧缺陷：每次 UDP 都 +1 hit、+1 negative_hits）。
    #[tokio::test]
    async fn udp_policy_filtered_counts_only_policy_not_hit() {
        use std::net::Ipv4Addr;
        let tel = Arc::new(ServerTelemetry::new());
        let r = mk_fastkind_resolver(&tel, false);
        seed_fastkind_cache(&r, "aaaa244.example", "AAAA", 0, &[("2001:db8::1", 28)]);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let srv = DnsServer::start_multi_workers(r, tel.clone(), &[addr], &[], 1)
            .await
            .expect("UDP 服务启动");
        let before = tel.snapshot();
        let resp = udp_ask(addr, &query_packet("aaaa244.example", 28)).await;
        let after = tel.snapshot();
        assert_eq!(rcode_of(&resp), 0, "策略应答应是 NOERROR/NODATA");
        assert_eq!(ancount_of(&resp), 0, "ipv6=false 不得下发缓存的 AAAA");
        assert_eq!(
            after.policy_filtered_total - before.policy_filtered_total,
            1,
            "UDP 策略应答必须逐条计 policy_filtered_total"
        );
        assert_eq!(
            after.hit, before.hit,
            "策略应答不得计 hit（旧缺陷：每次 UDP +1）"
        );
        assert_eq!(
            after.negative_hits, before.negative_hits,
            "策略应答不得计 negative_hits（旧缺陷：每次 UDP +1）"
        );
        srv.shutdown().await;
    }

    /// ② UDP 正常缓存命中 A ⇒ `hit +1`（修复不得伤到正常命中路径）。
    #[tokio::test]
    async fn udp_cache_hit_still_counts_hit() {
        use std::net::Ipv4Addr;
        let tel = Arc::new(ServerTelemetry::new());
        let r = mk_fastkind_resolver(&tel, true);
        seed_fastkind_cache(&r, "a244.example", "A", 0, &[("192.0.2.1", 1)]);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let srv = DnsServer::start_multi_workers(r, tel.clone(), &[addr], &[], 1)
            .await
            .expect("UDP 服务启动");
        let before = tel.snapshot();
        let resp = udp_ask(addr, &query_packet("a244.example", 1)).await;
        let after = tel.snapshot();
        assert_eq!(rcode_of(&resp), 0, "缓存命中应回 NOERROR");
        assert_eq!(ancount_of(&resp), 1, "缓存里的 A 必须下发");
        assert_eq!(after.hit - before.hit, 1, "正常缓存命中仍计 hit");
        // **2.1.46（REV247 覆盖不足 #4）**：旧断言只看 hit，2.1.43 旧实现同样绿。
        // 补上"一次查询只落一个出口分类"的硬等式：total +1、miss 不变、无策略/负计。
        assert_eq!(after.total - before.total, 1, "一次 UDP 查询只计一次 total");
        assert_eq!(after.miss, before.miss, "缓存命中不得同时计 miss");
        assert_eq!(
            after.policy_filtered_total, before.policy_filtered_total,
            "正常缓存命中不得计 policy_filtered_total"
        );
        assert_eq!(
            after.negative_hits, before.negative_hits,
            "正向缓存命中不得计 negative_hits"
        );
        srv.shutdown().await;
    }

    /// ③ **UDP 与 TCP 同查询的计数必须一致**（本缺陷的核心判据：TCP 早已正确）。
    #[tokio::test]
    async fn udp_and_tcp_policy_counts_are_consistent() {
        use std::net::Ipv4Addr;
        let tel = Arc::new(ServerTelemetry::new());
        let r = mk_fastkind_resolver(&tel, false);
        seed_fastkind_cache(&r, "dual244.example", "AAAA", 0, &[("2001:db8::2", 28)]);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let srv = DnsServer::start_multi_workers(r, tel.clone(), &[addr], &[addr], 1)
            .await
            .expect("UDP+TCP 服务启动");
        let q = query_packet("dual244.example", 28);
        let b0 = tel.snapshot();
        let ru = udp_ask(addr, &q).await;
        let b1 = tel.snapshot();
        let rt = tcp_ask(addr, &q).await;
        let b2 = tel.snapshot();
        let d_udp = b1.policy_filtered_total - b0.policy_filtered_total;
        let d_tcp = b2.policy_filtered_total - b1.policy_filtered_total;
        assert_eq!(d_udp, 1, "UDP 一次策略应答 ⇒ policy_filtered_total +1");
        assert_eq!(d_tcp, 1, "TCP 一次策略应答 ⇒ policy_filtered_total +1");
        assert_eq!(d_udp, d_tcp, "UDP 与 TCP 同查询的计数口径必须一致");
        assert_eq!(b1.hit, b0.hit, "UDP 策略应答不得计 hit");
        assert_eq!(b2.hit, b1.hit, "TCP 策略应答不得计 hit");
        assert_eq!(
            b2.negative_hits, b0.negative_hits,
            "UDP/TCP 两侧都不得计 negative_hits"
        );
        assert_eq!(rcode_of(&ru), rcode_of(&rt), "UDP/TCP 应答 rcode 必须一致");
        assert_eq!(
            ancount_of(&ru),
            ancount_of(&rt),
            "UDP/TCP 应答 ancount 必须一致"
        );
        assert_eq!(ancount_of(&ru), 0, "ipv6=false ⇒ 两侧都不得下发 AAAA");
        srv.shutdown().await;
    }

    /// ④ 负缓存命中仍计 `negative_hits`（修复不得回归 2.1.12 的负缓存口径）。
    #[tokio::test]
    async fn udp_negative_cache_hit_still_counts_negative_hits() {
        use std::net::Ipv4Addr;
        let tel = Arc::new(ServerTelemetry::new());
        let r = mk_fastkind_resolver(&tel, true);
        seed_fastkind_cache(&r, "nx244.example", "A", 3, &[]);
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, free_port()));
        let srv = DnsServer::start_multi_workers(r, tel.clone(), &[addr], &[], 1)
            .await
            .expect("UDP 服务启动");
        let before = tel.snapshot();
        let resp = udp_ask(addr, &query_packet("nx244.example", 1)).await;
        let after = tel.snapshot();
        assert_eq!(rcode_of(&resp), 3, "负缓存命中应回 NXDOMAIN");
        assert_eq!(after.hit - before.hit, 1, "负缓存命中仍计 hit");
        assert_eq!(
            after.negative_hits - before.negative_hits,
            1,
            "负缓存命中仍计 negative_hits（不得回归）"
        );
        // **2.1.46（REV247 覆盖不足 #5）**：补"单次出口/不重复计 miss"的硬等式；
        // 旧实现（hit+neg 各 +1）也会让原来的两行绿，但多计 miss 会被这里抓住。
        assert_eq!(
            after.total - before.total,
            1,
            "一次负缓存命中只计一次 total"
        );
        assert_eq!(after.miss, before.miss, "负缓存命中不得同时计 miss");
        assert!(
            after.negative_hits <= after.hit,
            "negative_hits 必须是 hit 的子集：neg={} hit={}",
            after.negative_hits,
            after.hit
        );
        assert_eq!(
            after.policy_filtered_total, before.policy_filtered_total,
            "负缓存命中不得计 policy_filtered_total"
        );
        srv.shutdown().await;
    }
}
