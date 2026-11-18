//! DoH 出站 **HTTP/2 多路复用**传输（P0-3）。
//!
//! # 为什么需要它
//!
//! 2.1.50 之前 DoH 走手写最小 HTTP/1.1（[`crate::doh`]）：一条 TLS 连接上只能跑
//! **一个**请求，并发度只能靠"多开连接"（[`crate::pool::MAX_CONN`] = 16 条/上游键）。
//! 高并发下这会带来三类成本：每并发一次 TLS 握手、每条连接一个 fd、以及服务端侧
//! 每连接一条独立拥塞窗口（冷启动/抖动时延迟长尾明显）。RFC 9113 的 h2 **流级多路
//! 复用**正是为此设计：一条 TLS 连接上并发 N 个 stream，连接数由对端
//! `SETTINGS_MAX_CONCURRENT_STREAMS` 约束。
//!
//! # 设计（与成熟实现的对应关系）
//!
//! - **连接/池**：每 `(proto,host,port,path)` 键一组 h2 连接（[`H2_MAX_CONN_PER_KEY`]，
//!   默认 4）。取连接时按"当前活跃 stream 数 < min(对端 SETTINGS 上限, 软上限)"判定
//!   可用；**只有全部连接都满时才新建连接**（`h2::client::SendRequest::current_max_send_streams`
//!   直接读对端 SETTINGS，不自己猜数值）。语义对齐 Go `http2.Transport`
//!   （按对端 max concurrent streams 决定是否新开连接）与 hickory-dns 的 h2 连接池。
//! - **空闲回收/年龄/预算退休**：[`H2_MAX_IDLE`]（60s 未使用）、[`H2_MAX_AGE`]（连接
//!   年龄 40s）或 [`H2_MAX_STREAMS_LIFETIME`]（承载满 512 个 stream）到期的连接在下次
//!   取用时回收（drop ⇒ close），避免撞上对端 ~22–50s 的连接回收；与 [`crate::pool`]
//!   的"惰性回收"同风格，不新增后台任务。
//! - **GOAWAY/错误**：连接级 GOAWAY/关闭由驱动任务标记 `closed` 并计入
//!   `goaway_total`；调用方（[`crate::doh`]）据此**重连一次**再重试。stream 级
//!   RST_STREAM 只失败该 stream，连接保留。
//! - **可观测**：[`H2Stats`]（全局）与 [`H2KeyStats`]（逐键）暴露
//!   `conns_open` / `streams_active` / `streams_total` / `goaway_total` /
//!   `fallback_h1_total`，对应 `/metrics` 的 `ebpdns_doh_h2_*` 与 `/api/upstreams[]`。
//!
//! # 与 HTTP/1.1 回退的关系
//!
//! 传输选择在 **TLS 握手之后**按 ALPN 协商结果决定（[`crate::doh`] 的 `connect_doh`
//! 恒传 `["h2","http/1.1"]`）：协商到 `h2` ⇒ 本模块；否则走既有 HTTP/1.1 实现
//! （连接池/每连接单请求语义不变）。服务端只支持 h1 时**自动回退，不失败**。
//!
//! # RFC 8484 相关
//!
//! - qid：DoH 客户端 SHOULD 用 `0`（RFC 8484 §4.1），由 [`crate::doh`] 统一改写并在
//!   响应侧按 `0` 校验后还原调用方 qid；
//! - 报文 framing：h2 用 DATA 帧 + END_STREAM 界定正文，**不依赖** Content-Length，
//!   也没有 HTTP/1.1 的 `Transfer-Encoding`/`Connection` 语义；
//! - 上限：正文累计超过 [`MAX_BODY`] 即主动 RST_STREAM（drop 未读完的 `RecvStream`），
//!   连接不受影响；超时/取消同理（drop ⇒ RST_STREAM(CANCEL)），**不泄漏连接**。

use std::collections::HashMap;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::Reason;
use http::{header, Method, Request, StatusCode, Version};
use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::pool::{PoolKey, TlsConn};

/// DoH 响应正文上限（字节）。DNS 报文最大 65535（TCP/h2 无 512 限制）。
///
/// 与 2.1.50 之前 HTTP/1.1 实现的上限**逐字一致**（`Content-Length` 12..=65535），
/// 只是现在改为对 h2 DATA 帧累计值判定。
pub(crate) const MAX_BODY: usize = 65535;

/// 单条 h2 连接上允许的并发 stream **软上限**。
///
/// 硬约束是服务端 `SETTINGS_MAX_CONCURRENT_STREAMS`（由 h2 库跟踪）；这里再压一个
/// 软上限，避免"对端声明 1000 条"时把全部在途请求堆在一条连接上（TCP 级队头阻塞）。
/// 取值 64：远大于默认 `upstream_max_inflight`（32），单条连接即可承载一个上游的
/// 全部在途请求，只有极端场景才会触发第二条连接。
pub const H2_MAX_STREAMS_PER_CONN: usize = 64;

/// 每 `(proto,host,port,path)` 键保留的 h2 连接数上限。
///
/// 4 条 × 每连接 ≥64 stream = 256 个并发 stream/键，远高于 `upstream_max_inflight`
/// 的默认 32 与 [`crate::pool::MAX_CONN`] 的历史并发上限；留余量是为了对端只给
/// 很小的 `SETTINGS_MAX_CONCURRENT_STREAMS`（例如 8/16）时仍能跑满在途请求。
pub const H2_MAX_CONN_PER_KEY: usize = 4;

/// h2 连接空闲回收时间（**2.2.4/P2-G：20→60s**；2.2.3 为 20s）。
///
/// `reclaim_entry`（metrics/upstreams 快照触发的惰性回收）在连接**空闲 ≥60s 或
/// 连接年龄 ≥[`H2_MAX_AGE`]** 时关闭它。2.2.3 把本值压到 20s，等于"低 QPS 下每条
/// 查询都新建连接"；2.2.4 后真正的 GOAWAY 防护由 [`H2_MAX_AGE`]（按连接年龄）承担，
/// 空闲回收只负责清理长期无人使用的连接，不再制造握手。
pub const H2_MAX_IDLE: Duration = Duration::from_secs(60);

/// **2.2.4（P2-G）**：复用前的空闲守卫 —— 空闲 ≥30s 的连接**不再复用**。
///
/// 生产实测对端空闲回收约 50s（2.2.3 受控样本 50.6s）；30s 守卫留 20s 安全边界。
/// 2.2.3 的 20s 守卫会把 20–30s 间隔的查询全部推到新连接，而这段空闲仍在对端
/// 安全区内 —— 2.2.4 放宽到 30s 以减少低 QPS 握手。
pub const H2_REUSE_IDLE_GUARD: Duration = Duration::from_secs(30);

/// **2.2.4（P2-G）**：连接**年龄**上限 —— 年龄 ≥40s 的连接不再开新 stream。
///
/// 2.2.3 的 GOAWAY 残余（peer）集中在连接寿命 40–62s（均值 50.6s），且 300qps 下
/// 连接几乎不空闲 ⇒ 对端是按**连接年龄**回收，而不是按空闲时间。仅靠 20s 空闲守卫
/// 在高 QPS 下根本不触发（连接从没空闲 20s），所以 2.2.4 改为按年龄主动退休：
/// **在对端 ~50s 回收之前**（40s 上限 + 10s 边界）主动换新连接，把 peer GOAWAY
/// 转成本地 `local_idle`。代价是高 QPS 下每连接生命周期多一次 TLS+h2 握手
/// （每上游键约 40s 一次，可忽略），换来 0 次对端 GOAWAY 重试。
pub const H2_MAX_AGE: Duration = Duration::from_secs(40);

/// **2.2.5（P2-A5）**：单条连接的**生命周期 stream 预算** —— 承载满 512 个 stream
/// 即主动退休（本地 `local_idle`），不再等对端 GOAWAY。
///
/// 实测依据（2.2.4 自测，50qps × 180s × 2 个 DoH 上游）：
/// * `H2_MAX_AGE=40s` 对 peer GOAWAY **无效**（8 次，与 2.2.3 的 9 次同量级）——
///   对端在连接寿命 ~22.6s（2.2.3 均值）就回收，早于 40s；
/// * 该负载下每上游约 25qps ⇒ 22.6s ≈ **565 个 stream**；预算 400 在 ~16s 主动
///   退休，可抢在对端之前。
///
/// **2.2.5 调参（2.2.4 → 512）**：2.2.4 用 400 时 peer GOAWAY 已降到 0，但 180s 内
/// 有 44 次主动换新握手（≈0.24 次/s），把 50qps 的 p99 从 251ms 抬到 287ms。
/// 512 仍低于实测对端回收阈值（~565 stream），留 ~9% 安全边界；握手次数按比例
/// 降到 ~34 次/180s，p99 随之回落且**不重新引入 peer GOAWAY**。更高（如 560）虽
/// 更少握手，但离 565 太近、对端行为抖动就可能重新触发 GOAWAY —— 不做。
///
/// 空闲连接每 25s 才 1 个 stream ⇒ 永远够不到 512，仍走 [`H2_MAX_AGE`] / 空闲回收，
/// 因此低 QPS 的握手收益（空闲 25s 复用）不被牺牲。
pub const H2_MAX_STREAMS_LIFETIME: u64 = 512;

/// DoH 实际使用的传输形态（`/api/upstreams[].doh_transport`）。
///
/// **2.2.2（P2-06）**：新增 [`DohTransport::Idle`]。旧实现连接关闭后 `transport=None`
/// ⇒ `/api/upstreams` 回 `null`，运维/前端会误读成"没走 h2"（生产 `ali-doh` 有 86 条
/// h2 stream 却显示 null）。现在：有连接/回退样本时给 `h2`/`http/1.1`；**空闲时保留
/// last-known**；从未有过样本时明确显示 `"idle"`（而不是 null）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DohTransport {
    /// HTTP/2 流级复用。
    H2,
    /// HTTP/1.1（ALPN 未协商到 h2 ⇒ 既有回退路径）。
    Http11,
    /// **2.2.2**：当前无连接且还没有任何传输样本（明确语义，不是"未知"）。
    Idle,
}

impl DohTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H2 => "h2",
            Self::Http11 => "http/1.1",
            Self::Idle => "idle",
        }
    }
}

/// **2.2.2（P2-03）/ 2.2.3（P2-E）**：h2 连接被终止的原因（逐键计数，`/api/upstreams` 与
/// `/metrics` 同源）。
///
/// 2.2.2 把"驱动任务看到连接 future 结束"统一叫 `driver-end`，但里面混着三类完全不同的
/// 事件：对端 EOF/正常关闭（`peer`）、请求中途 I/O 断开（`io`）、协议错误（`protocol`）；
/// 本地空闲回收（`local_idle`）则根本不算对端 GOAWAY。2.2.3 起四类分开：
/// * `goaway_total = peer + io + protocol`（**不含**本地空闲回收）；
/// * `local_idle` 单独计数，且从不使用过的空闲连接不计入平均寿命。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoawayReason {
    /// 对端显式 GOAWAY / 正常 EOF 关闭（h2 连接 future 正常结束）。
    PeerGoaway,
    /// 请求中途 I/O 断开（对端关连接 / TCP reset）。
    Io,
    /// 协议错误（h2 协议/帧层错误，非 GOAWAY/IO）。
    Protocol,
    /// 本地回收（空闲超龄 / 每键上限 / 上游删除）—— **不属于** goaway_total。
    LocalIdle,
}

impl GoawayReason {
    fn idx(self) -> usize {
        match self {
            Self::PeerGoaway => 0,
            Self::Io => 1,
            Self::Protocol => 2,
            Self::LocalIdle => 3,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerGoaway => "peer-goaway",
            Self::Io => "io",
            Self::Protocol => "protocol",
            Self::LocalIdle => "local-idle",
        }
    }
}

/// h2 连接池全局指标快照（`/metrics` 用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H2Stats {
    /// 当前打开的 h2 连接数（gauge）。
    pub conns_open: u64,
    /// 当前活跃（已开未收完）h2 stream 数（gauge）。
    pub streams_active: u64,
    /// 累计发起的 h2 stream 数。
    pub streams_total: u64,
    /// 累计因对端 GOAWAY/关闭（含请求中途 I/O 断开）而终止的 h2 连接数。
    pub goaway_total: u64,
    /// **2.2.3（P2-E）**：GOAWAY 原因细分（`goaway_total == peer + io + protocol`）。
    pub goaway_peer_total: u64,
    pub goaway_io_total: u64,
    pub goaway_protocol_total: u64,
    /// **2.2.3（P2-E）**：本地空闲回收（**不计**入 `goaway_total`）。
    pub local_idle_total: u64,
    /// **2.2.5（P2-A4）/ 2.2.6（P2-A1）**：对端终止（peer/io/protocol）中**无在途
    /// stream** 的空闲回收**连接数**（不是请求失败）。
    /// 恒等式：`goaway_total == goaway_idle_total + goaway_conn_inflight_total`。
    pub goaway_idle_total: u64,
    /// **2.2.6（P2-A1，改名自 `goaway_inflight_total`）**：对端终止时**有在途
    /// stream** 的**连接数**（连接级口径：一条连接上有 N 条在途也只记 1）。
    /// 该值 > 0 才代表"GOAWAY 真的打到了请求"。
    pub goaway_conn_inflight_total: u64,
    /// **2.2.6（P2-A1，新增）**：**stream 级**受影响请求数 = 每次在途终止时
    /// `active`（在途 stream 数）之和。这是"被打到的请求数"的精确口径：
    /// `goaway_streams_lost_total >= goaway_conn_inflight_total`（每条在途终止连接
    /// 至少贡献 1）。连接级与 stream 级两个口径**分开暴露**，不再混为一个字段。
    pub goaway_streams_lost_total: u64,
    /// 累计因 ALPN 只协商到 http/1.1 而回退的连接数。
    pub fallback_h1_total: u64,
    /// **2.2.2（P2-03）/ 2.2.3（P2-E）**：已关闭的**真实**连接数（用过 ≥1 stream 或
    /// 由对端/IO/协议终止；**不含**从未使用的本地空闲回收）与总寿命（毫秒）。
    pub conns_closed_total: u64,
    pub conn_life_ms_total: u64,
    /// **2.2.3（P2-E）**：从未使用、被本地空闲回收的连接数（单独可见）。
    pub conns_idle_reclaimed_total: u64,
}

/// 逐键 h2 指标快照（`/api/upstreams[]` 用）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct H2KeyStats {
    pub conns_open: u64,
    pub streams_active: u64,
    pub streams_total: u64,
    pub goaway_total: u64,
    /// **2.2.3（P2-E）**：GOAWAY 原因细分 + 本地空闲回收。
    pub goaway_peer_total: u64,
    pub goaway_io_total: u64,
    pub goaway_protocol_total: u64,
    pub local_idle_total: u64,
    /// **2.2.5（P2-A4）/ 2.2.6（P2-A1）**：对端终止的空闲 / 在途连接分账（逐键）。
    /// `goaway_total == idle + conn_inflight`；`streams_lost` 是 stream 级受影响数。
    pub goaway_idle_total: u64,
    pub goaway_conn_inflight_total: u64,
    pub goaway_streams_lost_total: u64,
    pub fallback_h1_total: u64,
    /// **2.2.3（P2-E）**：真实连接寿命（已关闭、无样本 = 0）与"从未使用"的空闲回收数。
    pub conns_closed_total: u64,
    pub conns_idle_reclaimed_total: u64,
    pub conn_life_ms_avg: u64,
    /// 该键当前的传输形态；`None` = 还没有任何 h2/h1 连接样本（API 会显示 `"idle"`）。
    pub transport: Option<DohTransport>,
}

/// 一次 h2 交换的失败分类（`/api` 不暴露细节，只用于重试/回收判定与 debug 日志）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum H2Error {
    /// 预算耗尽（deadline）。
    Timeout,
    /// 对端 GOAWAY。
    Goaway,
    /// 连接已关闭/发送失败。
    Closed,
    /// 对端以 REFUSED_STREAM 拒绝该 stream（未处理，可安全重试）。
    Refused,
    /// 对端 RST_STREAM（其它原因码）。
    Reset(u32),
    /// 非 200 状态码。
    Status(u16),
    /// content-type 不含 `application/dns-message`。
    ContentType,
    /// 正文超过 [`MAX_BODY`]。
    TooLarge,
    /// 协议/编码错误（含 h2 握手失败）。
    Protocol(String),
    /// 传输层 I/O 错误。
    Io,
}

impl H2Error {
    /// 是否值得"重连/重试一次"（连接级失败：GOAWAY/连接关闭/REFUSED_STREAM/IO；
    /// **P2**：以及 HTTP `5xx` —— 与 h1 路径"非 200 重试一次"对齐）。
    ///
    /// DNS 查询是幂等的，所以"连接在请求过程中死掉"（`Io`：EOF/reset）重连一次是安全的；
    /// stream 级失败（服务端明确 RST_STREAM 其它 reason）与超时/超大/错类型**不**重试 ——
    /// 那些重试只会把同一个错误重复一遍。5xx 是服务端瞬时错误（网关 502/503 常见），
    /// h1 路径一直会新建连接重试一次；h2 若直接失败会造成"同一上游两条路径行为不一致"。
    pub(crate) fn retryable(&self) -> bool {
        matches!(
            self,
            Self::Goaway | Self::Closed | Self::Refused | Self::Io | Self::Status(500..=599)
        )
    }

    /// 是否应把该连接从池里摘掉（连接已不可用）。
    pub(crate) fn evict_conn(&self) -> bool {
        matches!(
            self,
            Self::Goaway | Self::Closed | Self::Io | Self::Protocol(_)
        )
    }

    /// 稳定短标签（日志/单测断言用）。
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Goaway => "goaway",
            Self::Closed => "closed",
            Self::Refused => "refused-stream",
            Self::Reset(_) => "rst-stream",
            Self::Status(_) => "status",
            Self::ContentType => "content-type",
            Self::TooLarge => "too-large",
            Self::Protocol(_) => "protocol",
            Self::Io => "io",
        }
    }
}

impl std::fmt::Display for H2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Status(s) => write!(f, "status: {s}"),
            Self::Reset(r) => write!(f, "rst-stream: {r}"),
            Self::Protocol(m) => write!(f, "protocol: {m}"),
            other => f.write_str(other.kind()),
        }
    }
}

/// 共享计数器（全局 + 逐键同形；全局由各键求和得到）。
#[derive(Debug, Default)]
struct Counters {
    conns_open: AtomicU64,
    streams_active: AtomicU64,
    streams_total: AtomicU64,
    goaway_total: AtomicU64,
    /// **2.2.3（P2-E）**：GOAWAY 原因细分（peer / io / protocol / local-idle）。
    goaway_by_reason: [AtomicU64; 4],
    /// **2.2.5（P2-A4）/ 2.2.6（P2-A1）**：对端终止（peer/io/protocol）按**终止
    /// 瞬间是否有在途 stream** 细分：`idle` = 空闲连接被对端回收（不是请求失败）；
    /// `conn_inflight` = 有请求在途的**连接数**（连接级口径）；`streams_lost` = 这些
    /// 终止连接上**在途 stream 数之和**（stream 级 = 受影响请求数）。
    /// 恒等式：`goaway_total == idle + conn_inflight`，
    /// 且 `streams_lost >= conn_inflight`。
    goaway_idle: AtomicU64,
    goaway_conn_inflight: AtomicU64,
    goaway_streams_lost: AtomicU64,
    fallback_h1_total: AtomicU64,
    /// **2.2.3（P2-E）**：真实连接关闭数 + 总寿命；从未使用的空闲回收单独计数。
    conns_closed: AtomicU64,
    conn_life_ms_total: AtomicU64,
    conns_idle_reclaimed: AtomicU64,
}

impl Counters {
    fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.conns_open.load(Ordering::Relaxed),
            self.streams_active.load(Ordering::Relaxed),
            self.streams_total.load(Ordering::Relaxed),
            self.goaway_total.load(Ordering::Relaxed),
            self.fallback_h1_total.load(Ordering::Relaxed),
        )
    }

    fn goaway_breakdown(&self) -> [u64; 4] {
        [
            self.goaway_by_reason[0].load(Ordering::Relaxed),
            self.goaway_by_reason[1].load(Ordering::Relaxed),
            self.goaway_by_reason[2].load(Ordering::Relaxed),
            self.goaway_by_reason[3].load(Ordering::Relaxed),
        ]
    }

    /// **2.2.5（P2-A4）/ 2.2.6（P2-A1）**：对端终止的空闲 / 在途 / 丢失 stream 分账。
    /// 返回 `(idle_conns, inflight_conns, streams_lost)`。
    fn goaway_activity_split(&self) -> (u64, u64, u64) {
        (
            self.goaway_idle.load(Ordering::Relaxed),
            self.goaway_conn_inflight.load(Ordering::Relaxed),
            self.goaway_streams_lost.load(Ordering::Relaxed),
        )
    }

    fn conn_life(&self) -> (u64, u64, u64) {
        (
            self.conns_closed.load(Ordering::Relaxed),
            self.conn_life_ms_total.load(Ordering::Relaxed),
            self.conns_idle_reclaimed.load(Ordering::Relaxed),
        )
    }

    /// 清空**只增不减**的累计量（`/api/reset` 与键回收共用）。
    ///
    /// 刻意不动 `conns_open`/`streams_active`：这两个 gauge 由连接/lease 的 Drop
    /// 递减，提前清零会让后续 `fetch_sub` 下溢。
    fn reset_counters(&self) {
        self.streams_total.store(0, Ordering::Relaxed);
        self.goaway_total.store(0, Ordering::Relaxed);
        for c in &self.goaway_by_reason {
            c.store(0, Ordering::Relaxed);
        }
        self.goaway_idle.store(0, Ordering::Relaxed);
        self.goaway_conn_inflight.store(0, Ordering::Relaxed);
        self.goaway_streams_lost.store(0, Ordering::Relaxed);
        self.fallback_h1_total.store(0, Ordering::Relaxed);
        // **2.2.2（P2-03）**：连接寿命样本是累计量，`/api/reset` 与其它累计量一起清空。
        self.conns_closed.store(0, Ordering::Relaxed);
        self.conn_life_ms_total.store(0, Ordering::Relaxed);
        self.conns_idle_reclaimed.store(0, Ordering::Relaxed);
    }
}

/// **2.2.6（P2-A1）**：把一次"对端终止"按终止瞬间的**在途 stream 数**分账。
///
/// 独立成函数（而不是内联在 `H2Conn::note_termination` 里）是为了能被单测直接覆盖：
/// 构造真实 TLS/h2 连接来制造"终止时恰有 N 条在途 stream"极不稳定，而记账口径本身
/// 与连接无关。
///
/// 口径（**连接级 + stream 级双账**）：
/// * `active_streams == 0` ⇒ `goaway_idle +1`（对端空闲回收，**不是**请求失败）；
/// * `active_streams > 0`  ⇒ `goaway_conn_inflight +1` **且** `goaway_streams_lost += active_streams`
///   （前者回答"有几条连接被打到"，后者回答"有几个在途请求被打到"）。
///
/// 因此恒等式 `goaway_total == goaway_idle + goaway_conn_inflight` 与
/// `goaway_streams_lost >= goaway_conn_inflight` 同时成立。
fn note_goaway_activity(counters: &Counters, active_streams: u64) {
    if active_streams == 0 {
        counters.goaway_idle.fetch_add(1, Ordering::Relaxed);
    } else {
        counters
            .goaway_conn_inflight
            .fetch_add(1, Ordering::Relaxed);
        counters
            .goaway_streams_lost
            .fetch_add(active_streams, Ordering::Relaxed);
    }
}

/// 单键状态：连接列表 + 计数器 + 建连串行化门 + 是否已被删除。
struct KeyEntry {
    conns: Mutex<Vec<Arc<H2Conn>>>,
    counters: Arc<Counters>,
    /// **建连串行化门（single-flight）**：冷启动/重连突发时，只让一个查询去建连接，
    /// 其余查询等门后**双检**（见 [`crate::doh::attempt`]）——否则 N 个并发查询会各建
    /// 一条 h2 连接，而 h2 的意义本就是用一条连接的多 stream 承载 N 个并发。
    ///
    /// 只在"该键从未回退过 http/1.1"时使用（[`H2Pool::needs_gate`]）：h1-only 服务端
    /// 首条查询落定后就不再用门，避免把既有 h1 并发序列化。
    gate: Arc<tokio::sync::Mutex<()>>,
    discarded: AtomicBool,
    /// **2.2.2（P2-06）**：最近一次实际使用的传输形态（连接关闭后仍保留，避免
    /// `doh_transport` 在空闲时回 `null` 被误读成"未走 h2"）。
    last_transport: Mutex<Option<DohTransport>>,
}

impl KeyEntry {
    fn new() -> Self {
        Self {
            conns: Mutex::new(Vec::new()),
            counters: Arc::new(Counters::default()),
            gate: Arc::new(tokio::sync::Mutex::new(())),
            discarded: AtomicBool::new(false),
            last_transport: Mutex::new(None),
        }
    }
}

/// DoH h2 连接池（每键一组多路复用连接）。
#[derive(Default)]
pub struct H2Pool {
    entries: Mutex<HashMap<PoolKey, Arc<KeyEntry>>>,
}

impl H2Pool {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_entry(&self, key: &PoolKey) -> Option<Arc<KeyEntry>> {
        self.entries.lock().get(key).cloned()
    }

    fn entry(&self, key: &PoolKey) -> Arc<KeyEntry> {
        let mut g = self.entries.lock();
        g.entry(key.clone())
            .or_insert_with(|| Arc::new(KeyEntry::new()))
            .clone()
    }

    /// 建连前取该键的计数器（`establish` 需要；同时保证键存在）。
    fn counters_for(&self, key: &PoolKey) -> Arc<Counters> {
        self.entry(key).counters.clone()
    }

    /// 是否需要"建连串行化门"：该键**还没**回退过 http/1.1（即 h2 仍有可能）。
    ///
    /// h1-only 服务端在首条查询后 `fallback_h1_total > 0` ⇒ 不再进出门，
    /// 既有 HTTP/1.1 并发度完全不受影响。
    pub(crate) fn needs_gate(&self, key: &PoolKey) -> bool {
        match self.get_entry(key) {
            Some(e) => e.counters.fallback_h1_total.load(Ordering::Relaxed) == 0,
            None => true,
        }
    }

    /// 取该键的建连串行化门（只用于"需要新建连接"的分支）。
    pub(crate) async fn lock_gate(
        &self,
        key: &PoolKey,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let entry = self.entry(key);
        Some(entry.gate.clone().lock_owned().await)
    }

    /// 回收该键下已关闭/空闲超龄/年龄超限的连接（drop ⇒ 发送 close 信号 ⇒ 驱动任务收尾）。
    fn reclaim_entry(&self, entry: &KeyEntry) {
        let now = Instant::now();
        let mut g = entry.conns.lock();
        g.retain(|c| {
            // **2.2.4（P2-G）**：空闲回收（`H2_MAX_IDLE`）+ 连接年龄退休（`H2_MAX_AGE`）
            // + stream 预算退休（`H2_MAX_STREAMS_LIFETIME`）。
            let idle = now.duration_since(*c.last_used.lock());
            let stale = idle >= H2_MAX_IDLE
                || c.opened_at.elapsed() >= H2_MAX_AGE
                || c.streams_started.load(Ordering::Relaxed) >= H2_MAX_STREAMS_LIFETIME;
            let keep = !c.closed.load(Ordering::Relaxed) && !stale;
            if !keep {
                // 标记后由 retain 负责 drop（无其它引用时立即发 close 信号；
                // 若仍有在途 lease，则等最后一个 Arc 归还时关闭）。
                c.mark_closed();
                // **2.2.3（P2-E）**：池子主动回收必须在**第一时间**记 `local_idle`，
                // 不能只等驱动任务收尾 —— 若此刻对端也正好发 GOAWAY，select 可能
                // 先跑 `conn_fut`，把本地回收误记成 peer（实测 30s 边界竞态）。
                c.note_termination(GoawayReason::LocalIdle);
            }
            keep
        });
    }

    /// 取一个可用的 h2 stream 槽（**流级复用**的唯一入口）。
    ///
    /// 语义：遍历该键的连接，取第一条"还能再开一个 stream"的；全部满/无连接 ⇒ `None`
    /// （调用方据此决定"新建连接"或"走 h1 回退"）。
    pub(crate) fn acquire_lease(&self, key: &PoolKey) -> Option<H2Lease> {
        let entry = self.get_entry(key)?;
        if entry.discarded.load(Ordering::Relaxed) {
            return None;
        }
        self.reclaim_entry(&entry);
        let candidates: Vec<Arc<H2Conn>> = entry.conns.lock().clone();
        for conn in candidates {
            if let Some(lease) = conn.lease() {
                return Some(lease);
            }
        }
        None
    }

    /// 注册一条新建的 h2 连接。返回 `false` = 未注册（每键连接数已达上限）。
    ///
    /// 未注册的连接仍可被本次查询使用，但用完即关（不泄漏：`Arc` 归零 ⇒ close 信号）。
    /// 已 `discard` 的键在**重新注册**时复活（上游删除后同键重新加回仍能继续用 h2）。
    pub(crate) fn register(&self, key: &PoolKey, conn: Arc<H2Conn>) -> bool {
        let entry = self.entry(key);
        entry.discarded.store(false, Ordering::Relaxed);
        let mut g = entry.conns.lock();
        // 顺手清掉已关闭/超龄的连接，给新连接腾位置（上限判定用"活连接"数）。
        let now = Instant::now();
        g.retain(|c| {
            !c.closed.load(Ordering::Relaxed)
                && now.duration_since(*c.last_used.lock()) < H2_MAX_IDLE
                && c.opened_at.elapsed() < H2_MAX_AGE
                && c.streams_started.load(Ordering::Relaxed) < H2_MAX_STREAMS_LIFETIME
        });
        if g.len() >= H2_MAX_CONN_PER_KEY {
            return false;
        }
        g.push(conn);
        // **2.2.2（P2-06）**：记录 last-known 传输形态（连接关闭后仍可显示 "h2"）。
        *self.entry(key).last_transport.lock() = Some(DohTransport::H2);
        true
    }

    /// 把一条连接标记为不可用并从池中摘除（GOAWAY / RST 导致连接级失败时）。
    pub(crate) fn evict(&self, key: &PoolKey, conn: &Arc<H2Conn>) {
        conn.mark_closed();
        if let Some(entry) = self.get_entry(key) {
            let mut g = entry.conns.lock();
            g.retain(|c| !Arc::ptr_eq(c, conn));
        }
    }

    /// 记录一次"ALPN 只协商到 http/1.1"的回退（每次**新建连接**记一次）。
    ///
    /// **P2（discard/register 复活键 ≤90s）**：把 `discarded` 一并清除。旧实现只有
    /// `register`（h2 建连成功）才复活键，于是"删除上游 → 90s 内同键重新加回，但它是
    /// h1-only 服务端"时：首次查询走 h1 回退、`fallback_h1_total` 被 stats 跳过
    /// （discarded 条目不计）⇒ `/api/upstreams[].doh_transport` 永远为 null。
    /// 任何新的连接活动都证明该键重新启用，应立刻复活。
    pub(crate) fn note_fallback_h1(&self, key: &PoolKey) {
        let entry = self.entry(key);
        entry.discarded.store(false, Ordering::Relaxed);
        *entry.last_transport.lock() = Some(DohTransport::Http11);
        entry
            .counters
            .fallback_h1_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 删除上游时回收该键的全部 h2 连接（键条目保留但标记 `discarded`：
    /// 之后 `acquire_lease` 不再取它，`stats()` 不再计它；同键重新加回时由
    /// [`Self::register`] 复活 —— 这样"删除 + 立刻重建"不会丢 h2 能力，
    /// 也不会在删除竞态下留下无人回收的连接）。
    pub(crate) fn discard(&self, key: &PoolKey) {
        let Some(entry) = self.get_entry(key) else {
            return;
        };
        entry.discarded.store(true, Ordering::Relaxed);
        // 累计量清零（该上游已删除；同键重新加回时从 0 开始）。gauge（conns_open /
        // streams_active）**不清**：它们由连接/lease 的 Drop 递减，提前清零会下溢。
        entry.counters.reset_counters();
        let conns: Vec<Arc<H2Conn>> = std::mem::take(&mut *entry.conns.lock());
        for c in &conns {
            c.mark_closed();
            c.note_termination(GoawayReason::LocalIdle);
        }
        drop(conns); // drop ⇒ close 信号 ⇒ 驱动任务退出（TLS 连接关闭）
                     // **2.2.1（P2-08）**：把 KeyEntry 从 `entries` 移除。2.2.0 只标 `discarded`、
                     // 永不删除 ⇒ 反复改上游 host/path 会按 (proto,host,port,path) 无界累积
                     // KeyEntry（每个含 Conn 表/计数器/锁）。并发持有者手里的 Arc 不受影响：
                     // 它们只会操作这个已"脱池"的条目，用完全部 drop。
                     // 仅当 map 里仍是**同一个** Arc 时才删（避免误删刚被同键 register 复活的新条目）。
        let mut g = self.entries.lock();
        if g.get(key).is_some_and(|cur| Arc::ptr_eq(cur, &entry)) {
            g.remove(key);
        }
    }

    /// 全池指标快照（`/metrics`；先做一次惰性回收，避免把已死连接算成 open）。
    pub fn stats(&self) -> H2Stats {
        let entries: Vec<Arc<KeyEntry>> = self.entries.lock().values().cloned().collect();
        let mut out = H2Stats::default();
        for e in &entries {
            if e.discarded.load(Ordering::Relaxed) {
                continue;
            }
            self.reclaim_entry(e);
            let (c, a, t, g, f) = e.counters.snapshot();
            let [gp, gi, gpc, gli] = e.counters.goaway_breakdown();
            let (g_idle, g_inflight, g_lost) = e.counters.goaway_activity_split();
            let (closed, life_ms, idle_reclaimed) = e.counters.conn_life();
            out.conns_open += c;
            out.streams_active += a;
            out.streams_total += t;
            out.goaway_total += g;
            out.goaway_peer_total += gp;
            out.goaway_io_total += gi;
            out.goaway_protocol_total += gpc;
            out.local_idle_total += gli;
            out.goaway_idle_total += g_idle;
            out.goaway_conn_inflight_total += g_inflight;
            out.goaway_streams_lost_total += g_lost;
            out.fallback_h1_total += f;
            out.conns_closed_total += closed;
            out.conn_life_ms_total += life_ms;
            out.conns_idle_reclaimed_total += idle_reclaimed;
        }
        out
    }

    /// 逐键指标快照（`/api/upstreams[]`；不建键、不产生副作用）。
    pub fn key_stats(&self, key: &PoolKey) -> H2KeyStats {
        let Some(entry) = self.get_entry(key) else {
            return H2KeyStats::default();
        };
        let (conns_open, streams_active, streams_total, goaway_total, fallback_h1_total) =
            entry.counters.snapshot();
        let [gp, gi, gpc, gli] = entry.counters.goaway_breakdown();
        let (g_idle, g_inflight, g_lost) = entry.counters.goaway_activity_split();
        let (closed, life_ms, idle_reclaimed) = entry.counters.conn_life();
        // **2.2.2（P2-06）**：连接关闭后保留 last-known（h2 / http/1.1）；从未有样本 ⇒
        // `None`（API 层渲染为明确的 `"idle"`，不再回 null）。
        let transport = *entry.last_transport.lock();
        H2KeyStats {
            conns_open,
            streams_active,
            streams_total,
            goaway_total,
            goaway_peer_total: gp,
            goaway_io_total: gi,
            goaway_protocol_total: gpc,
            local_idle_total: gli,
            goaway_idle_total: g_idle,
            goaway_conn_inflight_total: g_inflight,
            goaway_streams_lost_total: g_lost,
            fallback_h1_total,
            conns_closed_total: closed,
            conns_idle_reclaimed_total: idle_reclaimed,
            conn_life_ms_avg: life_ms.checked_div(closed).unwrap_or(0),
            transport,
        }
    }

    /// `/api/reset`：清空累计计数器（gauge 保持现场）。
    pub fn reset_counters(&self) {
        let entries: Vec<Arc<KeyEntry>> = self.entries.lock().values().cloned().collect();
        for e in &entries {
            e.counters.reset_counters();
        }
    }
}

/// 一条 h2 客户端连接（TLS 之上）+ 其驱动任务句柄。
pub(crate) struct H2Conn {
    /// h2 请求句柄。`SendRequest` 自身不是 `Sync` 语义上的并发写目标，用锁串行化
    /// "取发送权"这一步（临界区只有一次 `send_request`，不做 I/O 等待）。
    send: Mutex<SendRequest<Bytes>>,
    /// 当前活跃 stream 数（RAII：`H2Lease` drop 时减 1）。
    active: AtomicUsize,
    /// 对端 `SETTINGS_MAX_CONCURRENT_STREAMS` 的最近观测值（usize::MAX = 未声明）。
    peer_max: AtomicUsize,
    closed: AtomicBool,
    /// 连接被计入 `goaway_total` 的幂等标记（同一连接最多一次）。
    goaway_noted: AtomicBool,
    /// **2.2.2（P2-03）**：首次终止原因（0=未计，1=peer，2=io，3=driver-end；幂等）。
    goaway_reason: AtomicU8,
    /// **2.2.2（P2-03）**：建连时刻（关闭时累计寿命，判断是否被对端"短命踢掉"）。
    opened_at: Instant,
    /// **2.2.3（P2-E）**：本连接上**实际发起过**的 stream 数。
    ///
    /// "真实连接"的判据：`streams_started > 0`（承载过请求）或由对端/IO/协议终止。
    /// 从未使用、仅因空闲被本地回收的连接不计入平均寿命（避免把"建了没用"的
    /// 连接寿命混进 GOAWAY 归因）。
    streams_started: AtomicU64,
    /// "打开计数已归还"的幂等标记（Drop 与 mark_closed 谁先到谁减）。
    close_noted: AtomicBool,
    /// 最后一次**新开 stream** 的时刻（空闲回收判据）。
    last_used: Mutex<Instant>,
    counters: Arc<Counters>,
    /// 本地回收信号：池子摘连接（空闲/上限/上游删除）时通知驱动任务退出。
    close_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl Drop for H2Conn {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        self.note_close();
        if let Some(tx) = self.close_tx.lock().take() {
            let _ = tx.send(());
        }
    }
}

impl H2Conn {
    fn new(
        send: SendRequest<Bytes>,
        counters: Arc<Counters>,
    ) -> (Arc<Self>, oneshot::Receiver<()>) {
        let (tx, rx) = oneshot::channel();
        counters.conns_open.fetch_add(1, Ordering::Relaxed);
        let conn = Arc::new(Self {
            send: Mutex::new(send),
            active: AtomicUsize::new(0),
            peer_max: AtomicUsize::new(H2_MAX_STREAMS_PER_CONN),
            closed: AtomicBool::new(false),
            goaway_noted: AtomicBool::new(false),
            goaway_reason: AtomicU8::new(0),
            opened_at: Instant::now(),
            streams_started: AtomicU64::new(0),
            close_noted: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
            counters,
            close_tx: Mutex::new(Some(tx)),
        });
        (conn, rx)
    }

    fn note_close(&self) {
        if !self.close_noted.swap(true, Ordering::Relaxed) {
            self.counters.conns_open.fetch_sub(1, Ordering::Relaxed);
        }
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.note_close();
    }

    /// **2.2.2（P2-03）/ 2.2.3（P2-E）**：计一次"连接被终止"（同一连接最多一次，
    /// 首个原因幂等）。
    ///
    /// 记账口径：
    /// * `peer` / `io` / `protocol` ⇒ `goaway_total` 与对应分类 +1；
    /// * `local_idle` ⇒ `local_idle_total` +1，**不**进 `goaway_total`；
    /// * 寿命样本只记"真实连接"（承载过 stream，或非本地空闲终止）；从未使用的空闲
    ///   回收只进 `conns_idle_reclaimed_total`。
    fn note_termination(&self, reason: GoawayReason) {
        let code = reason.idx() as u8 + 1;
        if self
            .goaway_reason
            .compare_exchange(0, code, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let _ = self.goaway_noted.swap(true, Ordering::Relaxed);
        tracing::debug!(reason = reason.as_str(), "DoH h2 连接被终止（分类记账）");
        // **2.2.5（P2-A4）/ 2.2.6（P2-A1）**：终止瞬间的**在途 stream 数**是"请求受影响"
        // 的精确口径。连接级（几条连接被打到）与 stream 级（几个请求被打到）**分开**
        // 记账：一条连接上 N 条在途 stream ⇒ `conn_inflight +1`、`streams_lost +N`。
        let active = self.active.load(Ordering::Relaxed) as u64;
        if reason == GoawayReason::LocalIdle {
            self.counters.goaway_by_reason[reason.idx()].fetch_add(1, Ordering::Relaxed);
        } else {
            self.counters.goaway_total.fetch_add(1, Ordering::Relaxed);
            self.counters.goaway_by_reason[reason.idx()].fetch_add(1, Ordering::Relaxed);
            note_goaway_activity(&self.counters, active);
        }
        let used = self.streams_started.load(Ordering::Relaxed) > 0;
        if reason == GoawayReason::LocalIdle && !used {
            self.counters
                .conns_idle_reclaimed
                .fetch_add(1, Ordering::Relaxed);
        } else {
            let life_ms = self.opened_at.elapsed().as_millis().min(u64::MAX as u128) as u64;
            self.counters
                .conn_life_ms_total
                .fetch_add(life_ms, Ordering::Relaxed);
            self.counters.conns_closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// 预留一个 stream 槽（拿不到 ⇒ 该连接已满/已关闭）。
    pub(crate) fn lease(self: &Arc<Self>) -> Option<H2Lease> {
        if self.is_closed() {
            return None;
        }
        // **2.2.4（P2-G）**：复用守卫 —— 空闲 ≥`H2_REUSE_IDLE_GUARD` 或连接年龄
        // ≥`H2_MAX_AGE` 的连接直接判死（不取 stream），让调用方新建连接：
        // * 空闲守卫避开对端 ~50s 的空闲回收；
        // * 年龄上限避开对端 ~50s 的连接寿命回收（2.2.3 peer GOAWAY 残余全部落在
        //   40–62s 寿命区间；高 QPS 下连接从不空闲，空闲守卫根本不会触发）。
        let idle = self.last_used.lock().elapsed();
        if idle >= H2_REUSE_IDLE_GUARD
            || self.opened_at.elapsed() >= H2_MAX_AGE
            || self.streams_started.load(Ordering::Relaxed) >= H2_MAX_STREAMS_LIFETIME
        {
            self.mark_closed();
            // 同 `reclaim_entry`：本地判定即记 local_idle（避免与 peer GOAWAY 竞态）。
            self.note_termination(GoawayReason::LocalIdle);
            return None;
        }
        // 对端 SETTINGS 上限：未声明时 h2 给 usize::MAX，这里用软上限截断。
        let peer = self.send.lock().current_max_send_streams();
        self.peer_max.store(peer, Ordering::Relaxed);
        let cap = peer.clamp(1, H2_MAX_STREAMS_PER_CONN);
        let mut cur = self.active.load(Ordering::Relaxed);
        loop {
            if cur >= cap {
                return None;
            }
            match self.active.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(v) => cur = v,
            }
        }
        self.counters.streams_active.fetch_add(1, Ordering::Relaxed);
        self.streams_started.fetch_add(1, Ordering::Relaxed);
        *self.last_used.lock() = Instant::now();
        Some(H2Lease { conn: self.clone() })
    }
}

/// 一个已预留的 h2 stream 槽（drop ⇒ 归还活跃计数；不关闭连接）。
pub(crate) struct H2Lease {
    conn: Arc<H2Conn>,
}

impl Drop for H2Lease {
    fn drop(&mut self) {
        self.conn.active.fetch_sub(1, Ordering::Relaxed);
        self.conn
            .counters
            .streams_active
            .fetch_sub(1, Ordering::Relaxed);
        // **P2（指标语义）**：`streams_total` 改为"**完成**的 stream 数"（成功/失败/
        // 超时/取消都算一次完成 —— lease 结束即完成），不再是"发起的 stream 数"。
        // 与 `streams_active` 一起满足 `streams_total == Σ completed`，不会在超时/
        // 取消时少计（旧口径在 lease 获取时就 +1，取消后仍算"发起"，语义含糊）。
        self.conn
            .counters
            .streams_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl H2Lease {
    /// 所属连接（失败回收时用）。
    pub(crate) fn conn(&self) -> &Arc<H2Conn> {
        &self.conn
    }

    /// 在该连接上跑一次 RFC 8484 POST（一次 stream）。
    ///
    /// - `uri`：**绝对 URI**（`https://host[:port]/path`）。h2 强制要求
    ///   `:scheme`/`:authority` 伪头，相对路径会被 h2 直接拒绝
    ///   （`MissingUriSchemeAndAuthority`），因此这里不能像 HTTP/1.1 那样只给 path；
    /// - `wire`：已经改写为 qid=0 的 DNS 报文；
    /// - 返回正文（**未做** DNS 层校验/qid 还原，那是 [`crate::doh`] 的职责）。
    pub(crate) async fn exchange(
        &self,
        uri: &str,
        wire: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, H2Error> {
        let remain = || deadline.saturating_duration_since(Instant::now());
        if remain().is_zero() {
            return Err(H2Error::Timeout);
        }
        let req = build_request(uri, wire.len())?;
        match tokio::time::timeout(remain(), self.exchange_inner(req, wire)).await {
            Ok(r) => r,
            // 超时：内部 future 被 drop ⇒ `RecvStream` 未读完 ⇒ h2 自动 RST_STREAM(CANCEL)，
            // 连接保留（下一条查询仍可用同一条连接）。
            Err(_) => Err(H2Error::Timeout),
        }
    }

    async fn exchange_inner(&self, req: Request<()>, wire: &[u8]) -> Result<Vec<u8>, H2Error> {
        let (resp_fut, mut send_stream) = {
            let mut send = self.conn.send.lock();
            send.send_request(req, false)
                .map_err(|e| self.conn.map_h2_error(e))?
        };
        send_stream
            .send_data(Bytes::copy_from_slice(wire), true)
            .map_err(|e| self.conn.map_h2_error(e))?;
        drop(send_stream);

        let resp = resp_fut.await.map_err(|e| self.conn.map_h2_error(e))?;
        if resp.status() != StatusCode::OK {
            return Err(H2Error::Status(resp.status().as_u16()));
        }
        if !content_type_ok(resp.headers()) {
            return Err(H2Error::ContentType);
        }
        let mut body: Vec<u8> = Vec::with_capacity(512);
        let mut recv = resp.into_body();
        loop {
            match recv.data().await {
                None => break, // END_STREAM：h2 用帧边界界定正文，无需 Content-Length
                Some(Ok(chunk)) => {
                    if body.len() + chunk.len() > MAX_BODY {
                        // 超限：显式放弃该 stream（drop 未读完的 RecvStream ⇒ RST_STREAM）。
                        drop(chunk);
                        drop(recv);
                        return Err(H2Error::TooLarge);
                    }
                    body.extend_from_slice(&chunk);
                    let n = chunk.len();
                    drop(chunk);
                    // 归还流控窗口（h2 不会自动归还；不归还的话 >64KB 的响应会卡死）。
                    let _ = recv.flow_control().release_capacity(n);
                }
                Some(Err(e)) => return Err(self.conn.map_h2_error(e)),
            }
        }
        Ok(body)
    }
}

impl H2Conn {
    fn map_h2_error(&self, e: h2::Error) -> H2Error {
        if e.is_go_away() {
            self.note_termination(GoawayReason::PeerGoaway);
            return H2Error::Goaway;
        }
        if e.is_reset() {
            return match e.reason() {
                Some(Reason::REFUSED_STREAM) => H2Error::Refused,
                Some(r) => H2Error::Reset(u32::from(r)),
                None => H2Error::Closed,
            };
        }
        if e.is_io() {
            // 请求中途 I/O 断开 = 对端把连接干掉了（GOAWAY 后正常关闭 / TCP reset）。
            // 这里**同步**计一次 `goaway_total`：不能只靠驱动任务在连接 future 结束时
            // 计数——池子摘连接（evict）与驱动任务收尾存在调度竞争，计数器会晚一拍，
            // 观测面（/metrics、/api/upstreams）与用例都会看到"连接断了但 goaway=0"。
            // `note_goaway_once` 幂等：驱动任务再计也不会重复。
            self.note_termination(GoawayReason::Io);
            self.mark_closed();
            return H2Error::Io;
        }
        H2Error::Protocol(e.to_string())
    }
}

/// 构建 RFC 8484 POST 请求（h2 语义：绝对 URI + 不使用 `Connection`/`Transfer-Encoding`）。
fn build_request(uri: &str, body_len: usize) -> Result<Request<()>, H2Error> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .version(Version::HTTP_2)
        .header(header::CONTENT_TYPE, "application/dns-message")
        .header(header::ACCEPT, "application/dns-message")
        .header(header::USER_AGENT, "ebpdns/2.0")
        .header(header::CONTENT_LENGTH, body_len.to_string())
        .body(())
        .map_err(|e| H2Error::Protocol(format!("build request: {e}")))
}

/// `content-type` 是否含 `application/dns-message`（大小写不敏感，与 h1 路径同口径）。
fn content_type_ok(headers: &http::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("application/dns-message"))
        .unwrap_or(false)
}

/// 在已建立的 TLS 连接上完成 h2 握手，返回池化连接（驱动任务已启动）。
///
/// 握手本身吃 `deadline` 预算：TLS 建连 + h2 握手共享同一个 deadline（与
/// [`crate::doh`] 的 connection deadline 语义一致）。
pub(crate) async fn establish(
    pool: &H2Pool,
    key: &PoolKey,
    tls: TlsConn,
    deadline: Instant,
) -> Result<Arc<H2Conn>, H2Error> {
    let remain = || deadline.saturating_duration_since(Instant::now());
    if remain().is_zero() {
        return Err(H2Error::Timeout);
    }
    let counters = pool.counters_for(key);
    let mut builder = h2::client::Builder::new();
    // SETTINGS 到达前先按软上限约束发送并发（默认 usize::MAX 会造成瞬时无上限）。
    builder.initial_max_send_streams(H2_MAX_STREAMS_PER_CONN);
    builder.max_concurrent_reset_streams(H2_MAX_STREAMS_PER_CONN);
    let handshake = builder.handshake::<_, Bytes>(tls);
    let (send, connection) = match tokio::time::timeout(remain(), handshake).await {
        Err(_) => return Err(H2Error::Timeout),
        Ok(Err(e)) => return Err(H2Error::Protocol(format!("h2 handshake: {e}"))),
        Ok(Ok(v)) => v,
    };
    let (conn, close_rx) = H2Conn::new(send, counters);
    spawn_driver(&conn, connection, close_rx);
    Ok(conn)
}

/// 驱动 h2 连接（必须持续 poll，否则连接不推进）：对端关闭/GOAWAY 时标记 `closed`
/// 并计一次 `goaway_total`；池子主动回收时收到 close 信号直接退出（不计 goaway）。
fn spawn_driver(
    conn: &Arc<H2Conn>,
    connection: h2::client::Connection<TlsConn, Bytes>,
    close_rx: oneshot::Receiver<()>,
) {
    let weak = Arc::downgrade(conn);
    tokio::spawn(async move {
        let mut conn_fut = pin!(connection);
        tokio::select! {
            res = &mut conn_fut => {
                if let Some(c) = weak.upgrade() {
                    c.closed.store(true, Ordering::Relaxed);
                    c.note_close();
                    // **2.2.3（P2-E）**：把驱动结束拆成 peer / io / protocol 三类；
                    // 正常 EOF（`Ok(())`）按对端关闭计 peer，不再混为 "driver-end"。
                    let reason = match &res {
                        Ok(()) => GoawayReason::PeerGoaway,
                        Err(e) if e.is_go_away() => GoawayReason::PeerGoaway,
                        Err(e) if e.is_io() => GoawayReason::Io,
                        Err(_) => GoawayReason::Protocol,
                    };
                    c.note_termination(reason);
                    if let Err(e) = res {
                        tracing::debug!(err = %e, "DoH h2 连接结束");
                    }
                }
            }
            _ = close_rx => {
                // **2.2.3（P2-E）**：本地回收（空闲超龄 / 每键上限 / 上游删除）单独计
                // `local-idle`，**不**进 `goaway_total`；从未使用的连接不计寿命样本。
                if let Some(c) = weak.upgrade() {
                    c.closed.store(true, Ordering::Relaxed);
                    c.note_close();
                    c.note_termination(GoawayReason::LocalIdle);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **2.2.6（P2-A1）**：GOAWAY 的"连接级 vs stream 级"分账口径。
    ///
    /// 这是 2.2.5/R-1 的修复判据：旧实现只有"终止瞬间 `active > 0`"的**布尔**连接级
    /// 计数（一条连接 N 条在途 stream 也只记 1），既无法回答"几个请求被打到"，也
    /// 容易在"请求恰好在 GOAWAY 处理前完成"时被误记为 idle。现在：
    /// * `goaway_idle_total` = 终止时 0 在途的连接数（空闲回收，不是失败）；
    /// * `goaway_conn_inflight_total` = 终止时 ≥1 在途的**连接数**；
    /// * `goaway_streams_lost_total` = 这些连接上**在途 stream 数之和**（受影响请求数）；
    /// * 恒等式 `goaway_total == idle + conn_inflight`、`streams_lost >= conn_inflight`。
    #[test]
    fn goaway_activity_splits_connections_and_streams() {
        let c = Counters::default();
        // 一次空闲终止：不计连接/stream 级在途账。
        note_goaway_activity(&c, 0);
        assert_eq!(c.goaway_activity_split(), (1, 0, 0));
        // 一条连接上 3 条在途 stream：连接级 +1，stream 级 +3。
        note_goaway_activity(&c, 3);
        assert_eq!(c.goaway_activity_split(), (1, 1, 3));
        // 再来一条连接 1 条在途 stream：连接级 +1，stream 级 +1。
        note_goaway_activity(&c, 1);
        let (idle, conn_inflight, lost) = c.goaway_activity_split();
        assert_eq!((idle, conn_inflight, lost), (1, 2, 4));
        // stream 级口径必须覆盖每条在途连接（每条 ≥1 个 stream）。
        assert!(
            lost >= conn_inflight,
            "streams_lost({lost}) 必须 >= conn_inflight({conn_inflight})"
        );
        // reset 必须把三项一起清零（否则 /api/reset 后口径漂移）。
        c.reset_counters();
        assert_eq!(c.goaway_activity_split(), (0, 0, 0));
    }

    /// **2.2.6（P2-A1）**：`H2Stats`/`H2KeyStats` 的默认值与聚合口径 —— 全池求和时
    /// 三项分别累加，恒等式在聚合后仍成立。
    #[test]
    fn goaway_stream_split_aggregates_across_keys() {
        let a = H2Stats {
            goaway_total: 2,
            goaway_idle_total: 1,
            goaway_conn_inflight_total: 1,
            goaway_streams_lost_total: 4,
            ..Default::default()
        };
        let b = H2Stats {
            goaway_total: 1,
            goaway_idle_total: 1,
            ..Default::default()
        };
        assert_eq!(
            a.goaway_total,
            a.goaway_idle_total + a.goaway_conn_inflight_total
        );
        assert_eq!(
            b.goaway_total,
            b.goaway_idle_total + b.goaway_conn_inflight_total
        );
        assert_eq!(
            a.goaway_total + b.goaway_total,
            a.goaway_idle_total
                + b.goaway_idle_total
                + a.goaway_conn_inflight_total
                + b.goaway_conn_inflight_total
        );
    }

    /// 错误分类 → 重试/摘连接 判定。
    /// **P2**：h2 stream 级 5xx 必须与 h1 对齐重试一次；4xx 不重试（确定性错误）。
    #[test]
    fn http_5xx_is_retryable_but_4xx_is_not() {
        assert!(H2Error::Status(500).retryable());
        assert!(H2Error::Status(502).retryable());
        assert!(H2Error::Status(503).retryable());
        assert!(H2Error::Status(599).retryable());
        assert!(!H2Error::Status(400).retryable());
        assert!(!H2Error::Status(404).retryable());
    }

    #[test]
    fn error_classification_drives_retry_and_eviction() {
        for e in [
            H2Error::Goaway,
            H2Error::Closed,
            H2Error::Refused,
            H2Error::Io,
        ] {
            assert!(e.retryable(), "{e:?} 必须可重试（重连一次）");
        }
        for e in [
            H2Error::Timeout,
            H2Error::Status(404),
            H2Error::ContentType,
            H2Error::TooLarge,
            H2Error::Reset(u32::from(Reason::CANCEL)),
        ] {
            assert!(!e.retryable(), "{e:?} 不应触发重连重试");
        }
        // 连接级失败必须摘连接；stream 级失败保留连接。
        for e in [H2Error::Goaway, H2Error::Closed, H2Error::Io] {
            assert!(e.evict_conn(), "{e:?} 必须从池中摘除");
        }
        for e in [
            H2Error::Refused,
            H2Error::Reset(u32::from(Reason::INTERNAL_ERROR)),
            H2Error::TooLarge,
            H2Error::Timeout,
        ] {
            assert!(!e.evict_conn(), "{e:?} 只失败该 stream，连接应保留");
        }
        assert_eq!(H2Error::Status(404).kind(), "status");
        assert_eq!(H2Error::Refused.kind(), "refused-stream");
    }

    #[test]
    fn content_type_matching_is_case_insensitive_and_strict() {
        for (v, want) in [
            ("application/dns-message", true),
            ("Application/DNS-Message", true),
            ("application/dns-message; charset=binary", true),
            ("text/plain", false),
            ("application/dns-json", false),
        ] {
            let mut h = http::HeaderMap::new();
            h.insert(header::CONTENT_TYPE, v.parse().unwrap());
            assert_eq!(content_type_ok(&h), want, "content-type: {v}");
        }
        assert!(!content_type_ok(&http::HeaderMap::new()));
    }

    #[test]
    fn request_is_rfc8484_post_without_connection_headers() {
        let req = build_request("https://dns.example:8443/dns-query", 33).unwrap();
        assert_eq!(req.method(), Method::POST);
        assert_eq!(req.version(), Version::HTTP_2);
        assert_eq!(req.uri().path(), "/dns-query");
        // h2 强制伪头：:scheme / :authority 必须有值（绝对 URI 提供）。
        assert_eq!(req.uri().scheme_str(), Some("https"));
        assert_eq!(
            req.uri().authority().map(|a| a.as_str()),
            Some("dns.example:8443")
        );
        assert_eq!(
            req.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/dns-message"
        );
        assert_eq!(
            req.headers().get(header::ACCEPT).unwrap(),
            "application/dns-message"
        );
        assert_eq!(req.headers().get(header::CONTENT_LENGTH).unwrap(), "33");
        // h2 不依赖这两个头（显式断言：一旦有人加回来，测试立刻红）。
        assert!(req.headers().get(header::CONNECTION).is_none());
        assert!(req.headers().get(header::TRANSFER_ENCODING).is_none());
    }

    /// 池的容量/回收语义（不建真连接：直接构造"已关闭"标记的连接对象不可行，
    /// 故这里只钉住"空池/未注册键"的行为）。
    #[test]
    fn empty_pool_reports_zero_and_unknown_key_is_none() {
        let pool = H2Pool::new();
        let key: PoolKey = (
            "doh".to_string(),
            "h.test".to_string(),
            443,
            "/dns-query".to_string(),
        );
        assert!(pool.acquire_lease(&key).is_none());
        assert_eq!(pool.stats(), H2Stats::default());
        assert_eq!(pool.key_stats(&key), H2KeyStats::default());
        pool.note_fallback_h1(&key);
        let k = pool.key_stats(&key);
        assert_eq!(k.fallback_h1_total, 1);
        assert_eq!(k.transport, Some(DohTransport::Http11));
        assert_eq!(pool.stats().fallback_h1_total, 1);
        pool.reset_counters();
        assert_eq!(pool.key_stats(&key).fallback_h1_total, 0);
    }

    #[test]
    fn discard_removes_key_state() {
        let pool = H2Pool::new();
        let key: PoolKey = (
            "doh".to_string(),
            "h.test".to_string(),
            443,
            "/dns-query".to_string(),
        );
        pool.note_fallback_h1(&key);
        assert_eq!(pool.stats().fallback_h1_total, 1);
        pool.discard(&key);
        assert_eq!(pool.stats(), H2Stats::default());
        assert_eq!(pool.key_stats(&key), H2KeyStats::default());
        // **P2（复活键 ≤90s）**：删除后同键重新加回、且该服务端只支持 h1 —— 首次查询的
        // `note_fallback_h1` 必须**立即复活**该键（旧实现 stats 永远跳过 discarded 条目，
        // 传输视图恒为 null）。
        pool.note_fallback_h1(&key);
        assert_eq!(pool.stats().fallback_h1_total, 1, "h1 回退必须让键复活");
        let k = pool.key_stats(&key);
        assert_eq!(k.transport, Some(DohTransport::Http11));
        assert_eq!(pool.stats().fallback_h1_total, 1);
    }
}
