//! **[历史归因]** DoH / DoT 有界连接复用池（对齐 Python `upstream._ConnPool`）。
//!
//! - 每 `(proto, host, port, path)` 键最多 [`MAX_CONN`] 个并发连接（tokio 信号量）。
//! - acquire 取信号量槽后惰性复用空闲连接；空闲超龄（[`MAX_IDLE`]）连接取出即丢弃不回池。
//! - 降级弱校验连接（`degraded=true`）即用即弃，绝不入池复用。
//! - tokio `OwnedSemaphorePermit` 随 Drop 归还槽位，天然防 double-release。
//! - 每 10 次 acquire 触发一次全池空闲连接扫描回收。
//!
//! # A6（2.1.9）：空闲连接的**总量**与**每键**上限
//!
//! 旧实现只有"每键并发"上限（信号量 = [`MAX_CONN`]），**空闲队列本身无界**：
//! `release()` 无条件 `push_back`，每个键的空闲 deque 可涨到"历史上见过的最大并发"。
//! 键集合来自**配置里的上游**（攻击者不可直接枚举），因此不是远程 DoS；真正的
//! 风险是**配置面**：上游数量 × 每键残留连接 × fd 就是进程 fd 占用，而 2.1.8 的
//! 进程软限只有 **1024**（`Max open files 1024`，systemd 未设 `LimitNOFILE`）。
//! 两者叠加（大量上游 + 高并发残留）会先耗尽 fd，表现为
//! `Too many open files` → 全部上游随机失败（比"慢"更糟，且难以归因）。
//!
//! 修法（**保守默认**，不改变单上游行为）：
//! - [`MAX_IDLE_PER_KEY`] = [`MAX_CONN`]（当前 **16**）：单键空闲连接不超过其并发上限
//!   （P2 文档漂移修正：本节此前写 "= 4 = MAX_CONN"，但 `MAX_CONN` 早已是 16，
//!   且 `MAX_IDLE_PER_KEY` 的定义就是 `MAX_CONN`，不存在硬编码的 4）；
//! - [`MAX_TOTAL_IDLE`] = 256：全池空闲连接总量，超限按 **LRU（最早使用）** 逐出；
//! - [`MAX_IDLE`] 保持 30s 不变；
//! - **在途**连接不受影响（上限仍由各键信号量 + 调用方并发约束），
//!   故本改动不引入新的失败模式，只回收真正的空闲 fd。
//! - 内核侧同步收紧软限（`packaging/systemd/ebpdns.service` 的 `LimitNOFILE=65535`）。

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// **[历史归因]** 每键最大并发连接数（Python `_MAX_CONN`）。
pub const MAX_CONN: usize = 16;
/// **[历史归因]** 连接空闲超时（秒）（Python `_MAX_IDLE`）。
pub const MAX_IDLE: Duration = Duration::from_secs(30);
/// 每键**空闲**连接上限（A6）。旧实现无此上限：空闲 deque 可涨到历史最大并发。
pub const MAX_IDLE_PER_KEY: usize = MAX_CONN;
/// 全池**空闲**连接总量上限（A6）。超限按 LRU（最早 last_use）逐出到 90%。
pub const MAX_TOTAL_IDLE: usize = 256;

/// 池化的 TLS 连接（DoT 直接收发 DNS 帧；DoH 在其上跑最小 HTTP/1.1）。
pub type TlsConn = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

/// **2.1.21 第 2 轮（clippy `type_complexity`）**：池键借用 + 条目引用的元组别名。
/// 只是给既有类型起个名字（零语义变化），让 `Vec<(&PoolKey, &Arc<PoolEntry>)>` 可读。
type PoolKeyRef<'a> = (&'a (String, String, u16, String), &'a Arc<PoolEntry>);

/// 池化连接，附降级标记。
pub struct PooledConn {
    pub conn: TlsConn,
    /// 弱校验降级连接（check_hostname/SAN 跳过）：即用即弃，不入池。
    pub degraded: bool,
}

/// 空闲连接的**持有者**。真实实现包一条 TLS 连接；`#[cfg(test)]` 下退化为
/// 轻量 sentinel，使 A6 的「每键空闲上限 / 全池空闲上限 / LRU 逐出」可以在
/// **不建真 TLS 连接**的前提下被单测逐条钉死（不依赖网络/证书/特权）。
struct IdleHolder {
    #[cfg(not(test))]
    conn: TlsConn,
    /// 最后一次使用时间（A6 的 LRU 逐出与 [`MAX_IDLE`] 回收共用）。
    last_use: Instant,
}

impl IdleHolder {
    fn new(conn: TlsConn) -> Self {
        // 生产：握住真实连接（drop 即 close）。测试：sentinel 不持有连接，
        // 故 conn 在该配置下必须显式吞掉，避免 unused_variables。
        let _ = &conn;
        IdleHolder {
            #[cfg(not(test))]
            conn,
            last_use: Instant::now(),
        }
    }

    /// 仅测试用：构造 sentinel（无真实连接）。
    #[cfg(test)]
    fn sentinel(last_use: Instant) -> Self {
        IdleHolder { last_use }
    }

    /// 取出复用。生产为真实 TLS 连接；测试为 sentinel。
    fn reuse(self) -> Reuse {
        #[cfg(not(test))]
        {
            Reuse::Real(self.conn)
        }
        #[cfg(test)]
        {
            Reuse::Sentinel
        }
    }
}

struct PoolEntry {
    conns: parking_lot::Mutex<VecDeque<IdleHolder>>,
    sem: Arc<Semaphore>,
    discarded: AtomicBool,
}

/// 已取出的连接槽（持有信号量许可）。Drop 时归还槽位。
pub struct Checkout {
    entry: Arc<PoolEntry>,
    permit: OwnedSemaphorePermit,
}

/// 取出结果：真实复用的连接，或（仅测试路径）无真实连接的 sentinel。
///
/// **2.1.24**：clippy::large_enum_variant 在此**显式允许**，理由：
/// clippy 建议把 Real(TlsConn) 装箱以消除变体大小差，但本枚举是**连接复用热路径**的
/// 短生命周期值（into_pooled() 立刻解包），装箱会**每次复用多一次堆分配**换来的只是
/// 一个栈上枚举小几百字节 —— 那是拿热路径性能换 lint。正确修法（改池/改协议结构）超出
/// 不引入新功能的边界，故按 docs/CLIPPY.md 的口径登记为**有据可查的允许项**。
#[allow(clippy::large_enum_variant)]
enum Reuse {
    // 生产路径唯一构造点；测试构建下 `IdleHolder::reuse` 返回 Sentinel，
    // 故该变体在 `cfg(test)` 里"从未构造"（不是死代码）。
    #[allow(dead_code)]
    Real(TlsConn),
    #[cfg(test)]
    Sentinel,
}

impl Reuse {
    fn into_pooled(self) -> Option<PooledConn> {
        match self {
            Reuse::Real(conn) => Some(PooledConn {
                conn,
                degraded: false,
            }),
            #[cfg(test)]
            Reuse::Sentinel => None,
        }
    }
}

/// 按 key 维护可复用 TLS 连接组的连接池。
#[allow(clippy::type_complexity)]
pub struct ConnPool {
    entries: parking_lot::Mutex<HashMap<(String, String, u16, String), Arc<PoolEntry>>>,
    reclaim_counter: AtomicUsize,
    /// 全池**空闲**连接计数（A6）。用于 [`MAX_TOTAL_IDLE`] 限流；
    /// 丢弃时 `saturating_sub` 自校正，不会下溢/永久卡死。
    idle_total: AtomicUsize,
}

impl Default for ConnPool {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnPool {
    pub fn new() -> Self {
        ConnPool {
            entries: parking_lot::Mutex::new(HashMap::new()),
            reclaim_counter: AtomicUsize::new(0),
            idle_total: AtomicUsize::new(0),
        }
    }

    /// 全池空闲连接数（A6 观测/单测用）。
    pub fn idle_count(&self) -> usize {
        self.idle_total.load(Ordering::Relaxed)
    }

    /// 键数（A6 观测/单测用）。
    pub fn key_count(&self) -> usize {
        self.entries.lock().len()
    }

    fn entry(&self, key: &(String, String, u16, String)) -> Arc<PoolEntry> {
        let mut g = self.entries.lock();
        g.entry(key.clone())
            .or_insert_with(|| {
                Arc::new(PoolEntry {
                    conns: parking_lot::Mutex::new(VecDeque::new()),
                    sem: Arc::new(Semaphore::new(MAX_CONN)),
                    discarded: AtomicBool::new(false),
                })
            })
            .clone()
    }

    /// 取一个连接槽。`timeout` 为等信号量的上限。返回 `(checkout, reused_conn)`。
    /// `reused_conn` 为 None 表示调用方需新建连接（NEW）。池满超时返回 None。
    pub async fn acquire(
        &self,
        key: &(String, String, u16, String),
        timeout: Duration,
    ) -> Option<(Checkout, Option<PooledConn>)> {
        // 每 10 次 acquire 触发一次全池空闲回收（best-effort 无锁计数）。
        let c = self.reclaim_counter.fetch_add(1, Ordering::Relaxed) + 1;
        if c >= 10 {
            self.reclaim_counter.store(0, Ordering::Relaxed);
            self.reclaim_idle();
            self.trim_idle();
        }

        let entry = self.entry(key);
        let permit = match tokio::time::timeout(timeout, entry.sem.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => return None, // 池满超时。
        };
        // discard 竞态：本 entry 已被 discard 关闭了全部连接 → 直接新建。
        if entry.discarded.load(Ordering::Relaxed) {
            return Some((Checkout { entry, permit }, None));
        }
        let now = Instant::now();
        let reused = {
            let mut g = entry.conns.lock();
            loop {
                match g.pop_front() {
                    None => break None,
                    Some(h) => {
                        if now.duration_since(h.last_use) < MAX_IDLE {
                            let _ = self.idle_total.try_update(
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                                |v| Some(v.saturating_sub(1)),
                            );
                            break Some(h.reuse());
                        }
                        // 超龄：丢弃（drop 即 close）。
                        let _ =
                            self.idle_total
                                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                                    Some(v.saturating_sub(1))
                                });
                    }
                }
            }
        };
        // `reused: Option<Reuse>` → `Option<PooledConn>`（`Reuse` 只在测试里可能是 sentinel）。
        let pooled = match reused {
            Some(r) => r.into_pooled(),
            None => None,
        };
        Some((Checkout { entry, permit }, pooled))
    }

    /// 归还连接槽。`conn` 为 Some 且非降级/非废弃 → 入池复用；否则关闭不入池。
    ///
    /// A6：入池受**每键有空闲上限**（[`MAX_IDLE_PER_KEY`]）与**全池空闲总量**
    /// （[`MAX_TOTAL_IDLE`]）双重约束：超限的连接**直接 drop（close）**，
    /// 语义与"空闲超龄被回收"一致（下次 acquire 新建即可，不改变热路径正确性）。
    pub fn release(self: Arc<Self>, checkout: Checkout, conn: Option<PooledConn>) {
        let Checkout { entry, permit } = checkout;
        let mut requeue: Option<TlsConn> = None;
        if !entry.discarded.load(Ordering::Relaxed) {
            if let Some(pc) = conn {
                if !pc.degraded {
                    requeue = Some(pc.conn);
                }
                // degraded → 丢弃（drop 即 close）。
            }
        }
        if let Some(c) = requeue {
            let mut g = entry.conns.lock();
            // 每键空闲上限：满了就丢最旧的一条（LRU），保持 deque 有界。
            while g.len() >= MAX_IDLE_PER_KEY {
                if g.pop_front().is_some() {
                    let _ = self
                        .idle_total
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        });
                } else {
                    break;
                }
            }
            g.push_back(IdleHolder::new(c));
            self.idle_total.fetch_add(1, Ordering::Relaxed);
        }
        drop(permit); // 归还信号量槽位。
                      // 全池总量上限（A6）：超限按 LRU 逐出到 90%。
        self.trim_idle();
    }

    /// A6：把全池**空闲**连接修剪到 [`MAX_TOTAL_IDLE`] 以内。
    ///
    /// 逐出顺序：按 key 排序后**逐键轮转出队队首**（每键队首 = 该键最早使用的连接）
    /// → 全局近似 LRU，且不会一次性打空某个键的复用能力。
    /// 只动空闲 deque（不误关在途连接）；无空闲或未超限时是**零 I/O 的早返回**，
    /// 因此可以挂在 `release`/`acquire` 热路径上。
    pub fn trim_idle(&self) {
        let total = self.idle_total.load(Ordering::Relaxed);
        if total <= MAX_TOTAL_IDLE {
            return;
        }
        let target = MAX_TOTAL_IDLE * 9 / 10;
        let mut victims: Vec<IdleHolder> = Vec::new();
        let mut removed = 0usize;
        {
            let g = self.entries.lock();
            let mut entries: Vec<PoolKeyRef<'_>> = g.iter().collect();

            // 确定性顺序：按 key 排序后逐键出队最旧的一条，循环直到达标。
            entries.sort_by(|a, b| a.0.cmp(b.0));
            let mut drop_needed = total - target;
            'outer: while drop_needed > 0 {
                let mut progressed = false;
                for (_, e) in entries.iter() {
                    if drop_needed == 0 {
                        break 'outer;
                    }
                    if e.discarded.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some(h) = e.conns.lock().pop_front() {
                        victims.push(h);
                        removed += 1;
                        drop_needed -= 1;
                        progressed = true;
                    }
                }
                if !progressed {
                    break; // 全池已无空闲连接（计数偏高，下面自校正）。
                }
            }
        }
        if removed > 0 {
            let _ = self
                .idle_total
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(removed))
                });
        }
        // 持锁外 close（drop）被逐出的连接。
        drop(victims);
    }

    /// 主动扫描全池，关闭空闲超龄连接（仅关 deque 中的空闲连接，不误关在途）。
    pub fn reclaim_idle(&self) {
        let now = Instant::now();
        let mut drop_list: Vec<IdleHolder> = Vec::new();
        {
            let g = self.entries.lock();
            for e in g.values() {
                if e.discarded.load(Ordering::Relaxed) {
                    continue;
                }
                let mut cg = e.conns.lock();
                let mut keep = VecDeque::new();
                while let Some(h) = cg.pop_front() {
                    if now.duration_since(h.last_use) < MAX_IDLE {
                        keep.push_back(h);
                    } else {
                        drop_list.push(h);
                    }
                }
                *cg = keep;
            }
        }
        if !drop_list.is_empty() {
            let _ = self
                .idle_total
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(v.saturating_sub(drop_list.len()))
                });
        }
        // drop_list 中的连接 drop 即 close（不持锁做 I/O）。
        drop(drop_list);
    }

    /// 删除上游时回收该 key 的连接组。
    pub fn discard(&self, key: &(String, String, u16, String)) {
        let e = {
            let mut g = self.entries.lock();
            let e = g.remove(key);
            if let Some(e) = &e {
                e.discarded.store(true, Ordering::Relaxed);
            }
            e
        };
        if let Some(e) = e {
            let conns: Vec<IdleHolder> = std::mem::take(&mut *e.conns.lock()).into_iter().collect();
            if !conns.is_empty() {
                let _ = self
                    .idle_total
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                        Some(v.saturating_sub(conns.len()))
                    });
            }
            drop(conns); // close 全部空闲连接。
        }
    }

    /// 仅测试用：直接向某键的空闲队列塞 n 条 sentinel（不建真 TLS 连接），
    /// 以便在**无网络/无证书**的前提下钉死 A6 的容量上限语义。
    #[cfg(test)]
    fn seed_idle_for_test(&self, key: &(String, String, u16, String), n: usize, age_ms: u64) {
        let entry = self.entry(key);
        let last_use = Instant::now() - Duration::from_millis(age_ms);
        let mut g = entry.conns.lock();
        for _ in 0..n {
            g.push_back(IdleHolder::sentinel(last_use));
            self.idle_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 仅测试用：某键当前空闲连接数。
    #[cfg(test)]
    fn idle_for_test(&self, key: &(String, String, u16, String)) -> usize {
        self.entries
            .lock()
            .get(key)
            .map(|e| e.conns.lock().len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Key = (String, String, u16, String);

    fn k(n: usize) -> Key {
        (
            "doh".to_string(),
            format!("up{n}.test"),
            443,
            "/dns-query".to_string(),
        )
    }

    /// 每键空闲入池（与 `ConnPool::release` 的上限逻辑逐字同构）。抽出来是为了让
    /// 单测复用**生产同一套**逐出规则，而不是在测试里另写一份近似实现。
    fn push_capped(pool: &ConnPool, key: &Key, n: usize) {
        let entry = pool.entry(key);
        let mut g = entry.conns.lock();
        for _ in 0..n {
            while g.len() >= MAX_IDLE_PER_KEY {
                if g.pop_front().is_some() {
                    let _ = pool
                        .idle_total
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                            Some(v.saturating_sub(1))
                        });
                } else {
                    break;
                }
            }
            g.push_back(IdleHolder::sentinel(Instant::now()));
            pool.idle_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A6：**每键**空闲连接上限 —— 旧实现无上限，空转 N 次可堆 N 条。
    #[test]
    fn per_key_idle_is_capped_at_max_idle_per_key() {
        let pool = ConnPool::new();
        // 情形 1：入池次数不足上限时空闲数等于入池次数（不得凭空多出）。
        pool.seed_idle_for_test(&k(1), 2, 0);
        assert_eq!(pool.idle_for_test(&k(1)), 2);
        assert_eq!(pool.idle_count(), 2);
        // 情形 2：继续入池 → 恒 ≤ MAX_IDLE_PER_KEY。
        push_capped(&pool, &k(1), MAX_IDLE_PER_KEY + 8);
        assert_eq!(
            pool.idle_for_test(&k(1)),
            MAX_IDLE_PER_KEY,
            "每键空闲连接必须恒 ≤ MAX_IDLE_PER_KEY"
        );
        assert_eq!(pool.idle_count(), MAX_IDLE_PER_KEY);
        // 情形 3：从零开始堆 4× 上限，仍然只有上限条。
        let pool2 = ConnPool::new();
        push_capped(&pool2, &k(2), MAX_IDLE_PER_KEY * 4);
        assert_eq!(pool2.idle_for_test(&k(2)), MAX_IDLE_PER_KEY);
        assert_eq!(pool2.idle_count(), MAX_IDLE_PER_KEY);
    }

    /// A6：**全池**空闲上限 —— 键很多时总量必须有界（旧实现随键数线性增长）。
    #[test]
    fn global_idle_is_trimmed_to_max_total_idle() {
        let pool = ConnPool::new();
        let keys = 80usize;
        for i in 0..keys {
            pool.seed_idle_for_test(&k(i), MAX_IDLE_PER_KEY, 0);
        }
        let before = pool.idle_count();
        assert_eq!(before, keys * MAX_IDLE_PER_KEY);
        assert!(before > MAX_TOTAL_IDLE, "构造不足：{before} ≤ 上限");
        pool.trim_idle();
        let after = pool.idle_count();
        assert!(
            after <= MAX_TOTAL_IDLE,
            "全池空闲未被修剪: {after} > {MAX_TOTAL_IDLE}"
        );
        assert!(after >= MAX_TOTAL_IDLE * 9 / 10, "修剪过度: {after}");
        // 逐出后计数与**实际** deque 内容一致（无漂移）。
        let real: usize = (0..keys).map(|i| pool.idle_for_test(&k(i))).sum();
        assert_eq!(real, after, "idle_total 与实际空闲数漂移");
        // 幂等：再修一次不变。
        pool.trim_idle();
        assert_eq!(pool.idle_count(), after);
    }

    /// A6：`reclaim_idle` 关掉超龄空闲连接并同步计数（不漏减）。
    #[test]
    fn reclaim_idle_closes_aged_and_keeps_counter_in_sync() {
        let pool = ConnPool::new();
        pool.seed_idle_for_test(&k(1), 2, 60_000); // 60s > MAX_IDLE(30s) → 全部超龄
        pool.seed_idle_for_test(&k(2), 2, 0); // 新鲜
        assert_eq!(pool.idle_count(), 4);
        pool.reclaim_idle();
        assert_eq!(pool.idle_count(), 2, "超龄 2 条应被回收且计数同步");
        assert_eq!(pool.idle_for_test(&k(1)), 0);
        assert_eq!(pool.idle_for_test(&k(2)), 2);
    }

    /// A6：`discard` 清空该键空闲连接并同步全池计数。
    #[test]
    fn discard_clears_key_and_counter() {
        let pool = ConnPool::new();
        pool.seed_idle_for_test(&k(1), 3, 0);
        pool.seed_idle_for_test(&k(2), 1, 0);
        assert_eq!(pool.idle_count(), 4);
        pool.discard(&k(1));
        assert_eq!(pool.idle_count(), 1, "discard 后计数应只剩另一键的 1 条");
        assert_eq!(pool.key_count(), 1);
        assert_eq!(pool.idle_for_test(&k(2)), 1);
    }

    /// A6 回归护栏：上限常量的相对关系（改错任何一项都会被这里拦住）。
    ///
    /// 全是编译期常量比较：clippy 的 ssertions_on_constants / eq_op
    /// 在此**故意**放行（本测试的**唯一目的**就是钉死常量之间的关系）。
    #[test]
    #[allow(clippy::assertions_on_constants, clippy::eq_op)]
    fn a6_limits_are_conservative_and_ordered() {
        assert_eq!(MAX_IDLE_PER_KEY, MAX_CONN, "每键空闲不应超过每键并发上限");
        assert!(
            MAX_TOTAL_IDLE >= MAX_IDLE_PER_KEY,
            "全池上限必须 ≥ 单键上限，否则单键就会被立刻逐出"
        );
        assert!(
            MAX_TOTAL_IDLE < 1024,
            "全池空闲上限必须显著小于 2.1.8 的 fd 软限(1024)，否则 1024 下仍会 EMFILE"
        );
        assert_eq!(MAX_IDLE, Duration::from_secs(30), "MAX_IDLE 语义未变");
    }
}
