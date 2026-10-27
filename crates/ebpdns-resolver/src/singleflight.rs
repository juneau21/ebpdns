//! **2.1.16（功能 2）**：在途查询合并（single-flight）。
//!
//! 问题：同一条 `CacheKey` 的并发 miss 各自向上游发查询。冷启动 / 随机子域压测下
//! N 路并发打同一个名字 ⇒ 上游 wire 请求被放大 N 倍（实测 `upstream_wire_requests`
//! 与 `total` 同阶增长），既是上游侧排队的直接来源，也是"随机子域场景永远命不中缓存"
//! 这一结构性问题的主要放大器。
//!
//! 实现：**每键一个 `tokio::sync::OnceCell`**（不是手写 `Notify` 状态机 —— 见 [`Entry`]
//! 的注释说明为什么手写版会在并发下退化成"人人都当 leader"）。
//!
//! 语义：
//! - **第一个**到达者真正执行 `f()`，其余同键到达者 `await` 同一个 `OnceCell`，
//!   **不重复执行**；
//! - **发起者被取消（future drop / `abort`）**：`OnceCell` 丢弃未完成的初始化，
//!   下一个等待者的 `get_or_init` **自己接手重跑** —— 等待者绝不挂死，也拿不到
//!   "半截/错误"的答案；
//! - **等待者自身超时**：调用方在自己的超时预算内 `select!`/`timeout` 掉 `run()` 即可；
//!   drop 掉的那个等待者不持有任何资源，发起者继续跑完并把结果交给其余等待者，
//!   且**不会**让 `f` 多跑一次；
//! - 表在**最后一个参与者**离开时摘除该键（`RefGuard`，正常/panic/取消三条路径都覆盖），
//!   因此**不会无界增长**。
//!
//! 为什么合并的是「上游扇出结果」而不是整个 `resolve()`：`finish_resolve` 之后的
//! 负缓存写入 / serve-stale / 规则复查都必须**逐调用方**执行（P2-B：预取链路
//! `mode.is_single()` 禁止写负缓存）。只合并"最贵的、纯幂等的"那一段，
//! 语义风险最小、收益最大。

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::OnceCell;

/// 单个键的共享格：`OnceCell` 天然提供"并发只初始化一次"的语义。
///
/// 为什么用 `tokio::sync::OnceCell` 而不是手写 `Notify` + 状态机（第一版即栽在这里）：
/// - **并发只跑一次**：`get_or_init` 保证同键并发调用者中恰有一个执行初始化闭包，
///   其余等待其完成（这是它的文档语义，不需要自己维护"follower 注册/唤醒"）；
/// - **初始化者被取消**（future drop / `abort`）：`OnceCell` **丢弃未完成的初始化**，
///   下一个调用者的 `get_or_init` 会**自己接手重跑** —— 天然满足"Ieader 取消后
///   follower 绝不挂死、也不会拿到半截结果"；手写版需要 `Drop` 守卫 + 唤醒，
///   且极易踩 `Notify::notified()` 的"首次 poll 才注册"竞态；
/// - **等待者自身超时**：drop 掉自己的 `get_or_init` future 即可，不影响初始化者与
///   其余等待者，也**不会**让初始化闭包多跑一次。
struct Entry<T> {
    cell: Arc<OnceCell<T>>,
    /// 参与者引用计数：归零时从表里摘除，保证表**不会无界增长**。
    refs: AtomicUsize,
}

impl<T> Entry<T> {
    fn new() -> Self {
        Self {
            cell: Arc::new(OnceCell::new()),
            refs: AtomicUsize::new(0),
        }
    }
}

/// 参与者守卫：无论正常返回 / panic / 被取消，都要把引用计数减一，并在归零时摘表。
struct RefGuard<T> {
    map: Arc<Mutex<HashMap<String, Arc<Entry<T>>>>>,
    key: String,
    entry: Arc<Entry<T>>,
}

impl<T> Drop for RefGuard<T> {
    fn drop(&mut self) {
        if self.entry.refs.fetch_sub(1, Ordering::AcqRel) == 1 {
            // 最后一个参与者离开 → 摘表（只摘"自己这一代"的 Entry）。
            let mut g = self.map.lock();
            if let Some(cur) = g.get(&self.key) {
                if Arc::ptr_eq(cur, &self.entry) {
                    g.remove(&self.key);
                }
            }
        }
    }
}

/// 在途合并器（按 `String` 键；调用方用 `CacheKey` 的稳定字符串形式）。
#[derive(Default)]
pub struct SingleFlight<T> {
    map: Arc<Mutex<HashMap<String, Arc<Entry<T>>>>>,
}

impl<T> SingleFlight<T> {
    pub fn new() -> Self {
        Self {
            map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 当前在途键数（测试/观测用）。
    pub fn inflight(&self) -> usize {
        self.map.lock().len()
    }

    /// 执行 `f`，同键并发只执行一次。`T` 必须可克隆（每个调用者各拿到一份）。
    ///
    /// 注意 `f` 是 `FnOnce`：正常路径下它至多被调用一次；只有在"初始化者被取消"
    /// 的异常路径上，才会由**另一个调用者**带着自己的 `f` 重跑（这正是我们要的语义）。
    pub async fn run<F, Fut>(&self, key: String, f: F) -> T
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
        T: Clone,
    {
        self.run_tagged(key, f).await.0
    }

    /// 同 [`SingleFlight::run`]，但**额外返回"本次调用是否真的执行了 `f`"**。
    ///
    /// # 为什么需要它（**2.1.23 / `DEF-221-04`**）
    ///
    /// "业务账（`dns_ok`/`dns_fail`）按**物理上游应答**记一次"这条口径要求：
    /// **只有真正发起上游扇出的那一个调用者**去记账，被合并的跟随者（follower）
    /// **不记**。2.1.21 把记账点从 `finish_resolve`（逐调用方）挪到了
    /// `resolve_inner` 的 single-flight 之后 —— 但那一行仍然**逐调用方**执行，
    /// 于是"5 路并发同名 ⇒ 1 次 wire 查询、`dns_ok +5`"依旧成立（审计复现）。
    ///
    /// 判据必须是"**本次调用有没有执行初始化闭包**"：
    /// * 返回 `true` ⇒ 本调用是 leader（或初始化者被取消后接手的那一个）
    ///   ⇒ **它**负责记账；
    /// * 返回 `false` ⇒ 本调用是 follower，拿到的是别人已经算好的结果
    ///   ⇒ **不**记账（否则一条物理应答被记 N 次）。
    ///
    /// 实现：`OnceCell::get_or_init` 保证闭包**至多被调用一次**，因此用一个
    /// `AtomicBool` 由闭包置位即可精确判定（不需要额外加锁，也不改 `Entry` 结构）。
    pub async fn run_tagged<F, Fut>(&self, key: String, f: F) -> (T, bool)
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T>,
        T: Clone,
    {
        let entry = {
            let mut g = self.map.lock();
            g.entry(key.clone())
                .or_insert_with(|| Arc::new(Entry::new()))
                .clone()
        };
        entry.refs.fetch_add(1, Ordering::AcqRel);
        let _guard = RefGuard {
            map: self.map.clone(),
            key: key.clone(),
            entry: entry.clone(),
        };
        // 闭包置位 ⇒ 只有"真的跑了 `f`"的那个调用者看到 `true`。
        let ran = std::sync::atomic::AtomicBool::new(false);
        let v = entry
            .cell
            .get_or_init(|| {
                ran.store(true, Ordering::Release);
                f()
            })
            .await;
        let was_leader = ran.load(Ordering::Acquire);
        (v.clone(), was_leader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// **功能 2 核心门禁**：N 路并发同键 → 上游/被合并体**只执行 1 次**，
    /// 且 N 个调用者拿到**同一个**结果。
    #[tokio::test]
    async fn s2_single_flight_n_concurrent_same_key_runs_once() {
        let sf: Arc<SingleFlight<u64>> = Arc::new(SingleFlight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ts = Vec::new();
        for _ in 0..32 {
            let sf = sf.clone();
            let calls = calls.clone();
            ts.push(tokio::spawn(async move {
                sf.run("k".to_string(), || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        // 让所有 follower 有机会在 leader 完成前到达。
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        7u64
                    }
                })
                .await
            }));
        }
        let mut got = Vec::new();
        for t in ts {
            got.push(t.await.expect("join"));
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "32 路并发同键必须只触发 1 次上游（实测 {} 次）",
            calls.load(Ordering::SeqCst)
        );
        assert!(
            got.iter().all(|v| *v == 7),
            "全部 follower 必须拿到同一结果"
        );
        assert_eq!(sf.inflight(), 0, "全部离开后表必须清空（不得无界增长）");
    }

    /// 不同键**不得**被合并。
    #[tokio::test]
    async fn s2_different_keys_are_not_coalesced() {
        let sf: Arc<SingleFlight<u64>> = Arc::new(SingleFlight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let mut ts = Vec::new();
        for i in 0..8u64 {
            let sf = sf.clone();
            let calls = calls.clone();
            ts.push(tokio::spawn(async move {
                sf.run(format!("k{i}"), || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        i
                    }
                })
                .await
            }));
        }
        for t in ts {
            t.await.expect("join");
        }
        assert_eq!(calls.load(Ordering::SeqCst), 8, "8 个不同键必须各自执行");
        assert_eq!(sf.inflight(), 0);
    }

    /// **leader 被取消 ⇒ follower 绝不挂死**，且会自己成为新 leader 拿到结果。
    #[tokio::test]
    async fn s2_leader_cancel_does_not_hang_followers() {
        let sf: Arc<SingleFlight<u64>> = Arc::new(SingleFlight::new());
        let calls = Arc::new(AtomicUsize::new(0));

        // leader：永不完成（等一个不会触发的 notify），随后被 abort。
        let leader = {
            let sf = sf.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                sf.run("k".to_string(), || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::pending::<()>().await;
                        0u64
                    }
                })
                .await
            })
        };
        // 等 leader 真的进去。
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert_eq!(sf.inflight(), 1, "leader 在途时表里应恰好 1 项");

        // follower：自身有超时预算，但 leader 被 abort 后它应当**立刻**接手而不是等满。
        let follower = {
            let sf = sf.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                sf.run("k".to_string(), || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        42u64
                    }
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(40)).await;
        leader.abort();
        let v = tokio::time::timeout(Duration::from_secs(3), follower)
            .await
            .expect("follower 必须在 leader 取消后自行接手（不得挂死）")
            .expect("join");
        assert_eq!(v, 42, "follower 转 leader 后必须拿到自己那次的结果");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "leader 1 次 + 接手者 1 次 = 2 次（不得重复放大）"
        );
        assert_eq!(sf.inflight(), 0);
    }

    /// 等待者自身超时（drop 掉 `run()` 的 future）不得影响 leader 与其余 follower。
    #[tokio::test]
    async fn s2_follower_timeout_does_not_break_leader_or_others() {
        let sf: Arc<SingleFlight<u64>> = Arc::new(SingleFlight::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let leader = {
            let sf = sf.clone();
            let calls = calls.clone();
            tokio::spawn(async move {
                sf.run("k".to_string(), || {
                    let calls = calls.clone();
                    async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(120)).await;
                        5u64
                    }
                })
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        // 这个 follower 自己超时（10ms < 120ms）→ 其 future 被 drop。
        let impatient = {
            let sf = sf.clone();
            tokio::spawn(async move {
                tokio::time::timeout(
                    Duration::from_millis(10),
                    sf.run("k".to_string(), || async { 999u64 }),
                )
                .await
            })
        };
        let patient = {
            let sf = sf.clone();
            tokio::spawn(async move { sf.run("k".to_string(), || async { 999u64 }).await })
        };
        assert!(
            impatient.await.expect("join").is_err(),
            "自身超时的 follower 必须超时返回（不影响别人）"
        );
        assert_eq!(
            patient.await.expect("join"),
            5,
            "其余 follower 正常拿到 leader 结果"
        );
        assert_eq!(leader.await.expect("join"), 5);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "超时 follower 不得让 `f` 多跑一次"
        );
        assert_eq!(sf.inflight(), 0);
    }
}
