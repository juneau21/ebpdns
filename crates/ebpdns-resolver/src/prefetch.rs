//! **[历史归因]** 预取待办队列：对齐 Python `_prefetch_pending = OrderedDict`。
//! 插入序稳定可预测；重新调度已有 key → 移到 MRU 末尾。
//! 用 VecDeque（序）+ HashMap（数据）实现 OrderedDict 语义。
//!
//! **阶段 3-14**：待办项额外携带 **DNSSEC（DO）变体**位 —— 与 `CacheKey::dnssec`
//! 同一维度。队列键里带 `|DO` 后缀，因此同域名的 DO 与非 DO 待办是**两条独立项**，
//! 续期回填时各写各的键（否则会把 DO 条目刷新成非 DO 键，反之亦然）。

use std::collections::{HashMap, VecDeque};

/// 待办项：`(domain, qtype, dnssec)`。
pub type PrefetchJob = (String, String, bool);

/// 预取待办有序映射。
pub struct PendingMap {
    order: VecDeque<String>,
    data: HashMap<String, PrefetchJob>,
    /// **2.1.50（FIX-PREFETCH-SWEEP）**：全量补扫游标（round-robin）。
    /// 每轮从缓存里取 `prefetch_max` 个键刷新，游标推进保证所有键都能轮到。
    sweep_cursor: usize,
}

impl Default for PendingMap {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingMap {
    pub fn new() -> Self {
        Self {
            order: VecDeque::new(),
            data: HashMap::new(),
            sweep_cursor: 0,
        }
    }

    /// 调度：新 key 插入末尾；已有 key 移到末尾（move_to_end）。
    /// 超 `max` 上限驱逐最旧（队首），防随机子域放大堆积。
    ///
    /// **阶段 3-14**：`dnssec` 随待办一起存下（回填时按它重建 `CacheKey`）。
    pub fn schedule(&mut self, key: &str, domain: &str, qtype: &str, dnssec: bool, max: usize) {
        if self.data.contains_key(key) {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
        self.data.insert(
            key.to_string(),
            (domain.to_string(), qtype.to_string(), dnssec),
        );
        self.order.push_back(key.to_string());
        while self.order.len() > max {
            if let Some(old) = self.order.pop_front() {
                self.data.remove(&old);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// 当前插入序的 key 列表。
    pub fn order(&self) -> Vec<String> {
        self.order.iter().cloned().collect()
    }

    /// **2.1.50（FIX-PREFETCH-SWEEP）**：全量补扫 —— 返回本轮起始下标（round-robin），
    /// 并把游标推进 `budget`，保证下一轮从上次结束处继续（所有键都能轮到）。
    pub fn advance_sweep(&mut self, total: usize, budget: usize) -> usize {
        if total == 0 || budget == 0 {
            self.sweep_cursor = 0;
            return 0;
        }
        let start = self.sweep_cursor % total;
        self.sweep_cursor = (start + budget) % total;
        start
    }

    /// 取走并清空整个队列（FIFO 序）。后台预取循环每轮快照消费。
    ///
    /// **阶段 3-14**：返回 `(队列键, domain, qtype, dnssec)`。
    pub fn drain_all(&mut self) -> Vec<(String, String, String, bool)> {
        let mut out = Vec::with_capacity(self.order.len());
        while let Some(key) = self.order.pop_front() {
            if let Some((domain, qtype, dnssec)) = self.data.remove(&key) {
                out.push((key, domain, qtype, dnssec));
            }
        }
        out
    }

    /// **2.2.3（P2-C）**：只读快照（不移除队列项）。
    ///
    /// 低流量暂停出队时用它把待办带进本轮"考虑集合"，但真正消费仍走 `drain_all`；
    /// 队列在此保持有界（`schedule` 的 `max` 仍然生效），有流量时下一轮即可恢复。
    pub fn snapshot(&self) -> Vec<(String, String, String, bool)> {
        let mut out = Vec::with_capacity(self.order.len());
        for key in &self.order {
            if let Some((domain, qtype, dnssec)) = self.data.get(key) {
                out.push((key.clone(), domain.clone(), qtype.clone(), *dnssec));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **阶段 3-14**：DO 与非 DO 的同一域名是**两条独立待办**（互不覆盖）。
    #[test]
    fn dnssec_variants_are_independent_queue_entries() {
        let mut m = PendingMap::new();
        m.schedule("a.test|A", "a.test", "A", false, 16);
        m.schedule("a.test|A|DO", "a.test", "A", true, 16);
        assert_eq!(m.len(), 2, "两种变体必须各占一项");
        let drained = m.drain_all();
        assert_eq!(drained.len(), 2);
        assert_eq!(
            drained[0],
            (
                "a.test|A".to_string(),
                "a.test".to_string(),
                "A".to_string(),
                false
            )
        );
        assert_eq!(
            drained[1],
            (
                "a.test|A|DO".to_string(),
                "a.test".to_string(),
                "A".to_string(),
                true
            )
        );
    }

    /// 既有的"重复调度移到 MRU 末尾"语义不变。
    #[test]
    fn reschedule_moves_to_end_for_same_variant() {
        let mut m = PendingMap::new();
        m.schedule("a|A", "a", "A", false, 16);
        m.schedule("b|A", "b", "A", false, 16);
        m.schedule("a|A", "a", "A", false, 16);
        assert_eq!(m.len(), 2);
        assert_eq!(m.order(), vec!["b|A".to_string(), "a|A".to_string()]);
    }
}
