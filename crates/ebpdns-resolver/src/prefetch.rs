//! **[历史归因]** 预取待办队列：对齐 Python `_prefetch_pending = OrderedDict`。
//! 插入序稳定可预测；重新调度已有 key → 移到 MRU 末尾。
//! 用 VecDeque（序）+ HashMap（数据）实现 OrderedDict 语义。

use std::collections::{HashMap, VecDeque};

/// 预取待办有序映射。
pub struct PendingMap {
    order: VecDeque<String>,
    data: HashMap<String, (String, String)>,
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
        }
    }

    /// 调度：新 key 插入末尾；已有 key 移到末尾（move_to_end）。
    /// 超 `max` 上限驱逐最旧（队首），防随机子域放大堆积。
    pub fn schedule(&mut self, key: &str, domain: &str, qtype: &str, max: usize) {
        if self.data.contains_key(key) {
            if let Some(pos) = self.order.iter().position(|k| k == key) {
                self.order.remove(pos);
            }
        }
        self.data
            .insert(key.to_string(), (domain.to_string(), qtype.to_string()));
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

    /// 取走并清空整个队列（FIFO 序）。后台预取循环每轮快照消费。
    pub fn drain_all(&mut self) -> Vec<(String, String, String)> {
        let mut out = Vec::with_capacity(self.order.len());
        while let Some(key) = self.order.pop_front() {
            if let Some((domain, qtype)) = self.data.remove(&key) {
                out.push((key, domain, qtype));
            }
        }
        out
    }
}
