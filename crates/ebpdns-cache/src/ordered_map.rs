//! **[历史归因]** 有序映射（对齐 Python `collections.OrderedDict`），O(1) 的 move_to_end / pop。
//!
//! 用 arena 双向链表 + HashMap 实现：head = LRU（最久未访问），tail = MRU（最近访问）。
//! 提供 head→tail 的顺序遍历与按位置的键快照（用于轮转 purge 游标）。

use std::collections::HashMap;

struct Node<K, V> {
    prev: Option<usize>,
    next: Option<usize>,
    key: K,
    value: V,
}

/// 有序映射。`K` 需可哈希克隆。
pub struct OrderedMap<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    map: HashMap<K, usize>,
    nodes: Vec<Option<Node<K, V>>>,
    head: Option<usize>,
    tail: Option<usize>,
    free: Vec<usize>,
    len: usize,
}

impl<K, V> Default for OrderedMap<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> OrderedMap<K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            nodes: Vec::new(),
            head: None,
            tail: None,
            free: Vec::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    pub fn get(&self, k: &K) -> Option<&V> {
        let idx = *self.map.get(k)?;
        self.nodes[idx].as_ref().map(|n| &n.value)
    }

    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let idx = *self.map.get(k)?;
        self.nodes[idx].as_mut().map(|n| &mut n.value)
    }

    fn alloc(&mut self, key: K, value: V) -> usize {
        if let Some(i) = self.free.pop() {
            self.nodes[i] = Some(Node {
                prev: None,
                next: None,
                key,
                value,
            });
            i
        } else {
            self.nodes.push(Some(Node {
                prev: None,
                next: None,
                key,
                value,
            }));
            self.nodes.len() - 1
        }
    }

    /// 把节点从链表摘下（不释放 arena 槽位，由调用者决定）。
    fn unlink(&mut self, idx: usize) {
        let (prev, next) = match self.nodes[idx].as_ref() {
            Some(n) => (n.prev, n.next),
            None => return,
        };
        if let Some(p) = prev {
            if let Some(pn) = self.nodes[p].as_mut() {
                pn.next = next;
            }
        } else {
            self.head = next;
        }
        if let Some(nx) = next {
            if let Some(nn) = self.nodes[nx].as_mut() {
                nn.prev = prev;
            }
        } else {
            self.tail = prev;
        }
        if let Some(node) = self.nodes[idx].as_mut() {
            node.prev = None;
            node.next = None;
        }
    }

    fn push_back_idx(&mut self, idx: usize) {
        match self.tail {
            Some(t) => {
                if let Some(tn) = self.nodes[t].as_mut() {
                    tn.next = Some(idx);
                }
                if let Some(node) = self.nodes[idx].as_mut() {
                    node.prev = Some(t);
                    node.next = None;
                }
                self.tail = Some(idx);
            }
            None => {
                self.head = Some(idx);
                self.tail = Some(idx);
                if let Some(node) = self.nodes[idx].as_mut() {
                    node.prev = None;
                    node.next = None;
                }
            }
        }
    }

    fn push_front_idx(&mut self, idx: usize) {
        match self.head {
            Some(h) => {
                if let Some(hn) = self.nodes[h].as_mut() {
                    hn.prev = Some(idx);
                }
                if let Some(node) = self.nodes[idx].as_mut() {
                    node.next = Some(h);
                    node.prev = None;
                }
                self.head = Some(idx);
            }
            None => {
                self.head = Some(idx);
                self.tail = Some(idx);
                if let Some(node) = self.nodes[idx].as_mut() {
                    node.prev = None;
                    node.next = None;
                }
            }
        }
    }

    fn drop_node(&mut self, idx: usize) -> Option<(K, V)> {
        let node = self.nodes[idx].take()?;
        self.free.push(idx);
        self.len -= 1;
        Some((node.key, node.value))
    }

    /// 插入/更新键到 tail（MRU）。若已存在则替换值并移到 tail。
    pub fn insert(&mut self, k: K, v: V) {
        if let Some(&idx) = self.map.get(&k) {
            self.unlink(idx);
            if let Some(node) = self.nodes[idx].as_mut() {
                node.value = v;
            }
            self.push_back_idx(idx);
        } else {
            let idx = self.alloc(k.clone(), v);
            self.map.insert(k, idx);
            self.push_back_idx(idx);
            self.len += 1;
        }
    }

    /// 把已有键移到 tail（MRU），对应 `move_to_end(key)`。
    pub fn move_to_end(&mut self, k: &K) {
        if let Some(&idx) = self.map.get(k) {
            self.unlink(idx);
            self.push_back_idx(idx);
        }
    }

    /// 把已有键移到 head（LRU 端），对应 `move_to_end(key, last=False)`。
    pub fn move_to_front(&mut self, k: &K) {
        if let Some(&idx) = self.map.get(k) {
            self.unlink(idx);
            self.push_front_idx(idx);
        }
    }

    /// 删除指定键，返回被删的值。
    pub fn remove(&mut self, k: &K) -> Option<V> {
        let idx = self.map.remove(k)?;
        self.unlink(idx);
        self.drop_node(idx).map(|(_, v)| v)
    }

    /// 删除指定键并**连同键一起返回**（移动而非克隆），供跨段搬移用。
    ///
    /// C-07/C-09 的零分配搬移：TinyLFU 命中 probation 时要把条目晋升到 protected，
    /// 旧实现 `remove(key)` 丢掉存储的键、再用 `key.clone()` 重建（3 次 String 分配），
    /// 本方法把已拥有的键直接交还，搬移全程 0 分配。
    pub fn remove_entry(&mut self, k: &K) -> Option<(K, V)> {
        let idx = self.map.remove(k)?;
        self.unlink(idx);
        self.drop_node(idx)
    }

    /// 插入/更新键到 head（LRU 端），等价于 `insert()` + `move_to_front()`。
    ///
    /// 只需一次哈希查找且不克隆键（旧写法 `insert(k.clone(), v); move_to_front(&k)`
    /// 每次搬移多 3 次 String 分配）。
    pub fn push_front(&mut self, k: K, v: V) {
        if let Some(&idx) = self.map.get(&k) {
            self.unlink(idx);
            if let Some(node) = self.nodes[idx].as_mut() {
                node.value = v;
            }
            self.push_front_idx(idx);
        } else {
            let idx = self.alloc(k.clone(), v);
            self.map.insert(k, idx);
            self.push_front_idx(idx);
            self.len += 1;
        }
    }

    /// 删除 head（LRU 最久），返回 (key, value)。
    pub fn pop_front(&mut self) -> Option<(K, V)> {
        let h = self.head?;
        self.unlink(h);
        let (k, v) = self.drop_node(h)?;
        self.map.remove(&k);
        Some((k, v))
    }

    /// 查看 head（LRU）而不删除。
    pub fn front(&self) -> Option<(&K, &V)> {
        let h = self.head?;
        self.nodes[h].as_ref().map(|n| (&n.key, &n.value))
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.nodes.clear();
        self.free.clear();
        self.head = None;
        self.tail = None;
        self.len = 0;
    }

    /// 顺序迭代 head(LRU)→tail(MRU)。
    pub fn iter(&self) -> Iter<'_, K, V> {
        Iter {
            map: self,
            cur: self.head,
        }
    }

    /// 从 `start` 位置起取至多 `count` 个键的快照（对齐 `itertools.islice(keys, pos, pos+step)`）。
    pub fn range_keys(&self, start: usize, count: usize) -> Vec<K> {
        let mut out = Vec::with_capacity(count.min(self.len));
        let mut cur = self.head;
        let mut i = 0usize;
        while let Some(idx) = cur {
            if i >= start + count {
                break;
            }
            if i >= start {
                if let Some(node) = self.nodes[idx].as_ref() {
                    out.push(node.key.clone());
                }
            }
            i += 1;
            cur = self.nodes[idx].as_ref().and_then(|n| n.next);
        }
        out
    }

    /// 从 `start` 位置起取至多 `count` 个节点的 arena 索引（不克隆键）。
    ///
    /// 对齐 `itertools.islice(m.keys(), pos, pos+step)` 的**遍历序**，但只产出
    /// 索引：调用方随后用 [`value_at`](Self::value_at) 原地读、用
    /// [`remove_index`](Self::remove_index) 原地删，全流程不再克隆键、也不再做
    /// 第二次哈希查找。C-09 前这里是 `range_keys()`（克隆 64 个键，每个键 2~3 次
    /// String 分配）+ `get()`（哈希查找）+ `remove()`（又一次哈希查找）。
    pub fn range_indices(&self, start: usize, count: usize) -> Vec<usize> {
        let mut out = Vec::with_capacity(count.min(self.len));
        let mut cur = self.head;
        let mut i = 0usize;
        while let Some(idx) = cur {
            if i >= start + count {
                break;
            }
            if i >= start {
                out.push(idx);
            }
            i += 1;
            cur = self.nodes[idx].as_ref().and_then(|n| n.next);
        }
        out
    }

    /// 按 arena 索引读值（O(1)，不经过 HashMap）。
    pub fn value_at(&self, idx: usize) -> Option<&V> {
        self.nodes.get(idx)?.as_ref().map(|n| &n.value)
    }

    /// 按 arena 索引删除（O(1) 摘链 + 一次 HashMap 删除），返回被删值。
    pub fn remove_index(&mut self, idx: usize) -> Option<V> {
        let node = self.nodes.get_mut(idx)?.take()?;
        // 就地摘链：node 已持有 prev/next，无需再回读 self.nodes[idx]。
        match node.prev {
            Some(p) => {
                if let Some(pn) = self.nodes[p].as_mut() {
                    pn.next = node.next;
                }
            }
            None => self.head = node.next,
        }
        match node.next {
            Some(n) => {
                if let Some(nn) = self.nodes[n].as_mut() {
                    nn.prev = node.prev;
                }
            }
            None => self.tail = node.prev,
        }
        self.map.remove(&node.key);
        self.free.push(idx);
        self.len -= 1;
        Some(node.value)
    }
}

pub struct Iter<'a, K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    map: &'a OrderedMap<K, V>,
    cur: Option<usize>,
}

impl<'a, K, V> Iterator for Iter<'a, K, V>
where
    K: std::hash::Hash + Eq + Clone,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let idx = self.cur?;
        let node = self.map.nodes[idx].as_ref()?;
        self.cur = node.next;
        Some((&node.key, &node.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys_vec(m: &OrderedMap<&'static str, i32>) -> Vec<&'static str> {
        m.iter().map(|(k, _)| *k).collect()
    }

    #[test]
    fn move_to_end_preserves_chain() {
        let mut m: OrderedMap<&'static str, i32> = OrderedMap::new();
        m.insert("A", 1);
        m.insert("B", 2);
        m.insert("C", 3);
        m.insert("D", 4);
        // get(B) 触发 move_to_end：期望顺序 A,C,D,B（四项都在）。
        m.move_to_end(&"B");
        assert_eq!(keys_vec(&m), vec!["A", "C", "D", "B"]);
        assert_eq!(m.len(), 4);
    }

    #[test]
    fn repeated_get_chain_stays_complete() {
        let mut m: OrderedMap<usize, i32> = OrderedMap::new();
        const N: usize = 64;
        for i in 0..N {
            m.insert(i, i as i32);
        }
        // 多轮"随机" get（move_to_end）+ 更新已存在 key。
        let mut seed = 1u64;
        for _ in 0..2000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let k = (seed as usize) % N;
            m.move_to_end(&k);
        }
        // 可达节点数必须恒等于 len()（链不能断）。
        let reached = m.iter().count();
        assert_eq!(
            reached,
            m.len(),
            "forward chain broken: reached={reached} len={}",
            m.len()
        );
        // head→tail 顺序里每个 key 都能被 HashMap 查到。
        for (k, v) in m.iter() {
            assert_eq!(m.get(k), Some(v));
        }
    }

    #[test]
    fn remove_middle_reconnects_neighbors() {
        let mut m: OrderedMap<&'static str, i32> = OrderedMap::new();
        m.insert("A", 1);
        m.insert("B", 2);
        m.insert("C", 3);
        m.remove(&"B");
        assert_eq!(keys_vec(&m), vec!["A", "C"]);
        assert_eq!(m.len(), 2);
        // 再访问 A、C 不应 panic 或丢链。
        m.move_to_end(&"A");
        assert_eq!(keys_vec(&m), vec!["C", "A"]);
    }

    #[test]
    fn push_front_equivalent_to_insert_plus_move_to_front() {
        let mut a: OrderedMap<&'static str, i32> = OrderedMap::new();
        let mut b: OrderedMap<&'static str, i32> = OrderedMap::new();
        for k in ["A", "B", "C", "D"] {
            a.push_front(k, 1);
            b.insert(k, 1);
            b.move_to_front(&k);
        }
        assert_eq!(keys_vec(&a), keys_vec(&b));
        assert_eq!(keys_vec(&a), vec!["D", "C", "B", "A"]);
        // 已存在键：更新值并置 head（等价 insert + move_to_front）。
        a.push_front("B", 9);
        b.insert("B", 9);
        b.move_to_front(&"B");
        assert_eq!(keys_vec(&a), keys_vec(&b));
        assert_eq!(keys_vec(&a), vec!["B", "D", "C", "A"]);
        assert_eq!(a.get(&"B"), Some(&9));
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn remove_entry_returns_moved_key() {
        let mut m: OrderedMap<String, i32> = OrderedMap::new();
        m.insert("k1".to_string(), 1);
        m.insert("k2".to_string(), 2);
        let (k, v) = m.remove_entry(&"k1".to_string()).expect("present");
        assert_eq!(k, "k1");
        assert_eq!(v, 1);
        assert_eq!(m.len(), 1);
        assert!(m.get(&"k1".to_string()).is_none());
        assert!(m.remove_entry(&"gone".to_string()).is_none());
        // 搬移后链仍完整。
        assert_eq!(m.iter().count(), m.len());
    }

    #[test]
    fn range_indices_and_remove_index_keep_chain_intact() {
        let mut m: OrderedMap<usize, usize> = OrderedMap::new();
        const N: usize = 200;
        for i in 0..N {
            m.insert(i, i * 10);
        }
        let idxs = m.range_indices(64, 64);
        assert_eq!(idxs.len(), 64);
        // 索引读到的值必须与遍历序一致（第 64..128 个节点）。
        for (off, idx) in idxs.iter().enumerate() {
            assert_eq!(m.value_at(*idx), Some(&((64 + off) * 10)));
        }
        // 删掉抽样的一半，链不能断、len 必须同步。
        for idx in idxs.iter().step_by(2) {
            assert!(m.remove_index(*idx).is_some());
        }
        assert_eq!(m.len(), N - 32);
        assert_eq!(m.iter().count(), m.len());
        for (k, v) in m.iter() {
            assert_eq!(m.get(k), Some(v));
            assert_eq!(*v, k * 10);
        }
        // 越界索引安全返回 None。
        assert!(m.value_at(99_999).is_none());
        assert!(m.remove_index(99_999).is_none());
    }
}
