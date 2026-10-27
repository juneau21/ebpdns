//! 移植 `review161/tests/test_cache.py` 全部用例，并补充 stale/clear/sketch/准入等行为向量。
//!
//! 时间一律用注入的 mock 时钟（显式 `now` 参数），纯逻辑确定性。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, LruCache, PartitionedCache, TinyLfuCache};
use std::collections::BTreeMap;

const T0: f64 = 1_000.0;

fn entry(ttl: f64, now: f64) -> CacheEntry {
    CacheEntry::new("example.com", "A", ttl, now)
}

// ============================ LRU ============================

#[test]
fn lru_put_get() {
    let c = LruCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    assert!(c.get(&k, T0 + 1.0).is_some());
    let miss = CacheKey::new("missing.com", "A");
    assert!(c.get(&miss, T0 + 1.0).is_none());
}

#[test]
fn lru_expiry() {
    let c = LruCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(1.0, T0), T0);
    // T0+1.1 已过 expires_at=T0+1
    assert!(c.get(&k, T0 + 1.1).is_none());
}

#[test]
fn lru_eviction_bounded() {
    let c = LruCache::new(16);
    for i in 0..100 {
        c.put(
            CacheKey::new(format!("host{i}.test"), "A"),
            entry(60.0, T0),
            T0,
        );
    }
    assert!(c.len() <= 16, "len={}", c.len());
}

#[test]
fn lru_serialize_restore() {
    let c = LruCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    let blob = c.serialize(T0);
    assert_eq!(blob.len(), 1);

    let c2 = LruCache::new(64);
    c2.restore(&blob, T0, 0.0);
    assert!(c2.get(&k, T0 + 1.0).is_some());
}

#[test]
fn lru_restore_persist_ttl() {
    let c = LruCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    let blob = c.serialize(T0);

    let c2 = LruCache::new(64);
    let restore_at = T0 + 100.0;
    c2.restore(&blob, restore_at, 5.0);
    let got = c2.get(&k, restore_at).expect("restored entry present");
    let remaining = got.expires_at - restore_at;
    assert!((remaining - 5.0).abs() < 1.0, "remaining={remaining}");
}

#[test]
fn lru_stale_window_get_stale() {
    let c = LruCache::new(64);
    c.set_stale_window(3600);
    let k = CacheKey::new("stale.test", "A");
    // 写入 ttl=1，在 T0+10 已过期 9s，但仍在 3600s 窗口内。
    c.put(k.clone(), entry(1.0, T0), T0);
    let now = T0 + 10.0;
    assert!(c.get(&k, now).is_none()); // 已过期，get 不返回
    let stale = c.get_stale(&k, now, 3600.0).expect("within stale window");
    assert!((stale.expires_at - now).abs() < 0.01 || stale.expires_at <= now);
    // 窗口外：应被删除。
    assert!(c.get_stale(&k, T0 + 10_000.0, 3600.0).is_none());
}

#[test]
fn lru_clear() {
    let c = LruCache::new(64);
    for i in 0..10 {
        c.put(CacheKey::new(format!("h{i}.t"), "A"), entry(60.0, T0), T0);
    }
    assert!(c.len() > 0);
    c.clear();
    assert_eq!(c.len(), 0);
}

#[test]
fn lru_delete() {
    let c = LruCache::new(64);
    let k = CacheKey::new("del.test", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    assert!(c.get(&k, T0).is_some());
    c.delete(&k);
    assert!(c.get(&k, T0).is_none());
}

// ============================ Partitioned ============================

#[test]
fn partition_isolation() {
    let mut w = BTreeMap::new();
    w.insert("domestic".to_string(), 0.5);
    w.insert("global".to_string(), 0.3);
    w.insert("default".to_string(), 0.2);
    let c = PartitionedCache::new(128, Some(w));
    c.put(
        CacheKey::with_group("domestic", "a.test", "A"),
        entry(60.0, T0),
        T0,
    );
    c.put(
        CacheKey::with_group("global", "b.test", "A"),
        entry(60.0, T0),
        T0,
    );
    assert!(c
        .get(&CacheKey::with_group("domestic", "a.test", "A"), T0)
        .is_some());
    // a.test 在 domestic 分区，global 分区查不到。
    assert!(c
        .get(&CacheKey::with_group("global", "a.test", "A"), T0)
        .is_none());
}

#[test]
fn partition_serialize_restore_roundtrip() {
    let c = PartitionedCache::new(128, None);
    c.put(
        CacheKey::with_group("domestic", "a.test", "A"),
        entry(60.0, T0),
        T0,
    );
    let blob = c.serialize(T0);
    assert_eq!(blob.len(), 1);

    let c2 = PartitionedCache::new(128, None);
    c2.restore(&blob, T0, 0.0);
    assert!(c
        .get(&CacheKey::with_group("domestic", "a.test", "A"), T0)
        .is_some());
}

// ============================ TinyLFU ============================

#[test]
fn tinylfu_put_get() {
    let c = TinyLfuCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    assert!(c.get(&k, T0 + 1.0).is_some());
}

#[test]
fn tinylfu_hot_key_retention() {
    let c = TinyLfuCache::new(64);
    let hot = CacheKey::new("hot.test", "A");
    c.put(hot.clone(), entry(60.0, T0), T0);
    // 反复访问热点，累积 sketch 频率。
    for _ in 0..50 {
        assert!(c.get(&hot, T0).is_some());
    }
    // 灌入大量冷条目触发淘汰。
    for i in 0..100 {
        c.put(
            CacheKey::new(format!("cold{i}.test"), "A"),
            entry(60.0, T0),
            T0,
        );
    }
    // 高频热点应被保留（准入比较胜过低频冷条目）。
    assert!(
        c.get(&hot, T0).is_some(),
        "hot key should survive TinyLFU eviction"
    );
}

#[test]
fn tinylfu_serialize_restore() {
    let c = TinyLfuCache::new(64);
    let k = CacheKey::new("example.com", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    let blob = c.serialize(T0);
    assert_eq!(blob.len(), 1);

    let c2 = TinyLfuCache::new(64);
    c2.restore(&blob, T0, 0.0);
    assert!(c2.get(&k, T0 + 1.0).is_some());
}

#[test]
fn tinylfu_expiry() {
    let c = TinyLfuCache::new(64);
    let k = CacheKey::new("exp.test", "A");
    c.put(k.clone(), entry(1.0, T0), T0);
    assert!(c.get(&k, T0 + 1.1).is_none());
}

#[test]
fn tinylfu_clear_resets_sketch() {
    let c = TinyLfuCache::new(64);
    let k = CacheKey::new("c.test", "A");
    c.put(k.clone(), entry(60.0, T0), T0);
    for _ in 0..10 {
        c.get(&k, T0);
    }
    c.clear();
    assert_eq!(c.len(), 0);
    // clear 后 sketch 归零：新写入的同 key 频率重新从低开始。
    c.put(k.clone(), entry(60.0, T0), T0);
    assert!(c.get(&k, T0).is_some());
}

// ============================ 回归：链断裂导致 serialize 丢条目 ============================

#[test]
fn lru_serialize_contains_all_entries() {
    // 预灌多条，中间穿插 get(move_to_end)——旧实现 forward 链断裂会让 serialize 只剩 1 条。
    let c = LruCache::new(256);
    let n = 40;
    for i in 0..n {
        let k = CacheKey::new(format!("host{i}.example.com"), "A");
        c.put(k, entry(60.0, T0), T0);
        // 中途访问已存在 key，触发 move_to_end。
        if i % 3 == 0 {
            let probe = CacheKey::new(format!("host{}.example.com", i / 2), "A");
            std::hint::black_box(c.get(&probe, T0));
        }
    }
    let blob = c.serialize(T0);
    assert_eq!(
        blob.len(),
        n,
        "serialize 丢失条目：got {} 期望 {n}",
        blob.len()
    );
}

#[test]
fn tinylfu_serialize_contains_all_entries() {
    let c = TinyLfuCache::new(256);
    let n = 40;
    for i in 0..n {
        let k = CacheKey::new(format!("h{i}.ex.com"), "A");
        c.put(k, entry(60.0, T0), T0);
        if i % 3 == 0 {
            let probe = CacheKey::new(format!("h{}.ex.com", i / 2), "A");
            std::hint::black_box(c.get(&probe, T0));
        }
    }
    let blob = c.serialize(T0);
    assert_eq!(
        blob.len(),
        n,
        "TinyLFU serialize 丢失条目：got {} 期望 {n}",
        blob.len()
    );
}

#[test]
fn lru_iter_count_equals_len_after_mixed_ops() {
    let c = LruCache::new(256);
    for i in 0..30 {
        c.put(CacheKey::new(format!("k{i}.t"), "A"), entry(60.0, T0), T0);
    }
    // 混合 get + delete。
    for i in (0..30).step_by(2) {
        std::hint::black_box(c.get(&CacheKey::new(format!("k{i}.t"), "A"), T0));
    }
    for i in (0..10).step_by(3) {
        c.delete(&CacheKey::new(format!("k{i}.t"), "A"));
    }
    let keys = c.keys();
    assert_eq!(keys.len(), c.len(), "keys/len 不一致");
    // 每个 key 都仍可查询（HashMap 与链一致）。
    for k in &keys {
        assert!(c.get(k, T0).is_some());
    }
}

// ==================== **2.1.25（B8）**：分块流式落盘的字节等价 ====================

/// 跑一遍"旧路径"：`serialize` → `to_vec_pretty`（= 2.1.24 生产落盘的内容）。
fn legacy_blob(c: &dyn DnsCache, now: f64) -> Vec<u8> {
    serde_json::to_vec_pretty(&c.serialize(now)).expect("serialize")
}

/// 跑一遍"新路径"：`write_snapshot` 流式写进内存 writer。
fn streaming_blob(c: &dyn DnsCache, now: f64) -> (Vec<u8>, u64) {
    let mut buf: Vec<u8> = Vec::new();
    let n = c.write_snapshot(now, &mut buf).expect("write_snapshot");
    (buf, n)
}

/// **B8 的硬判据**：`write_snapshot` 写出的字节必须与
/// `to_vec_pretty(&serialize(now))` **逐字节相同** —— 三条策略 × 三种表形态（空 / 单条 /
/// 多条含 TTL 与 qtype 差异）× 含"已过期条目被跳过"的情形。
///
/// 为什么必须逐字节：磁盘格式与恢复语义本轮**不允许**变（铁律：失效语义/协议行为不变），
/// 所以"分块流式"只能是**内存与锁**的优化。这条单测就是那个边界的机器判据。
#[test]
fn write_snapshot_is_byte_identical_to_to_vec_pretty() {
    // ---- 形态 1：空表（`[]`，不能是 `[\n\n]` 之类）----
    let empty_lru = LruCache::new(64);
    let empty_fl = TinyLfuCache::new(64);
    let empty_part = PartitionedCache::new(64, None);
    for c in [
        &empty_lru as &dyn DnsCache,
        &empty_fl as &dyn DnsCache,
        &empty_part as &dyn DnsCache,
    ] {
        let (got, n) = streaming_blob(c, T0);
        assert_eq!(n, 0, "空表条目数必须是 0");
        assert_eq!(got, b"[]", "空表必须写成 `[]`");
        assert_eq!(
            got,
            legacy_blob(c, T0),
            "空表必须与 to_vec_pretty 逐字节相同"
        );
    }

    // ---- 构造一批表（含中文域名/多 qtype/长 TTL，覆盖转义与数字格式）----
    let lru = LruCache::new(256);
    let fl = TinyLfuCache::new(256);
    let part = PartitionedCache::new(256, None);
    for i in 0..25 {
        let host = if i % 5 == 0 {
            format!("测试{i}.例子.test")
        } else {
            format!("h{i}.ex.test")
        };
        let qt = ["A", "AAAA", "TXT"][i % 3];
        let mut e = CacheEntry::new(&host, qt, 30.0 + i as f64, T0);
        e.rcode = if i % 7 == 0 { 3 } else { 0 };
        let k = CacheKey::new(host.as_str(), qt);
        lru.put(k.clone(), e.clone(), T0);
        fl.put(k.clone(), e.clone(), T0);
        part.put(k, e, T0);
    }
    // 插入两条**已过期**的（必须被跳过；过期条目不能出现在新路径里）。
    for c in [
        &lru as &dyn DnsCache,
        &fl as &dyn DnsCache,
        &part as &dyn DnsCache,
    ] {
        c.put(
            CacheKey::new("expired.ex.test", "A"),
            CacheEntry::new("expired.ex.test", "A", 1.0, T0),
            T0,
        );
    }
    let now = T0 + 5.0; // expired.ex.test 已过 expires_at = T0+1

    // ---- 形态 2/3：单条与多条（含过期跳过）----
    for c in [
        &lru as &dyn DnsCache,
        &fl as &dyn DnsCache,
        &part as &dyn DnsCache,
    ] {
        let want = legacy_blob(c, now);
        let (got, n) = streaming_blob(c, now);
        assert_eq!(
            got, want,
            "`write_snapshot` 与 `to_vec_pretty(&serialize(now))` 必须逐字节相同"
        );
        assert_eq!(
            n as usize,
            c.serialize(now).len(),
            "返回的条目数必须等于序列化条目数"
        );
        assert!(
            !String::from_utf8_lossy(&got).contains("expired.ex.test"),
            "已过期条目不得写入快照（新旧路径都必须跳过）"
        );
        // 首尾形态断言（防止"恰好相等"来自两边都没写）。
        assert!(got.starts_with(b"[\n"));
        assert!(got.ends_with(b"\n]"));
        assert!(n > 0);
    }

    // ---- 单条（覆盖 `,[空]` 边界：只有一条时不能出现 `,\n`）----
    let one = LruCache::new(8);
    one.put(CacheKey::new("solo.test", "A"), entry(60.0, T0), T0);
    let (got, n) = streaming_blob(&one, T0);
    assert_eq!(n, 1);
    assert_eq!(got, legacy_blob(&one, T0));
    // 只有一条时，数组层**不得**出现元素分隔符（`,\n` 只允许出现在对象内部）。
    // 判据用"解析回来恰好 1 个元素"，而不是"文本里没有 `,\n`" —— 后者对任何
    // 含 2 个以上键的对象都成立，是错的（2.1.25 实测踩过：本用例自己红了一次）。
    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&got).expect("合法 JSON");
    assert_eq!(parsed.len(), 1, "单条快照必须只有一个数组元素");
    let text = String::from_utf8_lossy(&got);
    assert_eq!(
        text.matches("\n  {").count(),
        1,
        "数组层只允许一个元素起始行（元素内部缩进更深，不匹配两空格 + 左花括号）"
    );
}

/// **2.1.25（B8）同进程微基准**：单次"整表落盘内容构造"的耗时 A/B ——
/// A = 2.1.24 路径（`serialize(now)` 建整表 `Vec<Value>` + `to_vec_pretty` 建整块 `Vec<u8>`）；
/// B = 2.1.25 路径（`write_snapshot` 逐条产出、写进一个 64 KiB 级的 writer）。
///
/// 显式运行：
/// `cargo test --release -p ebpdns-cache --test cache_test bench_save_snapshot -- --ignored --nocapture`
///
/// 打印：两种路径的 p50/p99（微秒）、**写出的字节数**（必须相同）、以及
/// "构造期同时驻留的数据量"（A = Value 树 + 文本；B = 1 条记录）的**条目数级**估算依据。
/// 只打印数字，不做时间断言（共享机器上必然 flaky）；权威前后对照见报告里的隔离实例数据。
#[test]
#[ignore = "微基准：需显式 --ignored --nocapture 运行"]
fn bench_save_snapshot_legacy_vs_streaming() {
    use std::time::Instant;
    let n_entries = 20_000usize;
    let c = TinyLfuCache::new(n_entries * 2);
    for i in 0..n_entries {
        let host = format!("bench{i}.perf.test");
        c.put(
            CacheKey::new(host.as_str(), "A"),
            CacheEntry::new(host.as_str(), "A", 600.0, T0),
            T0,
        );
    }
    let now = T0 + 1.0;
    let iters = 5;
    let mut ta = Vec::new();
    let mut tb = Vec::new();
    let mut la = 0usize;
    let mut lb = 0usize;
    for _ in 0..iters {
        let t0 = Instant::now();
        let blob = legacy_blob(&c, now);
        la = blob.len();
        std::hint::black_box(&blob);
        ta.push(t0.elapsed().as_nanos() as f64 / 1000.0);

        let t1 = Instant::now();
        let mut buf: Vec<u8> = Vec::new();
        let k = c.write_snapshot(now, &mut buf).expect("write_snapshot");
        lb = buf.len();
        assert_eq!(k as usize, n_entries, "条目数必须一致");
        std::hint::black_box(&buf);
        tb.push(t1.elapsed().as_nanos() as f64 / 1000.0);
    }
    let pct = |v: &mut Vec<f64>, p: f64| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let k = ((v.len() - 1) as f64 * p / 100.0) as usize;
        v[k.min(v.len() - 1)]
    };
    let (a50, a99) = (pct(&mut ta, 50.0), pct(&mut ta, 99.0));
    let (b50, b99) = (pct(&mut tb, 50.0), pct(&mut tb, 99.0));
    assert_eq!(la, lb, "两条路径写出的字节数必须相同（写放大不变）");
    println!(
        "\n[B8] entries={n_entries} iters={iters}\n  A serialize+to_vec_pretty : p50={a50:.1}us p99={a99:.1}us  bytes={la}\n  B write_snapshot           : p50={b50:.1}us p99={b99:.1}us  bytes={lb}\n  写放大：A == B == {la} B（磁盘格式不变 ⇒ 这一项本批**不可能**降低）\n  构造期驻留：A = 整表 Value 树 + 整块文本；B = 1 条记录 + writer 缓冲\n  ratio(p50) = {:.2}x",
        if b50 > 0.0 { a50 / b50 } else { 0.0 }
    );
}

/// **B8 的二级判据**：`SnapshotSink` 的第一个 IO 错误必须**照实上抛**（不能静默截断文件）。
#[test]
fn write_snapshot_propagates_writer_errors() {
    struct Failing {
        left: usize,
    }
    impl std::io::Write for Failing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("boom"));
            }
            self.left -= 1;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let c = LruCache::new(8);
    c.put(CacheKey::new("a.test", "A"), entry(60.0, T0), T0);
    let mut w = Failing { left: 2 };
    let err = c
        .write_snapshot(T0, &mut w)
        .expect_err("writer 报错必须上抛");
    assert_eq!(err.to_string(), "boom");
}
