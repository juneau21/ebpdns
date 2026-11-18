//! **阶段 3-14：缓存键变体（DNSSEC）** —— 缓存层门禁。
//!
//! 覆盖三件事（不依赖 resolver / 网络）：
//! 1. DO 键与非 DO 键在**同一种策略**（`lru` / `s3fifo`）下是两条条目，互不命中；
//! 2. v1 JSON 键数组往返：`to_key_array()` 的 `"DO"` 尾巴能被 `restore()` 读回变体；
//! 3. 旧 2 元素键（无 `"DO"`）恢复为 `dnssec=false`（旧缓存文件向后兼容）。

use ebpdns_cache::{CacheAnswer, CacheEntry, CacheKey, DnsCache, LruCache, S3FifoCache};
use serde_json::json;

const NOW: f64 = 1_700_000_000.0;

fn entry(domain: &str, value: &str, ttl: f64) -> CacheEntry {
    CacheEntry {
        domain: domain.to_string(),
        qtype: "A".to_string(),
        rrsets: ebpdns_cache::rrset::rrsets_from_flat(&[CacheAnswer {
            value: value.into(),
            ttl,
            rtype: 1,
            name: None,
        }]),
        chosen: value.to_string(),
        ttl,
        rcode: 0,
        expires_at: NOW + ttl,
        rule_gen: 1,
        seq: 0,
    }
}

/// **不串条目**：同域名/qtype 的 DO 与非 DO 键必须各存一条、各取各的。
fn assert_no_cross_hit(c: &dyn DnsCache) {
    let plain = CacheKey::new("do-split.test", "A");
    let sec = CacheKey::new("do-split.test", "A").with_dnssec(true);
    assert_ne!(plain, sec);

    c.put(plain.clone(), entry("do-split.test", "1.1.1.1", 300.0), NOW);
    // 只放了非 DO 条目 ⇒ DO 键必须**读不到**（否则 DO 客户端会拿到非 DNSSEC 答案）。
    assert!(c.get(&sec, NOW + 0.5).is_none(), "DO 键不得命中非 DO 条目");

    c.put(sec.clone(), entry("do-split.test", "2.2.2.2", 300.0), NOW);
    assert_eq!(
        c.get(&sec, NOW + 0.5).map(|e| e.chosen),
        Some("2.2.2.2".to_string()),
        "DO 条目必须是它自己那条"
    );
    assert_eq!(
        c.get(&plain, NOW + 0.5).map(|e| e.chosen),
        Some("1.1.1.1".to_string()),
        "非 DO 条目必须仍是它自己那条"
    );
    // 删除其中一条不得影响另一条。
    c.delete(&sec);
    assert!(c.get(&sec, NOW + 0.6).is_none());
    assert!(c.get(&plain, NOW + 0.6).is_some());
}

#[test]
fn lru_do_and_non_do_entries_do_not_collide() {
    let c = LruCache::new(64);
    assert_no_cross_hit(&c);
}

#[test]
fn s3fifo_do_and_non_do_entries_do_not_collide() {
    let c = S3FifoCache::new(64);
    assert_no_cross_hit(&c);
}

/// **v1 JSON 键数组往返**：`serialize()` 写出的 `key` 数组带 `"DO"`，`restore()`
/// 必须把它还原成带变体的键（否则重启后 DO 条目退化成非 DO 条目）。
#[test]
fn serialize_restore_roundtrips_dnssec_variant() {
    let c = LruCache::new(64);
    let sec = CacheKey::new("roundtrip.test", "A").with_dnssec(true);
    let plain = CacheKey::new("roundtrip.test", "A");
    c.put(sec.clone(), entry("roundtrip.test", "3.3.3.3", 300.0), NOW);
    c.put(
        plain.clone(),
        entry("roundtrip.test", "4.4.4.4", 300.0),
        NOW,
    );

    let snap = c.serialize(NOW + 0.5);
    assert_eq!(snap.len(), 2, "两条变体必须各写一条记录");
    // DO 记录的键数组 = [domain, qtype, "DO"]；非 DO 记录仍是 [domain, qtype]。
    let arrays: Vec<Vec<String>> = snap
        .iter()
        .map(|v| {
            v["key"]
                .as_array()
                .expect("key 必须是数组")
                .iter()
                .map(|x| x.as_str().expect("key 元素必须是字符串").to_string())
                .collect()
        })
        .collect();
    assert!(
        arrays.contains(&vec![
            "roundtrip.test".to_string(),
            "A".to_string(),
            "DO".to_string()
        ]),
        "DO 键数组必须追加 \"DO\"：{arrays:?}"
    );
    assert!(
        arrays.contains(&vec!["roundtrip.test".to_string(), "A".to_string()]),
        "非 DO 键数组必须仍是旧形态（2 元素）：{arrays:?}"
    );

    let c2 = LruCache::new(64);
    c2.restore(&snap, NOW + 0.5, 0.0);
    assert_eq!(
        c2.get(&sec, NOW + 0.6).map(|e| e.chosen),
        Some("3.3.3.3".to_string()),
        "DO 条目恢复后必须仍在 DO 键上"
    );
    assert_eq!(
        c2.get(&plain, NOW + 0.6).map(|e| e.chosen),
        Some("4.4.4.4".to_string()),
        "非 DO 条目恢复后必须仍在非 DO 键上"
    );
}

/// **旧 2 元素键恢复为 `dnssec=false`**：手写一条"旧版文件"记录（键数组无 `"DO"`），
/// `restore()` 必须把它装进非 DO 键 —— 且 `dnssec=true` 的查询**读不到**它。
#[test]
fn legacy_two_element_key_restores_as_non_dnssec() {
    let c = LruCache::new(64);
    // 记录形状与旧版 `entry_to_json` 一致（`CacheEntry` 的 domain/qtype/chosen/ttl/
    // rcode/expires_at 都是必填字段；`key` 数组是 2 元素的旧形态）。
    let legacy = vec![json!({
        "key": ["legacy.test", "A"],
        "domain": "legacy.test",
        "qtype": "A",
        "answers": [{"value": "5.5.5.5", "ttl": 300.0, "type": 1}],
        "chosen": "5.5.5.5",
        "ttl": 300.0,
        "rcode": 0,
        // **绝对到期时间**（旧格式判定：缺它会被安全侧丢弃）。
        "expires_at": NOW + 300.0,
        "rule_gen": 1,
    })];
    c.restore(&legacy, NOW + 1.0, 0.0);
    let plain = CacheKey::new("legacy.test", "A");
    let sec = CacheKey::new("legacy.test", "A").with_dnssec(true);
    assert!(
        c.get(&plain, NOW + 2.0).is_some(),
        "旧 2 元素键必须恢复进**非 DO** 键"
    );
    assert!(
        c.get(&sec, NOW + 2.0).is_none(),
        "旧键没有 DNSSEC 变体 ⇒ DO 键不得命中它"
    );
}

/// **键数组编码是"向后兼容追加"**：`to_key_array()` 对 `dnssec=false` 的输出必须与
/// 旧版逐字节相同（旧文件可读），`true` 只在末尾多一个 `"DO"`。
#[test]
fn key_array_shape_is_backward_compatible() {
    assert_eq!(
        CacheKey::new("a.test", "A").to_key_array(),
        vec!["a.test".to_string(), "A".to_string()]
    );
    assert_eq!(
        CacheKey::new("a.test", "A")
            .with_dnssec(true)
            .to_key_array(),
        vec!["a.test".to_string(), "A".to_string(), "DO".to_string()]
    );
    assert_eq!(
        CacheKey::with_group("g", "a.test", "A").to_key_array(),
        vec!["g".to_string(), "a.test".to_string(), "A".to_string()]
    );
    assert_eq!(
        CacheKey::with_group("g", "a.test", "A")
            .with_dnssec(true)
            .to_key_array(),
        vec![
            "g".to_string(),
            "a.test".to_string(),
            "A".to_string(),
            "DO".to_string()
        ]
    );
}
