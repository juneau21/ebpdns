//! **阶段 B-2（RRset 对象级缓存）**：RRset 共享、持久化 v2 兼容、内存/共享率实测。
//!
//! ## 为什么单独一个测试二进制
//!
//! `rrset` 的两张弱引用表（RRset 表 / 字符串表）都是**进程级全局**的（这正是跨条目
//! 共享的前提）。lib 单元测试与 lru/s3fifo/persist 的用例并行跑在同一进程里，它们的
//! 写入路径也会悄悄 intern，于是"表项数必须恰好 +1 / 回落到原值"这类**确定性**断言
//! 会被邻居干扰。
//!
//! 本文件是独立的测试二进制（cargo 逐个运行 test binary，二进制内部的用例之间用
//! [`serial`] 串行化）⇒ 这里的表项数/命中数断言是**确定性**的，同时仍然走的是
//! **生产同一条**全局表路径（不是 `#[cfg(test)]` 特供实现）。
//!
//! ## 用例分工
//!
//! * [`same_rrset_is_shared_across_messages_with_different_cname_prefix`]：**B-2 核心**
//!   —— 两条消息的 CNAME 前缀不同，链尾 A RRset 的 `Arc::ptr_eq` 必须为真；
//! * [`rrsets_are_shared_via_all_write_paths`]：LRU put / S3FIFO put / v1 restore /
//!   v2 restore_records 四条写入入口都产出同一份 RRset；
//! * [`json_roundtrip_preserves_flat_answers_and_v2_shape`]：JSON 往返后扁平
//!   answers 逐字段/逐顺序一致，且序列化形态仍是 v2 的 `answers` 数组；
//! * [`binary_entry_codec_roundtrip_preserves_flat_answers`]：二进制 `entry_codec`
//!   往返一致（v2 字节契约不变）；
//! * [`legacy_v2_snapshot_answers_array_restores`]：**旧 v2 快照（只有 answers 数组）**
//!   可直接反序列化/恢复，并按相邻 `(name, rtype)` 重新分组；
//! * [`rrset_table_is_bounded`]：RRset 表有界（[`rrset::MAX_INTERNED`]），满则拒绝
//!   登记，不会无限增长；
//! * [`mem_probe_1000_shared_rrset_with_cnames`]（`#[ignore]`，跑法见函数注释）：
//!   1,000 条不同 CNAME 前缀但共享同一 A RRset 的消息 vs 全部不共享的对照组，
//!   报告 RSS / `Arc::strong_count` / intern 统计。

use std::sync::{Arc, Mutex, MutexGuard};

use ebpdns_cache::persist::EntryBody;
use ebpdns_cache::{rrset, CacheAnswer, CacheEntry, CacheKey, DnsCache, LruCache, S3FifoCache};

const NOW: f64 = 1_700_000_000.0;

/// 本二进制内串行化（表是进程级全局 ⇒ 用例之间必须串行，断言才有确定性）。
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// 进程内唯一内容（避免不同用例之间共享到同一表项）。
fn uniq(tag: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    format!(
        "{tag}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// 进程内唯一、形如 IPv4 的 RDATA（避免用例之间共享到同一字符串表项）。
fn uniq_ip() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    format!(
        "10.{}.{}.{}",
        (std::process::id() % 200) + 1,
        (n / 250) % 250,
        n % 250
    )
}

fn ans(value: &str, ttl: f64, rtype: u16, name: Option<&str>) -> CacheAnswer {
    CacheAnswer::new(value, ttl, rtype, name.map(Arc::from))
}

fn arc_ans(value: &str, ttl: f64, rtype: u16, name: Option<&str>) -> Arc<CacheAnswer> {
    Arc::new(ans(value, ttl, rtype, name))
}

/// 造一条完整的缓存条目（不同 domain，但可以用**内容相同**的扁平答案列表）。
fn entry(domain: &str, answers: &[CacheAnswer]) -> CacheEntry {
    let chosen = answers
        .iter()
        .find(|a| a.rtype == 1 || a.rtype == 28)
        .map(|a| a.value.to_string())
        .unwrap_or_default();
    CacheEntry {
        domain: domain.to_string(),
        qtype: "A".to_string(),
        rrsets: rrset::rrsets_from_flat(answers),
        chosen,
        ttl: 300.0,
        rcode: 0,
        expires_at: NOW + 300.0,
        rule_gen: 1,
        seq: 0,
    }
}

/// `CacheEntry` → `restore` 需要的 JSON 记录（v1 形态：`key` 数组 + 绝对 `expires_at`）。
fn record(e: &CacheEntry) -> serde_json::Value {
    let mut v = serde_json::to_value(e).expect("serialize entry");
    v.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!([e.domain.clone(), e.qtype.clone()]),
    );
    v
}

// ============================ 弱引用 / 统计 ============================

/// drop 之后 RRset 表项必须可被清理，且 `stats().0` **回落到** intern 之前。
#[test]
fn dropped_rrset_is_removed_by_sweep() {
    let _g = serial();
    // 清掉前面用例留下的死引用 ⇒ 从这里开始表项数有确定性基线。
    rrset::sweep();
    let n0 = rrset::stats().0;
    assert_eq!(
        n0, 0,
        "串行化后基线必须为 0（实测 {n0}，有别的用例泄漏了强引用？）"
    );

    let u = uniq("drop");
    let vals = vec![arc_ans(&u, 60.0, 1, None)];
    let arc = rrset::intern_rrset("", 1, &vals);
    assert_eq!(rrset::stats().0, n0 + 1, "唯一 RRset 必须新增恰好 1 个表项");
    drop(arc);
    assert_eq!(
        rrset::stats().0,
        n0 + 1,
        "drop 之后、sweep 之前：死引用仍占表项（这是有界设计的一部分）"
    );
    let removed = rrset::sweep();
    assert_eq!(removed, 1, "恰好 1 个死引用必须被回收");
    assert_eq!(
        rrset::stats().0,
        n0,
        "sweep 之后 `stats().0` 必须回落到 intern 之前（弱引用语义生效）"
    );
}

/// 相同 RRset 第二次 intern 计 1 次命中；不同内容不计。
#[test]
fn reuse_hits_are_counted() {
    let _g = serial();
    rrset::sweep();
    rrset::reset_stats();
    let u = uniq("hit");
    let vals = vec![arc_ans(&u, 60.0, 1, None)];
    let a = rrset::intern_rrset("", 1, &vals);
    assert_eq!(rrset::stats().1, 0, "首次 intern 不可能命中");
    let b = rrset::intern_rrset("", 1, &vals);
    assert!(Arc::ptr_eq(&a, &b), "相同内容必须复用同一 Arc");
    assert_eq!(rrset::stats().1, 1, "第二次相同内容必须计 1 次命中");
    let other = vec![arc_ans(&uniq("hit2"), 60.0, 1, None)];
    let _ = rrset::intern_rrset("", 1, &other);
    assert_eq!(rrset::stats().1, 1, "不同内容不得计入命中");
}

/// **B-2**：RRset 表**有界**（[`rrset::MAX_INTERNED`]）：填满后不再登记新 RRset，
/// stats 不越界；全部释放后 sweep 归零。
#[test]
fn rrset_table_is_bounded() {
    use ebpdns_cache::rrset::MAX_INTERNED;
    let _g = serial();
    rrset::sweep();
    assert_eq!(rrset::stats().0, 0, "串行化后基线必须为 0");

    // 每个 RRset 一个唯一 owner + 唯一 value ⇒ 互不相同。
    let keep: Vec<Arc<rrset::Rrset>> = (0..MAX_INTERNED + 1024)
        .map(|i| {
            let u = format!("b2-bound-{i}-{}", uniq("b"));
            rrset::intern_rrset(&u, 1, &[Arc::new(ans(&u, 60.0, 1, Some(&u)))])
        })
        .collect();
    assert_eq!(
        rrset::stats().0,
        MAX_INTERNED,
        "填满（含少量哈希碰撞余量）后表项数必须恰为上限"
    );

    // 表满且全活 ⇒ 新 RRset 不登记：两次 intern 得到两个独立实例（有界优先）。
    let overflow = uniq("b2-overflow");
    let vals = vec![Arc::new(ans(&overflow, 60.0, 1, None))];
    let a = rrset::intern_rrset(&overflow, 1, &vals);
    let b = rrset::intern_rrset(&overflow, 1, &vals);
    assert!(
        !Arc::ptr_eq(&a, &b),
        "表满时新 RRset 不得登记（两次 intern 不共享），否则上界失效"
    );
    assert_eq!(rrset::stats().0, MAX_INTERNED, "拒绝登记后表项数不得越界");

    drop(keep);
    let removed = rrset::sweep();
    assert_eq!(removed, MAX_INTERNED, "全部释放后 sweep 必须回收全部表项");
    assert_eq!(rrset::stats().0, 0, "sweep 后必须归零");
}

// ============================ 阶段 B-2：RRset 级共享 ============================

/// **B-2 核心用例**：两条消息的 CNAME 前缀不同，但链尾 `A` RRset（owner/类型/取值/
/// TTL 都相同）必须共享**同一个** `Arc<Rrset>`；前缀 CNAME RRset 则**不得**误共享。
#[test]
fn same_rrset_is_shared_across_messages_with_different_cname_prefix() {
    let _g = serial();
    let tag = uniq("b2share");
    let ip = uniq_ip();
    // 链尾 A 的 owner（两条消息相同）。
    let owner = format!("{tag}.edge.example");
    // 两条消息不同的 CNAME 前缀。
    let alias_a = format!("{tag}-a.example");
    let alias_b = format!("{tag}-b.example");
    let msg_a = vec![
        ans(&alias_a, 300.0, 5, None),
        ans(&owner, 300.0, 5, Some(&alias_a)),
        ans(&ip, 300.0, 1, Some(&owner)),
        ans(&ip, 300.0, 1, Some(&owner)), // 同一 RRset 内两条取值
    ];
    let msg_b = vec![
        ans(&alias_b, 300.0, 5, None),
        ans(&owner, 300.0, 5, Some(&alias_b)),
        ans(&ip, 300.0, 1, Some(&owner)),
        ans(&ip, 300.0, 1, Some(&owner)),
    ];
    let lru = LruCache::new(64);
    let (k1, k2) = (
        CacheKey::new(format!("{tag}-a.test"), "A"),
        CacheKey::new(format!("{tag}-b.test"), "A"),
    );
    lru.put(k1.clone(), entry(&format!("{tag}-a.test"), &msg_a), NOW);
    lru.put(k2.clone(), entry(&format!("{tag}-b.test"), &msg_b), NOW);
    let e1 = lru.get_arc(&k1, NOW).expect("命中 a");
    let e2 = lru.get_arc(&k2, NOW).expect("命中 b");
    assert_eq!(e1.rrsets.len(), 3);
    assert_eq!(e2.rrsets.len(), 3);
    assert_ne!(
        e1.domain, e2.domain,
        "两条消息必须来自不同缓存键（否则测不到跨消息共享）"
    );
    assert!(
        !Arc::ptr_eq(&e1.rrsets[0], &e2.rrsets[0]),
        "不同的 CNAME 前缀（value 不同）不得共享"
    );
    assert!(
        !Arc::ptr_eq(&e1.rrsets[1], &e2.rrsets[1]),
        "不同的 CNAME 中间跳（owner 不同）不得共享"
    );
    assert!(
        Arc::ptr_eq(&e1.rrsets[2], &e2.rrsets[2]),
        "相同链尾 A RRset 必须跨消息共享同一个 Arc<Rrset>（ptr_eq 为真）"
    );
    assert_eq!(e1.rrsets[2].owner.as_ref(), owner.as_str());
    assert_eq!(e1.rrsets[2].rtype, 1);
    assert_eq!(e1.rrsets[2].values.len(), 2);
    // 扁平化后仍逐字段/逐顺序等于原消息。
    assert_eq!(e1.flat_answers(), msg_a);
    assert_eq!(e2.flat_answers(), msg_b);
}

/// **B-2**：LRU put / S3FIFO put / v1 restore / v2 restore_records 四条写入入口都
/// 必须产出**同一份**链尾 RRset（全局表 ⇒ 与策略/入口无关）。
#[test]
fn rrsets_are_shared_via_all_write_paths() {
    let _g = serial();
    let tag = uniq("b2paths");
    let ip = uniq_ip();
    let owner = format!("{tag}.edge.example");
    let mk = |alias: &str| {
        vec![
            ans(alias, 300.0, 5, None),
            ans(&owner, 300.0, 5, Some(alias)),
            ans(&ip, 300.0, 1, Some(&owner)),
        ]
    };
    let msg_a = mk(&format!("{tag}-a.example"));
    let msg_b = mk(&format!("{tag}-b.example"));

    // ---- ① LRU::put ----
    let lru = LruCache::new(64);
    let k1 = CacheKey::new(format!("{tag}-lru-a.test"), "A");
    let k2 = CacheKey::new(format!("{tag}-lru-b.test"), "A");
    lru.put(k1.clone(), entry(&format!("{tag}-lru-a.test"), &msg_a), NOW);
    lru.put(k2.clone(), entry(&format!("{tag}-lru-b.test"), &msg_b), NOW);
    let e1 = lru.get_arc(&k1, NOW).expect("LRU a");
    let e2 = lru.get_arc(&k2, NOW).expect("LRU b");
    let a_rrset = Arc::clone(&e1.rrsets[2]);
    assert!(Arc::ptr_eq(&e1.rrsets[2], &e2.rrsets[2]));

    // ---- ② S3FIFO::put ----
    let s3 = S3FifoCache::new(64);
    let s1 = CacheKey::new(format!("{tag}-s3-a.test"), "A");
    let s2 = CacheKey::new(format!("{tag}-s3-b.test"), "A");
    s3.put(s1.clone(), entry(&format!("{tag}-s3-a.test"), &msg_a), NOW);
    s3.put(s2.clone(), entry(&format!("{tag}-s3-b.test"), &msg_b), NOW);
    let f1 = s3.get_arc(&s1, NOW).expect("S3FIFO a");
    let f2 = s3.get_arc(&s2, NOW).expect("S3FIFO b");
    assert!(
        Arc::ptr_eq(&a_rrset, &f1.rrsets[2]),
        "同一 RRset 在 LRU 与 S3FIFO 之间也必须共享（全局表）"
    );
    assert!(Arc::ptr_eq(&f1.rrsets[2], &f2.rrsets[2]));

    // ---- ③ v1 restore（JSON 记录 → restore_refs）----
    let lru2 = LruCache::new(64);
    let records = vec![
        record(&entry(&format!("{tag}-r-a.test"), &msg_a)),
        record(&entry(&format!("{tag}-r-b.test"), &msg_b)),
    ];
    lru2.restore(&records, NOW, 0.0);
    let r1 = lru2
        .get_arc(&CacheKey::new(format!("{tag}-r-a.test"), "A"), NOW)
        .expect("restore a");
    let r2 = lru2
        .get_arc(&CacheKey::new(format!("{tag}-r-b.test"), "A"), NOW)
        .expect("restore b");
    assert!(
        Arc::ptr_eq(&a_rrset, &r1.rrsets[2]),
        "v1 restore 必须命中 put 建立的那份共享 RRset"
    );
    assert!(Arc::ptr_eq(&r1.rrsets[2], &r2.rrsets[2]));

    // ---- ④ v2 restore_records（已解码条目 → 直接装入）----
    let lru3 = LruCache::new(64);
    let g1 = CacheKey::new(format!("{tag}-v2-a.test"), "A");
    let g2 = CacheKey::new(format!("{tag}-v2-b.test"), "A");
    lru3.restore_records(
        vec![
            (g1.clone(), entry(&format!("{tag}-v2-a.test"), &msg_a)),
            (g2.clone(), entry(&format!("{tag}-v2-b.test"), &msg_b)),
        ],
        NOW,
    );
    let v1 = lru3.get_arc(&g1, NOW).expect("v2 a");
    let v2 = lru3.get_arc(&g2, NOW).expect("v2 b");
    assert!(Arc::ptr_eq(&v1.rrsets[2], &v2.rrsets[2]));
    assert!(
        Arc::ptr_eq(&a_rrset, &v1.rrsets[2]),
        "restore_records 与 put 必须命中同一份（同一张全局表）"
    );

    // JSON 形态不变：`answers` 仍是**数组**（旧 v2 契约），且没有 `rrsets` 字段。
    let j = serde_json::to_value(&*e1).expect("to_value");
    assert!(
        j.get("answers").map(serde_json::Value::is_array) == Some(true),
        "CacheEntry 的 JSON 形态必须仍是 answers 数组：{j}"
    );
    assert!(
        j.get("rrsets").is_none(),
        "内部字段名 rrsets 不得泄漏到持久化 JSON：{j}"
    );
    assert_eq!(
        j.get("answers").and_then(|a| a.as_array()).map(Vec::len),
        Some(3)
    );
}

// ============================ JSON / 二进制 / 旧 v2 兼容 ============================

/// **B-2**：JSON 序列化/反序列化往返后，扁平 answers **逐字节/逐字段/顺序**一致；
/// 序列化形态仍是旧 v2 的扁平数组（`{value,ttl,type,name}`，无 `rrsets`）。
#[test]
fn json_roundtrip_preserves_flat_answers_and_v2_shape() {
    let _g = serial();
    let tag = uniq("b2json");
    let owner = format!("{tag}.edge.example");
    let flat = vec![
        ans(&format!("{tag}-cdn.example"), 300.0, 5, None),
        ans(&owner, 300.0, 5, Some(&format!("{tag}-cdn.example"))),
        ans(&format!("{tag}-ip1"), 300.0, 1, Some(&owner)),
        ans(&format!("{tag}-ip2"), 301.5, 1, Some(&owner)),
        ans(&format!("{tag}-v6"), 60.0, 28, None),
        // 末尾再来一个不同 (name,rtype) 组，确保分组边界也往返一致。
        ans(&format!("{tag}-txt"), 120.0, 16, None),
    ];
    let mut e = entry(&format!("{tag}.test"), &flat);
    e.rule_gen = 7;
    let j1 = serde_json::to_string(&e).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&j1).expect("parse");

    assert!(
        v.get("answers").map(serde_json::Value::is_array) == Some(true),
        "v2 形态：必须是 answers 数组"
    );
    assert!(v.get("rrsets").is_none(), "不得输出内部 rrsets 字段");
    let arr = v["answers"].as_array().expect("answers 数组");
    assert_eq!(arr.len(), flat.len(), "展开后条数必须与扁平答案一致");
    for (i, a) in flat.iter().enumerate() {
        let ja = &arr[i];
        assert_eq!(
            ja["value"],
            serde_json::json!(&*a.value),
            "第 {i} 条 value 必须逐字节一致"
        );
        assert_eq!(
            ja["ttl"],
            serde_json::json!(a.ttl),
            "第 {i} 条 ttl 必须一致"
        );
        assert_eq!(
            ja["type"],
            serde_json::json!(a.rtype),
            "第 {i} 条 type 必须一致"
        );
        match &a.name {
            None => assert!(ja["name"].is_null(), "第 {i} 条 name 必须仍是 null"),
            Some(n) => assert_eq!(ja["name"], serde_json::json!(&**n), "第 {i} 条 name 不一致"),
        }
    }

    // 往返：反序列化后的扁平 answers 逐字段相等；再序列化必须与第一次**逐字节相同**。
    let back: CacheEntry = serde_json::from_str(&j1).expect("deserialize");
    assert_eq!(
        back.flat_answers(),
        flat,
        "JSON 往返后扁平 answers 必须逐字段、逐顺序一致（含 name/ttl）"
    );
    let j2 = serde_json::to_string(&back).expect("re-serialize");
    assert_eq!(j1, j2, "JSON 往返必须逐字节稳定");
}

/// **B-2**：二进制 `entry_codec`（快照/WAL 共用）往返后扁平 answers 一致，且
/// **编码字节**与重新编码一致（v2 记录格式没有因 RRset 模型改变）。
#[test]
fn binary_entry_codec_roundtrip_preserves_flat_answers() {
    let _g = serial();
    let tag = uniq("b2bin");
    let owner = format!("{tag}.edge.example");
    let flat = vec![
        ans(&format!("{tag}-cdn.example"), 300.0, 5, None),
        ans(&owner, 300.0, 5, Some(&format!("{tag}-cdn.example"))),
        ans(&format!("{tag}-ip1"), 300.0, 1, Some(&owner)),
        ans(&format!("{tag}-ip2"), 300.0, 1, Some(&owner)),
    ];
    let mut e = entry(&format!("{tag}.test"), &flat);
    e.rule_gen = 9;
    let key = CacheKey::new(&e.domain, "A");
    let body = EntryBody::from_entry(&key, &e).expect("from_entry");
    let mut buf = Vec::new();
    body.encode(&mut buf).expect("encode");
    let decoded = EntryBody::decode(&buf).expect("decode");
    let back = decoded.to_entry().expect("to_entry");
    assert_eq!(
        back.flat_answers(),
        flat,
        "二进制往返后扁平 answers 必须逐字段、逐顺序一致"
    );
    assert_eq!(back.rrsets.len(), e.rrsets.len(), "RRset 分组数必须一致");
    assert_eq!(back.rule_gen, 9);
    // 重新编码：字节必须与第一次完全相同（记录格式与 RRset 分组无关）。
    let mut buf2 = Vec::new();
    EntryBody::from_entry(&key, &back)
        .expect("from_entry again")
        .encode(&mut buf2)
        .expect("encode again");
    assert_eq!(buf, buf2, "二进制编码必须逐字节稳定（v2 契约）");
}

/// **B-2**：**旧 v2 快照**（只有扁平 `answers` 数组、无 `seq`/`rule_gen`）可直接
/// 反序列化，并按相邻 `(name, rtype)` 重新分组；经 `LruCache::restore` 也能命中。
#[test]
fn legacy_v2_snapshot_answers_array_restores() {
    let _g = serial();
    let tag = uniq("b2legacy");
    let owner = format!("{tag}.edge.example");
    let legacy = serde_json::json!({
        "domain": format!("{tag}.test"),
        "qtype": "A",
        "answers": [
            {"value": format!("{tag}-cdn.example"), "ttl": 300.0, "type": 5},
            {"value": owner, "ttl": 300.0, "type": 5, "name": format!("{tag}-cdn.example")},
            {"value": "192.0.2.1", "ttl": 300.0, "type": 1, "name": owner},
            {"value": "192.0.2.2", "ttl": 300.0, "type": 1, "name": owner}
        ],
        "chosen": "192.0.2.1",
        "ttl": 300.0,
        "rcode": 0,
        "expires_at": NOW + 300.0
    });

    // ① 直接反序列化（v2 条目 → 3 个 RRset：CNAME(查询名) / CNAME(别名) / A）。
    let e: CacheEntry = serde_json::from_value(legacy.clone()).expect("legacy v2 必须可反序列化");
    assert_eq!(
        e.rrsets.len(),
        3,
        "相邻 (name,rtype) 必须重新分成 3 个 RRset"
    );
    assert!(
        e.rrsets[0].owner.is_empty(),
        "name=null 的 owner 必须是空串"
    );
    assert_eq!(e.rrsets[0].rtype, 5);
    assert_eq!(e.rrsets[1].owner.as_ref(), format!("{tag}-cdn.example"));
    assert_eq!(e.rrsets[2].values.len(), 2);
    assert_eq!(e.flat_answers().len(), 4);
    assert_eq!(e.rule_gen, 0, "缺 rule_gen 必须默认 0（旧文件语义）");
    assert_eq!(e.seq, 0, "seq 是运行时簿记，反序列化必须为 0");

    // ② 作为 v1/v2 恢复记录经 `LruCache::restore` 装入（key 数组 + 绝对 expires_at）。
    let mut rec = legacy;
    rec.as_object_mut().unwrap().insert(
        "key".to_string(),
        serde_json::json!([format!("{tag}.test"), "A"]),
    );
    let lru = LruCache::new(64);
    lru.restore(&[rec], NOW, 0.0);
    let got = lru
        .get_arc(&CacheKey::new(format!("{tag}.test"), "A"), NOW)
        .expect("旧 v2 条目必须恢复并可命中");
    assert_eq!(got.flat_answers().len(), 4);
    assert_eq!(got.rrsets.len(), 3);
    assert_eq!(got.rrsets[2].values.len(), 2);
    assert!(
        Arc::ptr_eq(
            &got.rrsets[2],
            &rrset::intern_rrset(
                &owner,
                1,
                &[
                    Arc::new(ans("192.0.2.1", 300.0, 1, Some(&owner))),
                    Arc::new(ans("192.0.2.2", 300.0, 1, Some(&owner))),
                ]
            )
        ),
        "恢复时重建的 RRset 必须进入全局表（与直接 intern 同一份）"
    );
}

// ============================ 阶段 B-1：字符串级共享（适配 B-2 模型） ============================

/// **阶段 B-1**：不同消息、**不同 RRset**（TTL 不同 ⇒ B-2 不会共享 RRset），只要
/// RDATA 字符串相同，`value`（以及相同 owner 的 `name`）就必须是同一份 `Arc<str>`。
#[test]
fn same_rdata_string_is_shared_across_rrsets() {
    let _g = serial();
    let tag = uniq("strshare");
    let ip = uniq_ip();
    let owner = format!("{tag}.cdn.example");
    let lru = LruCache::new(64);
    let keys: Vec<CacheKey> = (0..3)
        .map(|i| CacheKey::new(format!("{tag}-{i}.test"), "A"))
        .collect();
    // 三条条目的 RRset 都不同（TTL 递增 + 第 3 条带 owner name），但 IP 相同。
    lru.put(
        keys[0].clone(),
        entry(&format!("{tag}-0.test"), &[ans(&ip, 300.0, 1, None)]),
        NOW,
    );
    lru.put(
        keys[1].clone(),
        entry(&format!("{tag}-1.test"), &[ans(&ip, 301.0, 1, None)]),
        NOW,
    );
    lru.put(
        keys[2].clone(),
        entry(
            &format!("{tag}-2.test"),
            &[ans(&ip, 302.0, 1, Some(&owner))],
        ),
        NOW,
    );
    let e0 = lru.get_arc(&keys[0], NOW).expect("命中 0");
    let e1 = lru.get_arc(&keys[1], NOW).expect("命中 1");
    let e2 = lru.get_arc(&keys[2], NOW).expect("命中 2");
    assert!(
        !Arc::ptr_eq(&e0.rrsets[0], &e1.rrsets[0]),
        "TTL 不同 ⇒ RRset 必须不同（隔离出字符串级共享，而不是 B-2 顺带做到）"
    );
    assert!(
        Arc::ptr_eq(&e0.rrsets[0].values[0].value, &e1.rrsets[0].values[0].value),
        "相同 RDATA 字符串必须跨 RRset 共享同一份 Arc<str>"
    );
    assert!(
        Arc::ptr_eq(&e1.rrsets[0].values[0].value, &e2.rrsets[0].values[0].value),
        "第 3 个 RRset 多了 owner name，但 value 仍须共享"
    );
    assert_eq!(&*e0.rrsets[0].values[0].value, ip.as_str());
    // 相同 owner 名也走同一张字符串表（包括 RRset.owner 本身）。
    let owner_arc = rrset::intern_str(&owner);
    assert!(
        Arc::ptr_eq(e2.rrsets[0].values[0].name.as_ref().unwrap(), &owner_arc),
        "name 必须与 intern_str 返回同一份（可被后续条目复用）"
    );
    assert!(
        Arc::ptr_eq(&e2.rrsets[0].owner, &owner_arc),
        "Rrset.owner 必须与 name 指向同一份规范句柄"
    );
}

/// **阶段 B-1**：不同 RDATA 不得共享（内容相等是命中判定的硬条件）。
#[test]
fn different_rdata_strings_are_not_shared() {
    let _g = serial();
    let x = uniq_ip();
    let y = uniq_ip();
    let a = rrset::intern_str(&x);
    let b = rrset::intern_str(&y);
    assert!(!Arc::ptr_eq(&a, &b), "不同字符串不得共享（{x} vs {y}）");

    // 走缓存写路径同样不得误共享。
    let tag = uniq("strdiff");
    let lru = LruCache::new(8);
    let k1 = CacheKey::new(format!("{tag}-x.test"), "A");
    let k2 = CacheKey::new(format!("{tag}-y.test"), "A");
    lru.put(
        k1.clone(),
        entry(&format!("{tag}-x.test"), &[ans(&x, 60.0, 1, None)]),
        NOW,
    );
    lru.put(
        k2.clone(),
        entry(&format!("{tag}-y.test"), &[ans(&y, 60.0, 1, None)]),
        NOW,
    );
    let e1 = lru.get_arc(&k1, NOW).expect("命中 x");
    let e2 = lru.get_arc(&k2, NOW).expect("命中 y");
    assert!(
        !Arc::ptr_eq(&e1.rrsets[0].values[0].value, &e2.rrsets[0].values[0].value),
        "不同 RDATA 不得共享同一份 Arc<str>"
    );
}

/// **阶段 B-1**：字符串弱引用 —— drop 后可被 `sweep_str` 回收（表不延长寿命）。
#[test]
fn string_dead_weak_refs_are_sweepable() {
    let _g = serial();
    rrset::sweep_str();
    let n0 = rrset::stats_str().0;
    let u = uniq("strdrop");
    {
        let arc = rrset::intern_str(&u);
        assert_eq!(
            rrset::stats_str().0,
            n0 + 1,
            "唯一字符串必须新增恰好 1 个表项"
        );
        assert_eq!(Arc::strong_count(&arc), 1, "仅本用例持有强引用");
        drop(arc);
    }
    assert_eq!(
        rrset::stats_str().0,
        n0 + 1,
        "drop 之后、sweep 之前：死引用仍占表项（有界设计的一部分）"
    );
    let removed = rrset::sweep_str();
    assert!(
        removed >= 1,
        "sweep_str 必须能回收死弱引用（removed={removed}）"
    );
    assert_eq!(
        rrset::stats_str().0,
        n0,
        "sweep 之后表项数必须回落到 intern 之前"
    );
}

/// **阶段 B-1**：字符串表**有界**（[`rrset::MAX_INTERNED_STR`]）：填满后不再登记新串
/// （`intern_str` 回退到独立 `Arc`），stats 不越界；全部释放后 sweep 归零。
#[test]
fn string_table_is_bounded() {
    use ebpdns_cache::rrset::MAX_INTERNED_STR;
    let _g = serial();
    rrset::sweep_str();
    assert_eq!(rrset::stats_str().0, 0, "串行化后基线必须为 0");

    let keep: Vec<Arc<str>> = (0..MAX_INTERNED_STR + 1024)
        .map(|i| rrset::intern_str(&format!("b1-bound-{i}-{}", uniq("b"))))
        .collect();
    assert_eq!(
        rrset::stats_str().0,
        MAX_INTERNED_STR,
        "填满（含少量哈希碰撞余量）后表项数必须恰为上限"
    );

    // 表满且全活 ⇒ 新串不登记：两次 intern 得到两个独立实例（有界优先）。
    let overflow = uniq("b1-overflow");
    let a = rrset::intern_str(&overflow);
    let b = rrset::intern_str(&overflow);
    assert!(
        !Arc::ptr_eq(&a, &b),
        "表满时新串不得登记（两次 intern 不共享），否则上界失效"
    );
    assert_eq!(
        rrset::stats_str().0,
        MAX_INTERNED_STR,
        "拒绝登记后表项数不得越界"
    );

    drop(keep);
    let removed = rrset::sweep_str();
    assert_eq!(
        removed, MAX_INTERNED_STR,
        "全部释放后 sweep 必须回收全部表项"
    );
    assert_eq!(rrset::stats_str().0, 0, "sweep 后必须归零");
}

// ============================ 内存/共享率实测探针 ============================

#[cfg(target_os = "linux")]
fn rss_kb() -> u64 {
    // /proc/self/statm 第 2 列 = 常驻页数。
    let s = std::fs::read_to_string("/proc/self/statm").unwrap_or_default();
    let pages: u64 = s
        .split_whitespace()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(0);
    pages * 4 // 4 KiB/页 ⇒ KiB
}

#[cfg(not(target_os = "linux"))]
fn rss_kb() -> u64 {
    0
}

/// **B-2 内存探针**：N 条不同 CNAME 前缀的消息，`shared=true` 时链尾 A RRset 全部
/// 相同（应共享 1 个 `Arc<Rrset>`）；`shared=false` 时每条链尾 A RRset 都不同
/// （对照组）。两种模式**分两次独立进程**跑（RSS 基线才干净）：
///
/// ```text
/// # 共享组：1000 条不同 CNAME 前缀，共享同一个 A RRset
/// RR_B2_MEM_MODE=shared cargo test --release -p ebpdns-cache --test rrset_share_test -- \
///     --ignored --exact mem_probe_1000_shared_rrset_with_cnames --nocapture
/// # 对照组：1000 条全部不共享
/// RR_B2_MEM_MODE=unique cargo test --release -p ebpdns-cache --test rrset_share_test -- \
///     --ignored --exact mem_probe_1000_shared_rrset_with_cnames --nocapture
/// ```
#[test]
#[ignore = "实测探针：RR_B2_MEM_MODE=shared|unique cargo test ... -- --ignored --exact mem_probe_1000_shared_rrset_with_cnames --nocapture"]
fn mem_probe_1000_shared_rrset_with_cnames() {
    const N: usize = 1000;
    let mode = std::env::var("RR_B2_MEM_MODE").unwrap_or_else(|_| "shared".to_string());
    let shared = mode != "unique";
    let _g = serial();
    rrset::sweep();
    rrset::reset_stats();

    let shared_owner = "edge.b2-probe.example";
    let shared_ip = "10.10.0.1";
    let before = rss_kb();
    let cache = LruCache::new(N * 2);
    for i in 0..N {
        let alias = format!("probe{i}.b2-probe.example");
        let owner = if shared {
            shared_owner.to_string()
        } else {
            format!("edge{i}.b2-probe.example")
        };
        let ip = if shared {
            shared_ip.to_string()
        } else {
            format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256)
        };
        let flat = vec![
            ans(&alias, 300.0, 5, None),
            ans(&owner, 300.0, 5, Some(&alias)),
            ans(&ip, 300.0, 1, Some(&owner)),
        ];
        let d = format!("probe{i}.b2-probe.test");
        cache.put(CacheKey::new(d.clone(), "A"), entry(&d, &flat), NOW);
    }
    let after = rss_kb();
    let (interned, hits) = rrset::stats();
    let sample = cache
        .get_arc(&CacheKey::new("probe0.b2-probe.test", "A"), NOW)
        .expect("探针条目必须命中");
    let a_strong = Arc::strong_count(&sample.rrsets[2]);
    let ptr_eq_first_last = {
        let last = cache
            .get_arc(
                &CacheKey::new(format!("probe{}.b2-probe.test", N - 1), "A"),
                NOW,
            )
            .expect("最后一条必须命中");
        Arc::ptr_eq(&sample.rrsets[2], &last.rrsets[2])
    };
    println!(
        "RR_B2_MEM_RESULT mode={mode} entries={N} rss_delta_kb={} rrset_interned={interned} \
         rrset_hits={hits} a_rrset_strong={a_strong} ptr_eq_first_last={ptr_eq_first_last}",
        after as i64 - before as i64
    );
    // 每条消息 3 个 RRset；共享组只有链尾 A RRset 是相同的。
    let shared_sets = if shared { 1 } else { 0 };
    println!(
        "RR_B2_MEM_SUMMARY mode={mode} rrsets_per_entry=3 shared_rrset_kinds={shared_sets} \
         duplicated_a_rrsets={}",
        N - 1
    );
    if shared {
        assert_eq!(
            a_strong, N,
            "共享组：链尾 A RRset 的强引用数必须等于条目数（strong={a_strong}）"
        );
        assert!(ptr_eq_first_last, "共享组：首尾条目的 A RRset 必须 ptr_eq");
        // 每条消息 2 个唯一 CNAME 前缀 RRset + 1 个共享 A RRset ⇒ 表项 = 2N+1。
        assert_eq!(
            interned,
            2 * N + 1,
            "共享组：只有前缀 CNAME 唯一，链尾 A RRset 必须只有 1 个表项"
        );
        assert!(
            hits >= N - 1,
            "共享组：N-1 次链尾 RRset 复用必须计入命中（hits={hits}）"
        );
    } else {
        assert_eq!(a_strong, 1, "对照组：每条条目各自一份 A RRset");
        assert!(!ptr_eq_first_last, "对照组：首尾条目的 A RRset 不得 ptr_eq");
        assert_eq!(
            interned,
            3 * N,
            "对照组：3N 个 RRset 互不相同，不得有任何共享"
        );
    }
    drop(cache);
}
