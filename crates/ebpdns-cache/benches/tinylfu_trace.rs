//! A4 独立基准：tinylfu 三段比例 / 晋升闸门的**固定 trace 回放**。
//!
//! 目的：在**同一份实现**上，用可复现的数据决定"1/40/60 → 5/35/60 + 晋升水位"是否值得合并。
//! 本文件不参与 `cargo test`（`[[bench]] test = false`），也不触碰既有测试的任何断言。
//!
//! 运行（必须带 feature，否则 bench 目标被 `required-features` 跳过）：
//! ```text
//! cargo bench -p ebpdns-cache --features bench-policy --bench tinylfu_trace
//! ```
//!
//! 方法学
//! ------
//! - **时长**：两条 trace 各 1_000_000 次访问，xorshift64 固定种子 → 每次运行逐位相同。
//! - **trace-A `three_tier`（需求指定分布）**：80% 命中 1024 个热点域名（均匀）+
//!   15% 命中 65536 个中频域名（**二次方偏斜**，头部有真实重复）+ 5% 长尾扫描
//!   （每次一个新域名，只访问一次）。中频工作集 65536+ 远大于容量 → 必须有频率准入
//!   才能挡住一次性条目，是本轮 A4 的判别区。
//! - **trace-B `hot_scan`（"热点挺过冷插入"对抗场景）**：80% 命中 2048 个热点域名 +
//!   20% 长尾扫描（唯一域名）。只考验"扫描流会不会把热点挤出去"。
//! - **访问模型**：与生产一致 —— 先 `get_arc`，**未命中才** `put`（不是每次访问都写）。
//! - **TTL = 1e9 秒（永不过期）**：把"容量/准入"与"TTL 淘汰"分离，使结论只反映策略差异；
//!   `now` 恒为 `T0`。
//! - **驱逐次数**：因每次 put 都是"刚 miss 过的全新键"且无 TTL 过期，故
//!   `evictions = puts - final_len`（精确，不依赖埋点）。
//! - **耗时**：`ns/get` = 逐次 `Instant` 累加 / 命中+未命中总次数（含 `Instant::now()`
//!   自身约 20ns 开销，仅用于**变体之间横向对比**）；`ns/access` = 整轮回放墙钟 / N。
//! - **判定口径**（脚本会打印 `VERDICT` 行）：候选方案要在**两条 trace 上都不回退**
//!   （`hit >= baseline - 0.10pp`）且**至少一条 trace 提升 >= 0.50pp**，并且
//!   `ns/get` 不超过基线的 1.15 倍，才判"合"；否则判"不合"。

use ebpdns_cache::{CacheEntry, CacheKey, DnsCache, TinyLfuCache};
use std::time::Instant;

const N: usize = 1_000_000;
const T0: f64 = 1_000.0;
/// 永不过期：把容量/准入策略与 TTL 淘汰彻底分离。
const TTL: f64 = 1e9;

/// xorshift64：确定性、无依赖、够快。
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    #[inline]
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    #[inline]
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const TAG_HOT: u32 = 0;
const TAG_MID: u32 = 1;
const TAG_TAIL: u32 = 2;
const IDX_MASK: u32 = 0x0FFF_FFFF;

#[inline]
fn enc(tag: u32, idx: usize) -> u32 {
    (tag << 28) | (idx as u32 & IDX_MASK)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TraceKind {
    ThreeTier,
    HotScan,
}

impl TraceKind {
    fn name(self) -> &'static str {
        match self {
            TraceKind::ThreeTier => "three_tier(80/15/5)",
            TraceKind::HotScan => "hot_scan(80/0/20)",
        }
    }
}

/// 固定 trace：`Vec<u32>` 编码的访问序列 + 热点/中频键池（长尾键按需生成）。
struct Trace {
    kind: TraceKind,
    hot: Vec<CacheKey>,
    mid: Vec<CacheKey>,
    seq: Vec<u32>,
}

const HOT_THREE_TIER: usize = 1024;
const MID_THREE_TIER: usize = 65_536;
const HOT_SCAN: usize = 2_048;

fn build(kind: TraceKind) -> Trace {
    let mut rng = Rng::new(0xA4_2021_11);
    let (n_hot, n_mid) = match kind {
        TraceKind::ThreeTier => (HOT_THREE_TIER, MID_THREE_TIER),
        TraceKind::HotScan => (HOT_SCAN, 0),
    };
    let hot: Vec<CacheKey> = (0..n_hot)
        .map(|i| CacheKey::new(format!("h{i}.hot.test"), "A"))
        .collect();
    let mid: Vec<CacheKey> = (0..n_mid)
        .map(|i| CacheKey::new(format!("m{i}.mid.test"), "A"))
        .collect();
    let mut seq = Vec::with_capacity(N);
    let mut tail = 0usize;
    for _ in 0..N {
        let r = rng.below(1000);
        match kind {
            TraceKind::ThreeTier => {
                if r < 800 {
                    seq.push(enc(TAG_HOT, rng.below(n_hot)));
                } else if r < 950 {
                    // 二次方偏斜：把均匀索引压向头部（尾部仍有少量重复），
                    // 中频段因此有真实的热/冷分层，而不是纯 uniform 噪声。
                    let u = rng.below(n_mid);
                    let idx = (u * u) / n_mid.max(1);
                    seq.push(enc(TAG_MID, idx));
                } else {
                    seq.push(enc(TAG_TAIL, tail));
                    tail += 1;
                }
            }
            TraceKind::HotScan => {
                if r < 800 {
                    seq.push(enc(TAG_HOT, rng.below(n_hot)));
                } else {
                    seq.push(enc(TAG_TAIL, tail));
                    tail += 1;
                }
            }
        }
    }
    Trace {
        kind,
        hot,
        mid,
        seq,
    }
}

#[derive(Clone, Copy)]
struct Policy {
    win_pct: usize,
    prob_pct: usize,
    promote_min_freq: u8,
    restrict: bool,
}

impl Policy {
    fn label(self) -> String {
        let mut s = format!("{}/{}", self.win_pct, self.prob_pct);
        if self.promote_min_freq > 0 {
            s.push_str(&format!("+W{}", self.promote_min_freq));
        }
        if self.restrict {
            s.push_str("+R");
        }
        s
    }
}

struct Metrics {
    label: String,
    hits: u64,
    misses: u64,
    win: u64,
    prob: u64,
    prot: u64,
    len: u64,
    evictions: u64,
    ns_per_get: f64,
    ns_per_access: f64,
}

impl Metrics {
    fn hit_pct(&self) -> f64 {
        self.hits as f64 / (self.hits + self.misses) as f64 * 100.0
    }
}

fn replay(trace: &Trace, cap: usize, pol: Policy) -> Metrics {
    let c = TinyLfuCache::new_with_policy(
        cap,
        pol.win_pct,
        pol.prob_pct,
        pol.promote_min_freq,
        pol.restrict,
    );
    let mut hits = 0u64;
    let mut puts = 0u64;
    let mut get_ns = 0u128;
    let wall = Instant::now();
    for code in &trace.seq {
        let tag = code >> 28;
        // 长尾键按需生成（只访问一次，不预分配）；热点/中频直接用池内键。
        let owned;
        let key: &CacheKey = match tag {
            TAG_HOT => &trace.hot[(code & IDX_MASK) as usize],
            TAG_MID => &trace.mid[(code & IDX_MASK) as usize],
            _ => {
                owned = CacheKey::new(format!("s{}.scan.test", code & IDX_MASK), "A");
                &owned
            }
        };
        let t = Instant::now();
        let hit = c.get_arc(key, T0).is_some();
        get_ns += t.elapsed().as_nanos();
        if hit {
            hits += 1;
        } else {
            puts += 1;
            let e = CacheEntry::new(&key.domain, &key.qtype, TTL, T0);
            c.put(key.clone(), e, T0);
        }
    }
    let ns_per_access = wall.elapsed().as_nanos() as f64 / trace.seq.len() as f64;
    let s = c.summary();
    let len = s["used"].as_u64().unwrap_or(0);
    Metrics {
        label: pol.label(),
        hits,
        misses: puts,
        win: s["window"].as_u64().unwrap_or(0),
        prob: s["probation"].as_u64().unwrap_or(0),
        prot: s["protected"].as_u64().unwrap_or(0),
        len,
        evictions: puts.saturating_sub(len),
        ns_per_get: get_ns as f64 / trace.seq.len() as f64,
        ns_per_access,
    }
}

fn head(title: &str) {
    println!("\n### {title}");
}

fn table(rows: &[Metrics], cap: usize) {
    println!(
        "| 策略 | hit% | misses | window | probation | protected | 占用% | 驱逐 | ns/get | ns/access |"
    );
    println!("|---|---|---|---|---|---|---|---|---|---|");
    for m in rows {
        println!(
            "| {} | {:.2} | {} | {} | {} | {} | {:.1} | {} | {:.0} | {:.0} |",
            m.label,
            m.hit_pct(),
            m.misses,
            m.win,
            m.prob,
            m.prot,
            m.len as f64 / cap as f64 * 100.0,
            m.evictions,
            m.ns_per_get,
            m.ns_per_access,
        );
    }
}

fn cap_curve(trace: &Trace, pol: Policy, caps: &[usize]) {
    println!("| cache_size | hit% | 驱逐 | 占用% | ns/get |");
    println!("|---|---|---|---|---|");
    for &cap in caps {
        let m = replay(trace, cap, pol);
        println!(
            "| {} | {:.2} | {} | {:.1} | {:.0} |",
            cap,
            m.hit_pct(),
            m.evictions,
            m.len as f64 / cap as f64 * 100.0,
            m.ns_per_get
        );
    }
}

fn main() {
    println!("# ebpdns tinylfu A4 独立基准（固定 trace 回放，N={N} 次访问/条）");
    println!(
        "# 列含义：hit% = get 命中率；window/probation/protected = 终态三段占用（条）；\
         驱逐 = puts - final_len（无 TTL 过期，精确）；ns/get = 逐次计时均值（含 ~20ns 计时开销）"
    );

    let t_three = build(TraceKind::ThreeTier);
    let t_scan = build(TraceKind::HotScan);

    // 确定性自检：同一策略跑两遍，命中数必须逐位相同。
    for (name, tr) in [
        (t_three.kind.name(), &t_three),
        (t_scan.kind.name(), &t_scan),
    ] {
        let a = replay(
            tr,
            16_384,
            Policy {
                win_pct: 1,
                prob_pct: 40,
                promote_min_freq: 0,
                restrict: false,
            },
        );
        let b = replay(
            tr,
            16_384,
            Policy {
                win_pct: 1,
                prob_pct: 40,
                promote_min_freq: 0,
                restrict: false,
            },
        );
        assert_eq!(a.hits, b.hits, "trace {name} 非确定性");
        println!(
            "# 确定性自检 {name}: hits={} misses={}（两遍一致）",
            a.hits, a.misses
        );
    }

    let variants = [
        (
            Policy {
                win_pct: 1,
                prob_pct: 40,
                promote_min_freq: 0,
                restrict: false,
            },
            "基线 1/40/60",
        ),
        (
            Policy {
                win_pct: 5,
                prob_pct: 35,
                promote_min_freq: 0,
                restrict: false,
            },
            "比例 5/35/60",
        ),
        (
            Policy {
                win_pct: 5,
                prob_pct: 35,
                promote_min_freq: 2,
                restrict: false,
            },
            "5/35/60 + 水位2",
        ),
        (
            Policy {
                win_pct: 5,
                prob_pct: 35,
                promote_min_freq: 3,
                restrict: false,
            },
            "5/35/60 + 水位3",
        ),
        (
            Policy {
                win_pct: 5,
                prob_pct: 35,
                promote_min_freq: 4,
                restrict: false,
            },
            "5/35/60 + 水位4",
        ),
        (
            Policy {
                win_pct: 1,
                prob_pct: 40,
                promote_min_freq: 3,
                restrict: false,
            },
            "1/40/60 + 水位3",
        ),
        (
            Policy {
                win_pct: 5,
                prob_pct: 35,
                promote_min_freq: 3,
                restrict: true,
            },
            "5/35/60 + 水位3+受限",
        ),
        (
            Policy {
                win_pct: 1,
                prob_pct: 40,
                promote_min_freq: 3,
                restrict: true,
            },
            "1/40/60 + 水位3+受限",
        ),
    ];

    let mut base: [f64; 2] = [0.0; 2];
    let mut best: [f64; 2] = [0.0; 2];
    let mut best_label = [String::from("<none>"), String::from("<none>")];

    for (i, (name, tr)) in [
        (t_three.kind.name(), &t_three),
        (t_scan.kind.name(), &t_scan),
    ]
    .into_iter()
    .enumerate()
    {
        head(&format!("trace {name} @ cache_size=16384"));
        let rows: Vec<Metrics> = variants
            .iter()
            .map(|(p, _)| replay(tr, 16_384, *p))
            .collect();
        base[i] = rows[0].hit_pct();
        let base_ns = rows[0].ns_per_get;
        table(&rows, 16_384);
        // 逐候选与基线对比
        println!();
        println!("| 候选 | Δhit(pp) | Δ驱逐 | Δns/get | 判定 |");
        println!("|---|---|---|---|---|");
        for (row, (_, label)) in rows.iter().zip(variants.iter()) {
            let d = row.hit_pct() - base[i];
            let verdict = if d >= 0.50 && row.ns_per_get <= base_ns * 1.15 {
                "improve"
            } else if d <= -0.10 {
                "regress"
            } else {
                "neutral"
            };
            println!(
                "| {} | {:+.2} | {:+} | {:+.0} | {} |",
                label,
                d,
                row.evictions as i64 - rows[0].evictions as i64,
                row.ns_per_get - base_ns,
                verdict
            );
        }
        // 本 trace 的最佳候选（hit 优先，同 hit 取更快的）
        best[i] = rows[0].hit_pct();
        best_label[i] = variants[0].1.to_string();
        for (row, (_, label)) in rows.iter().zip(variants.iter()) {
            if row.hit_pct() > best[i] + 1e-12 {
                best[i] = row.hit_pct();
                best_label[i] = label.to_string();
            }
        }
        println!();
    }

    head("容量-命中率曲线（基线 1/40/60；回答\"16384 是否已受容量限制\"）");
    println!("trace {}:", t_three.kind.name());
    cap_curve(
        &t_three,
        Policy {
            win_pct: 1,
            prob_pct: 40,
            promote_min_freq: 0,
            restrict: false,
        },
        &[2_048, 4_096, 8_192, 16_384, 32_768, 65_536, 131_072],
    );
    println!("\ntrace {}:", t_scan.kind.name());
    cap_curve(
        &t_scan,
        Policy {
            win_pct: 1,
            prob_pct: 40,
            promote_min_freq: 0,
            restrict: false,
        },
        &[2_048, 4_096, 8_192, 16_384, 32_768, 65_536, 131_072],
    );

    head("VERDICT");
    println!(
        "best 命中率 = {:.2}% (three_tier, {}) / {:.2}% (hot_scan, {})；基线 = {:.2}% / {:.2}%",
        best[0], best_label[0], best[1], best_label[1], base[0], base[1]
    );
    println!(
        "Δbest = {:+.2}pp / {:+.2}pp",
        best[0] - base[0],
        best[1] - base[1]
    );
    println!(
        "# 判定规则：两条 trace 都不回退(< -0.10pp) 且至少一条 +>=0.50pp 且 ns/get <= 1.15x 基线 → 合"
    );
}
