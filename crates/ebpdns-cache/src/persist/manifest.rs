//! **`cache.manifest`** —— 物理路径就是配置的 `cache_file` 本身（§4.1、§5.2）。
//!
//! 它是**唯一的原子指针**：读方只信任这里列出的快照与 WAL 段。固定头 52 B +
//! 变长路径区 + `8×W` + 尾部 CRC32C。
//!
//! **2.1.46（REV247 B P2-11）**：`snap_bytes` 从 u32 提升到 u64（≥4 GiB 快照不再被
//! 截断）。格式版本 2 → 3；**读方继续接受版本 2**（旧头 48 B、u32 字段），升级时
//! 不会丢已有缓存现场；写方一律写版本 3。

use super::entry_codec::{put_i64, put_u16, put_u32, put_u64, Cur};
use super::{is_safe_leaf, PersistError, Result};

/// magic：`b"EBPC"`。
pub const MAGIC: [u8; 4] = *b"EBPC";
/// 本实现写的版本号。
pub const VERSION: u16 = 3;
/// 2.1.45 及以前写出的版本（只读兼容）。
pub const VERSION_V2: u16 = 2;
/// bit0：本文件由 v1 JSON 迁移而来。
pub const FLAG_MIGRATED_FROM_V1: u16 = 1;
/// bit1：上一次退出是优雅退出（WAL 已 flush）。
pub const FLAG_CLEAN_SHUTDOWN: u16 = 2;
/// 固定头长度（v3）。
pub const HEADER_LEN: usize = 52;
/// v2 固定头长度（只读兼容）。
pub const HEADER_LEN_V2: usize = 48;
/// `wal_count` 的硬上限（§5.2）。
///
/// **2.1.42（P1-3）**：2 → 8。R2 失败后下轮 R1 必须保留 `snapshot_seq` 之后的
/// **全部**段（可能有 3 段：旧快照依赖的前段 + R2 失败遗留段 + 新段）；若上限仍是 2，
/// 只能二选一，必然丢一段。正常 R2 成功后 manifest 仍只引用 1 段。
pub const MAX_WAL_SEGMENTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub flags: u16,
    /// 本 manifest 写入时的 **durable seq**（最后一条已 fsync 的 WAL 记录 seq；
    /// 无 WAL 时 = `snapshot_seq`）。
    pub seq: u64,
    /// 指向快照的 `snapshot_seq`，必须等于文件名后缀。
    pub snapshot_seq: u64,
    /// manifest 写入时刻 epoch ms。
    pub committed_ms: i64,
    /// **2.1.46（REV247 B P2-11）**：u64（旧格式 v2 的 u32 读入后零扩展）。
    pub snap_bytes: u64,
    pub snap_crc32c: u32,
    pub snap_entries: u32,
    /// 相对文件名，如 `ebpdns-cache.json.snap.123`。
    pub snap_path: String,
    /// 按 `base_seq` 升序。
    pub wal_paths: Vec<String>,
    pub wal_base_seq: Vec<u64>,
    /// 列出的 WAL 文件字节数之和（统计/阈值）。
    pub wal_bytes: u64,
}

impl Manifest {
    /// 编码（含尾部 CRC32C）。
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.wal_paths.len() > MAX_WAL_SEGMENTS
            || self.wal_base_seq.len() != self.wal_paths.len()
        {
            return Err(PersistError::BadField("wal_count/长度不匹配"));
        }
        if !is_safe_leaf(&self.snap_path) {
            return Err(PersistError::BadPath("snap_path"));
        }
        for p in &self.wal_paths {
            if !is_safe_leaf(p) {
                return Err(PersistError::BadPath("wal_path"));
            }
        }
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(&MAGIC);
        put_u16(&mut out, VERSION);
        put_u16(&mut out, self.flags);
        put_u64(&mut out, self.seq);
        put_u64(&mut out, self.snapshot_seq);
        put_i64(&mut out, self.committed_ms);
        put_u64(&mut out, self.snap_bytes);
        put_u32(&mut out, self.snap_crc32c);
        put_u32(&mut out, self.snap_entries);
        let s = self.snap_path.as_bytes();
        if s.is_empty() || s.len() > 255 {
            return Err(PersistError::BadField("snap_path_len"));
        }
        put_u16(&mut out, s.len() as u16);
        put_u16(&mut out, self.wal_paths.len() as u16);
        debug_assert_eq!(out.len(), HEADER_LEN);
        out.extend_from_slice(s);
        for p in &self.wal_paths {
            if p.len() > 255 {
                return Err(PersistError::BadField("wal_path_len"));
            }
            put_u16(&mut out, p.len() as u16);
        }
        for p in &self.wal_paths {
            out.extend_from_slice(p.as_bytes());
        }
        for b in &self.wal_base_seq {
            put_u64(&mut out, *b);
        }
        put_u64(&mut out, self.wal_bytes);
        let crc = super::crc32c(&out);
        put_u32(&mut out, crc);
        if out.len() as u64 > super::MANIFEST_MAX_BYTES {
            return Err(PersistError::BadField("manifest 超过 8 KiB"));
        }
        Ok(out)
    }

    /// 解码 + **完整校验**（任一失败 ⇒ manifest 无效，走 §7.4 回退）。
    ///
    /// `base` = `cache_file.file_name()`，用于核对 `snap_path` / `wal_paths` 的前缀与
    /// 十进制后缀（防止被篡改成任意路径）。
    pub fn decode(raw: &[u8], base: &str) -> Result<Self> {
        if raw.len() > super::MANIFEST_MAX_BYTES as usize {
            return Err(PersistError::BadField("manifest 超过 8 KiB"));
        }
        if raw.len() < 61 {
            return Err(PersistError::BadLen {
                expect: 61,
                got: raw.len() as u64,
            });
        }
        if raw[..4] != MAGIC {
            return Err(PersistError::BadMagic("EBPC"));
        }
        // 先校验尾部 CRC，再看字段（否则坏字节可能造出巨大的长度）。
        let body = &raw[..raw.len() - 4];
        let got_crc = u32::from_le_bytes([
            raw[raw.len() - 4],
            raw[raw.len() - 3],
            raw[raw.len() - 2],
            raw[raw.len() - 1],
        ]);
        if super::crc32c(body) != got_crc {
            return Err(PersistError::Crc("manifest"));
        }
        let mut cur = Cur::new(body);
        let _magic = cur.take(4, "magic")?;
        let version = cur.u16()?;
        // **2.1.46（REV247 B P2-11）**：v2（48 B 头 / u32 snap_bytes）只读兼容；
        // v3（52 B 头 / u64）为当前写出版本。`<2` 视为损坏（v1 没有 manifest）。
        let (header_len, legacy) = match version {
            VERSION => (HEADER_LEN, false),
            VERSION_V2 => (HEADER_LEN_V2, true),
            v => return Err(PersistError::UnsupportedVersion(v)),
        };
        let flags = cur.u16()?;
        let seq = cur.u64()?;
        let snapshot_seq = cur.u64()?;
        let committed_ms = cur.i64()?;
        let snap_bytes = if legacy {
            cur.u32()? as u64
        } else {
            cur.u64()?
        };
        let snap_crc32c = cur.u32()?;
        let snap_entries = cur.u32()?;
        let slen = cur.u16()? as usize;
        let w = cur.u16()? as usize;
        if slen == 0 || slen > 255 {
            return Err(PersistError::BadField("snap_path_len"));
        }
        if w > MAX_WAL_SEGMENTS {
            return Err(PersistError::BadField("wal_count > MAX"));
        }
        // 长度必须精确匹配（无尾随字节）：
        // `H + S + 2W + P + 8W + 8`，其中 P = 各 WAL 路径字节数之和，H 随版本为 48/52。
        let head_need = header_len + slen + 2 * w;
        if body.len() < head_need {
            return Err(PersistError::BadLen {
                expect: head_need as u64,
                got: body.len() as u64,
            });
        }
        let snap_b = cur.take(slen, "snap_path")?;
        let snap_path = std::str::from_utf8(snap_b)
            .map_err(|_| PersistError::BadField("snap_path 非 UTF-8"))?
            .to_string();
        let mut lens = Vec::with_capacity(w);
        for _ in 0..w {
            let n = cur.u16()? as usize;
            if n == 0 || n > 255 {
                return Err(PersistError::BadField("wal_path_len"));
            }
            lens.push(n);
        }
        let psum: usize = lens.iter().sum();
        let need = header_len + slen + 2 * w + psum + 8 * w + 8;
        if body.len() != need {
            return Err(PersistError::BadLen {
                expect: need as u64,
                got: body.len() as u64,
            });
        }
        let mut wal_paths = Vec::with_capacity(w);
        for n in lens {
            let b = cur.take(n, "wal_path")?;
            wal_paths.push(
                std::str::from_utf8(b)
                    .map_err(|_| PersistError::BadField("wal_path 非 UTF-8"))?
                    .to_string(),
            );
        }
        let mut wal_base_seq = Vec::with_capacity(w);
        for _ in 0..w {
            wal_base_seq.push(cur.u64()?);
        }
        let wal_bytes = cur.u64()?;
        if cur.remaining() != 0 {
            return Err(PersistError::BadField("manifest 尾部有多余字节"));
        }
        // ---- 路径校验（防篡改）----
        if !is_safe_leaf(&snap_path) {
            return Err(PersistError::BadPath("snap_path"));
        }
        let want_snap_prefix = format!("{base}.snap.");
        let got = snap_path
            .strip_prefix(&want_snap_prefix)
            .ok_or(PersistError::BadPath("snap_path 前缀"))?;
        if parse_seq(got) != Some(snapshot_seq) {
            return Err(PersistError::BadPath("snap_path 后缀 != snapshot_seq"));
        }
        let want_wal_prefix = format!("{base}.wal.");
        for (i, p) in wal_paths.iter().enumerate() {
            if !is_safe_leaf(p) {
                return Err(PersistError::BadPath("wal_path"));
            }
            let got = p
                .strip_prefix(&want_wal_prefix)
                .ok_or(PersistError::BadPath("wal_path 前缀"))?;
            if parse_seq(got) != Some(wal_base_seq[i]) {
                return Err(PersistError::BadPath("wal_path 后缀 != wal_base_seq"));
            }
        }
        // `wal_base_seq` 严格递增。
        for i in 1..wal_base_seq.len() {
            if wal_base_seq[i] <= wal_base_seq[i - 1] {
                return Err(PersistError::BadField("wal_base_seq 非递增"));
            }
        }
        Ok(Manifest {
            flags,
            seq,
            snapshot_seq,
            committed_ms,
            snap_bytes,
            snap_crc32c,
            snap_entries,
            snap_path,
            wal_paths,
            wal_base_seq,
            wal_bytes,
        })
    }

    /// `flags` 里的 bit0（v1 迁移而来）。
    pub fn migrated_from_v1(&self) -> bool {
        self.flags & FLAG_MIGRATED_FROM_V1 != 0
    }
    /// `flags` 里的 bit1（上次优雅退出）。
    pub fn clean_shutdown(&self) -> bool {
        self.flags & FLAG_CLEAN_SHUTDOWN != 0
    }
}

/// 十进制 `u64`（无前导零；`0` 合法）。`parse::<u64>` 接受 `+1`/前导零 ⇒ 必须自己判。
fn parse_seq(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 {
        return None;
    }
    if s.len() > 1 && s.starts_with('0') {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m() -> Manifest {
        Manifest {
            flags: 0,
            seq: 42,
            snapshot_seq: 40,
            committed_ms: 1_700_000_000_123,
            snap_bytes: 4096u64,
            snap_crc32c: 0xDEAD_BEEF,
            snap_entries: 17,
            snap_path: "ebpdns-cache.json.snap.40".into(),
            wal_paths: vec!["ebpdns-cache.json.wal.41".into()],
            wal_base_seq: vec![41],
            wal_bytes: 8192,
        }
    }

    const BASE: &str = "ebpdns-cache.json";

    #[test]
    fn roundtrip_one_wal() {
        let a = m();
        let raw = a.encode().unwrap();
        let b = Manifest::decode(&raw, BASE).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn roundtrip_zero_and_two_wal() {
        let mut a = m();
        a.wal_paths.clear();
        a.wal_base_seq.clear();
        a.wal_bytes = 0;
        let raw = a.encode().unwrap();
        assert_eq!(Manifest::decode(&raw, BASE).unwrap(), a);

        let mut b = m();
        b.wal_paths = vec![
            "ebpdns-cache.json.wal.41".into(),
            "ebpdns-cache.json.wal.90".into(),
        ];
        b.wal_base_seq = vec![41, 90];
        let raw = b.encode().unwrap();
        assert_eq!(Manifest::decode(&raw, BASE).unwrap(), b);
    }

    #[test]
    fn field_boundaries() {
        let mut a = m();
        a.seq = u64::MAX;
        a.committed_ms = i64::MIN;
        a.snap_bytes = u64::MAX;
        a.snap_entries = u32::MAX;
        a.wal_bytes = u64::MAX;
        a.snapshot_seq = 0;
        a.snap_path = format!("{BASE}.snap.0");
        let raw = a.encode().unwrap();
        assert_eq!(Manifest::decode(&raw, BASE).unwrap(), a);
    }

    // >>> PATCH242A P1-3 manifest-segments BEGIN
    /// **2.1.42（P1-3）**：3 段必须被接受（R2 失败后的 R1 现场：旧快照依赖段 +
    /// 遗留段 + 新段）；只有超过 `MAX_WAL_SEGMENTS` 才拒绝。
    #[test]
    fn accepts_three_wal_segments_but_rejects_over_max() {
        let mut a = m();
        a.wal_paths = (1..=3)
            .map(|i| format!("ebpdns-cache.json.wal.{i}"))
            .collect();
        a.wal_base_seq = vec![1, 2, 3];
        let raw = a.encode().expect("3 段是合法 R1 现场");
        assert_eq!(Manifest::decode(&raw, BASE).unwrap(), a);

        let mut over = m();
        over.wal_paths = (1..=super::MAX_WAL_SEGMENTS + 1)
            .map(|i| format!("ebpdns-cache.json.wal.{i}"))
            .collect();
        over.wal_base_seq = (1..=super::MAX_WAL_SEGMENTS as u64 + 1).collect();
        assert!(over.encode().is_err(), "超过上限必须拒绝");
    }
    // <<< PATCH242A P1-3 manifest-segments END

    #[test]
    fn rejects_malicious_paths() {
        let bad = [
            "../etc/passwd",
            "/etc/passwd",
            ".hidden",
            "sub/dir",
            "a\\b",
            "",
            "..",
        ];
        for p in bad {
            let mut a = m();
            a.snap_path = p.to_string();
            assert!(a.encode().is_err(), "应拒绝 snap_path={p}");
        }
    }

    #[test]
    fn rejects_path_not_matching_seq() {
        let mut a = m();
        a.snap_path = "ebpdns-cache.json.snap.39".into(); // snapshot_seq=40
        let raw = a.encode().unwrap();
        assert!(Manifest::decode(&raw, BASE).is_err());
        let mut b = m();
        b.wal_paths = vec!["ebpdns-cache.json.wal.99".into()];
        let raw = b.encode().unwrap();
        assert!(Manifest::decode(&raw, BASE).is_err());
    }

    #[test]
    fn rejects_leading_zero_suffix() {
        let mut a = m();
        a.snapshot_seq = 40;
        a.snap_path = "ebpdns-cache.json.snap.040".into();
        let raw = a.encode().unwrap();
        assert!(Manifest::decode(&raw, BASE).is_err());
    }

    #[test]
    fn rejects_wrong_base() {
        let raw = m().encode().unwrap();
        assert!(Manifest::decode(&raw, "other.json").is_err());
    }

    #[test]
    fn truncation_never_panics_and_never_accepts() {
        let raw = m().encode().unwrap();
        for cut in 0..raw.len() {
            let got = Manifest::decode(&raw[..cut], BASE);
            assert!(got.is_err(), "截断到 {cut} 竟然被接受");
        }
        // 完整时正常
        assert!(Manifest::decode(&raw, BASE).is_ok());
    }

    #[test]
    fn bitflips_detected_by_crc() {
        let raw = m().encode().unwrap();
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut v = raw.clone();
                v[i] ^= 1 << bit;
                // 只要求“不 panic”，且绝大多数被 CRC 拒（尾 4 字节是 CRC 自身，
                // 翻转它同样会被拒）。
                let r = Manifest::decode(&v, BASE);
                assert!(r.is_err(), "位翻转 i={i} bit={bit} 未被检出");
            }
        }
    }

    #[test]
    fn unsupported_version_reported() {
        let mut raw = m().encode().unwrap();
        // 手工改 version 字段并重算 CRC（模拟“未来版本”）。
        raw[4..6].copy_from_slice(&4u16.to_le_bytes());
        let n = raw.len();
        let crc = super::super::crc32c(&raw[..n - 4]);
        raw[n - 4..].copy_from_slice(&crc.to_le_bytes());
        match Manifest::decode(&raw, BASE) {
            Err(PersistError::UnsupportedVersion(4)) => {}
            other => panic!("期望 UnsupportedVersion(4)，得到 {other:?}"),
        }
    }

    /// **2.1.46（REV247 B P2-11）**：v2 manifest（48 B 头 / u32 `snap_bytes`）
    /// 必须继续可读；v3 写出的 u64 值必须原样往返（含 `> u32::MAX`）。
    #[test]
    fn v2_manifest_is_read_compatibly_and_v3_preserves_u64_snap_bytes() {
        // 手工构造 v2（2.1.45 及以前的字节布局）。
        let a = m();
        let mut raw = Vec::new();
        raw.extend_from_slice(&MAGIC);
        put_u16(&mut raw, VERSION_V2);
        put_u16(&mut raw, a.flags);
        put_u64(&mut raw, a.seq);
        put_u64(&mut raw, a.snapshot_seq);
        put_i64(&mut raw, a.committed_ms);
        put_u32(&mut raw, a.snap_bytes as u32);
        put_u32(&mut raw, a.snap_crc32c);
        put_u32(&mut raw, a.snap_entries);
        let sp = a.snap_path.as_bytes();
        put_u16(&mut raw, sp.len() as u16);
        put_u16(&mut raw, a.wal_paths.len() as u16);
        raw.extend_from_slice(sp);
        for p in &a.wal_paths {
            put_u16(&mut raw, p.len() as u16);
        }
        for p in &a.wal_paths {
            raw.extend_from_slice(p.as_bytes());
        }
        for b in &a.wal_base_seq {
            put_u64(&mut raw, *b);
        }
        put_u64(&mut raw, a.wal_bytes);
        let crc = super::super::crc32c(&raw);
        put_u32(&mut raw, crc);
        assert_eq!(
            raw.len(),
            HEADER_LEN_V2 + sp.len() + 2 + a.wal_paths[0].len() + 8 + 8 + 4
        );
        assert_eq!(Manifest::decode(&raw, BASE).unwrap(), a, "v2 必须只读兼容");

        // v3：4 GiB 以上不再截断。
        let mut big = m();
        big.snap_bytes = u32::MAX as u64 + 123;
        let round = Manifest::decode(&big.encode().unwrap(), BASE).unwrap();
        assert_eq!(round.snap_bytes, big.snap_bytes);
        assert!(round.snap_bytes > u32::MAX as u64);
    }

    #[test]
    fn too_large_rejected() {
        let mut raw = vec![0u8; (super::super::MANIFEST_MAX_BYTES + 1) as usize];
        raw[..4].copy_from_slice(&MAGIC);
        assert!(Manifest::decode(&raw, BASE).is_err());
    }

    /// **格式不变量（审计要求，必然进 CI）**：manifest **每一个字节 × 每一个 bit**
    /// 的翻转都必须被检出（尾部 CRC 覆盖 CRC 字段之前的全部字节；CRC 字段自身被翻转
    /// 同样导致不匹配），且**不 panic、不产生有效 manifest**。
    #[test]
    fn every_single_bit_flip_is_rejected() {
        for m in [m(), {
            let mut b = m();
            b.wal_paths.clear();
            b.wal_base_seq.clear();
            b.wal_bytes = 0;
            b
        }] {
            let raw = m.encode().unwrap();
            for i in 0..raw.len() {
                for bit in 0..8u8 {
                    let mut v = raw.clone();
                    v[i] ^= 1 << bit;
                    match Manifest::decode(&v, BASE) {
                        Err(_) => {}
                        Ok(ok) => panic!(
                            "byte {i} bit {bit} 翻转未被检出（解出 snapshot_seq={}）",
                            ok.snapshot_seq
                        ),
                    }
                }
            }
        }
    }

    /// **覆盖域自证**：manifest 只有**末尾 4 B**（CRC 字段自身）不在覆盖域内 ——
    /// 其前每一个字节都在 `crc32c(bytes[0..len-4])` 的作用域里（因此任意单 bit
    /// 翻转必被检出，见上一个用例）。这里把“字节 -> 字段”的对应关系也钉死，
    /// 避免未来新增字段时忘记它必须在尾部 CRC 之前。
    #[test]
    fn crc_domain_covers_every_byte_before_the_crc_field() {
        for a in [m(), {
            let mut b = m();
            b.wal_paths.push("ebpdns-cache.json.wal.90".into());
            b.wal_base_seq.push(90);
            b
        }] {
            let raw = a.encode().unwrap();
            let body = &raw[..raw.len() - 4];
            let got = u32::from_le_bytes(raw[raw.len() - 4..].try_into().unwrap());
            assert_eq!(super::super::crc32c(body), got);
            // 未被覆盖的字节数 = 4（只有 CRC 字段自身）。
            assert_eq!(raw.len() - body.len(), 4);
            // 固定头 52 B 的字段边界（v3）：magic 0..4 / version 4..6 / flags 6..8 /
            // seq 8..16 / snapshot_seq 16..24 / committed_ms 24..32 / snap_bytes 32..40 /
            // snap_crc32c 40..44 / snap_entries 44..48 / snap_path_len 48..50 /
            // wal_count 50..52 —— 全部 < 52，必然在覆盖域内。
            assert_eq!(HEADER_LEN, 52);
        }
    }

    #[test]
    fn header_len_constant_matches_encode() {
        let raw = m().encode().unwrap();
        assert_eq!(&raw[..4], &MAGIC);
        assert_eq!(HEADER_LEN, 52);
        // 头长度由 decode 的精确长度校验兜底：`body.len() == 52 + S + 2W + P + 8W + 8`。
        let decoded = Manifest::decode(&raw, BASE).unwrap();
        assert_eq!(decoded.snap_path.len(), 25); // "ebpdns-cache.json.snap.40"
    }
}
