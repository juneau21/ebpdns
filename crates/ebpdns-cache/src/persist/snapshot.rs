//! **`cache.snap.<seq>`** —— 二进制快照（§5.3）。
//!
//! ```text
//! 64 B 头（magic "EBPCSNP2" / version / header_len=64 / snapshot_seq / created_ms /
//!        entry_count / record_bytes / header_crc32c）
//! entry_count × 记录：u32 payload_len | u8 rec_type=1 | u8 flags | u16 reserved |
//!                     payload（u64 entry_seq ++ EntryBody）| u32 crc32c
//! 40 B 尾（magic "EBPCEOF2" / entry_count / snapshot_seq / record_bytes /
//!        body_crc32c / footer_crc32c）
//! ```
//!
//! **CRC 覆盖域（2.1.29 实施裁决，审计要求“头区任意单字节翻转必被检出”）**：
//! * `header_crc32c` 覆盖 **0..56 ++ 60..64**（头区除 CRC 字段自身之外的**每一个字节**，
//!   含 `reserved2`）—— 设计文档 §5.3.1 原写“覆盖 0..56”，会留下一个
//!   “翻转 4 字节不可检出”的保留区；本实现把 `reserved2` 纳入覆盖域，并额外约束
//!   **`reserved2` 必须为 0，非 0 即判该快照损坏**；
//! * `footer_crc32c` 覆盖 **0..36**（尾区除 CRC 字段自身的每一个字节）；
//! * 每条记录的 `crc32c` 覆盖**记录起点 .. payload 末尾**（含记录头）。
//!
//! 因此：头区/尾区/记录区**任何单字节翻转都会被检出**（单测
//! `header_any_single_bit_flip_is_rejected` 逐字节 × 逐 bit 扫描）。
//!
//! **不存 `remaining`**（读时现算）；**只收录 `entry.seq <= snapshot_seq` 且未过期**的条目
//! —— 过滤由调用方在迭代时做（§6.3.4 的一致性证明依赖它，不可省）。

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::entry_codec::{put_i64, put_u16, put_u32, put_u64, EntryBody};
use super::{crc32c, is_safe_leaf, PersistError, Result, MAX_RECORD_BYTES};
use crate::CacheKey;

pub const SNAP_MAGIC: [u8; 8] = *b"EBPCSNP2";
pub const FOOT_MAGIC: [u8; 8] = *b"EBPCEOF2";
pub const VERSION: u16 = 2;
pub const HEADER_LEN: usize = 64;
pub const FOOTER_LEN: usize = 40;
/// 记录头 8 B + 记录尾 CRC 4 B。
pub const REC_OVERHEAD: u64 = 12;
const REC_TYPE_ENTRY: u8 = 1;

/// 写完一份快照后的元数据（写 manifest 用）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SnapshotMeta {
    pub snapshot_seq: u64,
    pub entry_count: u32,
    pub file_len: u64,
    pub body_crc32c: u32,
}

fn header_bytes(
    snapshot_seq: u64,
    created_ms: i64,
    entry_count: u32,
    record_bytes: u64,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(&SNAP_MAGIC);
    put_u16(&mut h, VERSION);
    put_u16(&mut h, 0); // flags（保留 0）
    put_u32(&mut h, HEADER_LEN as u32);
    put_u64(&mut h, snapshot_seq);
    put_i64(&mut h, created_ms);
    put_u32(&mut h, entry_count);
    put_u32(&mut h, 0); // reserved0
    put_u64(&mut h, record_bytes);
    put_u64(&mut h, 0); // reserved1
    debug_assert_eq!(h.len(), 56);
    put_u32(&mut h, 0); // header_crc32c 占位（最后回填，**不覆盖自身**）
    put_u32(&mut h, 0); // reserved2（必须为 0）
    debug_assert_eq!(h.len(), HEADER_LEN);
    // **覆盖域 = 头区除 CRC 字段自身的每一个字节**（0..56 ++ 60..64）。
    //
    // 设计文档 §5.3.1 写的是“覆盖 0..56”，那样 `reserved2`（60..64）就不在任何
    // CRC 域内 —— 一个“翻转 4 字节不可检出”的保留区会被后来者当成“可放自由字段的洞”。
    // 2.1.29 实施裁决（审计要求）：**头区任意单字节翻转必被检出**，因此把 `reserved2`
    // 纳入覆盖域，并额外约束“必须为 0，非 0 即判损坏”。
    let crc = {
        let mut v = Vec::with_capacity(60);
        v.extend_from_slice(&h[..56]);
        v.extend_from_slice(&h[60..HEADER_LEN]);
        crc32c(&v)
    };
    h[56..60].copy_from_slice(&crc.to_le_bytes());
    h
}

fn footer_bytes(entry_count: u32, snapshot_seq: u64, record_bytes: u64, body_crc: u32) -> Vec<u8> {
    let mut f = Vec::with_capacity(FOOTER_LEN);
    f.extend_from_slice(&FOOT_MAGIC);
    put_u64(&mut f, entry_count as u64);
    put_u64(&mut f, snapshot_seq);
    put_u64(&mut f, record_bytes);
    put_u32(&mut f, body_crc);
    // 尾布局：magic(8) + entry_count(8) + snapshot_seq(8) + record_bytes(8) + body_crc(4)
    //         = 36 B，footer_crc32c 覆盖这 36 B，再 4 B 自身 ⇒ 共 40 B。
    debug_assert_eq!(f.len(), 36);
    let crc = crc32c(&f);
    put_u32(&mut f, crc); // footer_crc32c：覆盖 0..36
    debug_assert_eq!(f.len(), FOOTER_LEN);
    f
}

// ---------------- 写 ----------------

/// 快照写入器（**只写自己的 `.tmp`**，由 actor 负责 rename 与 manifest 切换）。
pub struct SnapshotWriter {
    path: std::path::PathBuf,
    w: BufWriter<File>,
    snapshot_seq: u64,
    created_ms: i64,
    entry_count: u32,
    record_bytes: u64,
    body_crc: u32,
    finished: bool,
}

impl SnapshotWriter {
    /// 创建 `<path>`（调用方传的是 `.tmp` 路径）并写入 64 B 头占位。
    pub fn create(path: &Path, snapshot_seq: u64, created_ms: i64) -> Result<Self> {
        let f = File::create(path)?;
        let mut w = BufWriter::with_capacity(256 * 1024, f);
        w.write_all(&header_bytes(snapshot_seq, created_ms, 0, 0))?;
        Ok(Self {
            path: path.to_path_buf(),
            w,
            snapshot_seq,
            created_ms,
            entry_count: 0,
            record_bytes: 0,
            body_crc: !0u32,
            finished: false,
        })
    }

    /// 追加一条记录（`entry_seq` 在前，其余是共用的 `EntryBody`）。
    pub fn push(&mut self, entry_seq: u64, body: &EntryBody) -> Result<()> {
        let mut payload = Vec::with_capacity(128);
        put_u64(&mut payload, entry_seq);
        body.encode(&mut payload)?;
        if payload.len() > MAX_RECORD_BYTES as usize {
            return Err(PersistError::BadField("快照记录超过 1 MiB"));
        }
        let mut rec = Vec::with_capacity(12 + payload.len());
        put_u32(&mut rec, payload.len() as u32);
        rec.push(REC_TYPE_ENTRY);
        rec.push(0); // flags
        put_u16(&mut rec, 0); // reserved
        rec.extend_from_slice(&payload);
        let crc = crc32c(&rec);
        put_u32(&mut rec, crc);
        self.body_crc = super::crc32c_update(self.body_crc, &rec);
        self.record_bytes += rec.len() as u64;
        self.entry_count = self.entry_count.saturating_add(1);
        self.w.write_all(&rec)?;
        Ok(())
    }

    /// 收尾：回填头、写尾、`fsync`。返回元数据。
    ///
    /// **不 rename** —— rename 由调用方在 fsync 之后做（§6.3.2）。
    pub fn finish(mut self) -> Result<SnapshotMeta> {
        let body_crc = super::crc32c_finalize(self.body_crc);
        self.w.write_all(&footer_bytes(
            self.entry_count,
            self.snapshot_seq,
            self.record_bytes,
            body_crc,
        ))?;
        self.w.flush()?;
        // 回到文件头重写（flush 之后缓冲区为空，seek 后写会落到偏移 0）。
        self.w.get_mut().seek(SeekFrom::Start(0))?;
        let h = header_bytes(
            self.snapshot_seq,
            self.created_ms,
            self.entry_count,
            self.record_bytes,
        );
        self.w.write_all(&h)?;
        self.w.flush()?;
        let w = self.w;
        let file = w
            .into_inner()
            .map_err(|e| PersistError::Io(e.into_error()))?;
        let len = file.metadata()?.len();
        file.sync_all()?;
        self.finished = true;
        Ok(SnapshotMeta {
            snapshot_seq: self.snapshot_seq,
            entry_count: self.entry_count,
            file_len: len,
            body_crc32c: body_crc,
        })
    }

    /// 放弃（删掉 `.tmp`；best-effort）。
    pub fn abort(self) {
        if !self.finished {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ---------------- 读 ----------------

/// 快照读取器（流式；**不**建整表 `Value`，也不把整文件读成文本）。
pub struct SnapshotReader {
    path: std::path::PathBuf,
    file_len: u64,
    snapshot_seq: u64,
    entry_count: u32,
    record_bytes: u64,
    body_crc: u32,
}

impl SnapshotReader {
    /// 打开并校验头/尾/长度（**不**扫描记录 —— 那是 [`SnapshotReader::for_each`]）。
    pub fn open(path: &Path) -> Result<Self> {
        let f = File::open(path)?;
        let file_len = f.metadata()?.len();
        if file_len < (HEADER_LEN + FOOTER_LEN) as u64 {
            return Err(PersistError::BadLen {
                expect: HEADER_LEN as u64 + FOOTER_LEN as u64,
                got: file_len,
            });
        }
        let mut h = [0u8; HEADER_LEN];
        let mut r = BufReader::new(f);
        r.read_exact(&mut h)?;
        if h[..8] != SNAP_MAGIC {
            return Err(PersistError::BadMagic("EBPCSNP2"));
        }
        let version = u16::from_le_bytes([h[8], h[9]]);
        if version != VERSION {
            return Err(PersistError::UnsupportedVersion(version));
        }
        let header_len = u32::from_le_bytes([h[12], h[13], h[14], h[15]]);
        if header_len as usize != HEADER_LEN {
            return Err(PersistError::BadField("header_len"));
        }
        // `reserved2`（60..64）**必须为 0**：非 0 即判该快照损坏（不只是 CRC 兜底）。
        let reserved2 = u32::from_le_bytes([h[60], h[61], h[62], h[63]]);
        if reserved2 != 0 {
            return Err(PersistError::BadField("reserved2 != 0"));
        }
        let hdr_crc = u32::from_le_bytes([h[56], h[57], h[58], h[59]]);
        // 覆盖域 = 0..56 ++ 60..64（**头区除 CRC 字段自身之外的全部字节**）。
        let crc_ok = {
            let mut v = Vec::with_capacity(60);
            v.extend_from_slice(&h[..56]);
            v.extend_from_slice(&h[60..HEADER_LEN]);
            crc32c(&v) == hdr_crc
        };
        if !crc_ok {
            return Err(PersistError::Crc("snapshot header"));
        }
        let snapshot_seq = u64::from_le_bytes(h[16..24].try_into().unwrap());
        let entry_count = u32::from_le_bytes([h[32], h[33], h[34], h[35]]);
        let record_bytes = u64::from_le_bytes(h[40..48].try_into().unwrap());
        // 长度必须精确：64 + record_bytes + 40。
        let expect = HEADER_LEN as u64 + record_bytes + FOOTER_LEN as u64;
        if file_len != expect {
            return Err(PersistError::BadLen {
                expect,
                got: file_len,
            });
        }
        // `entry_count <= (file_len - 104) / 12`：防坏头导致超大 `with_capacity`。
        if entry_count as u64 > (file_len - 104) / REC_OVERHEAD {
            return Err(PersistError::BadField("entry_count 与文件长度不符"));
        }
        // 读尾。
        let mut foot = [0u8; FOOTER_LEN];
        r.seek(SeekFrom::Start(file_len - FOOTER_LEN as u64))?;
        r.read_exact(&mut foot)?;
        if foot[..8] != FOOT_MAGIC {
            return Err(PersistError::BadMagic("EBPCEOF2"));
        }
        let f_crc = u32::from_le_bytes([foot[36], foot[37], foot[38], foot[39]]);
        if crc32c(&foot[..36]) != f_crc {
            return Err(PersistError::Crc("snapshot footer"));
        }
        let f_count = u64::from_le_bytes(foot[8..16].try_into().unwrap());
        let f_seq = u64::from_le_bytes(foot[16..24].try_into().unwrap());
        let f_bytes = u64::from_le_bytes(foot[24..32].try_into().unwrap());
        let body_crc = u32::from_le_bytes([foot[32], foot[33], foot[34], foot[35]]);
        if f_count != entry_count as u64 {
            return Err(PersistError::BadField("entry_count 头尾不一致"));
        }
        if f_seq != snapshot_seq {
            return Err(PersistError::BadField("snapshot_seq 头尾不一致"));
        }
        if f_bytes != record_bytes {
            return Err(PersistError::BadField("record_bytes 头尾不一致"));
        }
        Ok(Self {
            path: path.to_path_buf(),
            file_len,
            snapshot_seq,
            entry_count,
            record_bytes,
            body_crc,
        })
    }

    pub fn file_len(&self) -> u64 {
        self.file_len
    }
    pub fn snapshot_seq(&self) -> u64 {
        self.snapshot_seq
    }
    pub fn entry_count(&self) -> u32 {
        self.entry_count
    }
    pub fn body_crc32c(&self) -> u32 {
        self.body_crc
    }
    pub fn record_bytes(&self) -> u64 {
        self.record_bytes
    }

    /// 流式扫描全部记录。每条记录都校验 CRC 与 `rec_type`；所有记录字节的增量 CRC
    /// 必须等于尾部 `body_crc32c`。返回读到的记录数。
    ///
    /// **2.1.42（P1-2）：单条记录坏 ⇒ 跳过 + 计数，不再整份判 Corrupt。**
    ///
    /// 只有**无法定位到单条记录**的框架性错误（`rec_type` / 长度 / 头尾字段不一致 /
    /// 文件长度不符）才返回 `Err`；记录级 CRC / `EntryBody::decode` 失败计进
    /// [`RecordScan::failed`] 并继续。整段 body CRC 不匹配时：
    /// - 若至少有一条记录级失败（`failed > 0`）⇒ 坏字节已被定位，接受其余记录；
    /// - 若一条记录级失败都没有 ⇒ 仍按整份损坏返回（无法安全跳过）。
    pub fn for_each(
        &self,
        f: &mut dyn FnMut(u64, CacheKey, EntryBody) -> Result<()>,
    ) -> Result<RecordScan> {
        let file = File::open(&self.path)?;
        let mut r = BufReader::with_capacity(256 * 1024, file);
        r.seek(SeekFrom::Start(HEADER_LEN as u64))?;
        let mut body_crc = !0u32;
        let mut seen = 0u32;
        let mut failed = 0u32;
        let mut left = self.record_bytes;
        while left > 0 {
            if left < REC_OVERHEAD {
                return Err(PersistError::BadField("快照记录长度不足"));
            }
            let mut head = [0u8; 8];
            r.read_exact(&mut head)?;
            let plen = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
            let rec_type = head[4];
            if rec_type != REC_TYPE_ENTRY {
                return Err(PersistError::BadField("快照 rec_type != 1"));
            }
            if plen > MAX_RECORD_BYTES {
                return Err(PersistError::BadField("快照记录超过 1 MiB"));
            }
            let mut payload = vec![0u8; plen as usize];
            r.read_exact(&mut payload)?;
            let mut crcb = [0u8; 4];
            r.read_exact(&mut crcb)?;
            let want = u32::from_le_bytes(crcb);
            let mut rec = Vec::with_capacity(8 + payload.len());
            rec.extend_from_slice(&head);
            rec.extend_from_slice(&payload);
            // 无论该条是否可用，body CRC 都覆盖**实际文件字节**（这样整段 CRC
            // 仍能发现"坏字节"，而记录级 CRC 负责定位是哪一条）。
            body_crc = super::crc32c_update(body_crc, &rec);
            body_crc = super::crc32c_update(body_crc, &crcb);
            left -= REC_OVERHEAD + plen as u64;
            seen = seen.saturating_add(1);
            if crc32c(&rec) != want {
                // 2.1.42：单条记录 CRC 失败 ⇒ 跳过并计数（与 WAL `BadContent` 同口径）。
                failed = failed.saturating_add(1);
                continue;
            }
            if payload.len() < 8 {
                failed = failed.saturating_add(1);
                continue;
            }
            let entry_seq = u64::from_le_bytes(payload[..8].try_into().unwrap());
            let body = match EntryBody::decode(&payload[8..]) {
                Ok(body) => body,
                Err(_) => {
                    // 记录 CRC 通过但内容不可解码（例如写侧编码缺陷）⇒ 同样只丢这一条。
                    failed = failed.saturating_add(1);
                    continue;
                }
            };
            f(entry_seq, body.key.clone(), body)?;
        }
        if left != 0 {
            return Err(PersistError::BadField("快照 record_bytes 与实际不符"));
        }
        if super::crc32c_finalize(body_crc) != self.body_crc && failed == 0 {
            return Err(PersistError::Crc("快照 body_crc32c"));
        }
        if seen != self.entry_count {
            return Err(PersistError::BadField("快照 entry_count 与实际记录数不符"));
        }
        Ok(RecordScan {
            ok: seen.saturating_sub(failed),
            failed,
        })
    }
}

// >>> PATCH242A P1-2 record-scan BEGIN
/// **2.1.42（P1-2）**：快照逐条扫描结果（坏记录跳过而不是整份 Corrupt）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecordScan {
    /// 成功解码并交给回调的记录数。
    pub ok: u32,
    /// 记录级 CRC / 解码失败、被跳过的记录数。
    pub failed: u32,
}
// <<< PATCH242A P1-2 record-scan END

/// 校验一个“快照文件名后缀”是十进制 `u64`（manifest 侧已校验，这里给测试用）。
pub fn seq_suffix_ok(name: &str) -> bool {
    is_safe_leaf(name)
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::entry_codec::EntryBody;
    use crate::{CacheAnswer, CacheEntry, CacheKey};

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ebpdns-snap-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn entry(i: usize) -> (CacheKey, CacheEntry) {
        let k = CacheKey::new(format!("d{i}.test"), "A");
        let mut e = CacheEntry::new(format!("d{i}.test"), "A", 300.0, 1_700_000_000.0);
        e.chosen = format!("10.0.0.{}", i % 250);
        e.answers = vec![CacheAnswer {
            value: format!("10.0.0.{}", i % 250),
            ttl: 300.0,
            rtype: 1,
            name: None,
        }];
        (k, e)
    }

    fn build(dir: &Path, n: usize) -> SnapshotMeta {
        let p = dir.join("s.snap.7.tmp");
        let mut w = SnapshotWriter::create(&p, 7, 1_700_000_000_000).unwrap();
        for i in 0..n {
            let (k, e) = entry(i);
            let b = EntryBody::from_entry(&k, &e).unwrap();
            w.push(i as u64, &b).unwrap();
        }
        let m = w.finish().unwrap();
        std::fs::rename(&p, dir.join("s.snap.7")).unwrap();
        m
    }

    #[test]
    fn roundtrip_empty_and_many() {
        for n in [0usize, 1, 2, 100] {
            let dir = tmpdir("rt");
            let m = build(&dir, n);
            let path = dir.join("s.snap.7");
            assert_eq!(m.entry_count as usize, n);
            let r = SnapshotReader::open(&path).unwrap();
            assert_eq!(r.snapshot_seq(), 7);
            assert_eq!(r.entry_count() as usize, n);
            assert_eq!(r.file_len(), m.file_len);
            assert_eq!(r.body_crc32c(), m.body_crc32c);
            let mut got = 0u32;
            r.for_each(&mut |seq, k, b| {
                assert_eq!(seq, got as u64);
                assert_eq!(k.domain, format!("d{got}.test"));
                let e = b.to_entry()?;
                assert_eq!(e.answers[0].value, format!("10.0.0.{}", got as usize % 250));
                got += 1;
                Ok(())
            })
            .unwrap();
            assert_eq!(got as usize, n);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn truncation_always_rejected_without_panic() {
        let dir = tmpdir("trunc");
        let _ = build(&dir, 3);
        let src = dir.join("s.snap.7");
        let raw = std::fs::read(&src).unwrap();
        for cut in 0..raw.len() {
            let p = dir.join(format!("t.{cut}"));
            std::fs::write(&p, &raw[..cut]).unwrap();
            match SnapshotReader::open(&p) {
                Err(_) => {}
                Ok(r) => {
                    // 极少数“巧合长度合法”的截断也必须被记录扫描/CRC 拒掉。
                    let res = r.for_each(&mut |_, _, _| Ok(()));
                    assert!(res.is_err(), "截断到 {cut} 竟然通过记录扫描");
                }
            }
            let _ = std::fs::remove_file(&p);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bitflip_detected() {
        let dir = tmpdir("flip");
        let _ = build(&dir, 2);
        let src = dir.join("s.snap.7");
        let raw = std::fs::read(&src).unwrap();
        for i in 0..raw.len() {
            let mut v = raw.clone();
            v[i] ^= 0x01;
            let p = dir.join(format!("f.{i}"));
            std::fs::write(&p, &v).unwrap();
            let bad = match SnapshotReader::open(&p) {
                Err(_) => true,
                // **2.1.42（P1-2）**：记录区单 bit 翻转不再整份 Err，而是
                // `RecordScan.failed > 0`（该条被跳过）；两种都算"已检出"。
                Ok(r) => match r.for_each(&mut |_, _, _| Ok(())) {
                    Err(_) => true,
                    Ok(st) => st.failed > 0,
                },
            };
            assert!(bad, "位翻转 i={i} 未被检出");
            let _ = std::fs::remove_file(&p);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **格式不变量（审计要求，必然进 CI）**：快照**头区 64 B 的任意单字节 × 任意 bit
    /// 翻转都必须被检出**（CRC 覆盖 0..56++60..64，且 `reserved2` 另有“必须为 0”判定），
    /// 且检测过程**不 panic、不把坏数据当有效条目**。
    #[test]
    fn header_any_single_bit_flip_is_rejected() {
        let dir = tmpdir("hdrflip");
        let _ = build(&dir, 2);
        let raw = std::fs::read(dir.join("s.snap.7")).unwrap();
        for i in 0..HEADER_LEN {
            for bit in 0..8u8 {
                let mut v = raw.clone();
                v[i] ^= 1 << bit;
                let p = dir.join(format!("h.{i}.{bit}"));
                std::fs::write(&p, &v).unwrap();
                match SnapshotReader::open(&p) {
                    Err(_) => {}
                    Ok(r) => panic!(
                        "头部 byte {i} bit {bit} 翻转未被检出（open 成功，entries={}）",
                        r.entry_count()
                    ),
                }
                let _ = std::fs::remove_file(&p);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `reserved2` 非 0 ⇒ 明确判损坏（不只依赖 CRC）。
    #[test]
    fn reserved2_nonzero_is_corrupt() {
        let dir = tmpdir("res2");
        let _ = build(&dir, 1);
        let raw = std::fs::read(dir.join("s.snap.7")).unwrap();
        let mut v = raw.clone();
        // 写入 reserved2 = 1，并**重算**头 CRC（模拟“CRC 自洽但 reserved2 非法”）。
        v[60] = 1;
        let mut crc_in = Vec::new();
        crc_in.extend_from_slice(&v[..56]);
        crc_in.extend_from_slice(&v[60..HEADER_LEN]);
        let crc = crc32c(&crc_in);
        v[56..60].copy_from_slice(&crc.to_le_bytes());
        let p = dir.join("r.snap.7");
        std::fs::write(&p, &v).unwrap();
        match SnapshotReader::open(&p) {
            Err(PersistError::BadField(_)) => {}
            Err(e) => panic!("期望 BadField(reserved2)，得到 {e}"),
            Ok(_) => panic!("期望 BadField(reserved2)，却成功打开了快照"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_footer_mismatch_rejected() {
        let dir = tmpdir("mis");
        let _ = build(&dir, 1);
        let src = dir.join("s.snap.7");
        let mut raw = std::fs::read(&src).unwrap();
        // 改 entry_count 并重算 header CRC ⇒ 头尾不一致必须被拒。
        raw[32] = 9;
        let crc = crc32c(&raw[..56]);
        raw[56..60].copy_from_slice(&crc.to_le_bytes());
        let p = dir.join("m.snap.7");
        std::fs::write(&p, &raw).unwrap();
        assert!(SnapshotReader::open(&p).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
