//! **`cache.wal.<base_seq>`** —— 段日志（§5.4）。
//!
//! ```text
//! 32 B 段头（magic "EBPCWAL2" / version / flags / base_seq / created_ms / header_crc32c）
//! 记录：u8 rec_type | u32 body_len | u32 crc32c | body[body_len]
//!       crc 覆盖 [type || body_len(LE) || body]，**不含** crc 字段本身
//! ```
//!
//! 记录类型：`1=PUT 2=EVICT 3=CLEAR 4=COMMIT`。未知类型 ⇒ **本段判损坏**
//! （v2 不做“跳过未知类型”的伪前向兼容；前向兼容在 version 层，§9.2）。
//!
//! **判据（§7.3）**：只有“尾部不完整/尾部 CRC 失败”算 `Tail`（忽略 + 截断），
//! 中段损坏算 `Corrupt`。**永不判撕裂**，**绝不 panic**。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::entry_codec::{decode_key, encode_key, put_i64, put_u32, put_u64, Cur, EntryBody};
use super::{crc32c, PersistError, Result, MAX_RECORD_BYTES};
use crate::CacheKey;

pub const WAL_MAGIC: [u8; 8] = *b"EBPCWAL2";
pub const VERSION: u16 = 2;
pub const HEADER_LEN: usize = 32;
pub const REC_HDR_LEN: u64 = 9;

pub const T_PUT: u8 = 1;
pub const T_EVICT: u8 = 2;
pub const T_CLEAR: u8 = 3;
pub const T_COMMIT: u8 = 4;

/// `EVICT.reason`（§5.4.2）。
pub const R_CAPACITY: u8 = 1;
pub const R_RULE_GEN: u8 = 2;
pub const R_ADMIN: u8 = 3;
pub const R_EXPLICIT: u8 = 4;
pub const R_RESIZE: u8 = 5;

/// `CLEAR.reason`。
pub const C_GROUP_FLIP: u8 = 1;
pub const C_ADMIN: u8 = 2;
pub const C_POLICY_SWAP: u8 = 3;
pub const C_RESYNC: u8 = 4;

// ---------------- 段头 ----------------

fn header_bytes(base_seq: u64, created_ms: i64) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_LEN);
    h.extend_from_slice(&WAL_MAGIC);
    h.extend_from_slice(&VERSION.to_le_bytes());
    h.extend_from_slice(&0u16.to_le_bytes());
    put_u64(&mut h, base_seq);
    put_i64(&mut h, created_ms);
    debug_assert_eq!(h.len(), 28);
    let crc = crc32c(&h);
    put_u32(&mut h, crc); // 覆盖 0..28
    debug_assert_eq!(h.len(), HEADER_LEN);
    h
}

/// 读段头并校验；返回 `base_seq`。
fn read_header(f: &mut File) -> std::result::Result<u64, WalOpenErr> {
    let mut h = [0u8; HEADER_LEN];
    f.seek(SeekFrom::Start(0)).map_err(WalOpenErr::Io)?;
    f.read_exact(&mut h).map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            WalOpenErr::BadHeader("段头不足 32 B")
        } else {
            WalOpenErr::Io(e)
        }
    })?;
    if h[..8] != WAL_MAGIC {
        return Err(WalOpenErr::BadHeader("magic"));
    }
    let version = u16::from_le_bytes([h[8], h[9]]);
    if version != VERSION {
        return Err(WalOpenErr::UnsupportedVersion(version));
    }
    let crc = u32::from_le_bytes([h[28], h[29], h[30], h[31]]);
    if crc32c(&h[..28]) != crc {
        return Err(WalOpenErr::BadHeader("header_crc32c"));
    }
    Ok(u64::from_le_bytes(h[12..20].try_into().unwrap()))
}

// ---------------- 记录编码（自由函数：actor 一次拼一批再 write） ----------------

fn frame(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(REC_HDR_LEN as usize + body.len());
    rec.push(typ);
    rec.extend_from_slice(&(body.len() as u32).to_le_bytes());
    let mut crc_input = Vec::with_capacity(5 + body.len());
    crc_input.push(typ);
    crc_input.extend_from_slice(&(body.len() as u32).to_le_bytes());
    crc_input.extend_from_slice(body);
    let crc = crc32c(&crc_input);
    rec.extend_from_slice(&crc.to_le_bytes());
    rec.extend_from_slice(body);
    rec
}

/// 编码一条 `PUT` 记录。
///
/// `key` 与 `e.key` 必须一致（`EntryBody` 自带键）；这里用 `debug_assert` 兜住调用方
/// 传错键的低级错误，release 下无开销。
pub fn encode_put(seq: u64, key: &CacheKey, e: &EntryBody) -> Result<Vec<u8>> {
    debug_assert_eq!(&e.key, key);
    let mut body = Vec::with_capacity(128);
    put_u64(&mut body, seq);
    let mut eb = Vec::with_capacity(128);
    e.encode(&mut eb)?;
    if eb.len() > MAX_RECORD_BYTES as usize - 8 {
        return Err(PersistError::BadField("PUT body 超过 1 MiB"));
    }
    body.extend_from_slice(&eb);
    Ok(frame(T_PUT, &body))
}

/// 编码一条 `EVICT` 记录。
pub fn encode_evict(seq: u64, key: &CacheKey, reason: u8) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(48);
    put_u64(&mut body, seq);
    body.push(reason);
    encode_key(key, &mut body)?;
    Ok(frame(T_EVICT, &body))
}

/// 编码一条 `CLEAR` 记录。
pub fn encode_clear(seq: u64, reason: u8) -> Vec<u8> {
    let mut body = Vec::with_capacity(9);
    put_u64(&mut body, seq);
    body.push(reason);
    frame(T_CLEAR, &body)
}

/// 编码一条 `COMMIT` 记录。
pub fn encode_commit(seq: u64, committed_ms: i64, record_count: u32, bytes: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(24);
    put_u64(&mut body, seq);
    put_i64(&mut body, committed_ms);
    put_u32(&mut body, record_count);
    put_u32(&mut body, bytes);
    frame(T_COMMIT, &body)
}

// ---------------- 写 ----------------

/// WAL 段写入器（**只由 actor 单线程写**，§6.4）。
pub struct WalWriter {
    path: PathBuf,
    file: File,
    base_seq: u64,
    /// 当前文件字节数（含段头）。
    bytes: u64,
    /// 最后一个“完整记录”的末尾偏移（失败后截到这里再追加）。
    pub valid_len: u64,
}

impl WalWriter {
    /// 新建段：写段头 → `fsync` → `fsync(dir)`。
    ///
    /// 若同名文件已存在（上次失败的孤儿）⇒ **截断重建**（调用方保证它未被 manifest 引用）。
    pub fn create(path: &Path, base_seq: u64, created_ms: i64) -> Result<Self> {
        let f = File::create(path)?;
        let mut w = std::io::BufWriter::new(f);
        w.write_all(&header_bytes(base_seq, created_ms))?;
        w.flush()?;
        let file = w
            .into_inner()
            .map_err(|e| PersistError::Io(e.into_error()))?;
        file.sync_all()?;
        if let Some(dir) = path.parent() {
            super::fsync_dir(dir);
        }
        Ok(Self {
            path: path.to_path_buf(),
            file,
            base_seq,
            bytes: HEADER_LEN as u64,
            valid_len: HEADER_LEN as u64,
        })
    }

    /// 打开已存在的段继续追加（恢复 tail 截断之后）。
    ///
    /// 必须 `read(true).write(true)`：读段头要 `seek(0)+read_exact`，只开 `write` 会
    /// 得到 `EBADF`（2.1.29 实测踩过：初始快照后的 open_append 因此失败）。
    pub fn open_append(path: &Path, base_seq: u64, valid_len: u64) -> Result<Self> {
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let got = read_header(&mut f).map_err(|e| match e {
            WalOpenErr::Io(e) => PersistError::Io(e),
            WalOpenErr::UnsupportedVersion(v) => PersistError::UnsupportedVersion(v),
            WalOpenErr::BadHeader(w) => PersistError::BadField(w),
        })?;
        if got != base_seq {
            return Err(PersistError::BadField("WAL 段头 base_seq 与文件名不符"));
        }
        let len = f.metadata()?.len();
        if valid_len < HEADER_LEN as u64 || valid_len > len {
            return Err(PersistError::BadField("valid_len 越界"));
        }
        if valid_len != len {
            f.set_len(valid_len)?;
            f.sync_all()?;
        }
        f.seek(SeekFrom::Start(valid_len))?;
        Ok(Self {
            path: path.to_path_buf(),
            file: f,
            base_seq,
            bytes: valid_len,
            valid_len,
        })
    }

    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 追加一批**已编码**的记录字节（一次 `write_all`）。
    ///
    /// 失败时调用方应 `truncate_to_valid()`（§6.2：绝不接在半条后面写）。
    pub fn append_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.file.write_all(bytes)?;
        self.bytes += bytes.len() as u64;
        self.valid_len = self.bytes;
        Ok(())
    }

    /// `fdatasync`（一次覆盖整批）。
    pub fn sync_data(&mut self) -> Result<()> {
        self.file.sync_data()?;
        Ok(())
    }

    /// 截掉半条记录（失败恢复用）。
    pub fn truncate_to_valid(&mut self) -> Result<()> {
        self.file.set_len(self.valid_len)?;
        self.file.seek(SeekFrom::Start(self.valid_len))?;
        self.bytes = self.valid_len;
        Ok(())
    }
}

// ---------------- 读 ----------------

/// 打开 WAL 失败的原因。
#[derive(Debug)]
pub enum WalOpenErr {
    Io(std::io::Error),
    /// 段头 magic/长度/CRC 非法 ⇒ 该段不可用。
    BadHeader(&'static str),
    /// `version > 2`（未来格式）：**不覆盖**、禁用写。
    UnsupportedVersion(u16),
}

/// 读记录失败的原因（决定“截断”还是“损坏”）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalErr {
    /// 尾部不完整（头/体/CRC 半写，或尾随全零）⇒ **忽略并截断**，计 `tail_records`。
    Tail {
        valid_len: u64,
        trailing: u64,
    },
    /// 中段损坏 ⇒ 最后一段按尾部截断 + ERROR；非最后一段回退。
    Corrupt {
        off: u64,
        why: &'static str,
    },
    Io(String),
}

/// 一条已解出的记录。
#[derive(Debug)]
pub enum WalRec {
    Put {
        seq: u64,
        body: EntryBody,
    },
    Evict {
        seq: u64,
        key: CacheKey,
        reason: u8,
    },
    Clear {
        seq: u64,
        reason: u8,
    },
    Commit {
        seq: u64,
        committed_ms: i64,
        record_count: u32,
        bytes: u32,
    },
}

impl WalRec {
    pub fn seq(&self) -> u64 {
        match self {
            WalRec::Put { seq, .. }
            | WalRec::Evict { seq, .. }
            | WalRec::Clear { seq, .. }
            | WalRec::Commit { seq, .. } => *seq,
        }
    }
}

/// `next()` 的结果：正常记录，或“框架完好但内容不可用”（计 `failed` 并继续）。
#[derive(Debug)]
pub enum WalItem {
    Rec(WalRec),
    BadContent,
}

/// WAL 段读取器（流式；只读 manifest 列出的段）。
pub struct WalReader {
    file: File,
    path: PathBuf,
    base_seq: u64,
    file_len: u64,
    pos: u64,
    last_seq: Option<u64>,
}

impl WalReader {
    /// 打开并校验段头；`expected_base` 来自 manifest（必须与段头一致）。
    pub fn open(path: &Path, expected_base: u64) -> std::result::Result<Self, WalOpenErr> {
        let mut file = File::open(path).map_err(WalOpenErr::Io)?;
        let got = read_header(&mut file)?;
        if got != expected_base {
            return Err(WalOpenErr::BadHeader("段头 base_seq 与 manifest 不符"));
        }
        let file_len = file.metadata().map_err(WalOpenErr::Io)?.len();
        if file_len < HEADER_LEN as u64 {
            return Err(WalOpenErr::BadHeader("段长度小于段头"));
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            base_seq: got,
            file_len,
            pos: HEADER_LEN as u64,
            last_seq: None,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn base_seq(&self) -> u64 {
        self.base_seq
    }
    pub fn file_len(&self) -> u64 {
        self.file_len
    }
    /// 当前读取位置（= 最后一条完整记录的末尾）。
    pub fn valid_len(&self) -> u64 {
        self.pos
    }

    /// 本段**已读到**的最后一条记录的 `seq`（`None` = 还没读到记录）。
    ///
    /// 恢复侧用它兜底 `next_seq`（2.1.34：`seq` 回退不再判损坏，故这里如实返回原值）。
    pub fn last_seq(&self) -> Option<u64> {
        self.last_seq
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> std::result::Result<(), WalErr> {
        self.file
            .seek(SeekFrom::Start(off))
            .map_err(|e| WalErr::Io(e.to_string()))?;
        self.file
            .read_exact(buf)
            .map_err(|e| WalErr::Io(e.to_string()))
    }

    fn rest_is_all_zero(&mut self, off: u64, n: u64) -> bool {
        // 上界：超过 1 MiB 的“全零尾”不可能是半写残留，直接判损坏。
        if n > MAX_RECORD_BYTES as u64 {
            return false;
        }
        let mut buf = vec![0u8; n as usize];
        if self.read_at(off, &mut buf).is_err() {
            return false;
        }
        buf.iter().all(|b| *b == 0)
    }

    /// 读下一条记录。
    ///
    /// 名字叫 `next` 但不实现 `Iterator`（它返回 `Result` 且带“尾部截断/损坏”两类
    /// 领域错误，不是 `Option` 语义）—— 显式允许这条 lint，避免为了名字去改 20 处调用点。
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> std::result::Result<Option<WalItem>, WalErr> {
        let start = self.pos;
        let remaining = self.file_len.saturating_sub(start);
        if remaining == 0 {
            return Ok(None);
        }
        if remaining < REC_HDR_LEN {
            return Err(WalErr::Tail {
                valid_len: start,
                trailing: remaining,
            });
        }
        let mut hdr = [0u8; REC_HDR_LEN as usize];
        self.read_at(start, &mut hdr)?;
        let typ = hdr[0];
        let blen = u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]);
        let want_crc = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]);
        if blen > MAX_RECORD_BYTES {
            return if remaining < REC_HDR_LEN + blen as u64 {
                Err(WalErr::Tail {
                    valid_len: start,
                    trailing: remaining,
                })
            } else {
                Err(WalErr::Corrupt {
                    off: start,
                    why: "body_len > 1MiB",
                })
            };
        }
        if remaining < REC_HDR_LEN + blen as u64 {
            return Err(WalErr::Tail {
                valid_len: start,
                trailing: remaining,
            });
        }
        let mut body = vec![0u8; blen as usize];
        self.read_at(start + REC_HDR_LEN, &mut body)?;
        // CRC 覆盖 [type || body_len || body]。
        let mut crc_in = Vec::with_capacity(5 + body.len());
        crc_in.push(typ);
        crc_in.extend_from_slice(&blen.to_le_bytes());
        crc_in.extend_from_slice(&body);
        if crc32c(&crc_in) != want_crc {
            let after = self.file_len - (start + REC_HDR_LEN + blen as u64);
            if after == 0 || self.rest_is_all_zero(start + REC_HDR_LEN + blen as u64, after) {
                return Err(WalErr::Tail {
                    valid_len: start,
                    trailing: remaining,
                });
            }
            // >>> PATCH242A P1-2 wal-badcontent BEGIN
            // **2.1.42（P1-2）**：单条记录 CRC 失败但**长度框架完好** ⇒ 跳过该条
            // （计 `BadContent` 并继续），与快照侧"单条坏 ⇒ 跳过 + 计数"对齐。
            // 旧行为：中段 CRC mismatch ⇒ 整段 Corrupt ⇒ 恢复侧按 valid_len 截断，
            // 该条之后的全部好记录被丢。未知类型/长度非法仍是段级损坏。
            self.pos = start + REC_HDR_LEN + blen as u64;
            return Ok(Some(WalItem::BadContent));
            // <<< PATCH242A P1-2 wal-badcontent END
        }
        let next_pos = start + REC_HDR_LEN + blen as u64;
        // 未知类型 ⇒ 本段判损坏（§5.4.2）。
        let decoded = match decode_record(typ, &body) {
            Ok(Some(r)) => r,
            // 内容不可用但框架完好 ⇒ 计 failed 并继续。
            Ok(None) => {
                self.pos = next_pos;
                return Ok(Some(WalItem::BadContent));
            }
            Err(e) => return Err(WalErr::Corrupt { off: start, why: e }),
        };
        // **2.1.34（D1）**：**不再**把 `seq` 回退判成损坏。
        //
        // 旧实现要求数据记录 seq 严格递增（`COMMIT` 只允许 >=），一旦某条正常 CRC
        // 的记录回退就把**整段**判 `Corrupt`，恢复侧再“按尾部截断”⇒ 该记录之后
        // 全部丢弃（实测一次丢 59%）。`seq` 只用于**幂等/去重**，不是完整性判据：
        // 完整性由 CRC32C + 长度 + 结构校验保证；顺序由恢复侧按 seq 排序合并。
        //
        // 因此这里仍然解析 `seq`（`decoded.seq()`），但**不**因回退返回错误。
        let seq = decoded.seq();
        self.last_seq = Some(seq);
        self.pos = next_pos;
        Ok(Some(WalItem::Rec(decoded)))
    }
}

/// 解码记录体。返回 `Ok(None)` = 内容不可用（应计 `failed` 并跳过），
/// `Err(why)` = 未知类型 / 结构性非法（本段判损坏）。
fn decode_record(typ: u8, body: &[u8]) -> std::result::Result<Option<WalRec>, &'static str> {
    match typ {
        T_PUT => {
            if body.len() < 8 {
                return Ok(None);
            }
            let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
            match EntryBody::decode(&body[8..]) {
                Ok(b) => Ok(Some(WalRec::Put { seq, body: b })),
                Err(_) => Ok(None),
            }
        }
        T_EVICT => {
            if body.len() < 9 {
                return Ok(None);
            }
            let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
            let reason = body[8];
            if !(1..=5).contains(&reason) {
                return Ok(None);
            }
            let mut cur = Cur::new(&body[9..]);
            match decode_key(&mut cur) {
                Ok(key) if cur.remaining() == 0 => Ok(Some(WalRec::Evict { seq, key, reason })),
                _ => Ok(None),
            }
        }
        T_CLEAR => {
            if body.len() != 9 {
                return Ok(None);
            }
            let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
            let reason = body[8];
            if !(1..=4).contains(&reason) {
                return Ok(None);
            }
            Ok(Some(WalRec::Clear { seq, reason }))
        }
        T_COMMIT => {
            if body.len() != 24 {
                return Ok(None);
            }
            let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
            let committed_ms = i64::from_le_bytes(body[8..16].try_into().unwrap());
            let record_count = u32::from_le_bytes(body[16..20].try_into().unwrap());
            let bytes = u32::from_le_bytes(body[20..24].try_into().unwrap());
            Ok(Some(WalRec::Commit {
                seq,
                committed_ms,
                record_count,
                bytes,
            }))
        }
        // 未知类型：本段判损坏。
        _ => Err("未知 rec_type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persist::entry_codec::EntryBody;
    use crate::{CacheAnswer, CacheEntry, CacheKey};

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "ebpdns-wal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn body(i: usize) -> EntryBody {
        let k = CacheKey::new(format!("w{i}.test"), "A");
        let mut e = CacheEntry::new(format!("w{i}.test"), "A", 60.0, 1_700_000_000.0);
        e.answers = vec![CacheAnswer {
            value: format!("10.1.0.{}", i % 250),
            ttl: 60.0,
            rtype: 1,
            name: None,
        }];
        EntryBody::from_entry(&k, &e).unwrap()
    }

    #[test]
    fn header_roundtrip_and_bad_magic() {
        let dir = tmpdir("hdr");
        let p = dir.join("w.wal.5");
        let w = WalWriter::create(&p, 5, 1).unwrap();
        assert_eq!(w.bytes(), 32);
        drop(w);
        let mut f = File::open(&p).unwrap();
        assert_eq!(read_header(&mut f).map_err(|_| ()), Ok(5));
        // magic 坏
        let mut raw = std::fs::read(&p).unwrap();
        raw[0] = b'X';
        std::fs::write(&p, &raw).unwrap();
        assert!(matches!(
            WalReader::open(&p, 5),
            Err(WalOpenErr::BadHeader(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn header_any_single_bit_flip_is_rejected() {
        // **格式不变量（审计要求，必然进 CI）**：WAL 段头 32 B 的任意单字节 × 任意 bit
        // 翻转都必须被检出（`header_crc32c` 覆盖 0..28；28..32 是 CRC 自身），
        // 且不 panic。
        let dir = tmpdir("hdrflip");
        let p = dir.join("w.wal.7");
        let w = WalWriter::create(&p, 7, 1_700_000_000_000).unwrap();
        drop(w);
        let raw = std::fs::read(&p).unwrap();
        assert_eq!(raw.len(), HEADER_LEN);
        for i in 0..HEADER_LEN {
            for bit in 0..8u8 {
                let mut v = raw.clone();
                v[i] ^= 1 << bit;
                let p2 = dir.join(format!("h.{i}.{bit}"));
                std::fs::write(&p2, &v).unwrap();
                match WalReader::open(&p2, 7) {
                    Err(_) => {}
                    Ok(_) => panic!("WAL 段头 byte {i} bit {bit} 翻转未被检出"),
                }
                let _ = std::fs::remove_file(&p2);
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn put_evict_clear_commit_roundtrip() {
        let dir = tmpdir("rec");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let mut batch = Vec::new();
        let k0 = CacheKey::new("w0.test", "A");
        let k1 = CacheKey::new("w1.test", "A");
        batch.extend_from_slice(&encode_put(1, &k0, &body(0)).unwrap());
        batch.extend_from_slice(&encode_put(2, &k1, &body(1)).unwrap());
        batch.extend_from_slice(&encode_evict(3, &k0, R_CAPACITY).unwrap());
        batch.extend_from_slice(&encode_clear(4, C_GROUP_FLIP));
        batch.extend_from_slice(&encode_commit(4, 1_700_000_000_000, 4, 99));
        w.append_bytes(&batch).unwrap();
        w.sync_data().unwrap();
        drop(w);

        let mut r = WalReader::open(&p, 1).unwrap();
        let mut types = Vec::new();
        let mut seqs = Vec::new();
        while let Some(item) = r.next().unwrap() {
            match item {
                WalItem::Rec(rec) => {
                    types.push(match &rec {
                        WalRec::Put { .. } => T_PUT,
                        WalRec::Evict { .. } => T_EVICT,
                        WalRec::Clear { .. } => T_CLEAR,
                        WalRec::Commit { .. } => T_COMMIT,
                    });
                    seqs.push(rec.seq());
                }
                WalItem::BadContent => panic!("不应有 BadContent"),
            }
        }
        assert_eq!(types, vec![T_PUT, T_PUT, T_EVICT, T_CLEAR, T_COMMIT]);
        assert_eq!(seqs, vec![1, 2, 3, 4, 4]);
        assert_eq!(r.valid_len(), std::fs::metadata(&p).unwrap().len());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// C1/C2/C5：各种半写尾部 ⇒ `Tail`（**不判撕裂**）。
    #[test]
    fn partial_tail_is_tail_not_tear() {
        let dir = tmpdir("tail");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let k0 = CacheKey::new("w0.test", "A");
        let k1 = CacheKey::new("w1.test", "A");
        let rec1 = encode_put(1, &k0, &body(0)).unwrap();
        let rec2 = encode_put(2, &k1, &body(1)).unwrap();
        w.append_bytes(&rec1).unwrap();
        w.append_bytes(&rec2).unwrap();
        w.sync_data().unwrap();
        drop(w);
        let full = std::fs::read(&p).unwrap();
        // 只在**第二条记录内**逐字节截断：第一条必须完整可见，第二条必须判 Tail。
        for cut in 1..rec2.len() {
            let p2 = dir.join(format!("t.{cut}"));
            std::fs::write(&p2, &full[..full.len() - cut]).unwrap();
            let mut r = WalReader::open(&p2, 1).unwrap();
            assert!(matches!(r.next().unwrap(), Some(WalItem::Rec(_))));
            match r.next() {
                Err(WalErr::Tail { .. }) => {}
                other => panic!("cut={cut} 期望 Tail，得到 {other:?}"),
            }
            let _ = std::fs::remove_file(&p2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn trailing_zeros_after_record_is_tail() {
        let dir = tmpdir("zeros");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let k = CacheKey::new("w0.test", "A");
        w.append_bytes(&encode_put(1, &k, &body(0)).unwrap())
            .unwrap();
        w.sync_data().unwrap();
        drop(w);
        // 追加 16 个 0 字节（模拟“文件被扩展但未写内容”）。
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[0u8; 16]).unwrap();
        drop(f);
        let mut r = WalReader::open(&p, 1).unwrap();
        assert!(matches!(r.next().unwrap(), Some(WalItem::Rec(_))));
        match r.next() {
            Err(WalErr::Tail { .. }) => {}
            other => panic!("期望 Tail，得到 {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.42（P1-2）**：中段单条记录 CRC 失败且后面还有非零字节 ⇒
    /// `BadContent` 跳过该条，**后续好记录仍可读**（与快照侧同口径）。
    #[test]
    fn middle_corruption_is_skipped_as_bad_content() {
        let dir = tmpdir("mid");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        for i in 0..3usize {
            let k = CacheKey::new(format!("w{i}.test"), "A");
            w.append_bytes(&encode_put(i as u64 + 1, &k, &body(i)).unwrap())
                .unwrap();
        }
        w.sync_data().unwrap();
        drop(w);
        let mut raw = std::fs::read(&p).unwrap();
        // 破坏第一条记录的一个 body 字节。
        raw[HEADER_LEN + 12] ^= 0xFF;
        std::fs::write(&p, &raw).unwrap();
        let mut r = WalReader::open(&p, 1).unwrap();
        match r.next() {
            Ok(Some(WalItem::BadContent)) => {}
            other => panic!("期望 BadContent，得到 {other:?}"),
        }
        let mut good = 0usize;
        while let Ok(Some(item)) = r.next() {
            if matches!(item, WalItem::Rec(_)) {
                good += 1;
            }
        }
        assert_eq!(good, 2, "坏记录之后的 2 条好记录不得丢失");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **2.1.34（D1）**：`seq` 回退**不再**判损坏。
    ///
    /// 旧实现要求数据记录 seq 严格递增，一条 CRC 正常的回退记录会让**整段**判
    /// `Corrupt`，恢复侧再“按尾部截断”⇒ 该记录之后全部丢弃（实测丢 0.75–59%）。
    /// 现在完整性只由 CRC/长度/结构决定；顺序由 `recover` 按 seq 排序合并。
    #[test]
    fn non_monotonic_seq_is_not_corrupt() {
        let dir = tmpdir("seq");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let k0 = CacheKey::new("w0.test", "A");
        let k1 = CacheKey::new("w1.test", "A");
        let k2 = CacheKey::new("w2.test", "A");
        w.append_bytes(&encode_put(5, &k0, &body(0)).unwrap())
            .unwrap();
        w.append_bytes(&encode_put(3, &k1, &body(1)).unwrap())
            .unwrap();
        w.append_bytes(&encode_put(4, &k2, &body(2)).unwrap())
            .unwrap();
        w.sync_data().unwrap();
        drop(w);
        let mut r = WalReader::open(&p, 1).unwrap();
        let mut got = Vec::new();
        while let Some(it) = r.next().expect("seq 回退不得判损坏") {
            if let WalItem::Rec(rec) = it {
                got.push(rec.seq());
            }
        }
        assert_eq!(got, vec![5, 3, 4], "读侧必须按文件顺序如实返回全部记录");
        assert_eq!(r.last_seq(), Some(4));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_type_is_corrupt() {
        let dir = tmpdir("unk");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let mut b = Vec::new();
        b.extend_from_slice(&9u64.to_le_bytes());
        w.append_bytes(&frame(9, &b)).unwrap();
        w.sync_data().unwrap();
        drop(w);
        let mut r = WalReader::open(&p, 1).unwrap();
        assert!(matches!(r.next(), Err(WalErr::Corrupt { .. })));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn oversized_body_len_is_tail_when_truncated() {
        let dir = tmpdir("big");
        let p = dir.join("w.wal.1");
        let w = WalWriter::create(&p, 1, 1).unwrap();
        drop(w);
        // 头 + 一个声明 2 MiB body 的半条记录。
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&[T_PUT]).unwrap();
        f.write_all(&2_000_000u32.to_le_bytes()).unwrap();
        f.write_all(&[0u8; 16]).unwrap();
        drop(f);
        let mut r = WalReader::open(&p, 1).unwrap();
        match r.next() {
            Err(WalErr::Tail { .. }) => {}
            other => panic!("期望 Tail，得到 {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn truncate_to_valid_removes_half_record() {
        let dir = tmpdir("trunc2");
        let p = dir.join("w.wal.1");
        let mut w = WalWriter::create(&p, 1, 1).unwrap();
        let k = CacheKey::new("w0.test", "A");
        let rec = encode_put(1, &k, &body(0)).unwrap();
        w.append_bytes(&rec).unwrap();
        w.sync_data().unwrap();
        let good = w.bytes();
        // 手工追加半条，并把 valid_len 保持在完整记录末尾。
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(&rec[..5]).unwrap();
        drop(f);
        w.truncate_to_valid().unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().len(), good);
        drop(w);
        let mut r = WalReader::open(&p, 1).unwrap();
        assert!(matches!(r.next().unwrap(), Some(WalItem::Rec(_))));
        assert!(r.next().unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
