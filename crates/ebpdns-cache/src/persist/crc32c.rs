//! **CRC32C（Castagnoli）树内实现** —— 零新依赖（H1），§17.1。
//!
//! 多项式：reflected `0x82F63B78`（正写 `0x1EDC6F41`）。非加密校验：防意外损坏，
//! 不防篡改（与 `state_store` 的威胁模型一致）。**不**用 `crc32fast`（那是 IEEE 多项式）。

/// Castagnoli 多项式（reflected）。
const POLY: u32 = 0x82F6_3B78;

const fn make_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

static TABLE: [u32; 256] = make_table();

/// 一次性 CRC32C。
pub fn crc32c(data: &[u8]) -> u32 {
    !crc32c_update(!0u32, data)
}

/// 增量 CRC32C：`crc32c_update(0xFFFF_FFFF, a)` 再 `update(_, b)` == `crc32c(a||b)`。
pub fn crc32c_update(mut c: u32, data: &[u8]) -> u32 {
    for &b in data {
        c = TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    c
}

/// 分片增量：一把把 `&[u8]` 喂进去（调用方自己维护 `0xFFFF_FFFF` 初值）。
pub fn crc32c_finalize(c: u32) -> u32 {
    !c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_123456789() {
        // 可外部复核的 RFC 3720 / iSCSI 标准向量。
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn incremental_equals_oneshot() {
        let d = b"ebpdns-cache-v2";
        let a = crc32c(d);
        let b = crc32c_finalize(crc32c_update(crc32c_update(!0, &d[..4]), &d[4..]));
        assert_eq!(a, b);
    }

    #[test]
    fn incremental_three_parts() {
        let d = b"snapshot+wal+manifest";
        for cut1 in 0..d.len() {
            for cut2 in cut1..d.len() {
                let c = crc32c_update(!0, &d[..cut1]);
                let c = crc32c_update(c, &d[cut1..cut2]);
                let c = crc32c_finalize(crc32c_update(c, &d[cut2..]));
                assert_eq!(c, crc32c(d), "cut1={cut1} cut2={cut2}");
            }
        }
    }

    #[test]
    fn detects_single_bit_flip() {
        let d = b"the quick brown fox jumps over the lazy dog";
        let base = crc32c(d);
        for i in 0..d.len() {
            for bit in 0..8 {
                let mut v = d.to_vec();
                v[i] ^= 1 << bit;
                assert_ne!(crc32c(&v), base, "bit flip at {i}/{bit} not detected");
            }
        }
    }
}
