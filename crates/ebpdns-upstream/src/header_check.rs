//! 响应结构校验：`_is_header_only`（QDCOUNT!=1 拒绝）、qid 提取，
//! **[历史归因]** 以及按上游自适应降级的 0x20 大小写校验状态机（对齐 Python `upstream.py`）。

use std::collections::HashMap;
use std::time::Instant;

use ebpdns_proto::query::check_0x20;

/// **[历史归因]** 连续多少次 0x20 大小写失配后对该上游关闭 0x20 校验（Python `_0x20_FAIL_LIMIT`）。
const FAIL_LIMIT: u32 = 3;
/// **[历史归因]** 降级后多少秒自动重新启用 0x20 校验（Python `_0x20_RECOVER_S`）。
const RECOVER_SECS: u64 = 600;

/// 是否为畸形 / header-only 响应（QDCOUNT != 1 即拒绝）。
///
/// **[历史归因]** 对齐 Python `_is_header_only`：合法响应恒 echo 查询的 question（QDCOUNT==1），
/// 故 qdcount!=1 本身即结构异常。`len<12` 的短帧由调用方前置长度判断兜底，此处返回 false。
pub fn is_header_only(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    // data[4:6] 为 QDCOUNT。
    let qd = u16::from_be_bytes([data[4], data[5]]);
    qd != 1
}

/// 取响应/查询的 DNS qid（前 2 字节）。长度不足返回 `None`。
pub fn qid_of(data: &[u8]) -> Option<u16> {
    if data.len() < 2 {
        return None;
    }
    Some(u16::from_be_bytes([data[0], data[1]]))
}

struct X20Entry {
    /// 连续 0x20 失配次数。
    misses: u32,
    /// 降级（关闭 0x20 校验）时刻；None 表示未降级。
    disabled_since: Option<Instant>,
}

/// 按上游自适应降级的 0x20 投毒防护状态机。
///
/// 部分上游/中间盒会把查询名规范化为小写后回显，导致逐位失配 → 响应被误当投毒丢弃。
/// 按上游统计连续失配，达 [`FAIL_LIMIT`] 后关闭该校验（直接接受 qid/源校验通过的响应），
/// 满 [`RECOVER_SECS`] 后自动重新启用。
#[derive(Default)]
pub struct X20Controller {
    inner: parking_lot::Mutex<HashMap<String, X20Entry>>,
}

impl X20Controller {
    pub fn new() -> Self {
        Self::default()
    }

    /// 查询开头调用：若已降级且超过恢复窗口，自动重新启用 0x20 校验。
    pub fn maybe_recover(&self, up_id: &str, now: Instant) {
        if up_id.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        if let Some(e) = g.get_mut(up_id) {
            if let Some(since) = e.disabled_since {
                if now.duration_since(since).as_secs() >= RECOVER_SECS {
                    g.remove(up_id);
                }
            }
        }
    }

    /// 该上游当前是否已降级（跳过 0x20 校验）。
    pub fn is_disabled(&self, up_id: &str) -> bool {
        matches!(
            self.inner.lock().get(up_id),
            Some(e) if e.disabled_since.is_some()
        )
    }

    /// 记录一次 0x20 失配（每查询最多调用一次）。达到阈值则降级。
    pub fn record_mismatch(&self, up_id: &str, now: Instant) {
        if up_id.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        let e = g.entry(up_id.to_string()).or_insert(X20Entry {
            misses: 0,
            disabled_since: None,
        });
        if e.disabled_since.is_some() {
            return; // 已降级，不再累计。
        }
        e.misses += 1;
        if e.misses >= FAIL_LIMIT {
            e.disabled_since = Some(now);
        }
    }

    /// 记录一次 0x20 通过（或已降级）的响应：清零连续失配计数。
    pub fn record_success(&self, up_id: &str) {
        if up_id.is_empty() {
            return;
        }
        let mut g = self.inner.lock();
        if let Some(e) = g.get_mut(up_id) {
            e.misses = 0;
        }
    }

    /// **单临界区**完成「读降级态 → 计失配 → 判定是否接受」。
    ///
    /// 修复并发回归：旧实现先 `is_disabled()` 取快照、再 `record_mismatch()`、
    /// 最后又独立加锁重读，读-改-写不在同一临界区 —— 同一上游的 3 条并发伪造响应
    /// 可同时观察到「未降级」并各自返回 false/true 的混合结果，使 0x20 投毒防护
    /// **[历史归因]** 在窗口内被静默绕过（Python `upstream.py` 在同一把 `_0x20_lock` 内完成）。
    ///
    /// 返回 `true` = 接受该响应；`false` = 失配且未降级，应丢弃继续等。
    pub fn note_mismatch_accept(&self, up_id: &str, now: Instant) -> bool {
        if up_id.is_empty() {
            // 无上游标识（如本地合成应答）：不做降级统计，按未降级处理。
            return false;
        }
        let mut g = self.inner.lock();
        let e = g.entry(up_id.to_string()).or_insert(X20Entry {
            misses: 0,
            disabled_since: None,
        });
        if e.disabled_since.is_some() {
            return true; // 已降级：接受。
        }
        e.misses += 1;
        if e.misses >= FAIL_LIMIT {
            e.disabled_since = Some(now);
            return true; // 本次触发降级：接受，避免阈值处误丢。
        }
        false
    }

    /// **[历史归因]** 删除上游时清理其 0x20 状态（对齐 Python `discard_upstream_conns`）。
    pub fn discard(&self, up_id: &str) {
        self.inner.lock().remove(up_id);
    }
}

/// 对一条明文（UDP/裸 TCP）响应做 0x20 校验判定。
///
/// 返回 `true` = 接受该响应；`false` = 失配且未降级，应丢弃继续等。
/// 同时按结果更新连续失配计数（成功清零；失配累计）。`counted` 标记本查询是否已计过一次失配。
pub fn evaluate_x20(
    ctrl: &X20Controller,
    up_id: &str,
    query: &[u8],
    response: &[u8],
    now: Instant,
    counted: &mut bool,
) -> bool {
    if check_0x20(query, response) {
        ctrl.record_success(up_id);
        return true;
    }
    // 失配：只有第一次（本查询尚未计过）才进入状态机；后续不再重复累计。
    if *counted {
        // 本查询已计过失配：直接按当前降级态判定（单次加锁读）。
        return ctrl.is_disabled(up_id);
    }
    *counted = true;
    ctrl.note_mismatch_accept(up_id, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_only_tightened() {
        // qd=1/an=1 正常；qd=1/an=0 (NODATA/NXDOMAIN) 放行。
        let resp = |qd: u16, an: u16| -> Vec<u8> {
            let mut v = Vec::new();
            v.extend(0x1234u16.to_be_bytes());
            v.extend(0x8180u16.to_be_bytes());
            v.extend(qd.to_be_bytes());
            v.extend(an.to_be_bytes());
            v.extend(0u16.to_be_bytes());
            v.extend(0u16.to_be_bytes());
            v
        };
        assert!(!is_header_only(&resp(1, 1)));
        assert!(!is_header_only(&resp(1, 0)));
        assert!(is_header_only(&resp(0, 0)));
        assert!(is_header_only(&resp(0, 5)));
        assert!(!is_header_only(&[0u8; 8]));
    }
}
