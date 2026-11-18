//! **[历史归因]** 通配规则 → 锚定正则。忠实对齐 Python `resolver._wildcard_to_regex`。

/// 通配元字符（除 `*` 外）需转义的集合。
fn needs_escape(c: char) -> bool {
    matches!(
        c,
        '.' | '^' | '$' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
    )
}

/// 把通配表达式 `m`（已规范化小写、无尾点、至少含一个 `*`）翻译成锚定正则。
///
/// 翻译规则（对齐 R-fix）：
/// - 裸 `*` → `^.*$`（匹配任意域名，R18/P2-1 修复裸 `*` 失效）；
/// - 前导 `*`（如 `*ads.com` / `*.ads.com`）→ `(?:.*\.)?`（零层或多层子域 + 点），
///   其后紧跟的 `.` 一并吞掉；`*` 落在标签边界，不命中 `myads.com`；
/// - 其余 `*` → `[^.]*`（不跨标签），由两侧字面量保证至少消耗一个字符。
pub fn wildcard_to_regex(m: &str) -> String {
    let mut out = String::with_capacity(m.len() + 8);
    out.push('^');
    let bytes = m.as_bytes();
    let mut i = 0usize;
    if m.starts_with('*') {
        if m == "*" {
            return "^.*$".to_string();
        }
        out.push_str("(?:.*\\.)?");
        i = 1;
        // i 指向的 '.' 吞掉（*.core → core）
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
        }
    }
    // body = m[i..]
    for c in m[i..].chars() {
        if c == '*' {
            out.push_str("[^.]*");
        } else if needs_escape(c) {
            out.push('\\');
            out.push(c);
        } else {
            out.push(c);
        }
    }
    out.push('$');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_star_matches_anything() {
        assert_eq!(wildcard_to_regex("*"), "^.*$");
    }

    #[test]
    fn suffix_star_dot() {
        // *.ads.com → ^(?:\*\.)?ads\.com$ （前导 * 吞掉其后 .）
        assert_eq!(wildcard_to_regex("*.ads.com"), "^(?:.*\\.)?ads\\.com$");
    }

    #[test]
    fn prefix_star_no_dot() {
        // *ads.com → ^(?:\*\.)?ads\.com$
        assert_eq!(wildcard_to_regex("*ads.com"), "^(?:.*\\.)?ads\\.com$");
    }

    #[test]
    fn internal_star_stays_in_label() {
        // ads* → ^ads[^.]*$ （R18：尾部 * 不再剥离）
        assert_eq!(wildcard_to_regex("ads*"), "^ads[^.]*$");
    }

    #[test]
    fn infix_star() {
        // *ac*.com：前导 *(?:.*\.)?，ac 字面，*→[^.]*，.com 转义
        assert_eq!(wildcard_to_regex("*ac*.com"), "^(?:.*\\.)?ac[^.]*\\.com$");
    }
}
