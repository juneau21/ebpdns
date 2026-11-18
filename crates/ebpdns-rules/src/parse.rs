//! 域名列表文本解析：hosts / AdBlock(AdGuard) / dnsmasq / SmartDNS / Surge / Clash YAML。
//!
//! **[历史归因]** 忠实对齐 Python `api._parse_domain_list`（resolver._parse_domain_list 是其子集）。
//! 导出去重后的域名列表（保留 `*.` 通配与 `re:` 高级规则前缀）。

use once_cell::sync::Lazy;
use regex::Regex;
use std::net::IpAddr;

static RE_YAML_KEY: Lazy<Regex> = Lazy::new(|| Regex::new(r"^[a-z_]+\s*:\s*$").unwrap());
static RE_DNSMASQ: Lazy<Regex> = Lazy::new(|| Regex::new(r"address\s*=\s*/([^\s]+)").unwrap());
static RE_DNSMASQ2: Lazy<Regex> = Lazy::new(|| Regex::new(r"^address\s+/([^/\s]+)").unwrap());
static RE_SURGE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:DOMAIN-SUFFIX|DOMAIN|DOMAIN-KEYWORD|HOST-SUFFIX|HOST)\s*,\s*(.+)$").unwrap()
});
static RE_CLASH: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^- *["'+]*\.?([A-Za-z0-9_.-]+)"#).unwrap());
static RE_ADBLOCK: Lazy<Regex> = Lazy::new(|| Regex::new(r"^\|\|([^/^]+)").unwrap());
static RE_DOMAIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(\*\.)?[a-z0-9_\-]+(\.[a-z0-9_\-]+)*$").unwrap());

/// match 字段字节上限（对齐 api 4096）。
const MATCH_MAX_BYTES: usize = 4096;

fn has_control_char(s: &str) -> bool {
    s.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// 单条 token 清洗 + 校验，决定是否收入。
fn add(tok: &str, out: &mut Vec<String>, seen: &mut std::collections::HashSet<String>) {
    // strip / 去 []() / 去尾点 / 小写。
    let tok = tok.trim().trim_matches(&['[', ']', '(', ')'] as &[_]);
    let tok = tok.trim_matches('.').to_ascii_lowercase();
    if tok.is_empty() {
        return;
    }
    // 裸 IP（hosts 首列）不是域名，跳过。
    if tok
        .trim_matches(&['[', ']'] as &[_])
        .parse::<IpAddr>()
        .is_ok()
    {
        return;
    }
    // 高级规则前缀 re:：原样保留并做加载期合法性闸门（对齐 api._check_rule_regex）。
    if let Some(rest) = tok.strip_prefix("re:") {
        if tok.len() > MATCH_MAX_BYTES || has_control_char(&tok) {
            return;
        }
        if rest.trim().is_empty() {
            return; // 拒绝裸 re:（空体恒命中零宽位置 = 屏蔽全域）
        }
        if Regex::new(rest).is_err() {
            return; // 非法正则 → 跳过
        }
        if seen.insert(tok.clone()) {
            out.push(tok);
        }
        return;
    }
    // 普通域名：去路径/端口，再用域名白名单正则校验。
    let tok = tok.split('/').next().unwrap_or("");
    let tok = tok.split(':').next().unwrap_or("");
    let tok = tok.trim_matches('.');
    if !RE_DOMAIN.is_match(tok) {
        return;
    }
    if seen.insert(tok.to_string()) {
        out.push(tok.to_string());
    }
}

/// 解析域名列表文本 → 去重后的域名/规则列表。
pub fn parse_domain_list(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // 注释 / AdGuard 例外（@@ 语义是放行，不能当拦截导入）。
        if line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        if line.starts_with("@@") {
            continue;
        }
        // YAML 顶层键（payload: / rules:）非域名。
        if RE_YAML_KEY.is_match(line) {
            continue;
        }
        // dnsmasq: address=/a.com/b.com/ 一行可含多个域名。
        if let Some(m) = RE_DNSMASQ.captures(line) {
            let inner = m.get(1).map(|x| x.as_str()).unwrap_or("").trim_matches('/');
            for seg in inner.split('/') {
                add(seg, &mut out, &mut seen);
            }
            continue;
        }
        if let Some(m) = RE_DNSMASQ2.captures(line) {
            add(
                m.get(1).map(|x| x.as_str()).unwrap_or(""),
                &mut out,
                &mut seen,
            );
            continue;
        }
        // Surge / Clash 命名规则行。
        if let Some(m) = RE_SURGE.captures(line) {
            add(
                m.get(1).map(|x| x.as_str()).unwrap_or(""),
                &mut out,
                &mut seen,
            );
            continue;
        }
        // Clash YAML 列表项：- '+.域名'
        if let Some(m) = RE_CLASH.captures(line) {
            add(
                m.get(1).map(|x| x.as_str()).unwrap_or(""),
                &mut out,
                &mut seen,
            );
            continue;
        }
        // AdBlock: ||domain^
        if let Some(m) = RE_ADBLOCK.captures(line) {
            let host = m
                .get(1)
                .map(|x| x.as_str())
                .unwrap_or("")
                .trim_end_matches('^');
            add(host, &mut out, &mut seen);
            continue;
        }
        // 兜底：hosts / 纯域名 / 逗号分隔。
        //
        // 旧实现只取 `split_whitespace().last()` 再按逗号切 —— 于是
        // `a.com,b.com,c.com`（整行逗号分隔，订阅里极常见）只解析出最后一个域名。
        // 改为：整行按空白切分，每个 token 再按逗号切分，逐段交给 `add`；
        // hosts 行（`0.0.0.0 blocked.example`）的裸 IP 段由 `add` 的 IP 过滤丢弃，
        // **[历史归因]** 行为与 Python `_parse_domain_list` 的「逐列取候选」一致。
        for part in line.split_whitespace() {
            for seg in part.split(',') {
                add(seg, &mut out, &mut seen);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_format() {
        let t = "127.0.0.1 example.com\n127.0.0.1 ads.test\n::6 localhost";
        let d = parse_domain_list(t);
        assert!(d.contains(&"example.com".to_string()));
        assert!(d.contains(&"ads.test".to_string()));
        // 裸 IP / localhost 之类
        assert!(!d.iter().any(|x| x == "127.0.0.1"));
    }

    #[test]
    fn adguard_and_comments() {
        let t = "! title line\n# comment\n||ads.com^\n@@||allow.com^\n||track.net^";
        let d = parse_domain_list(t);
        assert!(d.contains(&"ads.com".to_string()));
        assert!(!d.iter().any(|x| x.contains("allow.com"))); // @@ 例外跳过
        assert!(d.contains(&"track.net".to_string()));
    }

    #[test]
    fn skips_bare_ip_and_invalid() {
        let d = parse_domain_list("1.2.3.4\nnot a space line\n_.bad\nok.com");
        assert!(d.contains(&"ok.com".to_string()));
        assert!(!d.iter().any(|x| x == "1.2.3.4"));
    }

    #[test]
    fn dedup_preserves_wildcard() {
        let t = "*.cdn.com\n*.cdn.com\ncdn.com";
        let d = parse_domain_list(t);
        assert_eq!(d.iter().filter(|x| x.as_str() == "*.cdn.com").count(), 1);
        assert!(d.contains(&"cdn.com".to_string()));
    }
}
