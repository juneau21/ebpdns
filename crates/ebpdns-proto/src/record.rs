//! 资源记录（Resource Record）与 question。

use crate::rdata::RData;

/// DNS question 段条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

/// 一条资源记录。`rdata` 为解析后的结构化数据（OPT 已在解析侧跳过，不在此出现）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

impl ResourceRecord {
    /// **[历史归因]** 与 Python 答案字典 `rdata` 字段对齐的字符串值。
    pub fn rdata_str(&self) -> String {
        self.rdata.as_display()
    }
}

/// **[历史归因]** 响应构造的答案输入（对应 Python 的 answer dict：`{type, value, ttl?, name?}`）。
#[derive(Debug, Clone)]
pub struct AnswerInput<'a> {
    /// 记录类型；为 0 时回退到调用方的 `fallback_type`。
    pub rtype: u16,
    /// rdata 字符串值（IP / 域名 / "pref mx" / "p w port target" 等）。
    pub value: &'a str,
    /// 可选 TTL（None → 默认 300）。
    pub ttl: Option<u32>,
    /// 可选 owner name（None → 用统一 `owner_name` 预编码）。
    pub name: Option<&'a str>,
}

impl<'a> AnswerInput<'a> {
    pub fn new(rtype: u16, value: &'a str) -> Self {
        AnswerInput {
            rtype,
            value,
            ttl: None,
            name: None,
        }
    }
    pub fn with_ttl(mut self, ttl: u32) -> Self {
        self.ttl = Some(ttl);
        self
    }
    pub fn with_name(mut self, name: &'a str) -> Self {
        self.name = Some(name);
        self
    }
}
