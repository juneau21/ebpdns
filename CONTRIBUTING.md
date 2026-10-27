# 贡献指南

感谢参与 ebpdns。本项目当前版本（v2.1.1）为 Rust 重写，行为以
Python v1.9.162 为参照基准；实际对照状态（已对齐 / 未验证 / 已知缺口）以 README.md 「与 v1.9.162 的对照状态」为准。

## 开发约定

- **行为对齐优先**：任何改动不得偏离 Python v1.9.162 的既定行为；如确需变更，
  请在 PR 中说明理由，并同步更新规格与测试。
- **核心 DNS 自研**：报文编解码与解析编排不引入第三方 DNS 核心（如 hickory）。
- 提交前必须通过三道质量门：
  ```bash
  cargo fmt --all --check
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
  ```
- TLS 提供方保持统一（ring 或 aws-lc-rs 二选一，勿混用）；详见 `CONVENTIONS.md`。

## unsafe 策略

- 用户态数据面目标为**零 unsafe**；确需 unsafe（FFI 等）时：
  - 集中在最小模块；
  - 每处 unsafe 必须附带 `// SAFETY:` 注释，论证边界、对齐与初始化；
  - 在审查报告的 unsafe 清单中登记。

## 测试

- 新功能必须带单元/集成测试；修复 bug 先写能复现的测试再修复。
- Python 侧 244 个行为向量所覆盖的语义，在 Rust 侧应有对应测试。
- 断言需具体、可防回归，避免仅断言宽泛区间造成“假绿”。

## 提交信息

建议使用 `type(scope): 简述`，如 `fix(resolver): 熔断按语义 rcode 喂点`。

## 许可证

提交即表示你同意以 GPL-3.0-or-later 许可你的贡献。
