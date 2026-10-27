# clippy 门禁与**有据可查的允许清单**

本文回答两个问题：**① 现在的 clippy 判据是什么？② 剩下的 `#[allow(...)]` 都是什么、为什么允许？**
所有数字由仓库实测（`grep -rn 'allow(clippy::' crates web tools --include '*.rs'` + 人工核对），
不写"某版本当时清了多少"的历史结论。

## 1. 判据

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings   # web/ 独立 workspace
cargo fmt --all --check
```

- `--all-targets`：lib / bin / 集成测试 / 基准编译单元都必须过（只跑 lib 会漏测试代码里的 deny lint）。
- `-D warnings`：任何新告警都是失败。
- `web/` 被根 workspace `exclude`，必须单独跑（`env -u CARGO_TARGET_DIR`）。
- 单入口：`bash scripts/check_all.sh` 的第 5、8、9 项。

## 2. 当前实测状态

| 项 | 实测 |
|---|---|
| `cargo clippy --workspace --all-targets` | 0 warning / 0 error（允许项见 §3） |
| `cargo fmt --all --check` | 干净 |
| `#[allow(clippy::...)]` 站点 | **43 处**（同一行含两个 lint 的按两个计） |
| 不同 lint 种类 | **19 个** |
| `#[allow(dead_code)]` 站点 | **27 处** |

> **"22 改 / 3 allow" 的口径**：代码清理阶段按审计清单删除了 **22 处** `#[allow(dead_code)]`
> （删除或收进 `#[cfg(test)]`），并保留 **3 类** clippy 允许（`doc_lazy_continuation` /
> `large_enum_variant` / `field_reassign_with_default`）。但"只剩 3 条"是**错误结论**：
> 本树实测仍有 43 处 clippy allow / 27 处 dead_code allow —— 它们全部逐项登记在 §3，
> 未登记的新 allow 不得合入。

## 3. 允许清单（按 lint 汇总）

| # | lint | 站点数 | 位置 / 理由 |
|---:|---|---:|---|
| 1 | `clippy::too_many_arguments` | 14 | 协议编码/解析与扇出函数的参数是**线格式字段**或**编排上下文**，合并成结构体只会把同一组参数换个地方展开，且会改动调用点顺序；逐处在函数上方注释。 |
| 2 | `clippy::doc_lazy_continuation` | 4 | 三个 lib crate 的 crate 级 `#![allow]` + 1 处文档注释。命中的全部是**中文文档注释**：该 lint 用 Markdown 列表缩进规则判连续性，中文条目在 `*`/`-` 后跟全角标点时被误判为"新段落缺空行"。按建议改只是重排中文说明，不改代码行为。 |
| 3 | `clippy::type_complexity` | 4 | 上游扇出/查询闭包/直方图行的嵌套类型；已抽 3 个 type alias，剩余 4 处抽 alias 会让签名跨模块泄漏内部类型。 |
| 4 | `clippy::manual_clamp` | 4 | 区间钳制写在 `match`/分支里且与"0 = 关闭"语义耦合；改成 `clamp` 会改变 0 值的分支顺序。 |
| 5 | `clippy::assertions_on_constants` | 2 | 测试里对常量做断言；已尽量改成编译期 `const _: () = assert!(...)`，剩余两处需要运行时上下文。 |
| 6 | `clippy::while_let_loop` | 2 | TCP 帧循环/读循环需要保留"读到 None 才退出"的显式 `loop`，改成 `while let` 会把退出条件藏进模式匹配。 |
| 7 | `clippy::large_enum_variant` | 1 | `enum Reuse` 的 `Real(TlsConn)` 是连接复用热路径的短生命周期值；装箱 = 每次复用多一次堆分配，只为缩小栈上枚举。 |
| 8 | `clippy::field_reassign_with_default` | 1 | 对抗性测试夹具按"逐字段覆盖默认值"构造 `ResolverConfig`，字段设置与断言交织；产品代码里的同类问题已按建议改掉。 |
| 9 | `clippy::should_implement_trait` | 1 | WAL 读取器的 `next` 与 `Iterator::next` 语义不同（返回 `Result` 且带段边界），实现 trait 会误导调用方。 |
| 10 | `clippy::eq_op` | 1 | 与 `assertions_on_constants` 同一行，用于断言两个常量相等（自比较是有意的契约检查）。 |
| 11 | `clippy::empty_line_after_doc_comments` | 1 | 中文文档块与代码之间的空行是排版需要，删掉会降低可读性。 |
| 12 | `clippy::format_in_format_args` | 1 | `/metrics` 命中率需要先算 `neg_ratio` 再进外层 `format!`；拆开后六位小数逐位不变。 |
| 13 | `clippy::manual_range_contains` | 1 | 区间判断与协议常量表并列书写，改成 `contains` 会打乱"逐类型一行"的可审计格式。 |
| 14 | `clippy::needless_borrows_for_generic_args` | 1 | 调用点需要保持 `&String` 以匹配既有泛型签名，去掉借用会改变类型推断。 |
| 15 | `clippy::missing_const_for_thread_local` | 1 | `thread_local!` 的初始化表达式依赖运行时状态，不能 const。 |
| 16 | `clippy::needless_range_loop` | 1 | 循环同时按下标访问两个数组，`iter()` 无法表达。 |
| 17 | `clippy::redundant_closure` | 1 | 闭包捕获方式与函数指针不同，去糖会改变生命周期。 |
| 18 | `clippy::neg_cmp_op_on_partial_ord` | 1 | 浮点比较需要保留 `!(a < b)` 的 NaN 语义，改成 `>=` 会把 NaN 判成真。 |
| 19 | `clippy::manual_is_multiple_of` | 1 | 测试里的取模断言与边界值并列，改成 `is_multiple_of` 会降低可读性。 |

> 允许的粒度是 **lint + 作用域**，不是"整文件免责"：crate 级 `#![allow]` 只用于
> `doc_lazy_continuation`（三个 lib crate），其余全部是单函数/单实现的 `#[allow]`。
> 新增 allow 必须在同一行或上一行写明理由，并在本表登记；否则评审拒绝。

## 4. dead_code 的登记口径

- 27 处 `#[allow(dead_code)]` 中，测试夹具与对账 helper 优先收进 `#[cfg(test)]`，
  平台 ABI 字段（Win32 时区结构）与 feature 组合差异**必须保留**并注明。
- 删除死代码前先跑 `cargo clippy --workspace --all-targets` 与 `cargo test --workspace`；
  只删"全仓零引用且不在测试/宏/重导出里"的项。
- 任何"看着像指标、实际是桩"的函数（永远返回 0）优先删除，而不是保留 allow。

## 5. 未做项

- `pedantic` / `nursery` 组未开启：会引入数百条风格建议，与"不改变可观测行为"的目标无关。
- `unsafe` 未做专项安全审计；新增 `unsafe` 必须有 `// SAFETY:` 注释并在评审单列。
- 允许清单会随上游 clippy 规则变化而复核；若某条 lint 被上游改判，按新建议修掉并删除对应 allow。
