#!/bin/bash
# =============================================================================
# ebpdns **2.1.28（B1/B2）**：release 构建的 `--remap-path-prefix` 规范值（**单一来源**）
#
# 为什么需要它：交付的 `bin/ebpdns` 里会嵌进**构建机的绝对路径**（2.1.26 实测：
# `/root/` 命中 627 次、`cargo/registry` 574 次、构建目录名 `e226` 9 次）——
# 那既是构建环境的泄漏，也是"同一份源码换个绝对路径构建就换一份字节"的一部分
# 原因（2.1.26 的 B5 只做到"跨 target 目录逐字节可复现"，跨源码路径仍不可复现）。
#
# 做法：把 **源码根** 常量化为 `/build/ebpdns`（2.1.28 起交付链**真的在那个路径构建**，
# 见 `make_packages_221r2.sh` 第 1/2 步）、把 **cargo registry** 常量化为
# `/cargo/registry`、把 **rustup 工具链**常量化为 `/rust`（2.1.28 新增：抹掉 2.1.27
# 交付物里残留的 53 条 `/root/.rustup/toolchains/.../library/...`）。
# 目标目录（`<root>/target`、`<root>/web/target`）都在源码根之下，
# 因此被第一条前缀覆盖，不需要单独一条规则。
#
# **只动构建参数，不动 `[profile.release]`**：`lto` / `codegen-units` / `opt-level`
# 一行未改（2.1.26 的 B5 已实测"改档位治不了跨路径不可复现"，而且那是性能档位）。
#
# 用法：
#   RUSTFLAGS="$(bash scripts/_repro_flags.sh <tree-root>)"        bash ...cargo build...
#   RUSTFLAGS="$(bash scripts/_repro_flags.sh <tree-root> --wasm)" bash web/build.sh
#
# 输出：**一行**、空格分隔的 flags（可直接塞进 RUSTFLAGS）；不换行、不带尾随空白。
# 注意：`--wasm` 目前与原生**同一套**前缀（wasm 的 target 目录同样在源码根下）；
# 保留这个开关是为了将来 wasm 侧需要额外规则时**只有一个改动点**。
#
# **wasm 对 remap 敏感（2.1.27 实测，2.1.28 复测）**：不带 remap 构建的 `app_bg.wasm`
# 与交付的那份**不是同一份字节**（2.1.27 实测差 320 B：89ffcb05…/5,799,794 vs
# 7996695f…/5,799,474）⇒ 交付链**必须**用本脚本的 `--wasm` 输出，不得手写/省略。
# =============================================================================
set -uo pipefail

ROOT="${1:-}"
MODE="${2:-native}"
if [ -z "$ROOT" ]; then
  echo "usage: bash scripts/_repro_flags.sh <tree-root> [--wasm]" >&2
  exit 2
fi
[ -d "$ROOT" ] || { echo "tree-root 不存在：$ROOT" >&2; exit 2; }
case "$MODE" in
  native|--wasm) ;;
  *) echo "未知模式：$MODE（只接受 --wasm）" >&2; exit 2 ;;
esac

# 物理路径：符号链接会让 remap 前缀与实际传给 rustc 的路径对不上（实测过）。
ROOT="$(cd "$ROOT" && pwd -P)"

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
REGISTRY="$CARGO_HOME_DIR/registry"
if [ -d "$REGISTRY" ]; then
  REGISTRY="$(cd "$REGISTRY" && pwd -P)"
fi

# **2.1.28（B1）**：rustup 工具链路径（`$HOME/.rustup/toolchains/<tc>/lib/rustlib/src/rust/library/...`）
# 在 2.1.27 的交付 bin 里残留 53 条。它不随源码路径变，但**随构建用户 HOME 变**，属于
# "构建环境泄漏"；归一成 `/rust` 后任何用户/CI 构建出的字节都一致。目录不存在时仍然发出
# 这条 remap（rustc 对不存在的前缀只是不命中，不会报错）。
RUSTUP_DIR="${RUSTUP_HOME:-$HOME/.rustup}"
if [ -d "$RUSTUP_DIR" ]; then
  RUSTUP_DIR="$(cd "$RUSTUP_DIR" && pwd -P)"
fi

FLAGS="--remap-path-prefix=$ROOT=/build/ebpdns"
FLAGS="$FLAGS --remap-path-prefix=$REGISTRY=/cargo/registry"
FLAGS="$FLAGS --remap-path-prefix=$RUSTUP_DIR=/rust"

# **边界**：这里**刻意**不加 `-C metadata` / `-C extra-filename` /
# `-C link-arg=-Wl,--build-id=sha1`：
#   * `-C metadata` 会被 cargo 自己的 `-C metadata=<hash>` **覆盖**（RUSTFLAGS 追加在最后），
#     而 `-C extra-filename` 会让 cargo 的产物文件名与 `--extern` 名字对不上（实测直接
#     编译失败）。两者都属于"改 cargo 的哈希输入"，不是本批的目标；
#   * build-id 由链接器默认策略决定，不注入。
# **2.1.28 的结论**：跨源码路径的逐字节差异（2.1.27 残差 700 B）来自 ThinLTO 的
# `llvm.<module-hash>`，它**不经过** `--remap-path-prefix`；2.1.28 用**固定物理构建路径**
# （交付链与 `_repro_crosspath.sh` 都播种到 `/build/ebpdns`）消除它，而不是改 cargo 的哈希。
printf '%s' "$FLAGS"
