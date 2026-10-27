#!/usr/bin/env bash
# =============================================================================
# ebpdns 2.1.19（2.1.18 修复项 4 / 2.1.18 遗留修复项 2）：**可复现 release 构建** + 稳定摘要校验
# =============================================================================
#
# ⚠️ **醒目警示（2.1.19 起已隔离，但仍请先读）** ⚠️
#
#   * 2.1.18 的本脚本在 wasm 轮里直接跑 `web/build.sh`，而后者写 `web/dist`
#     ⇒ **运行本脚本会改写 `web/dist`，请先备份**：实测把冻结的交付链 wasm
#     `d08c17e5…` 覆盖成 remap 版 `5996e590…`，破坏 `EMBEDDED == DIST` 门禁。
#   * **2.1.19 起已隔离**：wasm 的 target 与产物分别走 `WEB_TARGET_DIR` /
#     `WEB_DIST_DIR`，两者都指到本脚本的 `REPRO_OUT_DIR/wasm-*` 下，
#     因此**本脚本不再触碰 `web/dist`**（收尾会用逐文件 md5 清单自证
#     `DIST_UNTOUCHED: YES`）。
#   * 即便如此，**仍建议先备份 `web/dist`**（例如 `cp -a web/dist /root/dist.bak`）：
#     若有人外部设置了 `REPRO_WASM_DIST_DIR=web/dist`，隔离就会被主动关掉；
#     那时收尾自证会报 `DIST_UNTOUCHED: NO` 并以非 0 退出。
#
# 背景（2.1.17 交付报告错误清单 E1）：同一棵源码树、同一套 cargo 参数，连续三次
# `cargo build --release --bin ebpdns --features embed-frontend` 得到**三个不同的
# md5**（d7136787… / 917d7343… / 1b75cd6d…）。于是"二进制 md5"完全不能当发布门禁，
# 只能用 wasm 的逐字节复现性当代理证据。
#
# 本脚本做五件事：
#   1) **规范化构建环境**（固定 `SOURCE_DATE_EPOCH`、`CARGO_INCREMENTAL=0`、
#      `--remap-path-prefix` 抹掉**源码根 / registry / 目标目录**三处绝对路径、
#      `-C metadata`/`-C extra-filename` 固定、显式 `--build-id=sha1`），
#      然后构建两次（第二**轮前删除产物强制重链**，不再 touch 源码）；
#   2) 比较两次产物的 **md5** 与 **稳定摘要**（剥离 build-id/note 段后的内容哈希）；
#   3) **跨 target 目录矩阵**（`REPRO_CROSS_DIRS`）：N 个不同 `CARGO_TARGET_DIR`
#      各跑 R 轮，断言**跨目录 md5 相同** —— 见下方"为什么需要这一步"；
#   4) wasm 侧同样两轮（**隔离输出**，见上方警示）；
#   5) 输出一份可粘贴的证据块（供交付报告）与退出码：
#        0 = 逐字节可复现（md5 相同）
#        3 = md5 不同但**稳定摘要**相同（等价可复现，差异集中在被剥离的段）
#        4 = 两者都不同（不可复现 —— 脚本会打印首个差异字节、所属 section、
#            差异 section 清单与 `llvm.<hash>` 匿名符号样本，便于精确定位）
#
# **为什么需要"跨 target 目录"这一步（2.1.18 实测的关键边界）**：
# rustc 在 `lto="thin"`（`Cargo.toml` 的 `[profile.release]`）下会把内部化后的
# 局部符号命名为 `anon.<cgu>.<name>.llvm.<module-hash>`，其中 `module-hash`
# 是 **ThinLTO 模块标识（= 目标目录里 bitcode 的路径）**的哈希 —— 于是
# **目标目录不同 ⇒ 同一棵树产出不同字节**（差异只在 `.text`/`.data.rel.ro`/
# `.strtab`/`.symtab`/`.note.gnu.build-id` 的少数几簇，反汇编文本完全相同）。
# 只做"同目录两轮"会**漏掉**这一类不可复现，所以本脚本默认两轮 + 可选跨目录矩阵。
#
# 用法：
#   bash scripts/f218-repro-build.sh                 # 同目录两轮（默认 target-fix219）
#   REPRO_SKIP_WASM=1 bash scripts/f218-repro-build.sh   # 跳过 wasm 前端（只做 bin）
#   REPRO_NATIVE_TARGET_DIR=/root/rc-a REPRO_SKIP_WASM=1 bash scripts/f218-repro-build.sh
#   # 跨 target 目录矩阵（N 目录 × R 轮）：
#   REPRO_SKIP_WASM=1 REPRO_CROSS_DIRS="/root/rc-a /root/rc-b /root/rc-c" \
#     bash scripts/f218-repro-build.sh
#   REPRO_CROSS_ROUNDS=2 REPRO_JOBS=2 ...      # 每目录轮数 / 并行度
#   REPRO_CROSS_SEED=1 ...                     # 第 2..N 个目录由首目录 `cp -a` 播种
#                                              # （只测**链接**路径敏感性，省时）
#   REPRO_OUT_DIR=/root/f219-repro-out ...     # 全部产物/日志/隔离 wasm 的根目录
#
# 依赖：cargo/rustc（$HOME/.cargo/bin）、readelf/objcopy/nm/objdump（binutils）、md5sum、
#       wasm-bindgen（web/build.sh 需要）。全部在目标机 Debian 13 上实测可用。
set -uo pipefail

export PATH="${HOME}/.cargo/bin:${PATH}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

OUT_DIR="${REPRO_OUT_DIR:-${REPRO_OUT_BASE:-/root}/f219-repro-out}"
LOG="$OUT_DIR/repro.log"
mkdir -p "$OUT_DIR"

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
rule() { say "================================================================"; }

# ---------------------------------------------------------------- 0) 版本/工具链
VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1)"
RUSTC_V="$(rustc --version 2>/dev/null || echo 'rustc?')"
CARGO_V="$(cargo --version 2>/dev/null || echo 'cargo?')"
LD_V="$(ld --version 2>/dev/null | head -1 || echo 'ld?')"
HOST_TRIPLE="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
LTO_CFG="$(sed -n '/^\[profile.release\]/,/^\[/p' Cargo.toml | grep -E '^(lto|codegen-units)' | tr '\n' ' ')"

# --------------------------------------------------- 1) SOURCE_DATE_EPOCH（固定）
# 取值优先级：环境变量 > 仓库内 BUILD_EPOCH 文件 > 仓库内固定常量。
# 为什么必须固定：rustc 会把 SOURCE_DATE_EPOCH 用于 archive 成员时间戳
# 与部分诊断输出；不固定则每次构建的 `.rlib`/目标文件时间戳都不同，链接结果随之变化。
EPOCH="${SOURCE_DATE_EPOCH:-}"
if [ -z "$EPOCH" ] && [ -f "$ROOT/BUILD_EPOCH" ]; then
  EPOCH="$(tr -d ' \t\r\n' < "$ROOT/BUILD_EPOCH")"
fi
case "$EPOCH" in
  ''|*[!0-9]*) EPOCH=1760486400 ;;
esac
export SOURCE_DATE_EPOCH="$EPOCH"

# ---------------------------------------------------------- 2) 规范化构建环境
export CARGO_INCREMENTAL=0
export CARGO_ENCODED_RUSTFLAGS=""
export LC_ALL=C
export TZ=UTC

# 目标目录：**必须由本脚本显式指定**。**2.1.19 起 wasm 侧不再依赖 `unset
# CARGO_TARGET_DIR`** —— `web/build.sh` 改为用 `--target-dir "$WEB_TARGET_DIR"` 显式
# 覆盖（2.1.17 登记过"CARGO_TARGET_DIR 泄漏 ⇒ wasm 产到错误目录"这个坑）。
NATIVE_TARGET_DIR="${REPRO_NATIVE_TARGET_DIR:-/root/target-fix219}"
TMPDIR_REAL="${TMPDIR:-/tmp}"
mkdir -p "$NATIVE_TARGET_DIR"

# **2.1.19（2.1.18 遗留修复项 2）**：脚本启动时先给 `web/dist` 拍一份**逐文件 md5 清单**快照，
# 收尾再拍一次对比 —— 把"本脚本没改写 dist"变成可验证事实（2.1.18 无任何此类检查，
# 所以 remap 版 wasm 悄悄覆盖冻结 dist 一直没被发现）。
DIST_SNAP_BEFORE=""
if [ -d "$ROOT/web/dist" ]; then
  DIST_SNAP_BEFORE="$(cd "$ROOT/web/dist" && find . -type f -print0 | sort -z | xargs -0 md5sum | md5sum | awk '{print $1}')"
fi

# RUSTFLAGS 构造：三处绝对路径全部抹成**与机器无关的常量占位符**。
#
# `$NATIVE_TARGET_DIR=/target` 这一条是 2.1.18 补上的关键项：
# ThinLTO 的 `llvm.<module-hash>` 匿名符号名会把**目标目录路径**带进符号表
# （见文件头"为什么需要跨 target 目录这一步"），不规范化则"换目录即换字节"。
make_rustflags() {
  local target_dir="$1" remap_target=""
  # `REPRO_NO_TARGET_REMAP=1`：**A/B 反证专用**（关掉目标目录规范化，用来证明
  # "跨目录不可复现"确实由目标目录路径引起）。正常构建**不要**设它。
  if [ "${REPRO_NO_TARGET_REMAP:-0}" != "1" ]; then
    remap_target="  --remap-path-prefix=$target_dir=/target"
  fi
  printf '%s' " \
  --remap-path-prefix=$ROOT=/ebpdns \
  --remap-path-prefix=$HOME/.cargo/registry=/cargo/registry \
$remap_target \
  --remap-path-prefix=$TMPDIR_REAL=/tmp \
  -C metadata=ebpdns-2.1.21-repro \
  -C extra-filename=-repro \
  -C link-arg=-Wl,--build-id=sha1"
}
# wasm 专用：`-Wl,--build-id=sha1` 只对 GNU ld 有意义（rust-lld 会报错），故只保留 remap。
#
# **2.1.19（2.1.18 遗留修复项 2）**：wasm 的 target 目录现在由 `$1`（`WEB_TARGET_DIR`）给定并一并
# 规范化 —— 2.1.18 写死 `$ROOT/web/target`，因此那时"wasm 在任何别的 target 目录下
# 都不可复现"，也无法隔离输出。
make_wasm_rustflags() {
  local wasm_target="${1:-$ROOT/web/target}"
  printf '%s' " \
  --remap-path-prefix=$ROOT=/ebpdns \
  --remap-path-prefix=$HOME/.cargo/registry=/cargo/registry \
  --remap-path-prefix=$wasm_target=/web-target \
  --remap-path-prefix=$TMPDIR_REAL=/tmp"
}
export RUSTFLAGS="$(make_rustflags "$NATIVE_TARGET_DIR")"

rule
say "ebpdns 可复现构建（2.1.21）"
say "  version            : $VERSION"
say "  rustc              : $RUSTC_V"
say "  cargo              : $CARGO_V"
say "  host               : ${HOST_TRIPLE:-?}"
say "  linker             : $LD_V"
say "  release profile    : ${LTO_CFG:-?}  ← lto=thin 是 llvm.<hash> 匿名符号的来源"
say "  SOURCE_DATE_EPOCH  : $SOURCE_DATE_EPOCH"
say "  CARGO_INCREMENTAL  : $CARGO_INCREMENTAL"
say "  CARGO_TARGET_DIR   : $NATIVE_TARGET_DIR"
say "  RUSTFLAGS          :$(printf '%s' "$RUSTFLAGS" | tr '\n' ' ')"
say "  workspace root     : $ROOT"
rule

# 稳定摘要：剥离「链接器注记」类 section（build-id / .comment / .note.*）后对
# 剩余文件内容取 md5。
#
# **实现细节（实测踩过）**：GNU objcopy 的 `--only-section=a,b,c`（逗号列表）
# **不报错但产出 0 字节**（得到 d41d8cd9… 这个"空文件 md5"的假摘要），
# 因此必须写成**多个 `-j <段>`**。段列表用**显式白名单**（可分配代码/数据/
# 重定位/动态链接段），避免把 `.comment`/`.note.*` 这些注记段算进摘要。
STABLE_SECTIONS="-j .text -j .rodata -j .data -j .data.rel.ro -j .eh_frame \
-j .eh_frame_hdr -j .gcc_except_table -j .init_array -j .fini_array -j .tdata \
-j .dynsym -j .dynstr -j .gnu.hash -j .hash -j .dynamic -j .interp -j .plt \
-j .got -j .got.plt -j .rela.dyn -j .rela.plt"
stable_digest() {
  local bin="$1" tmp
  tmp="$(mktemp)" || return 1
  # shellcheck disable=SC2086
  if objcopy -O binary $STABLE_SECTIONS "$bin" "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    md5sum "$tmp" | awk '{print $1}'
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  printf 'WHOLE_FILE:'
  md5sum "$bin" | awk '{print $1}'
}

md5_of() { md5sum "$1" | awk '{print $1}'; }

# 反汇编**文本**哈希：作为"语义等价"旁证（跨目录字节不同但指令流相同时用它说话）。
#
# **必须 `tail -n +2`**：`objdump -d` 的**第一行是 `<输入文件名>:     file format …`**
# —— 直接哈希会把"输入文件名"算进去（实测：同一份字节复制成两个不同文件名时哈希不同）。
disasm_digest() {
  local bin="$1"
  objdump -d --no-show-raw-insn "$bin" 2>/dev/null | tail -n +2 | md5sum | awk '{print $1}'
}

# 列出两个二进制**逐 section** 不同的段名（一行输出，便于粘贴）。
diff_sections() {
  local a="$1" b="$2" out="" sec ha hb
  for sec in $(readelf -S "$a" 2>/dev/null | sed -n 's/.*\] \(\.[a-zA-Z0-9._-]*\) .*/\1/p' | sort -u); do
    [ -n "$sec" ] || continue
    ha="$(objcopy -O binary --only-section="$sec" "$a" /dev/stdout 2>/dev/null | md5sum | awk '{print $1}')"
    hb="$(objcopy -O binary --only-section="$sec" "$b" /dev/stdout 2>/dev/null | md5sum | awk '{print $1}')"
    [ "$ha" != "$hb" ] && out="$out $sec"
  done
  printf '%s' "${out# }"
}

# 打印 `llvm.<hash>` / `anon.` 匿名符号样本（ThinLTO 路径泄漏的指纹）。
anon_symbols() {
  local bin="$1" n="${2:-6}"
  nm -a "$bin" 2>/dev/null | grep -oE '(anon\.|llvm\.)[A-Za-z0-9._]+' | sort -u | head -n "$n" | tr '\n' ' '
}

build_once() {
  local tag="$1" target_dir="$2"
  # **强制重链**：删掉最终产物，cargo 会重跑链接步骤。
  # 为什么不用 `touch 源码`：① 会改动 `crates/**` 的 mtime（冻结判据不允许任何触碰）；
  # ② 我们真正要测的是**链接阶段**的确定性（ThinLTO 的匿名符号就在这一步生成）。
  rm -f "$target_dir/release/ebpdns"
  say "[$tag] cargo build --release --bin ebpdns --features embed-frontend  (CARGO_TARGET_DIR=$target_dir)"
  (
    export CARGO_TARGET_DIR="$target_dir"
    export RUSTFLAGS="$(make_rustflags "$target_dir")"
    cargo build --release --offline -j "${REPRO_JOBS:-1}" \
      --bin ebpdns --features embed-frontend
  ) >>"$LOG" 2>&1
  local rc=$?
  if [ $rc -ne 0 ]; then
    say "[$tag] 构建失败 rc=$rc（详见 $LOG）"
    return $rc
  fi
  local bin="$target_dir/release/ebpdns"
  if [ ! -f "$bin" ]; then
    say "[$tag] 构建返回 0 但产物不存在：$bin"
    return 4
  fi
  cp -f "$bin" "$OUT_DIR/ebpdns.$tag"
  say "[$tag] md5        = $(md5_of "$OUT_DIR/ebpdns.$tag")"
  say "[$tag] sha256     = $(sha256sum "$OUT_DIR/ebpdns.$tag" | awk '{print $1}')"
  say "[$tag] size       = $(stat -c %s "$OUT_DIR/ebpdns.$tag")"
  say "[$tag] stable     = $(stable_digest "$OUT_DIR/ebpdns.$tag")"
  say "[$tag] disasm     = $(disasm_digest "$OUT_DIR/ebpdns.$tag")"
  say "[$tag] build-id   = $(readelf -n "$OUT_DIR/ebpdns.$tag" 2>/dev/null | sed -n 's/.*Build ID: //p' | head -1)"
  return 0
}

# =============================================================================
# 模式 A：同目录两轮（默认）
# =============================================================================
same_dir_mode() {
  rm -f "$OUT_DIR"/ebpdns.a "$OUT_DIR"/ebpdns.b
  build_once a "$NATIVE_TARGET_DIR" || exit 4
  build_once b "$NATIVE_TARGET_DIR" || exit 4

  local A="$OUT_DIR/ebpdns.a" B="$OUT_DIR/ebpdns.b"
  local MD5A MD5B STA STB
  MD5A="$(md5_of "$A")"; MD5B="$(md5_of "$B")"
  STA="$(stable_digest "$A")"; STB="$(stable_digest "$B")"

  rule
  say "结论（同 target 目录两轮）"
  say "  CARGO_TARGET_DIR = $NATIVE_TARGET_DIR"
  say "  md5(a)          = $MD5A"
  say "  md5(b)          = $MD5B"
  say "  stable(a)       = $STA"
  say "  stable(b)       = $STB"
  if [ "$MD5A" = "$MD5B" ]; then
    say "  VERDICT: BYTE_REPRODUCIBLE（同目录两轮逐字节相同）"
    return 0
  elif [ "$STA" = "$STB" ]; then
    say "  VERDICT: STABLE_REPRODUCIBLE（字节不同，稳定摘要相同 ⇒ 差异只在被剥离的段）"
    say "  DIFFERING_SECTIONS: $(diff_sections "$A" "$B")"
    return 3
  else
    say "  VERDICT: NOT_REPRODUCIBLE（md5 与稳定摘要都不同）"
    say "  首个差异字节：$(cmp "$A" "$B" 2>&1 | head -1)"
    say "  DIFFERING_SECTIONS: $(diff_sections "$A" "$B")"
    say "  anon/llvm 符号样本(a): $(anon_symbols "$A")"
    say "  anon/llvm 符号样本(b): $(anon_symbols "$B")"
    say "  反汇编文本 md5(a)=$(disasm_digest "$A") md5(b)=$(disasm_digest "$B")"
    return 4
  fi
}

# =============================================================================
# 模式 B：跨 target 目录矩阵（REPRO_CROSS_DIRS="dir1 dir2 dir3"）
# =============================================================================
cross_dir_mode() {
  local dirs=($1) rounds="${REPRO_CROSS_ROUNDS:-2}"
  local n=${#dirs[@]}
  say "跨 target 目录矩阵：$n 个目录 × $rounds 轮"
  say "  目录：${dirs[*]}"
  say "  REPRO_CROSS_SEED=${REPRO_CROSS_SEED:-0}（1 = 第 2..N 个目录由首目录 cp -a 播种，只测链接路径敏感性）"
  local idx=0
  for d in "${dirs[@]}"; do
    idx=$((idx + 1))
    mkdir -p "$d"
    if [ "${REPRO_CROSS_SEED:-0}" = "1" ] && [ "$idx" -gt 1 ]; then
      say "[seed] cp -a ${dirs[0]}/. $d/ （复用首目录的编译产物，只重跑链接）"
      rm -rf "$d"; mkdir -p "$d"
      cp -a "${dirs[0]}/." "$d/" >>"$LOG" 2>&1
    fi
    local r=1
    while [ "$r" -le "$rounds" ]; do
      build_once "$(basename "$d").r$r" "$d" || return 4
      r=$((r + 1))
    done
  done

  rule
  say "跨目录结论"
  local seen="" line mism=0 first_bin="" b
  for d in "${dirs[@]}"; do
    local r=1
    while [ "$r" -le "$rounds" ]; do
      b="$OUT_DIR/ebpdns.$(basename "$d").r$r"
      line="$(basename "$d").r$r  md5=$(md5_of "$b")  stable=$(stable_digest "$b")  size=$(stat -c %s "$b")  disasm=$(disasm_digest "$b")"
      say "  $line"
      [ -z "$first_bin" ] && first_bin="$b"
      seen="$seen $(md5_of "$b")"
      r=$((r + 1))
    done
  done
  local uniq
  uniq="$(printf '%s\n' $seen | sort -u | wc -l)"
  say "  唯一 md5 个数 = $uniq（期望 1）"

  # 与首个产物对比：逐对给出 DIFFERING_SECTIONS 与匿名符号样本
  local all_same=1
  for d in "${dirs[@]}"; do
    local r=1
    while [ "$r" -le "$rounds" ]; do
      b="$OUT_DIR/ebpdns.$(basename "$d").r$r"
      if [ "$(md5_of "$b")" != "$(md5_of "$first_bin")" ]; then
        all_same=0
        say "  DIFF vs $(basename "$first_bin"): $(basename "$d").r$r"
        say "    DIFFERING_SECTIONS: $(diff_sections "$first_bin" "$b")"
        say "    anon/llvm 符号样本: $(anon_symbols "$b")"
        say "    disasm 文本相同? $([ "$(disasm_digest "$first_bin")" = "$(disasm_digest "$b")" ] && echo YES || echo NO)"
      fi
      r=$((r + 1))
    done
  done

  if [ "$uniq" = "1" ]; then
    say "  CROSS_DIR_VERDICT: BYTE_REPRODUCIBLE_ACROSS_TARGET_DIRS"
    return 0
  fi
  say "  CROSS_DIR_VERDICT: NOT_REPRODUCIBLE_ACROSS_TARGET_DIRS（同目录内仍逐字节可复现）"
  say "  ⇒ 达成范围边界：**同 target 路径下逐字节可复现**；跨 target 路径的差异来源见上"
  say "     （lto=\"thin\" 的 llvm.<module-hash> 匿名符号把目标目录路径带进了符号表）"
  return 4
}

EXIT=4
if [ -n "${REPRO_CROSS_DIRS:-}" ]; then
  cross_dir_mode "$REPRO_CROSS_DIRS"; EXIT=$?
else
  same_dir_mode; EXIT=$?
fi

# ---------------------------------------- 4) wasm 侧的逐字节复现（可跳过）
# **2.1.19（2.1.18 遗留修复项 2）：wasm 侧完全隔离，绝不触碰 `web/dist`。**
#
# 2.1.18 的缺陷（实测）：本脚本在 wasm 轮里直接 `cd web && bash build.sh`，而
# `web/build.sh` 把产物写到 `web/dist` ⇒ **注入 remap 的构建覆盖了冻结的交付链 dist**
# （`web/dist/app_bg.wasm` 实测从 `d08c17e5…` 变成 `5996e590…`），
# 直接破坏"交付链一致 / `EMBEDDED == DIST`"两条门禁。
#
# 现在：`WEB_TARGET_DIR` 与 `WEB_DIST_DIR` 都指到**本脚本自己的** `REPRO_OUT_DIR` 下，
# 因此 wasm 的中间产物与最终产物都不在源码树里；`web/dist` 物理上不可能被写。
# 收尾还会 `md5sum` 复核 `web/dist`（见文件末尾），把"没碰"变成**可验证**的事实。
WASM_TARGET_DIR="${REPRO_WASM_TARGET_DIR:-$OUT_DIR/wasm-target}"
WASM_DIST_DIR="${REPRO_WASM_DIST_DIR:-$OUT_DIR/wasm-dist}"
if [ "${REPRO_SKIP_WASM:-0}" != "1" ]; then
  rule
  say "wasm 前端（web/）逐字节复现"
  say "  WEB_TARGET_DIR = $WASM_TARGET_DIR   （隔离，非 web/target）"
  say "  WEB_DIST_DIR   = $WASM_DIST_DIR   （隔离，**非** web/dist）"
  # **不再需要 unset CARGO_TARGET_DIR**：`web/build.sh` 现在用 `--target-dir` 显式覆盖，
  # 根 workspace 的 `CARGO_TARGET_DIR` 泄漏不进来（2.1.17 登记过这个坑）。
  # **注意（跨目标目录的边界）**：wasm 侧的产物路径由 `WEB_TARGET_DIR` 决定，
  # 因此现在**跨 target 目录也能做 wasm 复现**（2.1.18 只能在 `web/target` 布局下做）。
  W1=""
  for round in a b; do
    # **2.1.18（修复项 25）**：wasm **始终**注入规范化 remap（源码根 / registry /
    # wasm target 目录），只**去掉** `-Wl,--build-id=sha1`（那是 GNU ld 专用，rust-lld 会报错）。
    # 目的：让"全流程模式"与"`REPRO_SKIP_WASM=1` 的 bin-only 模式"**嵌入同一份 wasm**
    # ⇒ 两种模式的 bin md5 收敛到同一个值。
    #
    # **边界（已量化，勿含糊）**：若 bin-only 模式运行时嵌进二进制里的 wasm **不是**
    # 由本脚本（同一套 wasm 规范化标志）产出的（例如交付链的普通 `web/build.sh` 产物），
    # 则它嵌入的是"外部 wasm" ⇒ 两种模式的 bin md5 必然不同，而**同模式跨 target
    # 目录仍然逐字节一致**。脚本会打印"内嵌 wasm 检查"，据此判定差异来源是 wasm 还是 bin。
    ( export WEB_TARGET_DIR="$WASM_TARGET_DIR" WEB_DIST_DIR="$WASM_DIST_DIR"; \
      export RUSTFLAGS="$(make_wasm_rustflags "$WASM_TARGET_DIR")"; cd web && bash build.sh ) >>"$LOG" 2>&1
    rc=$?
    if [ $rc -ne 0 ]; then say "  web/build.sh 失败 rc=$rc（详见 $LOG）"; EXIT=$(( EXIT>4 ? EXIT : 4 )); break; fi
    cp -f "$WASM_DIST_DIR/app_bg.wasm" "$OUT_DIR/app_bg.wasm.$round"
    say "  wasm($round) md5 = $(md5_of "$OUT_DIR/app_bg.wasm.$round") size=$(stat -c %s "$OUT_DIR/app_bg.wasm.$round")"
    if [ "$round" = "a" ]; then W1="$(md5_of "$OUT_DIR/app_bg.wasm.a")"; else
      W2="$(md5_of "$OUT_DIR/app_bg.wasm.$round")"
      if [ "$W1" = "$W2" ]; then say "  VERDICT: WASM_BYTE_REPRODUCIBLE（$W1）"
      # **跨模式归因**：把"二进制内嵌的 wasm md5"打出来 —— 两种模式 bin md5 不同的
      # 时候，第一件事就是比这一行（不同 ⇒ 差异来自 wasm 而非 bin 规范化）。
      for tag in a b; do
        bin="$OUT_DIR/ebpdns.$tag"
        [ -f "$bin" ] || continue
        emb=$(python3 - "$bin" "$OUT_DIR/app_bg.wasm.$tag" <<'PY'
import hashlib, sys
b = open(sys.argv[1], 'rb').read()
d = open(sys.argv[2], 'rb').read()
print('MATCH@%d' % b.find(d) if b.find(d) >= 0 else 'EMBEDDED_DIFFERS')
PY
)
        say "  内嵌 wasm 检查(ebpdns.$tag) = $emb（期望 MATCH@…；对照的是**本脚本产出的隔离 wasm**，不是 web/dist）"
      done; else say "  VERDICT: WASM_NOT_REPRODUCIBLE（$W1 vs $W2）"; EXIT=$(( EXIT>4 ? EXIT : 4 )); fi
    fi
  done
else
  rule
  say "wasm 前端：已跳过（REPRO_SKIP_WASM=1）—— **未改写 web/dist**（本脚本任何模式下都不改写）"
fi

# =============================================================================
# 5) **收尾自证：`web/dist` 未被本脚本改动**
# =============================================================================
# 为什么值得单独一步：2.1.18 的缺陷恰恰是"脚本悄悄改写了冻结的 dist"，而当时
# **没有任何检查会发现它**。这里把"没碰"变成可验证事实：
#   * 若目录不存在（例如交付树本来就没有 dist），打印 `ABSENT`；
#   * 否则把两次 md5 清单都打印出来（`BEFORE` 是脚本启动时抓的，见下方 `DIST_SNAP_BEFORE`）。
rule
say "web/dist 未被改写的自证"
if [ -d "$ROOT/web/dist" ]; then
  DIST_AFTER="$(cd "$ROOT/web/dist" && find . -type f -print0 | sort -z | xargs -0 md5sum | md5sum | awk '{print $1}')"
  say "  web/dist 清单 md5(after)  = $DIST_AFTER"
  say "  web/dist 清单 md5(before) = ${DIST_SNAP_BEFORE:-<未采集>}"
  if [ -n "${DIST_SNAP_BEFORE:-}" ] && [ "$DIST_SNAP_BEFORE" = "$DIST_AFTER" ]; then
    say "  DIST_UNTOUCHED: YES（逐文件 md5 清单一致）"
  elif [ -z "${DIST_SNAP_BEFORE:-}" ]; then
    say "  DIST_UNTOUCHED: UNKNOWN（启动时未采集基线）"
  else
    say "  DIST_UNTOUCHED: **NO** —— 本脚本改写了 web/dist；请用 git/备份恢复后重跑"
    EXIT=$(( EXIT>4 ? EXIT : 4 ))
  fi
else
  say "  web/dist: ABSENT（本脚本全程使用隔离输出目录 $WASM_DIST_DIR）"
fi

rule
say "日志：$LOG"
say "产物：$OUT_DIR/（ebpdns.<tag>、可选 app_bg.wasm.{a,b}；wasm 中间产物在 $WASM_TARGET_DIR）"
say "EXIT=$EXIT"
exit "$EXIT"
