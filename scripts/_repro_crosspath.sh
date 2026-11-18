#!/bin/bash
# =============================================================================
# ebpdns **2.1.28（B1）**：**异路径双构建比对** —— 同一份源码放在两个不同绝对路径下，
# 各自把源码树**播种到固定构建路径** `/build/ebpdns` 再构建，`bin/ebpdns` 是否逐字节相同？
#
# 背景（2.1.26/2.1.27 实测，已登记）：三个发布档位（thin / fat / strip）在**同一棵树、
# 同一 target 目录**下重复构建**逐字节相同**，但换成**另一个源码路径**就不同
# （2.1.27 实测残差 700 B，成因是 ThinLTO 的 `llvm.<module-hash>` 对**物理构建路径**敏感，
# 而 `--remap-path-prefix` 只改诊断/调试信息里的路径、改不到它）。改 `[profile.release]`
# 治不了它（而且那是性能档位，本批禁止）。2.1.28 的做法是**固定物理构建路径**：
# 交付链与本源都把源码树播种到 `/build/ebpdns` 再构建（见 `make_packages_221r2.sh` 第 1/2 步）。
#
# 做法：
#   1) 把当前树复制到两个**不同绝对路径**下（默认 `$HOME/f228-xpath/rp-a/ebpdns-<v>` 与
#      `.../rp-b/ebpdns-<v>`）；
#   2) 每个来源树各自：播种到 `/build/ebpdns` → 源码 mtime 钉到 `BUILD_EPOCH` →
#      重编 wasm（带 remap）→ 把 dist mtime 钉到 `BUILD_EPOCH` → `cargo clean -p` 后
#      构建 `embed-frontend` 二进制（带 remap）→ 产物搬到 `$BASE/bin-<tag>/ebpdns`；
#   3) `cmp` 两个二进制；不同则打印**首个差异偏移**、差异 section 清单、差异字节数；
#   4) 用 A 的来源树**再构建一次**（同固定路径）⇒ 证明"同路径重复构建逐字节相同"；
#   5) 两侧 `--version` / `--help` 逐字节比对，`EMBEDDED==DIST` 各自成立；
#   6) **路径残留计数**：`$ROOT` / `/root/` / `/root/.rustup` / `/root/.cargo` /
#      `cargo/registry` / `/build/ebpdns` / `/rust/toolchains` 的命中次数
#      （remap + 固定路径到底抹掉了什么）；
#   7) 收尾自证**没有碰过**源树的 `web/dist`（本脚本只在副本/固定路径里构建）。
#
# 用法：
#   bash scripts/_repro_crosspath.sh                     # 用默认 base
#   bash scripts/_repro_crosspath.sh /root/x228 --keep   # 指定 base 并保留副本
#   REPRO_XPATH_SEED=1 bash scripts/_repro_crosspath.sh  # 已存在副本时重新播种（默认复用）
#   REPRO_XPATH_SKIP_ROUND2=1 bash scripts/_repro_crosspath.sh
#       # 跳过"同路径第二轮"（省一次整树构建；同路径判据也可由打包两轮给出）
#   EBP_BUILD_ROOT=/build/ebpdns bash scripts/_repro_crosspath.sh   # 固定构建路径（默认）
#
# 退出码：0 = 异路径逐字节相同（跨路径可复现成立）
#         1 = 异路径不同（**如实失败**：打印首个差异偏移与差异 section）
#         2 = 环境/构建失败（不是判据失败）
# =============================================================================
set -uo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

BASE="${1:-${HOME}/f228-xpath}"
case "$BASE" in
  --*) BASE="${HOME}/f228-xpath" ;;
esac
KEEP=0
for a in "$@"; do
  [ "$a" = "--keep" ] && KEEP=1
done
unset CARGO_TARGET_DIR

BPATH="${EBP_BUILD_ROOT:-/build/ebpdns}"

VERSION="$(sed -n '/^\[workspace.package\]/,/^\[/p' Cargo.toml \
  | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1)"
[ -n "$VERSION" ] || { echo "无法从 Cargo.toml 解析版本号" >&2; exit 2; }
EPOCH="$(tr -d '[:space:]' < BUILD_EPOCH 2>/dev/null || true)"
[ -n "$EPOCH" ] || { echo "BUILD_EPOCH 缺失（可复现构建必需）" >&2; exit 2; }
NAME="ebpdns-${VERSION}"

# **2.1.28（B1 的根因）**：`rust-embed` 会把 `web/dist` 文件的 `last_modified` 与 `created`
# 编进二进制（`rust-embed-utils`：`source_date_epoch.or(created)`）。不设 `SOURCE_DATE_EPOCH`
# 时 `created` = 文件系统 btime（每次重编/拷贝 dist 都变）⇒ 两次全量构建字节不同。
# 交付链与本源都必须导出同一个 `BUILD_EPOCH`，这是"跨时间/跨来源路径逐字节相同"的前提。
export SOURCE_DATE_EPOCH="$EPOCH"

A_PARENT="$BASE/rp-a"; B_PARENT="$BASE/rp-b"
A="$A_PARENT/$NAME";   B="$B_PARENT/$NAME"
LOG="$BASE/crosspath.log"
mkdir -p "$BASE" || exit 2

say() { printf '%s\n' "$*" | tee -a "$LOG"; }
rule() { say "----------------------------------------------------------------"; }

# 源树 web/dist 的快照（收尾自证"没碰过"）
DIST_BEFORE=""
if [ -d "$ROOT/web/dist" ]; then
  DIST_BEFORE="$(cd "$ROOT/web/dist" && find . -type f -print0 | sort -z | xargs -0 md5sum | md5sum | awk '{print $1}')"
fi

rule
say "ebpdns 异路径双构建比对（2.1.28 / B1：固定构建路径）  $(date -u '+%FT%TZ')"
say "  源码树         : $ROOT"
say "  版本           : $VERSION"
say "  BUILD_EPOCH    : $EPOCH"
say "  固定构建路径   : $BPATH"
say "  A              : $A"
say "  B              : $B"
say "  RECLAIM        : ${REPRO_XPATH_RECLAIM:-0}（1 = 每棵构建完立即回收 target）"
say "  说明           : 每个来源树都**播种到同一个物理路径**再构建；remap 仍按该路径计算"
say "  df             : $(df -h / | tail -1)"
rule

seed_tree() { # $1 = target dir
  local dst="$1"
  rm -rf "$dst"
  mkdir -p "$dst" || return 1
  # 只复制"源码树"该有的东西：排除构建产物与出包目录（与源码包口径一致）。
  tar -C "$ROOT" \
      --exclude='./target' --exclude='./web/target' --exclude='./web/dist' \
      --exclude='./dist-packages' --exclude='./.git' \
      --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
      -cf - . 2>/dev/null | tar -C "$dst" -xpf - 2>/dev/null
  [ -f "$dst/Cargo.toml" ]
}

build_all() { # $1 = 来源树, $2 = tag
  local src="$1" tag="$2" log="$BASE/build-$2.log"
  local FLAGS FLAGS_WASM
  say "[$tag] 来源树 = $src"
  # **固定物理构建路径**：清空后从来源树播种（tar 保留 mtime）。
  rm -rf "$BPATH"
  mkdir -p "$BPATH" || return 2
  tar -C "$src" -cf - . 2>/dev/null | tar -C "$BPATH" -xpf - 2>/dev/null
  [ -f "$BPATH/Cargo.toml" ] || { say "[$tag] **播种 $BPATH 失败**"; return 2; }
  # remap 的前缀必须是**这次构建实际使用的物理路径**（= $BPATH）；
  # cargo registry / rustup 的前缀由 `_repro_flags.sh` 现算。
  FLAGS="$(bash "$HERE/_repro_flags.sh" "$BPATH")" || return 2
  FLAGS_WASM="$(bash "$HERE/_repro_flags.sh" "$BPATH" --wasm)" || return 2
  say "[$tag] RUSTFLAGS      = $FLAGS"
  say "[$tag] RUSTFLAGS(wasm) = $FLAGS_WASM"
  say "[$tag] 构建开始（日志 $log）  df=$(df -h / | tail -1 | awk '{print $4}')"
  (
    cd "$BPATH" || exit 2
    # ① 源码 mtime 钉到 EPOCH（与交付链第 1 步同口径）
    find web/src -type f -name '*.rs' -print0 | xargs -0 -r touch -d "@$EPOCH"
    for f in web/Cargo.toml web/index.html web/style.css web/build.rs; do
      [ -f "$f" ] && touch -d "@$EPOCH" "$f"
    done
    # ② 重编 wasm（带 remap）
    rm -rf web/target web/dist
    ( cd web && RUSTFLAGS="$FLAGS_WASM" bash build.sh )
    # ③ dist mtime 钉到 EPOCH（rust-embed 会把 mtime 编进二进制）
    find web/dist -maxdepth 1 -type f -print0 | xargs -0 -r touch -d "@$EPOCH"
    # ④ 二进制（带 remap）；先清掉内嵌那一层的目标文件，避免复用上一轮的 rlib
    cargo clean -p ebpdns-server --release >/dev/null 2>&1 || true
    cargo clean -p ebpdns --release >/dev/null 2>&1 || true
    RUSTFLAGS="$FLAGS" cargo build --release --offline --bin ebpdns --features embed-frontend
  ) >>"$log" 2>&1
  local rc=$?
  if [ $rc -ne 0 ] || [ ! -f "$BPATH/target/release/ebpdns" ]; then
    say "[$tag] **构建失败** rc=$rc（详见 $log）"
    return 2
  fi
  # 把产物**搬出**固定路径（后面会清空它；比对也不该依赖构建目录）。
  # **必须让两份副本同名**（`bin-<tag>/ebpdns`）：clap 的 `--help` 会把 `argv[0]` 的
  # basename 打进 `Usage:` 行，若一份叫 `bin.A`、一份叫 `bin.B`，`--help` 就会"不同"——
  # 那是**harness 造出来的差异**（2.1.27 实测踩到），不是产品差异。
  mkdir -p "$BASE/bin-$tag" || return 2
  cp -f "$BPATH/target/release/ebpdns" "$BASE/bin-$tag/ebpdns" || return 2
  say "[$tag] bin  md5=$(md5sum "$BASE/bin-$tag/ebpdns" | cut -d' ' -f1) size=$(stat -c %s "$BASE/bin-$tag/ebpdns")"
  say "[$tag] wasm md5=$(md5sum "$BPATH/web/dist/app_bg.wasm" | cut -d' ' -f1) size=$(stat -c %s "$BPATH/web/dist/app_bg.wasm")"
  # EMBEDDED == DIST（用**这次构建**的 dist，而不是来源树里可能过期的 dist）
  if python3 "$HERE/_embed_check.py" "$BASE/bin-$tag/ebpdns" "$BPATH/web/dist" >"$BASE/embed.$tag.txt" 2>&1; then
    say "[$tag] EMBEDDED_EQ_DIST=YES  $(grep -o 'BIN_MD5=.*' "$BASE/embed.$tag.txt")"
  else
    say "[$tag] **EMBEDDED_EQ_DIST=NO**（详见 $BASE/embed.$tag.txt）"
    return 2
  fi
  if [ "${REPRO_XPATH_RECLAIM:-0}" = "1" ]; then
    rm -rf "$BPATH"
    say "[$tag] 已回收固定构建路径（RECLAIM=1）  df=$(df -h / | tail -1 | awk '{print $4}')"
  fi
  return 0
}

# ---------------- 播种两棵异路径来源树 ----------------
if [ "${REPRO_XPATH_SEED:-0}" = "1" ] || [ ! -f "$A/Cargo.toml" ] || [ ! -f "$B/Cargo.toml" ]; then
  say "播种两棵异路径来源树（tar 复制，保留 mtime）…"
  seed_tree "$A" || { echo "seeding A failed" >&2; exit 2; }
  seed_tree "$B" || { echo "seeding B failed" >&2; exit 2; }
fi

# ---------------- A / B 各构建一次 ----------------
build_all "$A" A || exit 2
build_all "$B" B || exit 2

ABIN="$BASE/bin-A/ebpdns"
BBIN="$BASE/bin-B/ebpdns"
AM="$(md5sum "$ABIN" | cut -d' ' -f1)"
BM="$(md5sum "$BBIN" | cut -d' ' -f1)"
ASZ="$(stat -c %s "$ABIN")"
BSZ="$(stat -c %s "$BBIN")"

rule
say "异路径结果"
say "  A: md5=$AM size=$ASZ"
say "  B: md5=$BM size=$BSZ"
VERDICT=1
if [ "$AM" = "$BM" ]; then
  say "  **X_PATH_BIN_IDENTICAL=YES**（不同来源路径、同一固定构建路径 ⇒ 逐字节相同）"
  VERDICT=0
else
  say "  **X_PATH_BIN_IDENTICAL=NO**（字节不同 —— 如实记录，不修饰）"
  say "  首个差异字节：$(cmp "$ABIN" "$BBIN" 2>&1 | head -1)"
  say "  差异字节数  ：$(cmp -l "$ABIN" "$BBIN" 2>/dev/null | wc -l) / $ASZ"
  # 逐 section 定位（objcopy 单段提取；逗号列表在 2.1.19 实测会静默产出 0 字节）
  DIFFSEC=""
  for s in $(readelf -S "$ABIN" 2>/dev/null | sed -n 's/.*\] \(\.[a-zA-Z0-9._-]*\).*/\1/p' | sort -u); do
    ha="$(objcopy -O binary --only-section="$s" "$ABIN" /dev/stdout 2>/dev/null | md5sum | awk '{print $1}')"
    hb="$(objcopy -O binary --only-section="$s" "$BBIN" /dev/stdout 2>/dev/null | md5sum | awk '{print $1}')"
    [ "$ha" != "$hb" ] && DIFFSEC="$DIFFSEC $s"
  done
  say "  差异 section：${DIFFSEC# }"
  say "  cgu/anon 符号样本(A)：$(nm -a "$ABIN" 2>/dev/null | grep -oE '(anon\.|llvm\.)[A-Za-z0-9._]+|[A-Za-z0-9_]+\.(llvm\.)?[0-9a-f]{16}-cgu\.[0-9]+' | sort -u | head -4 | tr '\n' ' ')"
  say "  cgu/anon 符号样本(B)：$(nm -a "$BBIN" 2>/dev/null | grep -oE '(anon\.|llvm\.)[A-Za-z0-9._]+|[A-Za-z0-9_]+\.(llvm\.)?[0-9a-f]{16}-cgu\.[0-9]+' | sort -u | head -4 | tr '\n' ' ')"
fi

# ---------------- 路径残留计数（remap + 固定路径到底抹掉了什么）----------------
rule
say "路径残留计数（strings -a | grep -c；A/B 两侧 + 源树路径）"
for pair in "A:$ABIN" "B:$BBIN"; do
  tag="${pair%%:*}"; bin="${pair#*:}"
  say "  [$tag] 源码树路径命中        = $(strings -a "$bin" | grep -c -F "$ROOT" || true)"
  say "  [$tag] /root/ 命中           = $(strings -a "$bin" | grep -c '/root/' || true)"
  say "  [$tag] /root/.rustup 命中    = $(strings -a "$bin" | grep -c '/root/.rustup' || true)"
  say "  [$tag] /root/.cargo 命中     = $(strings -a "$bin" | grep -c '/root/.cargo' || true)"
  say "  [$tag] cargo/registry 命中   = $(strings -a "$bin" | grep -c 'cargo/registry' || true)"
  say "  [$tag] /build/ebpdns 命中    = $(strings -a "$bin" | grep -c -F '/build/ebpdns' || true)"
  say "  [$tag] /rust/toolchains 命中 = $(strings -a "$bin" | grep -c '/rust/toolchains' || true)"
done

# ---------------- 同路径重复构建（同一固定路径再来一次）----------------
rule
say "同路径重复构建（A 的来源树 → 固定路径第二轮）"
if [ "${REPRO_XPATH_SKIP_ROUND2:-0}" = "1" ]; then
  say "  SAME_PATH_RB_IDENTICAL=SKIPPED（REPRO_XPATH_SKIP_ROUND2=1）"
  say "  说明：同路径重复构建的逐字节判据由**打包两轮**给出 —— \`make_packages_221r2.sh\` 两次"
  say "        在同一固定路径里各清一次、各构建一次，两轮 bin md5 相同即 SAME_PATH_RB_IDENTICAL=YES。"
else
  build_all "$A" A2 || exit 2
  A2BIN="$BASE/bin-A2/ebpdns"
  A2M="$(md5sum "$A2BIN" | cut -d' ' -f1)"
  say "  A.r1 md5=$AM"
  say "  A.r2 md5=$A2M"
  if [ "$A2M" = "$AM" ]; then
    say "  **SAME_PATH_RB_IDENTICAL=YES**"
  else
    say "  **SAME_PATH_RB_IDENTICAL=NO**（同路径重复构建都不稳定 ⇒ 先查 rust-embed mtime / 增量）"
    VERDICT=1
  fi
fi

# ---------------- 对外行为面：--version / --help ----------------
rule
say "对外行为面比对"
"$ABIN" --version >"$BASE/ver.A.txt" 2>&1
"$BBIN" --version >"$BASE/ver.B.txt" 2>&1
if cmp -s "$BASE/ver.A.txt" "$BASE/ver.B.txt"; then
  say "  --version 相同：$(tr -d '\n' <"$BASE/ver.A.txt")"
else
  say "  **--version 不同**：A=$(tr -d '\n' <"$BASE/ver.A.txt") B=$(tr -d '\n' <"$BASE/ver.B.txt")"
  VERDICT=1
fi
"$ABIN" --help >"$BASE/help.A.txt" 2>&1
"$BBIN" --help >"$BASE/help.B.txt" 2>&1
if cmp -s "$BASE/help.A.txt" "$BASE/help.B.txt"; then
  say "  --help 相同（$(wc -l <"$BASE/help.A.txt") 行）"
else
  say "  **--help 不同**"
  VERDICT=1
fi

# ---------------- 收尾：源树 web/dist 未被改写 ----------------
rule
if [ -d "$ROOT/web/dist" ]; then
  DIST_AFTER="$(cd "$ROOT/web/dist" && find . -type f -print0 | sort -z | xargs -0 md5sum | md5sum | awk '{print $1}')"
  if [ -n "$DIST_BEFORE" ] && [ "$DIST_BEFORE" = "$DIST_AFTER" ]; then
    say "  DIST_UNTOUCHED=YES（源树 web/dist 逐文件 md5 清单一致）"
  else
    say "  **DIST_UNTOUCHED=NO** —— 本脚本改写了源树 web/dist（不应发生）"
    exit 2
  fi
else
  say "  DIST_UNTOUCHED=ABSENT（源树没有 web/dist）"
fi

if [ "$KEEP" = "1" ]; then
  say "  保留副本：$A / $B（固定构建路径 $BPATH 也保留）"
else
  say "  回收来源副本：$A_PARENT / $B_PARENT（--keep 可保留）"
  rm -rf "$A_PARENT" "$B_PARENT"
  rm -rf "$BPATH"
fi
say "  产物副本：$BASE/bin-A/ebpdns / $BASE/bin-B/ebpdns（**同名**，比对用的就是这两份字节）"
say "  df：$(df -h / | tail -1)"
say "CROSSPATH_VERDICT=$([ "$VERDICT" = "0" ] && echo BYTE_IDENTICAL || echo DIFF)  $(date -u '+%FT%TZ')"
if [ "$VERDICT" = "0" ]; then
  say "X_PATH_BIN_IDENTICAL=YES"
else
  say "X_PATH_BIN_IDENTICAL=NO"
fi
say "日志：$LOG"
exit "$VERDICT"
