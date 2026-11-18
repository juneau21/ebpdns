#!/bin/bash
# =============================================================================
# ebpdns **2.1.28（A1）**：离线重建等价门的**单入口**（发现输入 + 统一退出码）
#
# 判据本体在 `scripts/_rebuild_equiv.py`：
#   空目录解**上一版源码包** → 按文件名排序执行 `patch233_*.py` → 与**本树**逐文件比对
#   （字节相等；**不跑 cargo、不跑任何构建**）⇒ `CHANGED=ADDED=REMOVED=0`。
#
# 输入发现顺序（任一命中即可，**只认上一版**，不会拿本版源码包冒充）：
#   * 上一版源码包：`$EBP_PREV_SRC` → `<tree>/packaging/prev/*-src.tar.*`
#     → `<tree>/dist-packages/prev/*-src.tar.*` → `<tree>/../prev/*-src.tar.*`
#     → `$HOME/e228/prev/*-src.tar.*`（**2.2.6/P2-A7**：支持 `.tar.gz` 与 `.tar.xz`）
#   * 补丁目录：`$EBP_PATCHES` → `<tree>/packaging/prev/patches`
#     → `<tree>/dist-packages/prev/patches` → `<tree>/../patches`
#     → `$HOME/e228/prev/patches`
#
# **2.2.5（P2-A3）**：补丁前缀不再写死 `patch233_*.py` —— 目录里任何
# `patchNNN_*.py`（三位版本号）都接受，`_rebuild_equiv.py` 自动选**最新一代**前缀。
# 这样每个版本只需把"上一版源码包 + 本版增量补丁"放进 `<tree>/packaging/prev/`，
# 门禁即可真实执行（2.2.4 之前因缺少这两样输入长期 SKIP）。
#
# 用法：
#   bash scripts/_rebuild_equiv.sh <tree-root>              # 缺输入 ⇒ SKIP（rc=3）
#   bash scripts/_rebuild_equiv.sh <tree-root> --require    # 缺输入 ⇒ FAIL（rc=1）
#   EBP_PREV_SRC=... EBP_PATCHES=... bash scripts/_rebuild_equiv.sh <tree-root>
#
# 退出码：0 = PASS（CHANGED=ADDED=REMOVED=0）；1 = FAIL（有差异/补丁失败/--require 缺输入）；
#         3 = SKIP（缺输入，未加 --require）。
#
# `--selftest`：负向对照 —— 把补丁目录里**最后一个**补丁拿掉再跑，必须 `rc=1`
#   （证明"缺一个补丁 ⇒ 门禁必红"，而不是"补丁有没有都绿"）。缺输入时仍为 SKIP。
# =============================================================================
set -uo pipefail
ROOT="$(cd "${1:-$(dirname "$0")/..}" && pwd -P)"
shift 2>/dev/null || true
REQUIRE=0
SELFTEST=0
for a in "$@"; do
  [ "$a" = "--require" ] && REQUIRE=1
  [ "$a" = "--selftest" ] && SELFTEST=1
done

PREV="${EBP_PREV_SRC:-}"
if [ -z "$PREV" ]; then
  for c in "$ROOT/packaging/prev"/*-src.tar.* \
           "$ROOT/dist-packages/prev"/*-src.tar.* \
           "$ROOT/../prev"/*-src.tar.* \
           "$HOME/e228/prev"/*-src.tar.*; do
    if [ -f "$c" ]; then PREV="$c"; break; fi
  done
fi

PATCHES="${EBP_PATCHES:-}"
if [ -z "$PATCHES" ]; then
  for c in "$ROOT/packaging/prev/patches" \
           "$ROOT/dist-packages/prev/patches" \
           "$ROOT/../patches" \
           "$HOME/e228/prev/patches"; do
    if [ -d "$c" ] && ls "$c"/patch[0-9][0-9][0-9]_*.py* >/dev/null 2>&1; then
      PATCHES="$c"; break
    fi
  done
fi

if [ -z "$PREV" ] || [ ! -f "$PREV" ] || [ -z "$PATCHES" ] || [ ! -d "$PATCHES" ]; then
  if [ "$REQUIRE" = "1" ]; then
    echo "REBUILD_EQUIV=FAIL（缺输入：prev-src=${PREV:-<未找到>} patches=${PATCHES:-<未找到>}）"
    exit 1
  fi
  echo "REBUILD_EQUIV=SKIP（未提供上一版源码包/补丁目录；用 EBP_PREV_SRC / EBP_PATCHES 指定）"
  exit 3
fi

if [ "$SELFTEST" = "1" ]; then
  # 负向对照：拿掉最后一个**内容**补丁 ⇒ 必须 FAIL（CHANGED/ADDED/REMOVED 至少一项非 0）。
  # **2.1.30**：排除 `*_manifest.py` —— 它只重算包内清单（`_md5_*.txt`），而清单被
  # `_rebuild_equiv.py` 的 GENERATED 规则排除；拿掉它不会产生任何 diff，
  # 负向对照会假绿（2.1.30 首跑实测：rc=0）。
  TMPD="$(mktemp -d "${TMPDIR:-/tmp}/rebuild-negctl.XXXXXX")" || exit 1
  trap 'rm -rf "$TMPD"' EXIT
  # **2.2.6（P2-A7）**：补丁可能是 `.py` / `.py.gz` / `.py.xz`（压缩发布）——负向对照按
  # 实际文件名拿掉最后一个内容补丁，其余原样拷入临时目录（`_rebuild_equiv.py` 支持压缩）。
  LAST="$(ls "$PATCHES"/patch[0-9][0-9][0-9]_*.py* 2>/dev/null | grep -v '_manifest' | sort | tail -1)"
  if [ -z "$LAST" ]; then
    echo "REBUILD_EQUIV_SELFTEST=SKIP（补丁目录里没有可用的 patchNNN_*.py[.gz] 内容补丁）"
    exit 3
  fi
  PREF="$(basename "$LAST" | sed 's/_.*//')"
  for p in "$PATCHES"/"$PREF"_*.py*; do
    [ "$p" = "$LAST" ] && continue
    cp -f "$p" "$TMPD/"
  done
  echo "  [negctl] 补丁目录 = $TMPD（拿掉 $(basename "$LAST")）"
  python3 "$ROOT/scripts/_rebuild_equiv.py" "$ROOT" --prev-src "$PREV" --patches "$TMPD"
  neg_rc=$?
  if [ "$neg_rc" = "1" ]; then
    echo "  PASS  REBUILD_EQUIV_SELFTEST=负向对照变红（缺补丁 ⇒ 门禁 rc=1；单补丁时为空补丁集失败路径）"
    exit 0
  fi
  echo "  FAIL  REBUILD_EQUIV_SELFTEST=负向对照**没有**变红（rc=$neg_rc；判据空转）"
  exit 1
fi

python3 "$ROOT/scripts/_rebuild_equiv.py" "$ROOT" --prev-src "$PREV" --patches "$PATCHES"
rc=$?
if [ "$rc" = "0" ]; then
  echo "REBUILD_EQUIV=PASS"
else
  echo "REBUILD_EQUIV=FAIL (rc=$rc)"
fi
exit "$rc"
