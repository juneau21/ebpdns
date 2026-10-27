#!/bin/bash
# =============================================================================
# ebpdns **2.1.28（A1）**：离线重建等价门的**单入口**（发现输入 + 统一退出码）
#
# 判据本体在 `scripts/_rebuild_equiv.py`：
#   空目录解**上一版源码包** → 按文件名排序执行 `patch233_*.py` → 与**本树**逐文件比对
#   （字节相等；**不跑 cargo、不跑任何构建**）⇒ `CHANGED=ADDED=REMOVED=0`。
#
# 输入发现顺序（任一命中即可，**只认上一版**，不会拿本版源码包冒充）：
#   * 上一版源码包：`$EBP_PREV_SRC` → `<tree>/dist-packages/prev/*-src.tar.gz`
#     → `<tree>/../prev/*-src.tar.gz` → `$HOME/e228/prev/*-src.tar.gz`
#   * 补丁目录：`$EBP_PATCHES` → `<tree>/dist-packages/prev/patches`
#     → `<tree>/../patches` → `$HOME/e228/prev/patches`
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
  for c in "$ROOT/dist-packages/prev"/*-src.tar.gz \
           "$ROOT/../prev"/*-src.tar.gz \
           "$HOME/e228/prev"/*-src.tar.gz; do
    if [ -f "$c" ]; then PREV="$c"; break; fi
  done
fi

PATCHES="${EBP_PATCHES:-}"
if [ -z "$PATCHES" ]; then
  for c in "$ROOT/dist-packages/prev/patches" \
           "$ROOT/../patches" \
           "$HOME/e228/prev/patches"; do
    if [ -d "$c" ] && { ls "$c"/patch233_*.py >/dev/null 2>&1 || ls "$c"/patch233_*.py >/dev/null 2>&1; }; then
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
  # **2.1.30**：排除 `*_manifest.py` —— 它只重算 `_md5_prod.txt` / `_md5_src.txt`，而这两个
  # 生成物被 `_rebuild_equiv.py` 的 GENERATED 白名单排除；拿掉它不会产生任何 diff，
  # 负向对照会假绿（2.1.30 首跑实测：rc=0）。
  TMPD="$(mktemp -d "${TMPDIR:-/tmp}/rebuild-negctl.XXXXXX")" || exit 1
  trap 'rm -rf "$TMPD"' EXIT
  LAST="$(ls "$PATCHES"/patch233_*.py 2>/dev/null | grep -v '_manifest' | sort | tail -1)"
  if [ -z "$LAST" ]; then
    echo "REBUILD_EQUIV_SELFTEST=SKIP（补丁目录里没有可用的 patch233_*.py 内容补丁）"
    exit 3
  fi
  PREF="$(basename "$LAST" | sed 's/_.*//')"
  for p in "$PATCHES"/"$PREF"_*.py; do
    [ "$p" = "$LAST" ] && continue
    cp -f "$p" "$TMPD/"
  done
  echo "  [negctl] 补丁目录 = $TMPD（拿掉 $(basename "$LAST")）"
  python3 "$ROOT/scripts/_rebuild_equiv.py" "$ROOT" --prev-src "$PREV" --patches "$TMPD"
  neg_rc=$?
  if [ "$neg_rc" = "1" ]; then
    echo "  PASS  REBUILD_EQUIV_SELFTEST=负向对照变红（缺一个补丁 ⇒ CHANGED/ADDED/REMOVED 非 0）"
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
