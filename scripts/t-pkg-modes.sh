#!/bin/bash
# =============================================================================
# ebpdns 2.1.43：**包权限规范化**验收（`check_all` 第 14 项；打包第 6a 步）
#
# 背景（2.1.42 交付实测缺陷）：源码包里 **154 个文件是 0666**（world-writable，含
# `web/build.sh`），权限完全继承解包环境；打包链此前**没有任何一处**规范化 ⇒ 交付包
# 可能带 world-writable 文件、`*.sh` 不可执行。2.1.43 起打包链
# （`scripts/make_packages_221r2.sh` 第 4b/5 步）强制：`*.sh`/`*.py` **0755**、
# 数据文件 **0644**、目录 **0755**。本脚本是那条规则的**独立判据** —— 在**解包后的
# 真实包**上重跑一遍，而不是相信打包脚本自己的 `chmod`。
#
# 判据（每个 target 都必须全满足）：
#   1) 不存在 world-writable（权限位 o+w）的文件或目录；
#   2) `*.sh` / `*.py` 一律 0755（可执行，且不是 0777/0666）；
#   3) `install.sh`（包根）或 `packaging/install.sh`（源码树）存在且 0755；
#   4) `bin/ebpdns`（prod 包）/ `target/release/ebpdns`（构建树）存在时 0755；
#   5) 目录一律 0755；非 `*.sh`/`*.py` 的普通文件一律 0644。
#
# 用法：
#   bash scripts/t-pkg-modes.sh                    # 自动：dist-packages/*-{prod,src}.tar.gz；
#                                                  # 没有包产物 ⇒ 退到对**本树**跑同一套规则
#   bash scripts/t-pkg-modes.sh <tar.gz|dir> ...   # 逐个断言（包或目录）
#
# 退出码：0 = PASS；1 = FAIL（任一 target 任一判据红）；3 = SKIP（无输入）。
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
FAILED=0
TARGETS=0
TOTAL_FILES=0
TOTAL_DIRS=0

tmpdirs=()
cleanup() {
  local d
  for d in ${tmpdirs[@]+"${tmpdirs[@]}"}; do [ -n "$d" ] && rm -rf "$d"; done
}
trap cleanup EXIT

fail() { printf '  FAIL  %s\n' "$*"; FAILED=$((FAILED + 1)); }

PRUNE=(\( -name target -o -name .git -o -name dist-packages -o -name __pycache__ -o -name node_modules \) -prune -o)

scan() {
  local base="$1" label="$2"
  local world=0 sh=0 py=0 files=0 dirs=0
  if [ ! -d "$base" ]; then fail "$label: 不是目录：$base"; return; fi

  # 1) world-writable（文件 + 目录，prune 掉构建产物/缓存）
  local ww
  ww="$(find "$base" "${PRUNE[@]}" -perm -002 -print 2>/dev/null)"
  if [ -n "$ww" ]; then
    world="$(printf '%s\n' "$ww" | wc -l)"
    printf '%s\n' "$ww" | head -10 | while IFS= read -r p; do printf '  BAD   world-writable: %s\n' "${p#$base/}"; done
    fail "$label: world-writable 文件/目录 = $world（必须 0）"
  fi

  # 2) 目录一律 0755
  local d m
  while IFS= read -r d; do
    [ -z "$d" ] && continue
    m="$(stat -c '%a' "$d")"
    if [ "$m" != "755" ]; then fail "$label: 目录权限 $m != 755：${d#$base/}"; fi
    dirs=$((dirs + 1))
  done < <(find "$base" "${PRUNE[@]}" -type d -print 2>/dev/null)

  # 3) 文件：*.sh/*.py ⇒ 0755；可执行二进制 ⇒ 0755；其余 ⇒ 0644
  local f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    m="$(stat -c '%a' "$f")"
    case "$f" in
      */bin/ebpdns|*/target/release/ebpdns)
        # 可执行二进制**不适用**"数据 0644"规则（判据 5 单独断言 0755）。
        [ "$m" = "755" ] || fail "$label: ebpdns 二进制权限 $m != 755：${f#$base/}" ;;
      *.sh) sh=$((sh + 1)); [ "$m" = "755" ] || fail "$label: *.sh 权限 $m != 755：${f#$base/}" ;;
      *.py) py=$((py + 1)); [ "$m" = "755" ] || fail "$label: *.py 权限 $m != 755：${f#$base/}" ;;
      *) [ "$m" = "644" ] || fail "$label: 数据文件权限 $m != 644：${f#$base/}" ;;
    esac
    files=$((files + 1))
  done < <(find "$base" "${PRUNE[@]}" -type f -print 2>/dev/null)

  # 4) install.sh（包根优先，源码树退回 packaging/install.sh）
  local inst=""
  [ -f "$base/install.sh" ] && inst="$base/install.sh"
  if [ -z "$inst" ] && [ -f "$base/packaging/install.sh" ]; then inst="$base/packaging/install.sh"; fi
  if [ -z "$inst" ]; then
    fail "$label: 找不到 install.sh / packaging/install.sh"
  else
    m="$(stat -c '%a' "$inst")"
    [ "$m" = "755" ] || fail "$label: install.sh 权限 $m != 755（必须 0755）"
  fi

  # 5) 可执行二进制（prod 包 bin/ebpdns；构建树 target/release/ebpdns）
  local b
  for b in "$base/bin/ebpdns" "$base/target/release/ebpdns"; do
    [ -f "$b" ] || continue
    m="$(stat -c '%a' "$b")"
    [ "$m" = "755" ] || fail "$label: ebpdns 二进制权限 $m != 755：${b#$base/}"
  done

  TOTAL_FILES=$((TOTAL_FILES + files))
  TOTAL_DIRS=$((TOTAL_DIRS + dirs))
  printf '  %-40s files=%-4d dirs=%-4d sh=%-3d py=%-3d world_writable=%s\n' \
    "$label" "$files" "$dirs" "$sh" "$py" "${world:-0}"
}

targets=()
for a in "$@"; do targets+=("$a"); done
if [ "${#targets[@]}" -eq 0 ]; then
  shopt -s nullglob
  for p in "$ROOT"/dist-packages/*-prod.tar.gz "$ROOT"/dist-packages/*-src.tar.gz; do targets+=("$p"); done
  shopt -u nullglob
  if [ "${#targets[@]}" -eq 0 ]; then
    targets+=("$ROOT")
    printf '  INFO  未发现 dist-packages/*.tar.gz ⇒ 对当前树跑同一套规则：%s\n' "$ROOT"
  fi
fi

for t in "${targets[@]}"; do
  TARGETS=$((TARGETS + 1))
  case "$t" in
    *.tar.gz|*.tgz)
      td="$(mktemp -d "${TMPDIR:-/tmp}/tpkgmodes.XXXXXX")" || exit 1
      tmpdirs+=("$td")
      if ! tar -xzf "$t" -C "$td" 2>/dev/null; then
        fail "解包失败：$t"
        continue
      fi
      top="$(find "$td" -mindepth 1 -maxdepth 1 -type d | head -1)"
      [ -n "$top" ] || top="$td"
      scan "$top" "$(basename "$t")"
      ;;
    *) scan "$t" "$(basename "$t")" ;;
  esac
done

if [ "$FAILED" -ne 0 ]; then
  printf 'T_PKG_MODES=FAIL（targets=%d failed=%d）\n' "$TARGETS" "$FAILED"
  exit 1
fi
if [ "$TARGETS" -eq 0 ]; then
  printf 'T_PKG_MODES=SKIP（无输入）\n'
  exit 3
fi
printf 'T_PKG_MODES=PASS（targets=%d files=%d dirs=%d world_writable=0）\n' \
  "$TARGETS" "$TOTAL_FILES" "$TOTAL_DIRS"
exit 0
