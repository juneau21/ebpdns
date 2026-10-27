#!/usr/bin/env bash
# ============================================================================
# ebpdns **2.1.28**：`scripts/check_all.sh` 的**自测**（门禁自己的门禁）
#
#   bash scripts/check_all_selftest.sh          # 全跑（两条开关组合 + 静态判据 + 负向对照）
#   JOBS=1 RELEASE=0 bash scripts/check_all_selftest.sh
#
# **2.1.26 新增两条判据（B6：开关与文档的一致性）**：
#   ⑤ **开关清单一致性**：`scripts/check_all.sh` 头部注释里的开关集合必须与
#      `docs/PACKAGING.md §6b` 代码块里的**完全相同**，且每个开关在脚本里真的有实现
#      （`${NAME:-…}`）—— 2.1.25 的"`RELEASE=1` 只对第 4 步生效"就是"文档写了、
#      实现只做了一半"，而且**没有任何机器判据**能发现。
#   ⑥ **`RELEASE` 必须作用于两条 `cargo test`**（第 4 步全量 + 第 5 步 dist 新鲜度）：
#      判据是第 5 步的命令行里必须出现 `"${REL_ARGS[@]}"`。删掉它 ⇒ 本项红。
#
# **2.1.27 新增一条判据（A1：清单计数的负向对照）**：
#   ⑦ `python3 scripts/_doc_counts.py <root> --selftest` —— 影子副本里把清单作用域表里的
#      一个数字改小 1 ⇒ 必须 **rc=1 且给出 `file:line`**；改回 ⇒ 必须 rc=0。
#      2.1.26 实测：数字改小 1 之后四道门禁**仍然全 PASS**（"不得硬编码行数"没有机器判据）——
#      这一步把那次负向实验变成常规用例（对应 2.1.26 留证的 `negctl_hardcoded.log`）。
#
# **2.1.28 扩展（A2/A1）**：
#   ⑦ 扩成三条负向对照：树内行数字改小 1；**prod 行改回 2.1.27 的错误措辞**（prod 包里那条
#      命令只命中少数路径，旧措辞必然红）；src 包内跑 prod 清单的 FAILED 数改错。
#   ⑧ 新增"离线重建等价门"的负向对照：`_rebuild_equiv.sh --selftest` 拿掉最后一个
#      `patch230_*.py` ⇒ 必须 `rc=1`（补丁缺一必红，而不是"补丁有没有都绿"）。
#
# 为什么需要它（2.1.24 登记的唯一 P3 缺陷）：`scripts/check_all.sh` 第 5 步把
# `"${CARGO_EXTRA[@]}"` 放在 `--` **之后** ⇒ `OFFLINE=1 bash scripts/check_all.sh`
# 首跑即红：`--` 之后的一切都被 `cargo test` 原样转给**测试二进制**，
# 于是 `error: Unrecognized option: 'offline'`。**这个缺陷能连续存活两轮**
# 是因为"开关组合"没有任何机器判据 —— 只有人手跑过才知道。
#
# 本脚本把它拆成四条**可复现**的判据：
#   ① **静态**：`scripts/check_all.sh` 里任何一行都**不得**让 ` -- ` 出现在
#      `${CARGO_EXTRA...}` 之前（行内 `--` = 传给测试二进制的分隔符）；
#   ② **负向对照**：把 `--offline` 放到 `--` 之后，`cargo` 必须真的报
#      `Unrecognized option`（证明 ① 的判据不是空转）；
#   ③ **OFFLINE=1 SKIP_TEST=1** ⇒ `CHECK_ALL=PASS`（正是 2.1.24 红掉的那条组合）；
#   ④ **SKIP_TEST=1** ⇒ `CHECK_ALL=PASS`（离线关闭时的基线，防止"只在 OFFLINE 下才对"）。
#
# 退出码：0 = 四条全绿；1 = 至少一条红（逐条结果在最后汇总）。
# 说明：本脚本**不改**任何产物，也不替换 `check_all.sh` 的正式跑法 ——
# 交付前仍以 `OFFLINE=1 RELEASE=1 JOBS=1 bash scripts/check_all.sh` 为准。
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

FAILED=()
N=0
step() { N=$((N + 1)); printf '\n=== [%d] %s\n' "$N" "$*"; }
ok() { printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { printf '  RESULT: FAIL  (%s)\n' "$1"; FAILED+=("$1"); }

LOGDIR="${TMPDIR:-/tmp}/ebpdns-checkall-selftest.$$"
mkdir -p "$LOGDIR" || exit 1
cleanup() { rm -rf "$LOGDIR"; }
trap cleanup EXIT

# ---- 1) 静态判据：` -- ` 不得出现在 CARGO_EXTRA 之前 --------------------------
step "静态判据：scripts/check_all.sh 里 \` -- \` 不得先于 \${CARGO_EXTRA[@]}"
# awk 逐行判定：同一行里 ` -- ` 的下标必须**大于** `CARGO_EXTRA` 的下标
# （或该行根本没有 ` -- `）。`--test` / `--nocapture` 这类不含空格的形式不算分隔符。
BAD_ORDER="$(awk '
  /CARGO_EXTRA/ {
    p = index($0, " -- ")
    q = index($0, "CARGO_EXTRA")
    if (p > 0 && q > p) printf "  line %d: %s\n", NR, $0
  }
' scripts/check_all.sh)"
if [ -z "$BAD_ORDER" ]; then
  ok "static-order"
else
  bad "static-order"
  printf '%s\n' "$BAD_ORDER"
fi

# 同一条判据的正向形态必须在位（否则"没有坏行"可能只是"没有这一行"）。
if grep -q 'CARGO_EXTRA\[@\]}" -- ' scripts/check_all.sh; then
  ok "static-order-positive-form"
else
  bad "static-order-positive-form"
fi

# ---- 2) 负向对照：`--offline` 放在 `--` 之后必须被 cargo 拒绝 -----------------
step "负向对照：cargo ... -- --offline 必须报 Unrecognized option"
NEG_LOG="$LOGDIR/negctl.log"
if cargo test -p ebpdns-resolver --test web_dist_freshness -- --offline >"$NEG_LOG" 2>&1; then
  bad "negctl-cargo-rejects-offline-after--"
  tail -n 5 "$NEG_LOG"
elif grep -q "Unrecognized option" "$NEG_LOG"; then
  ok "negctl-cargo-rejects-offline-after--"
else
  # 非零退出但不是"参数被误当测试参数" ⇒ 判据无效（可能是编译失败），必须红。
  bad "negctl-cargo-rejects-offline-after--"
  printf '  未在输出里找到 `Unrecognized option`（负向对照失效）：\n'
  tail -n 5 "$NEG_LOG"
fi

# ---- 3) OFFLINE=1 SKIP_TEST=1（2.1.24 红掉的那条组合）------------------------
step "OFFLINE=1 SKIP_TEST=1 bash scripts/check_all.sh"
RUN_LOG="$LOGDIR/offline.log"
if OFFLINE=1 SKIP_TEST=1 bash scripts/check_all.sh >"$RUN_LOG" 2>&1; then
  if grep -q '^CHECK_ALL=PASS' "$RUN_LOG"; then
    ok "offline-skiptest"
  else
    bad "offline-skiptest"
    tail -n 20 "$RUN_LOG"
  fi
else
  bad "offline-skiptest"
  tail -n 40 "$RUN_LOG"
fi

# ---- 4) SKIP_TEST=1（离线关闭时的基线）---------------------------------------
step "SKIP_TEST=1 bash scripts/check_all.sh"
RUN_LOG="$LOGDIR/plain.log"
if SKIP_TEST=1 bash scripts/check_all.sh >"$RUN_LOG" 2>&1; then
  if grep -q '^CHECK_ALL=PASS' "$RUN_LOG"; then
    ok "skiptest"
  else
    bad "skiptest"
    tail -n 20 "$RUN_LOG"
  fi
else
  bad "skiptest"
  tail -n 40 "$RUN_LOG"
fi

# ---- 5) 开关清单一致性：脚本头部注释 vs docs/PACKAGING.md §6b ---------------
#
# **2.1.26（B6）**：2.1.25 的"`RELEASE=1` 只对第 4 步生效"在**文档与实现之间**留下了
# 一个静默缺口 —— 两处都"写了 RELEASE"，但一个指一条命令、一个指两条。
# 判据拆成两半：① 两处的**开关集合**必须相同；② 每个开关在脚本里必须有实现。
step "开关清单一致性：check_all.sh 头部 vs docs/PACKAGING.md §6b"
SW_SCAN='SKIP_TEST|RELEASE|OFFLINE|JOBS'
SW_SCRIPT="$(sed -n '1,40p' scripts/check_all.sh | grep -oE "($SW_SCAN)=" | tr -d '=' | sort -u | tr '\n' ' ')"
SW_DOC="$(awk '/^### 6b\./{f=1} f && /^```bash/{c=1; next} c && /^```/{exit} c' docs/PACKAGING.md \
  | grep -oE "($SW_SCAN)=" | tr -d '=' | sort -u | tr '\n' ' ')"
printf '  script=%s\n  doc   =%s\n' "$SW_SCRIPT" "$SW_DOC"
if [ -n "$SW_SCRIPT" ] && [ "$SW_SCRIPT" = "$SW_DOC" ]; then
  ok "switch-list-consistency"
else
  bad "switch-list-consistency"
fi
MISSING_IMPL=""
for s in $SW_SCRIPT; do
  grep -q "\${$s:-" scripts/check_all.sh || MISSING_IMPL="$MISSING_IMPL $s"
done
if [ -z "$MISSING_IMPL" ] && [ -n "$SW_SCRIPT" ]; then
  ok "switch-implemented"
else
  bad "switch-implemented"
  printf '  以下开关在 check_all.sh 里没有实现（`${NAME:-…}`）：%s\n' "$MISSING_IMPL"
fi

# ---- 6) RELEASE 必须作用于两条 cargo test（第 4 步 + 第 5 步）-----------------
step "RELEASE 同时作用于第 4 步（全量）与第 5 步（dist 新鲜度）"
if grep -q 'web_dist_freshness "${REL_ARGS\[@\]}"' scripts/check_all.sh \
   && grep -q 'TEST_ARGS+=(--release)' scripts/check_all.sh; then
  ok "release-applies-to-both-cargo-test-steps"
else
  bad "release-applies-to-both-cargo-test-steps"
  printf '  第 5 步缺 "${REL_ARGS[@]}" 或第 4 步缺 --release ⇒ 同一开关两种语义\n'
fi

# ---- 7) 文档计数门禁的负向对照（2.1.27 / A1；2.1.28 三条）----------------------
step "文档计数负向对照：_doc_counts.py --selftest（改错数字/改回旧措辞必须红，改回必须绿）"
if python3 scripts/_doc_counts.py "$ROOT" --selftest >"$LOGDIR/doccnt.log" 2>&1; then
  ok "doc-counts-negctl"
  grep -E 'DOC_COUNTS|selftest-' "$LOGDIR/doccnt.log" | sed 's/^/    /'
else
  bad "doc-counts-negctl"
  tail -n 20 "$LOGDIR/doccnt.log"
fi

# ---- 8) 离线重建等价门的负向对照（2.1.28 / A1）--------------------------------
# 判据：拿掉最后一个补丁 ⇒ 必须 `CHANGED/ADDED/REMOVED` 非 0（rc=1）。缺上一版源码包/
# 补丁目录时 `_rebuild_equiv.sh --selftest` 打印 SKIP（rc=3），本步按 SKIP 记（不算红）——
# 交付前会用 EBP_PREV_SRC / EBP_PATCHES 指定输入，那时这一步是真实执行。
step "离线重建负向对照：_rebuild_equiv.sh --selftest（拿掉一个补丁必须红）"
rb_rc=0
bash scripts/_rebuild_equiv.sh "$ROOT" --selftest >"$LOGDIR/rebuild.log" 2>&1 || rb_rc=$?
if [ "$rb_rc" = "0" ]; then
  ok "rebuild-equiv-negctl"
  grep -E 'REBUILD_EQUIV' "$LOGDIR/rebuild.log" | sed 's/^/    /'
elif [ "$rb_rc" = "3" ]; then
  printf '  RESULT: SKIP（未提供上一版源码包/补丁目录）\n'
else
  bad "rebuild-equiv-negctl"
  tail -n 20 "$LOGDIR/rebuild.log"
fi

# ---- 汇总 --------------------------------------------------------------------
printf '\n==================== SUMMARY ====================\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf 'CHECK_ALL_SELFTEST=PASS（%d 项全绿）\n' "$N"
  exit 0
fi
printf 'CHECK_ALL_SELFTEST=FAIL（%d/%d 项红）：%s\n' "${#FAILED[@]}" "$N" "${FAILED[*]}"
exit 1
