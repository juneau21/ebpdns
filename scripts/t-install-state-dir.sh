#!/usr/bin/env bash
# ============================================================================
# ebpdns **2.1.28**：`packaging/install.sh --state-dir` 透传与 rc 语义的**脚本级**用例
#
#   sudo bash scripts/t-install-state-dir.sh        # 需要 root（install.sh 的 require_root）
#
# 为什么需要它（2.1.24 的 8 条 installpaths FAIL）：`install.sh --migrate-config`
# **从不**把 `--state-dir` 透传给二进制，而 2.1.24 的语义是"配置里没有 `state_dir`
# 又没给 `--state-dir` ⇒ rc=3 只读报告" ⇒ 最常见的升级场景**必然** rc=3，看着像失败。
# 这条缺陷当时**没有任何脚本级判据**（只有"部署代理跑完发现 8 条 FAIL"）。
#
# 判据（每条都是断言，任何一条红 ⇒ 退出码 1）：
#   T1 静态：`apply_migrate_config` 里必须存在 `margs+=(--state-dir "$state_dir")`；
#   T2 rc=0：**显式** `--state-dir DIR` ⇒ 传进二进制的 argv 必须含 `--state-dir DIR`；
#   T3 rc=0：配置里有 `state_dir` 且未给旗标 ⇒ argv **不得**含 `--state-dir`，
#            并把"取配置里的"打出来（不替用户猜目录）；
#   T4 rc=3：配置无 `state_dir` 且未给旗标 ⇒ 返回 **3**、打印"未落盘"与**重跑命令**，
#            且配置目录**零新增文件**（不写 .bak / .tmp / state）；
#   T5 rc=4：二进制返回 4（重锚失败，服务在跑持锁）⇒ 返回 **4** 且打印"提交点未更新"；
#   T6 参数解析：`./install.sh --help` ⇒ rc=0、只打印用法（**不做安装**）；
#                `./install.sh --state-dir`（缺值）⇒ rc=1 + 明确错误。
#
# **安全**：本用例**不调用** `install.sh` 的 `main`（除 T6 的 `--help` / 缺值两条，
# 它们在任何写操作之前就退出），不触碰 `/usr/local/bin`、`/etc/ebpdns`、
# `/var/lib/ebpdns`、`systemctl`、53/8353 端口。全部动作发生在 `mktemp -d` 的临时目录里。
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
INSTALL="$HERE/packaging/install.sh"
FAILED=()
N=0
say() { N=$((N + 1)); printf '\n=== [%d] %s\n' "$N" "$*"; }
ok() { printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() {
  printf '  RESULT: FAIL  (%s)\n' "$1"
  FAILED+=("$1")
}

TMP="$(mktemp -d "${TMPDIR:-/tmp}/ebpdns-t-install-XXXXXX")" || exit 1
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# T1 静态判据：透传那一行必须在位（防止"行为用例被 fake 二进制掩盖"）
# ---------------------------------------------------------------------------
say "T1 静态：apply_migrate_config 必须显式透传 --state-dir"
if grep -qF 'margs+=(--state-dir "$state_dir")' "$INSTALL"; then
  ok "static-passthrough"
else
  bad "static-passthrough"
  printf '  未找到 `margs+=(--state-dir "$state_dir")` —— 透传又丢了？\n'
fi
if grep -qF 'migrate-config --config "$conf")' "$INSTALL"; then
  ok "static-base-args"
else
  bad "static-base-args"
fi

# ---------------------------------------------------------------------------
# 载入 install.sh 的**函数体**（删掉最后的入口调用），供 T2–T5 直接调用。
# 只做变量赋值 + 函数定义，不执行 main ⇒ 不写任何系统路径。
# ---------------------------------------------------------------------------
LIB="$TMP/install-lib.sh"
sed '/^main "\$@"$/d' "$INSTALL" >"$LIB"
# shellcheck disable=SC1090
source "$LIB"
# 该文件以 `set -euo pipefail` 开头；用例里要显式检查 rc ⇒ 关掉 -e。
set +eu

# 假二进制：把收到的 argv 追加到 $FAKE_LOG，然后按 $FAKE_RC 退出。
FAKE="$TMP/fake-ebpdns"
cat >"$FAKE" <<'EOS'
#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_LOG"
exit "${FAKE_RC:-0}"
EOS
chmod +x "$FAKE"
export FAKE_LOG="$TMP/argv.log"
export FAKE_RC=0

mkconf() { # $1 = 目标文件; $2 = state_dir 值（空 = 不写该键）
  if [ -n "${2:-}" ]; then
    printf '{\n  "config_version": 3,\n  "state_dir": "%s",\n  "upstreams": []\n}\n' "$2" >"$1"
  else
    printf '{\n  "config_version": 3,\n  "upstreams": []\n}\n' >"$1"
  fi
}

# ---------------------------------------------------------------------------
# T2 rc=0 + 显式 --state-dir 必须透传
# ---------------------------------------------------------------------------
say "T2 rc=0：显式 --state-dir 必须出现在二进制的 argv 里"
CONF="$TMP/t2/config.json"
mkdir -p "$TMP/t2"
mkconf "$CONF" ""
: >"$FAKE_LOG"
FAKE_RC=0
OUT="$(apply_migrate_config "$FAKE" "$CONF" "$TMP/t2/explicit-state" 2>&1)"
RC=$?
ARGV="$(cat "$FAKE_LOG")"
if [ "$RC" -eq 0 ] &&
  printf '%s' "$ARGV" | grep -qF -- "--state-dir $TMP/t2/explicit-state" &&
  printf '%s' "$ARGV" | grep -qF -- "migrate-config --config $CONF"; then
  ok "explicit-state-dir-passthrough"
else
  bad "explicit-state-dir-passthrough"
  printf '  rc=%s argv=%s\n%s\n' "$RC" "$ARGV" "$OUT"
fi
if printf '%s' "$OUT" | grep -qF "显式 --state-dir"; then
  ok "explicit-state-dir-logged"
else
  bad "explicit-state-dir-logged"
  printf '%s\n' "$OUT"
fi

# ---------------------------------------------------------------------------
# T3 rc=0 + 配置里有 state_dir ⇒ 不传旗标，并打印"取配置里的"
# ---------------------------------------------------------------------------
say "T3 rc=0：配置里有 state_dir ⇒ 不传 --state-dir，打印采用的是配置值"
mkdir -p "$TMP/t3"
CFG3="$TMP/t3/cfgstate"
CONF="$TMP/t3/config.json"
mkconf "$CONF" "$CFG3"
: >"$FAKE_LOG"
FAKE_RC=0
OUT="$(apply_migrate_config "$FAKE" "$CONF" "" 2>&1)"
RC=$?
ARGV="$(cat "$FAKE_LOG")"
if [ "$RC" -eq 0 ] && ! printf '%s' "$ARGV" | grep -qF -- "--state-dir"; then
  ok "config-state-dir-not-overridden"
else
  bad "config-state-dir-not-overridden"
  printf '  rc=%s argv=%s\n%s\n' "$RC" "$ARGV" "$OUT"
fi
if printf '%s' "$OUT" | grep -qF "取配置里的 state_dir=$CFG3"; then
  ok "config-state-dir-logged"
else
  bad "config-state-dir-logged"
  printf '%s\n' "$OUT"
fi
# cfg_state_dir 的解析本身也要对（它是"打印哪个目录"的唯一来源）。
if [ "$(cfg_state_dir "$CONF")" = "$CFG3" ]; then
  ok "cfg-state-dir-parser"
else
  bad "cfg-state-dir-parser"
fi

# ---------------------------------------------------------------------------
# T4 rc=3：配置无 state_dir 且未给旗标 ⇒ 只读报告、零写入
# ---------------------------------------------------------------------------
say "T4 rc=3：两者都没有 ⇒ 返回 3、给出重跑命令、**零写入**"
mkdir -p "$TMP/t4"
CONF="$TMP/t4/config.json"
mkconf "$CONF" ""
BEFORE_MD5="$(md5sum <"$CONF" | awk '{print $1}')"
BEFORE_LIST="$(find "$TMP/t4" -type f | sort)"
: >"$FAKE_LOG"
FAKE_RC=3
OUT="$(apply_migrate_config "$FAKE" "$CONF" "" 2>&1)"
RC=$?
AFTER_MD5="$(md5sum <"$CONF" | awk '{print $1}')"
AFTER_LIST="$(find "$TMP/t4" -type f | sort)"
if [ "$RC" -eq 3 ]; then
  ok "rc3-propagated"
else
  bad "rc3-propagated"
  printf '  rc=%s（期望 3）\n%s\n' "$RC" "$OUT"
fi
if printf '%s' "$OUT" | grep -qF "未落盘" &&
  printf '%s' "$OUT" | grep -qF -- "--migrate-config --state-dir <专用目录>"; then
  ok "rc3-hint-with-rerun-command"
else
  bad "rc3-hint-with-rerun-command"
  printf '%s\n' "$OUT"
fi
if [ "$BEFORE_MD5" = "$AFTER_MD5" ] && [ "$BEFORE_LIST" = "$AFTER_LIST" ]; then
  ok "rc3-zero-writes"
else
  bad "rc3-zero-writes"
  printf '  config md5 %s -> %s\n  files:\n%s\n' "$BEFORE_MD5" "$AFTER_MD5" "$AFTER_LIST"
fi
# 动手**之前**就要说清"预期 rc=3"（不能让运维先看到红再猜）。
if printf '%s' "$OUT" | grep -qF "退出码 3"; then
  ok "rc3-pre-announced"
else
  bad "rc3-pre-announced"
  printf '%s\n' "$OUT"
fi

# ---------------------------------------------------------------------------
# T5 rc=4：配置已写回、提交点未更新 ⇒ 必须区分于"失败"
# ---------------------------------------------------------------------------
say "T5 rc=4：重锚失败（服务持锁）⇒ 返回 4 且措辞是 WARN 而非 ERROR"
mkdir -p "$TMP/t5"
CONF="$TMP/t5/config.json"
mkconf "$CONF" ""
: >"$FAKE_LOG"
FAKE_RC=4
OUT="$(apply_migrate_config "$FAKE" "$CONF" "$TMP/t5/st" 2>&1)"
RC=$?
if [ "$RC" -eq 4 ]; then
  ok "rc4-propagated"
else
  bad "rc4-propagated"
  printf '  rc=%s（期望 4）\n%s\n' "$RC" "$OUT"
fi
if printf '%s' "$OUT" | grep -q "\[warn\]" &&
  printf '%s' "$OUT" | grep -qF "提交点未更新"; then
  ok "rc4-warn-not-error"
else
  bad "rc4-warn-not-error"
  printf '%s\n' "$OUT"
fi
if printf '%s' "$OUT" | grep -qF -- "--state-dir $TMP/t5/st"; then
  ok "rc4-hint-keeps-state-dir"
else
  bad "rc4-hint-keeps-state-dir"
  printf '%s\n' "$OUT"
fi

# ---------------------------------------------------------------------------
# T6 参数解析：--help / --state-dir 缺值（两者都在任何写操作之前退出）
# ---------------------------------------------------------------------------
say "T6 参数解析：--help 只打印用法；--state-dir 缺值必须报错"
if [ "$(id -u)" -ne 0 ]; then
  printf '  RESULT: SKIP  (t6-needs-root：install.sh 的 require_root)\n'
else
  OUT="$(bash "$INSTALL" --help 2>&1)"
  RC=$?
  if [ "$RC" -eq 0 ] && printf '%s' "$OUT" | grep -qF -- "--state-dir <DIR>" &&
    ! printf '%s' "$OUT" | grep -q "\[install\]"; then
    ok "help-prints-usage-and-exits"
  else
    bad "help-prints-usage-and-exits"
    printf '  rc=%s\n%s\n' "$RC" "$OUT"
  fi
  OUT="$(bash "$INSTALL" --state-dir 2>&1)"
  RC=$?
  if [ "$RC" -eq 1 ] && printf '%s' "$OUT" | grep -qF -- "--state-dir 需要一个目录参数"; then
    ok "state-dir-missing-value-rc1"
  else
    bad "state-dir-missing-value-rc1"
    printf '  rc=%s\n%s\n' "$RC" "$OUT"
  fi

  # ---- T6b **fail-closed（2.1.25 依裁决新增）**：未知参数必须 rc≠0 且**零副作用** ----
  #
  # "零副作用"的判据是**客观的**：安装脚本能改的东西里最容易误伤的是
  # `/usr/local/bin/ebpdns` 与 `/etc/ebpdns/config.json`。跑未知参数前后各取一次
  # md5/是否存在的快照，必须**逐位相同**；同时 `[install]` 日志头不得出现 ——
  # 那是"真的开始装了"的唯一标志（解析阶段在任何写操作之前）。
  say "T6b fail-closed：未知开关 / 未知动作 / 多余参数 一律 rc≠0 且零副作用"
  BIN_PROBE=/usr/local/bin/ebpdns
  CONF_PROBE=/etc/ebpdns/config.json
  snap() {
    local a b
    if [ -f "$BIN_PROBE" ]; then a="$(md5sum "$BIN_PROBE" | awk '{print $1}')"; else a=ABSENT; fi
    if [ -f "$CONF_PROBE" ]; then b="$(md5sum "$CONF_PROBE" | awk '{print $1}')"; else b=ABSENT; fi
    printf '%s|%s' "$a" "$b"
  }
  BEFORE="$(snap)"
  for CASE in "--no-such-flag" "-x" "--strict-config --typo start" "stat" "start extra" "--strict-config stat"; do
    # shellcheck disable=SC2086
    OUT="$(bash "$INSTALL" $CASE 2>&1)"
    RC=$?
    if [ "$RC" -ne 0 ] && ! printf '%s' "$OUT" | grep -q "\[install\]"; then
      ok "rejects[$CASE]"
    else
      bad "rejects[$CASE]"
      printf '  rc=%s（期望 ≠0，且不得出现 [install]）\n%s\n' "$RC" "$OUT"
    fi
  done
  AFTER="$(snap)"
  if [ "$BEFORE" = "$AFTER" ]; then
    ok "rejects-leave-zero-side-effects"
  else
    bad "rejects-leave-zero-side-effects"
    printf '  before=%s after=%s\n' "$BEFORE" "$AFTER"
  fi

  # ---- T6c 两种参数顺序解析结果必须相同（都 = start + STRICT） ----
  #
  # 为什么用 `parse_args` 而不是真的装一遍：真的装会写 /usr/local/bin、/etc/ebpdns、
  # 并 `systemctl restart` —— 那是部署代理的职责，本批**禁止**触碰生产。
  # "两种顺序都会启动"在解析层等价于"两种顺序都解出 action=start"；
  # `systemctl restart` + `NRestarts=0` 的现场验证归部署代理。
  say "T6c 两种参数顺序必须解析成同一个 (action=start, STRICT_CONFIG=1)"
  O1="$( ( parse_args --strict-config start 2>/dev/null
           printf 'ACTION=%s STRICT=%s MIG=%s' "$ARGS_ACTION" "${STRICT_CONFIG:-0}" "$DO_MIGRATE" ) 2>&1 )"
  O2="$( ( parse_args start --strict-config 2>/dev/null
           printf 'ACTION=%s STRICT=%s MIG=%s' "$ARGS_ACTION" "${STRICT_CONFIG:-0}" "$DO_MIGRATE" ) 2>&1 )"
  if [ "$O1" = "ACTION=start STRICT=1 MIG=0" ] && [ "$O2" = "$O1" ]; then
    ok "arg-order-equivalence"
  else
    bad "arg-order-equivalence"
    printf '  --strict-config start => %s\n  start --strict-config => %s\n' "$O1" "$O2"
  fi
  # 缺省（无参数）与显式 install 等价；`--state-dir` 只在 `--migrate-config` 下留存
  # （否则明确忽略，不得"生效一半"）。
  O3="$( ( parse_args 2>/dev/null
           printf 'ACTION=%s MIG=%s DIR=%s' "$ARGS_ACTION" "$DO_MIGRATE" "${MIGRATE_STATE_DIR:-}" ) 2>&1 )"
  O4="$( ( parse_args --migrate-config --state-dir /tmp/x 2>/dev/null
           printf 'ACTION=%s MIG=%s DIR=%s' "$ARGS_ACTION" "$DO_MIGRATE" "${MIGRATE_STATE_DIR:-}" ) 2>&1 )"
  O5="$( ( parse_args --state-dir /tmp/x 2>/dev/null
           printf 'ACTION=%s MIG=%s DIR=%s' "$ARGS_ACTION" "$DO_MIGRATE" "${MIGRATE_STATE_DIR:-}" ) 2>&1 )"
  if [ "$O3" = "ACTION=install MIG=0 DIR=" ] && [ "$O4" = "ACTION=install MIG=1 DIR=/tmp/x" ]; then
    ok "default-action-and-flag-capture"
  else
    bad "default-action-and-flag-capture"
    printf '  (no args) => %s\n  --migrate-config --state-dir /tmp/x => %s\n' "$O3" "$O4"
  fi
  if [ "$O5" = "ACTION=install MIG=0 DIR=" ]; then
    ok "state-dir-without-migrate-is-dropped"
  else
    bad "state-dir-without-migrate-is-dropped"
    printf '  --state-dir /tmp/x => %s（期望 DIR 为空）\n' "$O5"
  fi
fi

printf '\n==================== SUMMARY ====================\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf 'T_INSTALL_STATE_DIR=PASS（%d 项全绿）\n' "$N"
  exit 0
fi
printf 'T_INSTALL_STATE_DIR=FAIL（%d/%d 项红）：%s\n' "${#FAILED[@]}" "$N" "${FAILED[*]}"
exit 1
