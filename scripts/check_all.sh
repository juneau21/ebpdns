#!/usr/bin/env bash
# ============================================================================
# ebpdns **2.1.28**：一次跑完所有门禁（本地自查 / 交付前 / CI 单入口）
#
#   bash scripts/check_all.sh                 # 全跑（含 cargo test 全量）
#   SKIP_TEST=1 bash scripts/check_all.sh     # 只跑快门禁（fmt / clippy / 版本+文档）
#   RELEASE=1 bash scripts/check_all.sh       # 两条 cargo test（第 4/5 步）都加 --release
#   OFFLINE=1 bash scripts/check_all.sh       # 所有**解析依赖**的 cargo 命令加 --offline
#   JOBS=1 bash scripts/check_all.sh          # 并行度（默认 1，与交付口径一致）
#
# **2.1.26（B6：开关与文档的一致性）**：2.1.25 的标题行写"`RELEASE=1` cargo test --release"、
# 文档 §6b 写"`RELEASE=1` 给 `cargo test` 加 `--release`"，但实现**只**给第 4 步（全量）
# 加了 —— 第 5 步 `web_dist_freshness` 固定按 **debug** 编译。于是"交付口径
# `OFFLINE=1 RELEASE=1 JOBS=1`"与"实际跑的东西"在第五步上不一致（同一份开关，两种语义）。
# 现在第 5 步也吃 `RELEASE`；`TMPDIR` 一类**不是开关**，`OFFLINE` 也不作用于
# `cargo fmt`（它不解析依赖，加 `--offline` 只会报错）—— 头部注释与
# `docs/PACKAGING.md §6b` 现在逐字同义，并且由 `check_all_selftest.sh` 第 5 条判据
# 把"两处开关清单必须相同"钉死。
#
# **2.1.25（P3 修复：`OFFLINE=1` 第 5 步必红）**：2.1.24 的第 5 步把
# `"${CARGO_EXTRA[@]}"` 放在 `--` **之后** ⇒ `cargo test ... -- --nocapture --offline`
# 把 `--offline` 当成**测试二进制的参数**，首跑即 `error: Unrecognized option: 'offline'`。
# 现在所有 `CARGO_EXTRA` 展开一律在 `--` **之前**；`scripts/check_all_selftest.sh`
# 把这条判据钉成自测（含"放回错误位置必须变红"的负向对照）。
#
# 为什么需要它（2.1.24 可维护性项）：2.1.19–2.1.23 的门禁散在
#   `make check`（fmt+clippy+test）、`scripts/_version_consistency.py`、
#   `scripts/_embed_check.py`、`web_dist_freshness` 测试、打包脚本第 0/3 步……
# 于是"我该跑哪几条"只能靠记忆，实测漏跑过（2.1.23 的 `clippy`/`fmt` 就一直没清零）。
# 本脚本把它们收成**一个入口**，并且**前一步失败不中断后续步骤** ——
# 交付前需要一次看到**全部**结论，而不是修一条跑一轮。
#
# 顺序与包装脚本（`scripts/make_packages_221r2.sh`）的第 0/3 步保持一致；
# 区别是本脚本**不改动**任何产物（不重编 wasm、不重算清单）。
#
# **2.1.29（WEBGATE：`web/` 独立 workspace 的门禁盲区）**：根 `Cargo.toml` 把 `web/`
# 放进 `exclude`，所以第 2/3 步的根 fmt/clippy **完全不覆盖**前端 —— 2.1.28 实测
# web crate `fmt --check` 有 88 hunks、wasm32 clippy 有 23 条（`--all-targets` 下另加
# 2 条 dead_code）。现在新增**第 8/9 步**单独跑 web 的 fmt 与 wasm32 clippy；两条都
# `env -u CARGO_TARGET_DIR`（`web/build.sh` 的硬要求：web 用自己的 `web/target`）。
#
# 退出码：0 = 全绿；1 = 至少一项红（逐项结果在最后汇总）。
#
# **2.1.32**：新增第 13 步 `t-install-running` —— `install.sh start` 在「服务已在运行」
# 时不再 rc=1，而是检测旧实例（systemd active / 端口 exe=ebpdns）→ 先停后启 → rc=0；
# 别的进程占端口仍 rc≠0。第 12 步矩阵的第 10 行（容器）补齐 `check-config`。
#
# **2.1.43**：新增第 14 步 `t-pkg-modes` —— **解包后**断言无 world-writable、`*.sh`/`*.py`
# 0755、数据 0644、目录 0755、`install.sh`/`bin/ebpdns` 0755。2.1.42 交付实测：源码包
# 有 **154 个 0666 文件**（含 `web/build.sh`），打包链没有任何权限规范化。
set -uo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1

case "${1:-}" in
  -h|--help)
    sed -n '4,9p' "$0" | sed 's/^# \{0,1\}//'
    printf '\nweb/ 独立 workspace（2.1.29 起的第 8/9 步，均 env -u CARGO_TARGET_DIR）：\n'
    printf '  web fmt     cd web && cargo fmt --all --check\n'
    printf '  web clippy  cd web && cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings\n'
    printf '\n接口键集（2.1.30 第 10 步）：\n'
    printf '  python3 scripts/_interface_keys.py <root>   # 文档键集 == 隔离实例实测（缺二进制时 SKIP）\n'
    printf '\n配置键集 + 干净机安装矩阵（2.1.31 第 11/12 步）：\n'
    printf '  python3 scripts/_config_keys.py <root>      # 模板+default_config+运行期注入 == /api/config\n'
    printf '  bash scripts/t-install-matrix.sh            # 账号回退/无 systemd/端口/GLIBC/幂等/dry-run\n'
    printf '\nstart 运行语义（2.1.32 第 13 步）：\n'
    printf '  bash scripts/t-install-running.sh           # 旧实例先停后启/keep/dry/foreign（临时前缀）\n'
    printf '\n包权限规范化（2.1.43 第 14 步）：\n'
    printf '  bash scripts/t-pkg-modes.sh                 # 解包后断言（无包产物时对树断言）\n'
    exit 0
    ;;
esac

CARGO_EXTRA=()
[ "${OFFLINE:-0}" = "1" ] && CARGO_EXTRA+=(--offline)
JOBS="${JOBS:-1}"
# **2.1.26**：`RELEASE` 现在对**两条** `cargo test`（第 4 步全量 + 第 5 步 dist 新鲜度）同义。
REL_ARGS=()
[ "${RELEASE:-0}" = "1" ] && REL_ARGS+=(--release)

FAILED=()
N=0
step() { N=$((N + 1)); printf '\n=== [%d] %s\n' "$N" "$*"; }
ok() { printf '  RESULT: PASS  (%s)\n' "$1"; }
bad() { printf '  RESULT: FAIL  (%s)\n' "$1"; FAILED+=("$1"); }

# ---- 1) 版本 + 文档一致门禁（七处同版本；两条文档契约各四处）----
step "版本 + 文档一致门禁（scripts/_version_consistency.py）"
if python3 scripts/_version_consistency.py "$ROOT"; then
  ok "version+doc"
else
  bad "version+doc"
fi

# ---- 1b) 文档计数门禁（2.1.27 / A1：清单行数/文件数必须等于动态实测值）----
#
# 2.1.26 的实测漏洞：`docs/PACKAGING.md` 里写着"不得硬编码行数"，但**没有任何机器判据** ——
# 把清单作用域表里的 `N/N OK` 改小 1 之后，四道门禁**仍然全 PASS、rc=0**。
# 本步让"文档里的数字必须等于实测"变成硬断言（`scripts/_doc_counts.py`：claim +
# deny-by-default），负向对照（改一个数字必须变红）由 `scripts/check_all_selftest.sh` 跑。
#
# **2.1.28（A2）**：prod/src 作用域的 claim **必须真的在包产物里执行 `md5sum -c`** ——
# `dist-packages/` 里有当前版本的包时自动执行；没有时打印 SKIP（打包第 6b 步用
# `--require-pkgs` 跑一次，缺包产物 = 红）。
step "文档计数门禁（scripts/_doc_counts.py：清单行数/文件数 == 动态实测）"
if python3 scripts/_doc_counts.py "$ROOT"; then
  ok "doc-counts"
else
  bad "doc-counts"
fi

# ---- 1c) 离线重建等价门（2.1.28 / A1：上一版源码包 + patch230 == 本树，不跑构建）----
#
# 2.1.27 的教训：`patch227_*.py` 的版本 part 漏了 `web/Cargo.lock` 的版本行 ⇒ 离线重建
# `CHANGED=1`，而当时**没有任何判据**。本步用 `scripts/_rebuild_equiv.sh` 逐文件比对；
# 缺上一版源码包/补丁目录时打印 SKIP（交付环境用 EBP_PREV_SRC / EBP_PATCHES 指定）。
step "离线重建等价门（scripts/_rebuild_equiv.sh：上一版源码包 + patch230 == 本树）"
bash scripts/_rebuild_equiv.sh "$ROOT"
re_rc=$?
if [ "$re_rc" = "0" ]; then
  ok "rebuild-equiv"
elif [ "$re_rc" = "3" ]; then
  printf '  RESULT: SKIP（未提供上一版源码包/补丁目录）\n'
else
  bad "rebuild-equiv"
fi

# ---- 2) 格式化 ----
step "cargo fmt --all --check"
if cargo fmt --all --check; then ok "fmt"; else bad "fmt"; fi

# ---- 3) clippy（--all-targets 全目标 + -D warnings；允许项与理由见 docs/CLIPPY.md）----
# **2.1.39**：口径与 docs/CLIPPY.md §1 / web 第 9 步对齐 —— 任何 warning 都是失败。
step "cargo clippy --workspace --all-targets --offline -- -D warnings"
if cargo clippy --workspace --all-targets --offline -j "$JOBS" -- -D warnings; then
  ok "clippy"
else
  bad "clippy"
fi

# ---- 4) 全量测试 ----
if [ "${SKIP_TEST:-0}" = "1" ]; then
  step "cargo test（SKIP_TEST=1 ⇒ 跳过）"
  printf '  RESULT: SKIP\n'
else
  TEST_ARGS=(test --workspace)
  [ "${RELEASE:-0}" = "1" ] && TEST_ARGS+=(--release)
  step "cargo ${TEST_ARGS[*]} -j $JOBS --no-fail-fast ${CARGO_EXTRA[*]}"
  if cargo "${TEST_ARGS[@]}" -j "$JOBS" --no-fail-fast "${CARGO_EXTRA[@]}"; then
    ok "test"
  else
    bad "test"
  fi
fi

# ---- 5) web/dist 新鲜度 + cfg-* 覆盖（源码包无 dist ⇒ 测试内部自动跳过）----
#
# **2.1.25**：`"${CARGO_EXTRA[@]}"` 必须在 `--` **之前** —— `--` 之后的一切都会被
# `cargo test` 原样转给**测试二进制**，于是 `OFFLINE=1` 会变成
# `error: Unrecognized option: 'offline'`（2.1.24 首跑即红的那个缺陷）。
#
# **2.1.26**：本步也吃 `RELEASE`（与第 4 步同义）—— 2.1.25 只有第 4 步吃，
# 于是"`RELEASE=1` = 与交付口径一致"这句话在第五步上不成立（同一开关两种语义）。
step "web_dist_freshness（web/dist 不早于 web/src；每个 cfg-* id 都在 wasm 里）"
if cargo test -p ebpdns-resolver --test web_dist_freshness "${REL_ARGS[@]}" -j "$JOBS" "${CARGO_EXTRA[@]}" -- --nocapture; then
  ok "web_dist_freshness"
else
  bad "web_dist_freshness"
fi

# ---- 6) web/ 独立 workspace：格式化（根 workspace exclude 掉 web，必须单列）----
step "cargo fmt --all --check（web/ 独立 workspace）"
if ( cd web && env -u CARGO_TARGET_DIR cargo fmt --all --check ); then
  ok "web-fmt"
else
  bad "web-fmt"
fi

# ---- 7) web/ 独立 workspace：wasm32 clippy（-D warnings）----
#
# `env -u CARGO_TARGET_DIR`：web/build.sh 要求 web 用默认的 `web/target`；若继承根
# workspace 的 CARGO_TARGET_DIR，产物会落进根 target 并与 wasm32 依赖序列互相污染。
step "cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings（web/ 独立 workspace）"
if ( cd web && env -u CARGO_TARGET_DIR cargo clippy --target wasm32-unknown-unknown --all-targets -j "$JOBS" "${CARGO_EXTRA[@]}" -- -D warnings ); then
  ok "web-clippy"
else
  bad "web-clippy"
fi

# ---- 8) 接口键集门禁（2.1.30 新增第 10 项）--------------------------------
#
# 为什么需要它：`web/INTERFACE.md` 同时是**人读文档**与**前端契约**，但此前没有任何
# 机器判据证明"文档里列的 `/api/status` 键 == 实际响应键"。2.1.29 的 `used_live`
# 文档缺口就是这么漏掉的（字段在实现里、不在字典里，门禁全绿）。
# `_interface_keys.py` 从 INTERFACE.md 的标记块解析键集，与**隔离实例**逐键比对；
# 有 `target/{release,debug}/ebpdns` / `EBP_BIN` 时自动拉起临时实例（私有 state_dir +
# 临时端口），都没有时打印 SKIP —— 不拿"没跑"冒充绿。
step "接口键集门禁（scripts/_interface_keys.py：INTERFACE 键集 == 隔离实例实测）"
IK_LOG="$(mktemp)"
python3 scripts/_interface_keys.py "$ROOT" >"$IK_LOG" 2>&1
ik_rc=$?
cat "$IK_LOG"
if [ "$ik_rc" = "0" ] && grep -q '^INTERFACE_KEYS=PASS' "$IK_LOG"; then
  ok "interface-keys"
elif [ "$ik_rc" = "0" ] && grep -q '^INTERFACE_KEYS=SKIP' "$IK_LOG"; then
  printf '  RESULT: SKIP（未发现可执行二进制；构建后本项严格执行）\n'
else
  bad "interface-keys"
fi
rm -f "$IK_LOG"

# ---- 9) 配置键集门禁（2.1.31 新增第 11 项）--------------------------------
#
# 为什么需要它：2.1.30 的报告与 INTERFACE.md 把"配置键数"写死成 74，而**生产
# `/api/config` 实测 75** —— 多出来的那 1 个是 `rules` 镜像键（v2→v3 迁移把它从
# config.json 删除，运行期 `migrate_cfg` 从 `default_config()` 补回内存）。文档与
# 实现各说各的，且没有任何机器判据。`_config_keys.py` 从**随包模板 + default_config()
# + migrate_cfg 的运行期注入键**推导期望键集，与隔离实例实际 `/api/config` 逐键比对，
# 并断言文档里的"模板键数 / 运行期补键数 / 当前总键数"三个数字 == 实测。
step "配置键集门禁（scripts/_config_keys.py：模板+default_config+运行期注入 == 隔离实例实测）"
CK_LOG="$(mktemp)"
python3 scripts/_config_keys.py "$ROOT" >"$CK_LOG" 2>&1
ck_rc=$?
cat "$CK_LOG"
if [ "$ck_rc" = "0" ] && grep -q '^CONFIG_KEYS=PASS' "$CK_LOG"; then
  ok "config-keys"
elif [ "$ck_rc" = "0" ] && grep -q '^CONFIG_KEYS=SKIP' "$CK_LOG"; then
  printf '  RESULT: SKIP（未发现可执行二进制；构建后本项严格执行）\n'
else
  bad "config-keys"
fi
rm -f "$CK_LOG"

# ---- 10) 干净机安装矩阵（2.1.31 新增第 12 项）-----------------------------
# 现场缺陷：最小化 Debian/容器没有 `passwd` 包 ⇒ `install.sh:528` 的 `groupadd`
# 直接 `command not found` 并中止安装。2.1.31 把安装器改成"账号分级回退 + systemd 可选 +
# 端口/GLIBC 预检 + dry-run + uninstall"，本步用**临时前缀 + PATH 遮蔽**跑矩阵 1–9
# （不碰真机 /etc、/usr/local、systemd、53/8353）。非 root 时打印 SKIP（rc=0）。
step "干净机安装矩阵（scripts/t-install-matrix.sh：1–9；10 视容器能力 SKIP）"
IM_LOG="$(mktemp)"
bash scripts/t-install-matrix.sh >"$IM_LOG" 2>&1
im_rc=$?
cat "$IM_LOG"
if [ "$im_rc" = "0" ] && grep -q '^INSTALL_MATRIX=PASS' "$IM_LOG"; then
  ok "install-matrix"
elif [ "$im_rc" = "0" ] && grep -q '^INSTALL_MATRIX=SKIP' "$IM_LOG"; then
  printf '  RESULT: SKIP（需 root；当前非 root）\n'
else
  bad "install-matrix"
fi
rm -f "$IM_LOG"

# ---- 11) install.sh start 的运行实例语义（2.1.32 新增第 13 项）--------------
#
# 2.1.31 的端口预检让「服务已在运行时再跑 install.sh start」返回 rc=1，升级必须先手工
# `systemctl stop`。2.1.32 把 start 的语义改成：检测到**自家旧实例** ⇒ 打印 INFO、
# 先停后启、rc=0；端口被**别的进程**占用仍 rc≠0 并报 pid/exe/端口；另有 --restart /
# --keep-running / --dry-run。本步用**临时前缀 + systemctl shim + 高位端口**实测
# A1–A5（systemd 路径）与 B1–B4（无 systemd：SIGTERM→5s→SIGKILL），不碰真机服务。
# **2.1.38（安装器隔离）**：本项同时跑 `t-install-isolation.sh` —— 两条生产事故的回归：
# ① 端口只从目标前缀配置取（包内模板 53/8353 不得参与判定）；② 前缀外的 ebpdns 一律拒绝
# 停止（rc≠0 + pid/exe/端口）；③ unit 名与前缀绑定、`uninstall` 校验 unit 路径；
# ④ `--dry-run`/前缀模式默认不执行破坏性动作；⑤ fake systemctl 日志证明真 systemd 0 次。
step "install.sh 运行语义 + 安装器隔离（t-install-running.sh + t-install-isolation.sh）"
IR_LOG="$(mktemp)"
bash scripts/t-install-running.sh >"$IR_LOG" 2>&1
ir_rc=$?
bash scripts/t-install-isolation.sh >>"$IR_LOG" 2>&1
iso_rc=$?
cat "$IR_LOG"
if [ "$ir_rc" = "0" ] && grep -q '^T_INSTALL_RUNNING=PASS' "$IR_LOG" &&
  [ "$iso_rc" = "0" ] && grep -q '^T_INSTALL_ISOLATION=PASS' "$IR_LOG"; then
  ok "install-running+isolation"
elif [ "$ir_rc" = "0" ] && grep -q '^T_INSTALL_RUNNING=SKIP' "$IR_LOG" &&
  [ "$iso_rc" = "0" ] && grep -q '^T_INSTALL_ISOLATION=SKIP' "$IR_LOG"; then
  printf '  RESULT: SKIP（需 root + 已构建二进制；构建后本项严格执行）\n'
else
  bad "install-running+isolation"
fi
rm -f "$IR_LOG"

# ---- 14) 包权限规范化（2.1.43 新增第 14 项）--------------------------------
#
# 2.1.42 交付实测缺陷：源码包 **154 个文件 0666**（world-writable，含 `web/build.sh`），
# 且 `*.sh` 可执行位完全依赖解包环境 —— 打包链此前没有任何一处规范化。2.1.43 起
# `make_packages_221r2.sh` 第 4b/5b 步强制 `*.sh`/`*.py` 0755、数据 0644、目录 0755；
# 本步是**独立判据**：有包产物就对**解包后的真实包**断言，没有就对树跑同一套规则。
step "包权限规范化（scripts/t-pkg-modes.sh：无 world-writable / *.sh+*.py 0755 / 目录 0755）"
PM_LOG="$(mktemp)"
bash scripts/t-pkg-modes.sh >"$PM_LOG" 2>&1
pm_rc=$?
cat "$PM_LOG"
if [ "$pm_rc" = "0" ] && grep -q '^T_PKG_MODES=PASS' "$PM_LOG"; then
  ok "pkg-modes"
elif [ "$pm_rc" = "3" ] && grep -q '^T_PKG_MODES=SKIP' "$PM_LOG"; then
  printf '  RESULT: SKIP（无输入）\n'
else
  bad "pkg-modes"
fi
rm -f "$PM_LOG"

# ---- 汇总 ----
printf '\n==================== SUMMARY ====================\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf 'CHECK_ALL=PASS（%d 项全绿）\n' "$N"
  exit 0
fi
printf 'CHECK_ALL=FAIL（%d/%d 项红）：%s\n' "${#FAILED[@]}" "$N" "${FAILED[*]}"
exit 1
