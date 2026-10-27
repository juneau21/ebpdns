#!/bin/bash
# ============================================================================
# ebpdns 2.1.21 第 2 轮：**交付链**打包脚本（单一入口，顺序被硬编码）。
#
#   bash scripts/make_packages_221r2.sh            # 出包到 <root>/dist-packages
#
# 顺序（**不可调换** —— 第 1 轮的 P1「产物早于源码」就是顺序错造成的）：
#   0) 版本一致性硬门（七处同版本）
#   0b) 清单计数硬门（文档数字 == 动态实测；缺包产物时作用域 claim 为 SKIP）
#   0c) 离线重建等价门（**2.1.28 / A1**：上一版源码包 + patch233 == 本树；不跑构建）
#   1) 把源码树播种到**固定构建路径** `/build/ebpdns`，强制重编 wasm（清 target+dist，
#      touch web/src，`bash web/build.sh`；带 `--remap-path-prefix`，见 `scripts/_repro_flags.sh`）
#   2) 在**同一固定路径**构建 embed-frontend 二进制，产物拷回源码树
#   3) 门禁：EMBEDDED == DIST（结构）+ dist 新鲜度与 cfg-* 覆盖（web_dist_freshness 单测）
#   4) 清除构建标记 + 重算 _md5_prod.txt（**dist 已定稿**，清单必须在这之后算）
#   5) 打 prod 包 + src 包，两包内都必须带**同一份** `_md5_prod.txt`
#   6) 出包后自证：包内清单 md5sum -c 全 OK、prod 包白名单、两包清单逐字节相同
#   6b) 包内作用域自证（**2.1.28 / A2**）：`_doc_counts.py --require-pkgs` 真的在
#       prod/src 包里执行 `md5sum -c`，数字必须与文档一致
#
# **为什么把"重编 wasm"写死在打包脚本里**：AUDIT-221 DEF-221-02（P1）的实测教训 ——
# `web/src/pages/config.rs`（13:56）比 `web/dist/app_bg.wasm`（12:48）新 68 分钟，
# 于是交付的 wasm 里少了 `cfg-adatk` 控件（13 个新控件只交付 12 个）。人工记得
# "打包前先重编"是不可靠的；把它变成脚本第一步 + 一条单测护栏才行。
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
unset CARGO_TARGET_DIR

VERSION="${VERSION:-$(sed -n '/^\[workspace.package\]/,/^\[/p' "$ROOT/Cargo.toml" \
  | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1)}"
[ -n "$VERSION" ] || { echo "无法从 Cargo.toml 解析版本号" >&2; exit 1; }
NAME="ebpdns-${VERSION}"
OUT="${EBP_PKGOUT:-$ROOT/dist-packages}"
STAGE="$OUT/$NAME"
DIST="$ROOT/web/dist"
BIN="$ROOT/target/release/ebpdns"

say() { printf '\n=== %s\n' "$*"; }

# **2.1.43（打包权限规范化）**：同一套规则同时用于**源码树**与 **stage 目录** ——
# `*.sh` / `*.py` 强制 **0755**、其余普通文件 **0644**、目录 **0755**。
# 缺陷（2.1.42 交付实测）：源码包里 **154 个文件是 0666**（world-writable，含
# `web/build.sh`），打包链此前**没有任何一处**规范化权限 ⇒ 交付包权限完全继承解包环境。
perm_normalize() {
  local root="$1" label="${2:-perm}"
  find "$root" \
    \( -name target -o -name .git -o -name dist-packages -o -name __pycache__ -o -name node_modules \) -prune -o \
    -type d -print0 | xargs -0 -r chmod 0755
  find "$root" \
    \( -name target -o -name .git -o -name dist-packages -o -name __pycache__ -o -name node_modules \) -prune -o \
    -type f \( -name '*.sh' -o -name '*.py' \) -print0 | xargs -0 -r chmod 0755
  find "$root" \
    \( -name target -o -name .git -o -name dist-packages -o -name __pycache__ -o -name node_modules \) -prune -o \
    -type f ! -name '*.sh' ! -name '*.py' -print0 | xargs -0 -r chmod 0644
  printf '  %s: dirs=0755 sh/py=0755 data=0644\n' "$label"
}

say "0/6 版本一致性门禁（七处必须同版本；2.1.22 新增硬门）"
python3 "$ROOT/scripts/_version_consistency.py" "$ROOT"

# **2.1.27（A1）**：清单行数/文件数门禁 —— 文档里的数字必须等于**动态实测值**。
# 2.1.26 的负向证据：把 `docs/PACKAGING.md` 清单作用域表里的数字改小 1 后，四道门禁
# **仍然全 PASS**（"不得硬编码行数"当时只是文字约定）。本步让它变成 `exit 1`。
say "0b/6 清单计数门禁（scripts/_doc_counts.py：文档数字 == 动态实测值）"
python3 "$ROOT/scripts/_doc_counts.py" "$ROOT"

# **2.1.28（A1）**：离线重建等价门 —— 2.1.27 的教训是"补丁是否完备"**没有任何判据**
# （`patch227_*.py` 漏了 `web/Cargo.lock` 的版本行，离线重建 `CHANGED=1`，没人发现）。
# 本步：解上一版源码包 → 按序打 `patch233_*.py` → 与本树**逐文件字节比对**（不跑构建）。
# 缺上一版源码包/补丁目录时打印 SKIP（rc=3），交付环境用 EBP_PREV_SRC / EBP_PATCHES 指定。
say "0c/6 离线重建等价门（scripts/_rebuild_equiv.sh：上一版源码包 + patch233 == 本树）"
re_rc=0
bash "$ROOT/scripts/_rebuild_equiv.sh" "$ROOT" || re_rc=$?
if [ "$re_rc" = "3" ]; then
  echo "  **WARN** REBUILD_EQUIV=SKIP（未提供上一版源码包/补丁目录；交付时必须真实跑）"
elif [ "$re_rc" != "0" ]; then
  echo "  **REBUILD_EQUIV=FAIL**（rc=$re_rc）—— 补丁不完整，拒绝打包" >&2
  exit 1
fi

# **2.1.24（可复现打包）**：`BUILD_EPOCH` 是树内固定的打包时间戳，本脚本用它把
# 「打进二进制的前端产物元数据」钉死 —— 否则**同一棵树打两次包会得到不同的 bin md5**
# （2.1.22/2.1.23 已登记的"rust-embed 路径/mtime 效应"）。
EPOCH="$(tr -d '[:space:]' < "$ROOT/BUILD_EPOCH" 2>/dev/null || true)"
[ -n "$EPOCH" ] || { echo "BUILD_EPOCH 缺失或为空（可复现打包必需）" >&2; exit 1; }
echo "  BUILD_EPOCH=$EPOCH（$(date -u -d "@$EPOCH" +%FT%TZ 2>/dev/null || echo '?')）"

# **2.1.28（B1 的根因）**：`rust-embed` 会把 `web/dist` 每个文件的 `last_modified` **和
# `created`** 编进二进制（`rust-embed-utils` 8.13 的 `source_date_epoch.or(created)`）——
# 不设 `SOURCE_DATE_EPOCH` 时 `created` 是**文件系统的 btime**：每次重编 dist（或每次从别处
# 拷贝 dist）都会变 ⇒ 生成代码变 ⇒ ThinLTO 的 `llvm.<module-hash>` 变 ⇒ **同一份源码两次
# 全量构建字节不同**（2.1.27 把它误记成"跨路径/跨轮次"现象）。导出 `BUILD_EPOCH` 后，
# 两次不同时间、不同来源路径的全量构建逐字节相同（2.1.28 实测）。
export SOURCE_DATE_EPOCH="$EPOCH"

# **2.1.28（B1：固定构建路径）**：把源码树播种到**常量路径** `$BPATH` 再构建。
#
# 目的：让"源码放在哪个目录"不再影响字节（`--remap-path-prefix` 只改诊断/调试信息里的
# 路径）。**注意**：2.1.27 曾把"异路径不可复现"全部归因于 ThinLTO 对物理路径敏感；
# 2.1.28 实测其**真正主因**是上一条的 `created`（btime），固定路径是**另一条**独立收益
# （把 `$ROOT`/构建目录的绝对路径字节从产物里去掉）。
# `$BPATH` 可用 `EBP_BUILD_ROOT` 覆盖（默认 `/build/ebpdns`，与 remap 的目标一致）。
BPATH="${EBP_BUILD_ROOT:-/build/ebpdns}"

say "1/6 固定构建路径 $BPATH：播种源码树 + 强制重编 wasm（构建输入 mtime 统一到 BUILD_EPOCH）"
rm -rf "$BPATH"
mkdir -p "$BPATH"
# ① 源码 mtime 也钉到 EPOCH（**不是** `touch` 到"现在"）：
#    `web_dist_freshness` 的断言 ① 是"产物不得**早于**源码"，两者都等于 EPOCH ⇒ 恒成立；
#    若源码用 now、产物用 EPOCH，那条门禁会**正确地**报"产物过期"（等于自废门禁）。
find web/src -type f -name '*.rs' -print0 | xargs -0 -r touch -d "@$EPOCH"
for f in web/Cargo.toml web/index.html web/style.css web/build.rs; do
  [ -f "$f" ] && touch -d "@$EPOCH" "$f"
done
# ② 只播种"源码树该有的东西"（排除构建产物与出包目录；与源码包口径一致）。
tar -C "$ROOT" \
    --exclude='./target' --exclude='./web/target' --exclude='./web/dist' \
    --exclude='./dist-packages' --exclude='./.git' \
    --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
    -cf - . 2>/dev/null | tar -C "$BPATH" -xpf - 2>/dev/null
[ -f "$BPATH/Cargo.toml" ] || { echo "播种 $BPATH 失败" >&2; exit 1; }
echo "  build root = $BPATH（源码副本 $(find "$BPATH" -type f | wc -l) 个文件）"
( cd "$BPATH/web" && RUSTFLAGS="$(bash "$ROOT/scripts/_repro_flags.sh" "$BPATH" --wasm)" bash build.sh )
# ③ 产物 mtime 钉死 —— 这是"同一路径两次打包得到同一 bin md5"的**唯一**前提：
#    rust-embed 在编译期把 `web/dist/**` 的元数据编进二进制。
find "$BPATH/web/dist" -maxdepth 1 -type f -print0 | xargs -0 -r touch -d "@$EPOCH"
# ④ 把 dist **按字节**拷回源码树（包清单/EMBEDDED==DIST/新鲜度门禁都以树内 dist 为准）。
rm -rf "$DIST"
mkdir -p "$DIST"
cp -a "$BPATH/web/dist/." "$DIST/"
md5sum "$DIST"/app_bg.wasm
echo "  wasm bytes = $(stat -c %s "$DIST/app_bg.wasm")"
echo "  wasm mtime = $(stat -c %y "$DIST/app_bg.wasm")"

say "2/6 在固定路径 $BPATH 构建 embed-frontend 二进制（产物拷回源码树）"
# **2.1.24**：dist 的 mtime 现在比上一次构建产物**更旧**（= BUILD_EPOCH），cargo 会据此
# 判定"内嵌输入没变"而**跳过重新内嵌** ⇒ 交付的二进制里可能是**上一轮**的前端。
# 因此这里**强制**重编内嵌那一层。
#
# **2.1.24 二次修正（实测驱动）**：只清 `ebpdns-server` 时，同一棵树连打两次包的 bin
# **仍会差 40 字节** —— 因为 `ebpdns` **bin crate 自身**的目标文件被复用/重链，而它的
# `-C metadata` 会随 `ebpdns-server` rlib 的元数据一起变 ⇒ 这里清两个。
( cd "$BPATH" && cargo clean -p ebpdns-server --release && cargo clean -p ebpdns --release )
# **2.1.27（B3）+ 2.1.28（B1）**：release 构建注入 `--remap-path-prefix`（**只动构建参数**，
# `[profile.release]` 的 lto / codegen-units / opt-level 一行未改），且**在固定路径**上构建。
# ① 交付二进制里不再泄漏构建机的绝对路径（2.1.26 实测 `/root/` 命中 627 次、
#    `cargo/registry` 574 次）；② 让"同一份源码在不同绝对路径下构建"逐字节相同。
# 跨路径/同路径的实测由 `scripts/_repro_crosspath.sh` 给出（结论见 docs/PACKAGING.md §6d）。
REPRO_FLAGS="$(bash "$ROOT/scripts/_repro_flags.sh" "$BPATH")"
echo "  RUSTFLAGS = $REPRO_FLAGS"
( cd "$BPATH" && RUSTFLAGS="$REPRO_FLAGS" cargo build --release --bin ebpdns --features embed-frontend )
mkdir -p "$(dirname "$BIN")"
cp -f "$BPATH/target/release/ebpdns" "$BIN"
md5sum "$BIN"
echo "  bin bytes = $(stat -c %s "$BIN")"

say "3/6 门禁：EMBEDDED == DIST + dist 新鲜度/cfg-* 覆盖"
python3 "$ROOT/scripts/_embed_check.py" "$BIN" "$DIST"
cargo test --release -p ebpdns-resolver --test web_dist_freshness -- --nocapture

say "4/6 清除构建标记 + 重算 _md5_prod.txt（dist 已定稿）+ 导出 src 作用域清单"
python3 "$ROOT/scripts/_marker_strip.py" "$ROOT"
python3 "$ROOT/scripts/_manifest.py" "$ROOT"
MAN="$ROOT/_md5_prod.txt"
md5sum "$MAN"

# **2.1.26（P3：清单作用域）**：`_md5_prod.txt` 是**树根相对**的（行数 = 源码文件数 +
# `web/dist/*` 的条数），而**源码包按设计不含 `web/dist`** ⇒ 在 src 包内
# `md5sum -c _md5_prod.txt` 必然缺 dist 那几行（作用域差异，不是损坏，但等于
# "自校验永远红"）。这里用**同一份路径集合**导出只含源码的 `_md5_src.txt`
# （行数 = 清单行数 − dist 行数），随**源码包**交付 ⇒ 包内自校验有了一条恒成立的判据。
#
# **行数一律以生成结果为准，见 `_md5_src.txt` 的实际行数**：2.1.26 曾把当时的值写死在
# 这条注释里，而下一次加文件它就过期了（2.1.26 实测：注释里的行数与真实行数已经不符）。
# 2.1.27 起 `scripts/_doc_counts.py` 会把文档/注释里的数字与**动态实测**逐行比对。
#
# 写在 `$OUT`（= `dist-packages/`，源码包 tar 已 `--exclude` 它）而**不是**树内：
# 树里多一份未列入 `_md5_prod.txt` 的文件会让下一次 `_manifest.py` 把它算进清单行数，
# 于是"树内逐行全绿"这条既有硬门自己会漂移。产物在树外 ⇒ 两处判据互不影响。
SRC_MAN="$OUT/_md5_src.txt"
mkdir -p "$OUT"
python3 "$ROOT/scripts/_manifest.py" --src "$ROOT" "$SRC_MAN"
md5sum "$SRC_MAN"

say "4b/6 权限规范化（*.sh/*.py 0755、数据 0644、目录 0755）"
perm_normalize "$ROOT" "tree"
# 规范化后再算一次清单（权限位不进清单，但**顺序**保证：清单是最后一步产物）。
python3 "$ROOT/scripts/_manifest.py" "$ROOT" >/dev/null

say "5/6 出 prod 包 + src 包（两包同一份清单）"
# **2.1.22（P5）**：字节码缓存先在**树内**清掉（`scripts/__pycache__/` 是构建机残留：
# 打包脚本自己 import 过 `_manifest.py` 等模块），再用 tar `--exclude` 兜底，最后
# `_pack_verify.py` 对**包内名单**做硬断言。三层都要有 —— 只靠 tar 排除规则的话，
# 规则一旦被后人改动就是"静默交付二进制缓存"（解释器版本相关、不可审计）。
find "$ROOT" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "$ROOT" -name '*.pyc' -delete 2>/dev/null || true
find "$ROOT" -name '*.pyo' -delete 2>/dev/null || true
echo "  bytecode caches left in tree = $(find "$ROOT" -name '*.py[co]' -o -name '__pycache__' | wc -l) (must be 0)"

rm -rf "$STAGE"
mkdir -p "$STAGE"/bin "$STAGE"/web "$STAGE"/systemd "$STAGE"/etc/ebpdns
install -m 0755 "$BIN" "$STAGE/bin/ebpdns"
cp -a "$DIST/." "$STAGE/web/"
install -m 0755 "$ROOT/packaging/install.sh" "$STAGE/install.sh"
install -m 0644 "$ROOT/packaging/systemd/ebpdns.service" "$STAGE/systemd/ebpdns.service"
install -m 0644 "$ROOT/packaging/etc/ebpdns/config.json" "$STAGE/etc/ebpdns/config.json"
install -m 0644 "$ROOT/LICENSE" "$STAGE/LICENSE"
install -m 0644 "$ROOT/NOTICE" "$STAGE/NOTICE"
install -m 0644 "$MAN" "$STAGE/_md5_prod.txt"

say "5b/6 stage 权限规范化（install.sh 0755、bin/ebpdns 0755、数据 0644、目录 0755）"
perm_normalize "$STAGE" "stage"
chmod 0755 "$STAGE/bin/ebpdns"

mkdir -p "$OUT"
PROD="$OUT/${NAME}-prod.tar.gz"
SRC="$OUT/${NAME}-src.tar.gz"
# **2.1.24（可复现打包）**：把 tar 的**成员顺序/时间戳/属主**也钉死，否则"同一棵树打两次包"
# 的 tar md5 会因 readdir 顺序与 `_md5_prod.txt`/`web/` 目录的 mtime 抖动而不同。
#
# **能力探测必须是功能性的**（2.1.24 第一次实现踩过这个坑）：`tar --help` 里写的是
# `--sort=ORDER` 而不是 `--sort=name`，用 `grep --sort=name` 探测会**静默降级**成"无归一化"，
# 于是两个 src 包只差两个成员的 mtime（`web/` 目录与 `_md5_prod.txt`）⇒ 整包 md5 不同。
# 现在直接试跑一次（`-cf /dev/null -T /dev/null`），支持才启用。
TAR_DET=()
if tar --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
     -cf /dev/null -T /dev/null 2>/dev/null; then
  TAR_DET=(--sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner)
  echo "  tar 确定性模式：${TAR_DET[*]}"
else
  echo "  警告：本机 tar 不支持 --sort=name/--mtime ⇒ 包 md5 可能不稳定（bin md5 不受影响）"
fi
tar -C "$OUT" "${TAR_DET[@]}" -czf "$PROD" "$NAME"
# **2.1.26**：源码包要额外带上 `_md5_src.txt`（树**外**的 `$OUT` 里），因此用**第二个
# `-C`** 把它单独加进去，并给它单独一条 `--transform`：
#   `s,^\.,$NAME,`                  → `.`/`./crates` … ⇒ `$NAME`/`$NAME/crates` …
#   `s,^_md5_src\.txt$,$NAME/...,`  → `_md5_src.txt`   ⇒ `$NAME/_md5_src.txt`
# 两条 transform **按顺序对每个成员都试一遍**；`_md5_src.txt` 不以 `.` 开头、树内成员
# 也不叫这个名字 ⇒ 互不干扰（`_pack_verify.py` 第 3 道门按**包内名单**再判一次）。
#
# **2.1.28（A2 收尾）**：构建树的根目录里可能有一份**上一版源码包**解出来的 `_md5_src.txt`
# （从源码包解出来的树天然带它）。若不排除，src tar 会带**同名两个成员** —— 2.1.27 的
# harness 靠"打包前手工删掉"绕开，不是脚本行为。这里显式 `--exclude='./_md5_src.txt'`：
# 包内那份只来自 `$OUT`（本轮现算），成员唯一、内容可判。
tar -C "$ROOT" "${TAR_DET[@]}" -czf "$SRC" \
  --exclude='./target' --exclude='./web/target' --exclude='./web/dist' \
  --exclude='./dist-packages' --exclude='./.git' \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='*.pyo' \
  --exclude='./_md5_src.txt' \
  --transform="s,^\.,$NAME," \
  . \
  -C "$OUT" --transform="s,^_md5_src\.txt$,${NAME}/_md5_src.txt," _md5_src.txt
ls -l "$PROD" "$SRC"
md5sum "$PROD" "$SRC"

say "6/6 出包后自证"
python3 "$ROOT/scripts/_pack_verify.py" "$ROOT" "$STAGE" "$PROD" "$SRC"

# **2.1.43**：包权限自证 —— **解包后**断言（独立判据，不相信本脚本自己的 chmod）。
say "6a/6 包权限规范化自证（scripts/t-pkg-modes.sh：解包后断言）"
bash "$ROOT/scripts/t-pkg-modes.sh" "$PROD" "$SRC"

# **2.1.28（A2）**：包内作用域自证 —— `_doc_counts.py` 的 `prod`/`src` claim 必须**真的在
# 包产物里执行** `md5sum -c`（解包 → 在包内跑 → 执行结果进断言）。`--require-pkgs` 下
# 缺包产物 = 红，所以这一步同时证明"文档里的 prod 包数字是跑出来的，不是算出来的"。
say "6b/6 包内作用域自证（scripts/_doc_counts.py --require-pkgs）"
python3 "$ROOT/scripts/_doc_counts.py" "$ROOT" --prod-pkg "$PROD" --src-pkg "$SRC" --require-pkgs

say "完成"
"$STAGE/bin/ebpdns" --version
