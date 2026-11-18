#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文档计数门禁：**接口键集/包内文件数 == 动态实测值**。

## 口径（2.1.49 起）

2.1.49 的交付清单**只有包内 `_md5_package.txt` 一套**：它由打包脚本在包内容定稿后现算，
路径相对包根，`md5sum -c` 兼容。源码树内**不再保留**任何 md5 清单，因此本门禁也不再
断言"树内清单行数/两份作用域清单"这类数字 —— 那套 claim 已随树内清单一起删除。

本文件仍然负责：

1. **接口键集**（不依赖隔离实例的那一半）：`docs/INTERFACE.md` 的标记块行数/字段表行数
   必须等于声明数字，qtype 名单必须等于 `crates/ebpdns-proto/src/constants.rs` 的实际长度；
2. **prod 包白名单文件数**：文档里的 "N 个文件" 必须等于 `_pack_verify.py` 的 `ALLOWED`
   条目数；有真实 prod 包产物时还必须等于**包内实际文件数**；
3. **deny-by-default**：`SCAN_FILES` 里"清单/行数/文件数"语境中的数字必须由 claim 覆盖；
   表格行里的 `md5sum -c` 必须由 claim 执行（模板里已不再有这类表格行）。

包产物自动发现：`<tree>/dist-packages/ebpdns-<ver>-prod.tar.gz`（只认当前版本），
或环境变量 `DOC_COUNTS_PROD_PKG` / `--prod-pkg`。`--require-pkgs` 下缺包产物 = 红。

退出码：0 = 全部断言成立（含 selftest 的双向对照）；1 = 至少一处漂移 / 负向对照失效 /
（`--require-pkgs` 时）缺包产物。
"""
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile

# 被扫描的文件：这几处是"清单/文件数"出现过、且最容易再漂的地方。
SCAN_FILES = (
    "docs/PACKAGING.md",
    "scripts/make_packages_221r2.sh",
    "scripts/_pack_verify.py",
    "scripts/_manifest.py",
)

# `docs/INTERFACE.md` 的键集/计数也进本门禁（只按标记块/字段表做精确断言）。
INTERFACE = "docs/INTERFACE.md"
PROD_MANIFEST = "_md5_package.txt"

# deny-by-default 的**行作用域**：只扫"讲清单/行数/文件数"的那些行。
SCOPE_RX = re.compile(r"清单|manifest|_md5|ALLOWED|行数|作用域|白名单|src 包|prod 包|web/dist")

# 自校验命令：表格行里出现的必须"被某条 claim 执行过"。
CMD_RX = re.compile(r"md5sum\s+-c\s+(_md5_[a-z_]+\.txt)")


def read(root, rel):
    with io.open(os.path.join(root, rel.replace("/", os.sep)), encoding="utf-8") as fh:
        return fh.read()


def line_starts(text):
    """每行的起始偏移（用于把 claim 的整文件偏移换算成行号）。"""
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return starts


# 步骤标签（`say "4/6 …"` / `第 4/6 步`）**不是**计数：它是打包脚本的步骤编号约定。
STEP_LABEL_RX = re.compile(r"^\s*(?:say\s+)?[\"']?[0-9][0-9a-b]?/\d+\s")


def line_of(starts, pos):
    lo, hi = 0, len(starts) - 1
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid - 1
    return lo + 1  # 1-based


def workspace_version(root):
    inside = False
    for line in read(root, "Cargo.toml").splitlines():
        t = line.strip()
        if t.startswith("["):
            inside = t == "[workspace.package]"
            continue
        if inside:
            m = re.match(r'^version\s*=\s*"([^"]+)"', t)
            if m:
                return m.group(1)
    return None


def find_pkg(root, kind, explicit):
    """返回 (path or None, 来源说明)。只认**当前版本**的包名，避免旧包冒充。"""
    if explicit:
        return (explicit, "--%s-pkg" % kind)
    env = os.environ.get("DOC_COUNTS_%s_PKG" % kind.upper())
    if env:
        return (env, "env DOC_COUNTS_%s_PKG" % kind.upper())
    v = workspace_version(root)
    if v:
        cand = os.path.join(root, "dist-packages", "ebpdns-%s-%s.tar.gz" % (v, kind))
        if os.path.isfile(cand):
            return (cand, "dist-packages/<current-version>")
    return (None, "not found")


def extract_pkg(tar_path, dest):
    """解包到 dest，返回包内**唯一顶层目录**（没有顶层目录时返回 dest）。"""
    with tarfile.open(tar_path) as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:  # Python < 3.12 没有 filter 参数
            t.extractall(dest)
    tops = [n for n in os.listdir(dest) if os.path.isdir(os.path.join(dest, n))]
    files = [n for n in os.listdir(dest) if os.path.isfile(os.path.join(dest, n))]
    if len(tops) == 1 and not files:
        return os.path.join(dest, tops[0])
    return dest


def count_files(pkg_root):
    n = 0
    for _dp, _dn, fn in os.walk(pkg_root):
        n += len(fn)
    return n


# ---------------------------------------------------------------------------------------------
# 动态实测（唯一真值）
# ---------------------------------------------------------------------------------------------
def measure(root, prod_pkg=None, src_pkg=None):
    q = {}
    # prod 包白名单条目数：从 `_pack_verify.py` 的 `ALLOWED` 集合反算（不硬编码）
    pv = read(root, "scripts/_pack_verify.py")
    m = re.search(r"^ALLOWED\s*=\s*\{(.*?)^\}", pv, re.S | re.M)
    q["ALLOWED_FILES"] = len(re.findall(r'"([^"]+)"', m.group(1))) if m else -1
    q["PROD_PKG_FILES"] = q["ALLOWED_FILES"]
    q["_pkgs"] = {}
    tmp = tempfile.mkdtemp(prefix="doccnt-pkg-")
    try:
        rec = {"path": None, "how": "not found", "files": None}
        q["_pkgs"]["prod"] = rec
        path, how = find_pkg(root, "prod", prod_pkg)
        rec["path"], rec["how"] = path, how
        if path and os.path.isfile(path):
            dest = os.path.join(tmp, "prod")
            os.makedirs(dest)
            try:
                top = extract_pkg(path, dest)
            except (tarfile.TarError, OSError) as e:
                print("  FAIL  解包 %s 失败：%s" % (path, e))
            else:
                rec["root"] = top
                rec["files"] = count_files(top)
                q["PROD_PKG_FILES"] = rec["files"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return q


def scoped_ready(q, scope):
    """该作用域是否有真实产物可判（当前只有 prod 包）。"""
    if scope == "prod":
        return bool((q["_pkgs"].get("prod") or {}).get("path"))
    return True


# ---------------------------------------------------------------------------------------------
# 逐条 claim：(id, scope, 文件, 窄正则, 断言, 说明[, 期望命中次数])
# ---------------------------------------------------------------------------------------------
def _claims():
    def eq1(k1):
        def chk(q, nums):
            want = q[k1]
            return int(nums[0]) == want, "%s 实测 = %d" % (k1, want)

        return chk

    return [
        {
            # 两处：§1 的产物形态表与 §6 的包完整性判据（都写"白名单 N 个文件"）。
            "id": "pkg-prod-allowlist",
            "scope": "prod",
            "cmd": "（从 _pack_verify.py 的 ALLOWED 与包内实际文件数反算）",
            "file": "docs/PACKAGING.md",
            "pat": r"(?<![\w.])(\d+)\s*个文件",
            "check": eq1("PROD_PKG_FILES"),
            "desc": "prod 包白名单文件数 = ALLOWED 条目数 = 包内实际文件数",
            "want": 2,
        },
    ]


# ---------------------------------------------------------------------------------------------
# 计数语境 token（deny-by-default 兜底）
# ---------------------------------------------------------------------------------------------
COUNT_TOKENS = (
    re.compile(r"(?<![\w.])(\d{1,6})\s*行(?![\w])"),
    re.compile(r"(?<![\w.])(\d{1,6})\s*个文件"),
    re.compile(r"(?<![\w.])(\d{1,6})\s*(?:OK|FAILED)(?![\w])"),
    re.compile(r"(?<![\w.])(\d{1,6})\s*/\s*(\d{1,6})(?![\w.])"),
    re.compile(r"\b(?:lines|rows|files|paths)\s*=\s*(\d{1,6})"),
    re.compile(r"(?<![\w.])(\d{1,6})\s+(?:expected|files|paths|rows|lines)(?![\w])"),
)


def _marker_lines(text, name):
    m = re.search(
        r"<!--\s*%s_BEGIN\s*-->(.*?)<!--\s*%s_END\s*-->" % (name, name), text, re.S
    )
    if not m:
        return None
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip()]


def _persist_rows(text):
    """`cache.persist` 字段字典两张表的字段行数（键数）。"""
    try:
        start = text.index("### `/api/status.cache.persist`")
        end = text.index("**配置页两种空态文案", start)
    except ValueError:
        return -1
    body = text[start:end]
    keys = re.findall(r"^\|\s*`([a-z][a-z0-9_]*)`\s*\|", body, re.M)
    return len(list(dict.fromkeys(keys)))


def _pipeline_fields(text):
    m = re.search(r"`Pipeline\{([^`]+)\}`", text)
    if not m:
        return -1
    depth, parts, buf = 0, [], []
    for ch in m.group(1):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip():
        parts.append("".join(buf))
    return len([p for p in parts if p.split(":", 1)[0].strip()])


def _constants_counts(root):
    try:
        src = read(root, "crates/ebpdns-proto/src/constants.rs")
    except OSError:
        return (-1, -1)
    m = re.search(r"pub const SUPPORTED_QTYPES[^=]*=\s*&\[(.*?)\];", src, re.S)
    n_sup = len(re.findall(r'\(TYPE_[A-Z0-9_]+,\s*"[A-Z0-9]+"\)', m.group(1))) if m else -1
    m2 = re.search(r"pub fn qtype_must_reject\(t: u16\) -> bool \{(.*?)\n\}", src, re.S)
    n_rej = -1
    if m2:
        body = m2.group(1)
        n_rej = (1 if re.search(r"t\s*==\s*0", body) else 0)
        mm = re.search(r"matches!\(\s*t,(.*?)\)", body, re.S)
        if mm:
            n_rej += len(set(re.findall(r"TYPE_[A-Z0-9_]+", mm.group(1))))
    return (n_sup, n_rej)


def check_interface(root, verbose=True):
    """`INTERFACE.md` 的键集/字段/总数必须与**文档自身标记块/源码单一来源**一致。"""
    fails = []
    try:
        text = read(root, INTERFACE)
    except OSError as e:
        return [(INTERFACE, 0, "不可读：%s" % e)]
    status = _marker_lines(text, "STATUS_KEYS")
    counters = _marker_lines(text, "COUNTERS_KEYS")
    rules = _marker_lines(text, "RULES_KEYS")
    metrics = _marker_lines(text, "METRICS")
    persist_n = _persist_rows(text)
    pipeline_n = _pipeline_fields(text)
    sup_c, rej_c = _constants_counts(root)

    def claim(pat, label, want):
        m = re.search(pat, text, re.S)
        if not m:
            fails.append((INTERFACE, 0, "找不到计数声明：%s" % label))
            return
        got = int(m.group(1))
        if got != want:
            fails.append(
                (INTERFACE, line_of(line_starts(text), m.start()), "%s 声明 %d != 实测 %d" % (label, got, want))
            )

    if status is None or counters is None or rules is None or metrics is None:
        fails.append((INTERFACE, 0, "缺少 STATUS_KEYS / COUNTERS_KEYS / RULES_KEYS / METRICS 标记块"))
    else:
        claim(r"顶层字段（\*\*2\.1\.30 实测：(\d+) 个键\*\*）", "status 键数", len(status))
        claim(r"\| `counters` \| object \| 同代计数器表，\*\*(\d+) 个键\*\*", "counters 键数", len(counters))
        claim(r"三本账（\*\*2\.1\.30：(\d+) 个顶层键", "rules 键数", len(rules))
        # 正则不锁死小版本（判据不变）。
        claim(
            r"指标名全表（\*\*2\.\d+\.\d+：(\d+) 个 HELP family\*\*）",
            "metrics 指标名数",
            len(metrics),
        )
    claim(r"2\.1\.30 共 (\d+) 键", "persist 键数", persist_n)
    claim(r"（\*\*(\d+) 个字段\*\*", "pipeline 字段数", pipeline_n)
    claim(r"\*\*受理并缓存 (\d+) 型\*\*", "qtype 受理数", sup_c)
    claim(r"\*\*(\d+) 类一律 `NOTIMP`\*\*", "qtype 拒绝数", rej_c)
    if verbose:
        if fails:
            for rel, ln, msg in fails:
                print("  FAIL  %-28s %s:%d  %s" % ("interface-counts", rel, ln, msg))
        else:
            print(
                "  PASS  %-28s %s  status=%d counters=%d rules=%d persist=%d pipeline=%d metrics=%d qtype=%d/%d"
                % (
                    "interface-counts",
                    INTERFACE,
                    len(status or []),
                    len(counters or []),
                    len(rules or []),
                    persist_n,
                    pipeline_n,
                    len(metrics or []),
                    sup_c,
                    rej_c,
                )
            )
    return fails


def check(root, q, verbose=True, require_pkgs=False):
    """返回 (fails, hits, skips)。fails = [(file, line, msg)]；hits = {file: [(line, s, e)]}。"""
    fails = []
    skips = []
    hits = {}
    for claim in _claims():
        cid, rel, pat, chk, desc = claim["id"], claim["file"], claim["pat"], claim["check"], claim["desc"]
        scope = claim["scope"]
        want_n = claim.get("want", 1)
        text = read(root, rel)
        starts = line_starts(text)
        ms = list(re.compile(pat, re.M).finditer(text))
        if len(ms) != want_n:
            fails.append(
                (
                    rel,
                    line_of(starts, ms[0].start()) if ms else 0,
                    "claim `%s` 命中 %d 次（必须恰好 %d 次）—— %s" % (cid, len(ms), want_n, desc),
                )
            )
            continue
        for m in ms:
            hits.setdefault(rel, []).append((line_of(starts, m.start()), m.start(), m.end()))
        if not scoped_ready(q, scope):
            msg = "claim `%s`（作用域 %s）**没有在对应产物里执行** `%s`" % (cid, scope, claim["cmd"])
            if require_pkgs:
                fails.append((rel, line_of(starts, ms[0].start()), msg))
            else:
                skips.append((cid, scope))
            if verbose:
                print("  SKIP  %-28s %s:%d  %s" % (cid, rel, line_of(starts, ms[0].start()), msg))
            continue
        bad_here = []
        for m in ms:
            nums = [g for g in m.groups() if g is not None]
            good, want = chk(q, nums)
            ln = line_of(starts, m.start())
            if not good:
                bad_here.append((rel, ln, "claim `%s` 写成 %s，%s（%s）" % (cid, "/".join(nums), want, desc)))
        if not bad_here:
            if verbose:
                print(
                    "  PASS  %-28s %s:%d%s  %s"
                    % (cid, rel, line_of(starts, ms[0].start()), "" if want_n == 1 else "（%d 处）" % want_n, want)
                )
        else:
            fails.extend(bad_here)

    # ---- deny-by-default ①：计数语境里的数字必须落在某条 claim 的命中区间内 ----
    for rel in SCAN_FILES:
        text = read(root, rel)
        starts = line_starts(text)
        covered = hits.get(rel, [])
        for i, line in enumerate(text.splitlines(), 1):
            if SCOPE_RX.search(line) and not STEP_LABEL_RX.search(line):
                base = starts[i - 1]
                for rx in COUNT_TOKENS:
                    for m in rx.finditer(line):
                        pos = base + m.start()
                        if any(ln == i and s <= pos < e for (ln, s, e) in covered):
                            continue
                        fails.append(
                            (
                                rel,
                                i,
                                "未登记的计数数字 `%s`（要么由 claim 断言，要么改成动态表述）" % m.group(0).strip(),
                            )
                        )
            # ---- deny-by-default ②：表格行里的 `md5sum -c …` 必须被 claim 整行覆盖 ----
            if line.lstrip().startswith("|"):
                base = starts[i - 1]
                for m in CMD_RX.finditer(line):
                    pos = base + m.start()
                    if any(ln == i and s <= pos < e for (ln, s, e) in covered):
                        continue
                    fails.append(
                        (
                            rel,
                            i,
                            "未执行的自校验命令 `%s`（表格行里的命令式断言必须由带作用域的 claim 执行）"
                            % m.group(0).strip(),
                        )
                    )
    fails.extend(check_interface(root, verbose=verbose))
    return fails, hits, skips


def report(fails, q, skips):
    print("\n--- 动态实测（唯一真值）---")
    for k in ("ALLOWED_FILES", "PROD_PKG_FILES"):
        print("  %-16s = %s" % (k, q[k]))
    rec = q["_pkgs"].get("prod", {})
    if rec.get("path"):
        print("  %-16s = %s  files=%d (root=%s)" % ("prod", rec["path"], rec["files"], os.path.basename(rec.get("root", ""))))
    else:
        print("  %-16s = 未发现当前版本的 prod 包产物（%s）⇒ 包内文件数 claim 为 SKIP" % ("prod", rec.get("how")))
    if skips:
        print("\n  **%d 条 claim 因缺包产物未执行**：%s" % (len(skips), skips))
    if fails:
        print("\n  ---- 漂移清单（file:line）----")
        for rel, ln, msg in fails:
            print("  %s:%d  %s" % (rel, ln, msg))


# ---------------------------------------------------------------------------------------------
# 负向对照
# ---------------------------------------------------------------------------------------------
FIXTURE_SRC_MAP = {
    # prod 包布局（与 make_packages_221r2.sh / _pack_verify.py 的 ALLOWED 一致）
    "bin/ebpdns": "target/release/ebpdns",
    "install.sh": "packaging/install.sh",
    "systemd/ebpdns.service": "packaging/systemd/ebpdns.service",
    "etc/ebpdns/config.json": "packaging/etc/ebpdns/config.json",
    "LICENSE": "LICENSE",
    "NOTICE": "NOTICE",
    PROD_MANIFEST: None,
    "web/index.html": "web/dist/index.html",
    "web/app.js": "web/dist/app.js",
    "web/app_bg.wasm": "web/dist/app_bg.wasm",
    "web/style.css": "web/dist/style.css",
    "web/echarts.min.js": "web/dist/echarts.min.js",
    "web/favicon.svg": "web/dist/favicon.svg",
}


def build_fixture_pkg(root, dest):
    """**仅用于 --selftest**：按交付链的映射从树里合成一个 prod 包布局（文件数可判）。"""
    top = os.path.join(dest, "pkg")
    os.makedirs(top, exist_ok=True)
    for rel, src in FIXTURE_SRC_MAP.items():
        dp = os.path.join(top, rel.replace("/", os.sep))
        d = os.path.dirname(dp)
        if d:
            os.makedirs(d, exist_ok=True)
        if src is None:
            open(dp, "wb").close()
            continue
        sp = os.path.join(root, src.replace("/", os.sep))
        if os.path.isfile(sp):
            shutil.copy2(sp, dp)
        else:
            open(dp, "wb").close()
    return top


def selftest(root, q):
    print("\n--- 负向对照（--selftest）---")
    need = list(SCAN_FILES) + [INTERFACE, "crates/ebpdns-proto/src/constants.rs"]
    tmp = tempfile.mkdtemp(prefix="doccnt-")
    fx = tempfile.mkdtemp(prefix="doccnt-fx-")
    rc = 0
    try:
        for rel in need:
            dst = os.path.join(tmp, rel.replace("/", os.sep))
            d = os.path.dirname(dst)
            if d and not os.path.isdir(d):
                os.makedirs(d)
            shutil.copy2(os.path.join(root, rel.replace("/", os.sep)), dst)
        prod_fx = build_fixture_pkg(root, os.path.join(fx, "prod"))
        qfx = dict(q)
        qfx["PROD_PKG_FILES"] = count_files(prod_fx)
        qfx["_pkgs"] = {
            "prod": {"path": prod_fx, "root": prod_fx, "files": qfx["PROD_PKG_FILES"]},
        }
        print("  FIXTURE  prod files=%d (ALLOWED=%d)" % (qfx["PROD_PKG_FILES"], qfx["ALLOWED_FILES"]))

        f0, _h, _s = check(tmp, qfx, verbose=False)
        if f0:
            print("  FAIL  selftest-基线  影子副本未通过：%s" % (f0[:2],))
            rc = 1
        else:
            print("  PASS  selftest-基线  影子副本 PASS")

        rel = "docs/PACKAGING.md"
        p = os.path.join(tmp, rel)
        orig = io.open(p, encoding="utf-8").read()
        n = qfx["ALLOWED_FILES"]
        needle = "%d 个文件" % n
        if needle not in orig:
            print("  FAIL  selftest-定位  影子副本里找不到 `%s`（claim 与文档不同步）" % needle)
            rc = 1
        else:
            io.open(p, "w", encoding="utf-8", newline="\n").write(
                orig.replace(needle, "%d 个文件" % (n + 1), 1)
            )
            f1, _h, _s = check(tmp, qfx, verbose=False)
            if f1 and any(r[0] == rel and r[1] > 0 for r in f1):
                print("  PASS  selftest-负向①  白名单文件数改错后变红（file:line）：%s:%d" % (f1[0][0], f1[0][1]))
            else:
                print("  FAIL  selftest-负向①  改错数字后**没有**变红（判据空转）：fails=%r" % (f1[:2],))
                rc = 1
            io.open(p, "w", encoding="utf-8", newline="\n").write(orig)
            f2, _h, _s = check(tmp, qfx, verbose=False)
            if not f2:
                print("  PASS  selftest-回滚  改回后变绿（rc=0）")
            else:
                print("  FAIL  selftest-回滚  改回后仍红：%r" % (f2[:2],))
                rc = 1

        # ---- 负向②：INTERFACE.md 的 status 键数改错必须红 ----
        pint = os.path.join(tmp, INTERFACE.replace("/", os.sep))
        orig_i = io.open(pint, encoding="utf-8").read()
        nstat = len(_marker_lines(orig_i, "STATUS_KEYS") or [])
        needle_i = "实测：%d 个键" % nstat
        if needle_i not in orig_i:
            print("  FAIL  selftest-定位②  影子副本里找不到 `%s`" % needle_i)
            rc = 1
        else:
            io.open(pint, "w", encoding="utf-8", newline="\n").write(
                orig_i.replace(needle_i, "实测：%d 个键" % (nstat - 1), 1)
            )
            f3, _h, _s = check(tmp, qfx, verbose=False)
            if f3 and any(r[0] == INTERFACE for r in f3):
                print("  PASS  selftest-负向②  INTERFACE status 键数改错后变红：%s:%d" % (f3[0][0], f3[0][1]))
            else:
                print("  FAIL  selftest-负向②  INTERFACE 键数改错**没有**变红：%r" % (f3[:2],))
                rc = 1
            io.open(pint, "w", encoding="utf-8", newline="\n").write(orig_i)
            f4, _h, _s = check(tmp, qfx, verbose=False)
            if not f4:
                print("  PASS  selftest-回滚②  改回后变绿（rc=0）")
            else:
                print("  FAIL  selftest-回滚②  改回后仍红：%r" % (f4[:2],))
                rc = 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(fx, ignore_errors=True)
    return rc


def main():
    args = sys.argv[1:]
    opts = [a for a in args if a.startswith("--")]
    prod_pkg = src_pkg = None
    pos = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--prod-pkg" and i + 1 < len(args):
            prod_pkg = args[i + 1]
            i += 2
            continue
        if a == "--src-pkg" and i + 1 < len(args):
            src_pkg = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        pos.append(a)
        i += 1
    root = os.path.abspath(pos[0] if pos else ".")
    require = "--require-pkgs" in opts
    print("=== DOC_COUNTS gate (%s)%s" % (root, "  [require-pkgs]" if require else ""))
    q = measure(root, prod_pkg=prod_pkg, src_pkg=src_pkg)
    fails, _hits, skips = check(root, q, require_pkgs=require)
    if q["ALLOWED_FILES"] <= 0:
        fails.append(("scripts/_pack_verify.py", 0, "无法从 ALLOWED 反算 prod 包文件数"))
    if q["_pkgs"].get("prod", {}).get("path") and q["PROD_PKG_FILES"] != q["ALLOWED_FILES"]:
        fails.append(
            (
                "docs/PACKAGING.md",
                0,
                "prod 包内实际文件数 %d != ALLOWED 条目数 %d" % (q["PROD_PKG_FILES"], q["ALLOWED_FILES"]),
            )
        )
    report(fails, q, skips)
    if fails:
        print("\nDOC_COUNTS=FAIL (%d)" % len(fails))
        return 1
    tail = "（%d 条 claim + deny-by-default 兜底；全部等于动态实测值）" % len(_claims())
    if skips:
        tail += "  DOC_COUNTS_SCOPED=SKIP(%d)" % len(skips)
    else:
        tail += "  DOC_COUNTS_SCOPED=EXECUTED"
    print("\nDOC_COUNTS=PASS" + tail)
    if "--selftest" in opts:
        if selftest(root, q) != 0:
            return 1
        print("DOC_COUNTS_SELFTEST=PASS")
    else:
        print("DOC_COUNTS_GATE=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
