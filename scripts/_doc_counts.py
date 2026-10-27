#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""清单行数 / 文件数门禁（**2.1.28 / A2：作用域化 + 真执行**）。

## 为什么有它（2.1.26 的负向证据）

2.1.26 的 `docs/PACKAGING.md` 里写着"**不得硬编码 194/188/189/195**"，但**那句话本身没有
任何机器判据**。2.1.26 交付时实测：把清单作用域表里的 `189/189 OK` 改成 `188/188 OK`，
四道门禁（`VERSION_CONSISTENCY` / `DOC_CONSTRAINTS` / `RULES_CONTRACT` /
`MANIFEST_SCOPE_DOC`）**仍然全 PASS、rc=0** ⇒ 文档可以继续漂，只要没人肉眼比对。

2.1.27 把"数字 == 动态实测"做成了断言（`scripts/_doc_counts.py`），但**实测值里有两个是
算出来的、不是跑出来的**：`docs/PACKAGING.md` 当时写"prod 包内 `md5sum -c _md5_prod.txt`
= 199/199 OK（包内带 web/）"，而**那条命令从没在任何交付物里被执行过**。2.1.28 实测：
prod 包里只有白名单 13 个文件、前端资产摊平在 `web/`（不是 `web/dist/`）⇒ 在 prod 包里跑
prod 清单是 **6 OK / 176 FAILED**（**按设计**，不是损坏）。"写了一条命令 + 一个期望值，
却没有人跑过那条命令"就是本文件 2.1.28 要消灭的东西。

## 2.1.28 的三条规则

1. **claim 必须带作用域**（`tree` / `prod` / `src`）。
2. **`prod` / `src` 作用域的 claim 必须在对应的包产物里真的执行那条命令**
   （`md5sum -c <清单>`，优先调用真实 `md5sum`；宿主机没有时用 `hashlib` 等价实现并打印
   `engine=hashlib`），把**执行结果**纳入断言。找不到对应版本的包产物时：默认打印
   `SKIP`（`DOC_COUNTS_SCOPED=SKIP`），`--require-pkgs` 下变红 —— 交付链/打包后自证一律
   用 `--require-pkgs`，不允许"没跑也算绿"。
3. **禁止未执行的命令式断言**（deny-by-default 扩展）：`SCAN_FILES` 里任何**表格行**
   出现 `md5sum -c <清单>` 就必须被某条 claim 的命中区间**整行覆盖**；计数语境里的
   数字（`N 行` / `N 个文件` / `N OK` / `N/N` / `lines=` …）仍必须落在 claim 命中区间内。

## 动态实测（唯一真值，全部现算）

* `MANIFEST_LINES` / `DIST_LINES` / `SRC_LINES` / `TREE_SRC_FILES`：清单与树；
* `TREE_MD5_OK/FAILED`：在**树内**执行 `md5sum -c _md5_prod.txt`；
* `PROD_PKG_FILES`：prod 包**内实际文件数**（有产物时）/ `_pack_verify.py` 的 `ALLOWED`
  条目数（无产物时）；两者都有时必须相等；
* `PROD_MD5_OK/FAILED`：在**prod 包根**执行 `md5sum -c _md5_prod.txt`；
* `SRC_MD5_OK/FAILED`：在**src 包根**执行 `md5sum -c _md5_src.txt`；
* `SRC_PROD_OK/FAILED`：在**src 包根**执行 `md5sum -c _md5_prod.txt`（按设计缺 dist 行）。

## 纪律

本文件里**没有**"当前树有多少个文件"的常数：期望值全部从 `_md5_prod.txt` / `_md5_src.txt` /
树本身 / 包产物 / `_pack_verify.py` 的 `ALLOWED` 反算。文件数变化时**只有人工写的文档快照**
需要跟着改，而改错由本门禁负责抓住（打印 `file:line`）。

用法：

    python3 scripts/_doc_counts.py <tree-root>
    python3 scripts/_doc_counts.py <tree-root> --require-pkgs   # 缺包产物 ⇒ 红
    python3 scripts/_doc_counts.py <tree-root> --selftest       # 负向对照（含"改回旧错措辞必须红"）
    python3 scripts/_doc_counts.py <tree-root> --prod-pkg P --src-pkg S

包产物自动发现：`<tree>/dist-packages/ebpdns-<ver>-{prod,src}.tar.gz`（**只认当前版本**），
或环境变量 `DOC_COUNTS_PROD_PKG` / `DOC_COUNTS_SRC_PKG`。

退出码：0 = 全部断言成立（含 selftest 的双向对照）；1 = 至少一处漂移 / 负向对照失效 /
（`--require-pkgs` 时）缺包产物。
"""
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

# 被扫描的文件：这几处是"清单行数/文件数"出现过、且最容易再漂的地方。
SCAN_FILES = (
    "docs/PACKAGING.md",
    "scripts/make_packages_221r2.sh",
    "scripts/_pack_verify.py",
    "scripts/_manifest.py",
)

# **2.1.30**：`web/INTERFACE.md` 的键集/计数也进本门禁（不参与 deny-by-default 的
# 全文数字扫描 —— 那份文档里有大量历史编号；只按**标记块/字段表**做精确断言）。
INTERFACE = "web/INTERFACE.md"

# deny-by-default 的**行作用域**：只扫"讲清单/行数/文件数"的那些行。
SCOPE_RX = re.compile(r"清单|manifest|_md5|ALLOWED|行数|作用域|白名单|src 包|prod 包|web/dist")

MANIFEST = "_md5_prod.txt"
SRC_MANIFEST = "_md5_src.txt"
DIST_PREFIX = "web/dist/"

# 自校验命令：表格行里出现的必须"被某条 claim 执行过"。
CMD_RX = re.compile(r"md5sum\s+-c\s+(_md5_prod\.txt|_md5_src\.txt)")


def read(root, rel):
    with io.open(os.path.join(root, rel.replace("/", os.sep)), encoding="utf-8") as fh:
        return fh.read()


def line_starts(text):
    """每行的起始偏移（用于把 claim 的整文件偏移换算成行号/行内偏移）。"""
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


# ---------------------------------------------------------------------------------------------
# 执行自校验命令（优先真实 md5sum；没有则 hashlib 等价实现）
# ---------------------------------------------------------------------------------------------
def run_md5_check(pkg_root, manifest_name):
    """在 pkg_root 里执行 `md5sum -c <manifest>` 并返回 {engine, ok, failed, rc}。

    优先调用系统 `md5sum`（与文档里给人看的命令**逐字一致**）；宿主机（例如 Windows）
    没有 md5sum 时，用 hashlib 做**语义等价**的逐行校验，并在输出里标明 `engine=hashlib`
    —— 绝不"跳过不执行"。
    """
    man = os.path.join(pkg_root, manifest_name)
    if not os.path.isfile(man):
        return None
    if shutil.which("md5sum"):
        r = subprocess.run(
            ["md5sum", "-c", manifest_name], cwd=pkg_root, capture_output=True, text=True
        )
        ok = sum(1 for l in r.stdout.splitlines() if l.endswith(": OK"))
        failed = sum(1 for l in r.stdout.splitlines() if l.strip() and not l.endswith(": OK"))
        return {"engine": "md5sum", "ok": ok, "failed": failed, "rc": r.returncode}
    ok = failed = 0
    with io.open(man, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            digest, rel = line.split("  ", 1)
            p = os.path.join(pkg_root, rel.replace("/", os.sep))
            if os.path.isfile(p):
                with open(p, "rb") as f:
                    got = hashlib.md5(f.read()).hexdigest()
            else:
                got = None
            if got == digest:
                ok += 1
            else:
                failed += 1
    return {"engine": "hashlib", "ok": ok, "failed": failed, "rc": 0 if failed == 0 else 1}


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


def measure(root, prod_pkg=None, src_pkg=None):
    man_p = os.path.join(root, MANIFEST)
    if not os.path.exists(man_p):
        print("  FAIL  %s 缺失：无法做清单计数断言（先跑 scripts/_manifest.py）" % MANIFEST)
        return None
    rows = [l for l in io.open(man_p, encoding="utf-8").read().splitlines() if l.strip()]
    man = [line.split("  ", 1) for line in rows]
    q = {}
    q["MANIFEST_LINES"] = len(man)
    q["DIST_LINES"] = sum(1 for _d, rel in man if rel.startswith(DIST_PREFIX))
    q["SRC_LINES"] = q["MANIFEST_LINES"] - q["DIST_LINES"]
    src_paths = [rel for _d, rel in man if not rel.startswith(DIST_PREFIX)]
    missing = [rel for rel in src_paths if not os.path.isfile(os.path.join(root, rel.replace("/", os.sep)))]
    q["TREE_SRC_FILES"] = len(src_paths) - len(missing)
    q["_missing"] = missing
    # prod 包白名单条目数：从 `_pack_verify.py` 的 `ALLOWED` 集合反算（不硬编码）
    pv = read(root, "scripts/_pack_verify.py")
    m = re.search(r"^ALLOWED\s*=\s*\{(.*?)^\}", pv, re.S | re.M)
    q["ALLOWED_FILES"] = len(re.findall(r'"([^"]+)"', m.group(1))) if m else -1
    q["PROD_PKG_FILES"] = q["ALLOWED_FILES"]
    src_p = os.path.join(root, SRC_MANIFEST)
    q["SRC_MANIFEST_PRESENT"] = os.path.exists(src_p)
    q["SRC_MANIFEST_LINES"] = (
        sum(1 for l in io.open(src_p, encoding="utf-8") if l.strip()) if q["SRC_MANIFEST_PRESENT"] else -1
    )

    # ---- 树内：真的执行 md5sum -c ----
    tree = run_md5_check(root, MANIFEST)
    q["TREE_MD5_OK"] = tree["ok"] if tree else -1
    q["TREE_MD5_FAILED"] = tree["failed"] if tree else -1
    q["TREE_ENGINE"] = tree["engine"] if tree else "-"
    # 树内是否带 `web/dist`（构建树才有；源码包按设计不带）。"树内 204/204" 这条 claim
    # 只对**构建树**成立：源码包树里缺的正是 `web/dist/*`（那时应该用 src 作用域清单）。
    # **2.1.30**：`all([])` 为真会让"清单里一条 dist 行都没有"的源码包树被误判成构建树
    # （2.1.30 实测：源码包树重算清单后 DIST_LINES=0 ⇒ 旧判据空转、tree claim 假红）。
    q["_tree_has_dist"] = q["DIST_LINES"] > 0 and all(
        os.path.isfile(os.path.join(root, rel.replace("/", os.sep)))
        for _d, rel in man
        if rel.startswith(DIST_PREFIX)
    )

    # ---- prod / src 包：解包后**在包内**执行同一条命令 ----
    q["_scoped"] = {}
    q["_pkgs"] = {}
    tmp = tempfile.mkdtemp(prefix="doccnt-pkg-")
    try:
        for kind, explicit in (("prod", prod_pkg), ("src", src_pkg)):
            path, how = find_pkg(root, kind, explicit)
            rec = {"path": path, "how": how, "ok": None}
            q["_pkgs"][kind] = rec
            if not path or not os.path.isfile(path):
                continue
            dest = os.path.join(tmp, kind)
            os.makedirs(dest)
            try:
                top = extract_pkg(path, dest)
            except (tarfile.TarError, OSError) as e:
                print("  FAIL  解包 %s 失败：%s" % (path, e))
                continue
            rec["root"] = top
            rec["files"] = count_files(top)
            if kind == "prod":
                rec["md5_prod"] = run_md5_check(top, MANIFEST)
                q["PROD_MD5_OK"] = rec["md5_prod"]["ok"] if rec["md5_prod"] else -1
                q["PROD_MD5_FAILED"] = rec["md5_prod"]["failed"] if rec["md5_prod"] else -1
                q["PROD_PKG_FILES"] = rec["files"]  # 有产物时以**包内实际文件数**为准
            else:
                rec["md5_src"] = run_md5_check(top, SRC_MANIFEST)
                rec["md5_prod"] = run_md5_check(top, MANIFEST)
                q["SRC_MD5_OK"] = rec["md5_src"]["ok"] if rec["md5_src"] else -1
                q["SRC_MD5_FAILED"] = rec["md5_src"]["failed"] if rec["md5_src"] else -1
                q["SRC_PROD_OK"] = rec["md5_prod"]["ok"] if rec["md5_prod"] else -1
                q["SRC_PROD_FAILED"] = rec["md5_prod"]["failed"] if rec["md5_prod"] else -1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return q


def scoped_ready(q, scope, dist_required=True):
    """该作用域的包产物是否真的被执行过（有实测值）。"""
    rec = q["_pkgs"].get(scope) or {}
    if scope == "tree":
        # "树内"行只在**构建树**（带 web/dist）里可判定；源码包树里缺的正是 dist 那几行。
        # 白名单计数这类"从脚本反算"的 claim 不需要 dist（dist_required=False）。
        return (q["TREE_MD5_OK"] >= 0) and (q.get("_tree_has_dist", False) or not dist_required)
    if scope == "prod":
        return bool(rec.get("md5_prod"))
    if scope == "src":
        return bool(rec.get("md5_src")) and bool(rec.get("md5_prod"))
    return False


# ---------------------------------------------------------------------------------------------
# 逐条 claim：(id, scope, 文件, 窄正则, 断言, 说明[, 期望命中次数])
# 正则里的数字组必须**恰好**覆盖那一处给人看的数字；断言函数把它与动态实测值比较。
# 表格行里的 claim 正则必须覆盖**整行**（含 `md5sum -c …`），这样"命令式断言"才可判定。
# ---------------------------------------------------------------------------------------------
def _claims():
    def eq(k1, k2):
        def chk(q, nums):
            want = (q[k1], q[k2])
            got = tuple(int(x) for x in nums)
            return got == want, "实测 %s/%s = %d/%d" % (k1, k2, want[0], want[1])

        return chk

    def eq1(k1):
        def chk(q, nums):
            want = q[k1]
            return int(nums[0]) == want, "%s 实测 = %d" % (k1, want)

        return chk

    return [
        {
            "id": "pkg-md-tree-row",
            "scope": "tree",
            "cmd": "md5sum -c _md5_prod.txt",
            "file": "docs/PACKAGING.md",
            "pat": r"^\|\s*树内[^\n|]*\|\s*`md5sum -c _md5_prod\.txt`\s*\|\s*\*\*(\d+)/(\d+) OK\*\*",
            "check": eq("TREE_MD5_OK", "MANIFEST_LINES"),
            "desc": "树内自校验 OK 数 = 清单行数（命令在树内执行）",
        },
        {
            "id": "pkg-md-prod-row",
            "scope": "prod",
            "cmd": "md5sum -c _md5_prod.txt",
            "file": "docs/PACKAGING.md",
            "pat": r"^\|\s*prod 包内[^\n|]*\|\s*`md5sum -c _md5_prod\.txt`\s*\|\s*\*\*(\d+) OK / (\d+) FAILED\*\*",
            "check": eq("PROD_MD5_OK", "PROD_MD5_FAILED"),
            "desc": "prod 包内跑 prod 清单 = 包内实际命中的清单路径数 / 其余（按设计）",
        },
        {
            "id": "pkg-md-src-row",
            "scope": "src",
            "cmd": "md5sum -c _md5_src.txt",
            "file": "docs/PACKAGING.md",
            "pat": r"^\|\s*\*\*src 包内\*\*\s*\|\s*\*\*`md5sum -c _md5_src\.txt`\*\*\s*\|\s*\*\*(\d+)/(\d+) OK\*\*",
            "check": eq("SRC_MD5_OK", "SRC_LINES"),
            "desc": "src 包内自校验 OK 数 = src 作用域行数（命令在 src 包内执行）",
        },
        {
            "id": "pkg-md-src-prodscope-row",
            "scope": "src",
            "cmd": "md5sum -c _md5_prod.txt",
            "file": "docs/PACKAGING.md",
            "pat": r"^\|\s*src 包内\s*\|\s*`md5sum -c _md5_prod\.txt`\s*\|\s*(\d+) OK / (\d+) FAILED",
            "check": eq("SRC_PROD_OK", "SRC_PROD_FAILED"),
            "desc": "src 包内跑 prod 清单 = src 行数 OK / dist 行数 FAILED（命令在 src 包内执行）",
        },
        {
            # 两处：§0 的包布局表与 §6 的硬校验列表（都写"prod 包 = N 个文件"）。
            # 2.1.28 起 prod 包内实测文件数也必须等于 ALLOWED 条目数（见 measure/check）。
            "id": "pkg-md-prod-allowlist",
            "scope": "tree",
            "cmd": "（从 _pack_verify.py 的 ALLOWED 与包内实际文件数反算）",
            "file": "docs/PACKAGING.md",
            "pat": r"(?<![\w.])(\d+)\s*个文件",
            "check": eq1("PROD_PKG_FILES"),
            "desc": "prod 包白名单文件数 = ALLOWED 条目数 = 包内实际文件数",
            "want": 2,
            "dist_required": False,
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
    """**2.1.30**：INTERFACE.md 的键集/字段/总数必须与**文档自身标记块/源码单一来源**一致。

    实际响应侧的逐键比对在 `scripts/_interface_keys.py`（第 10 道门，需要隔离实例）；
    这里做的是**不依赖实例**的那一半：声明数字 == 标记块行数 == 字段表行数，
    以及 qtype 总数 == `ebpdns_proto::constants` 的名单长度。
    """
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
        # **2.1.43-A**：同 `_interface_keys.py` —— 正则不锁死小版本（判据不变）。
        claim(
            r"指标名全表（\*\*2\.1\.\d+：(\d+) 个 HELP family\*\*）",
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
        # 命中区间先登记（即使该作用域当前没有产物）——"命令式断言"的覆盖判定需要它。
        for m in ms:
            hits.setdefault(rel, []).append((line_of(starts, m.start()), m.start(), m.end()))
        if not scoped_ready(q, scope, claim.get("dist_required", True)):
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
            # ---- deny-by-default ②（2.1.28）：表格行里的 `md5sum -c …` 必须被 claim 整行覆盖 ----
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
    # ---- **2.1.30**：INTERFACE.md 的键集/字段/总数（不依赖隔离实例的那一半）----
    fails.extend(check_interface(root, verbose=verbose))
    return fails, hits, skips


def report(fails, q, skips):
    print("\n--- 动态实测（唯一真值）---")
    for k in ("MANIFEST_LINES", "DIST_LINES", "SRC_LINES", "TREE_SRC_FILES", "ALLOWED_FILES", "PROD_PKG_FILES"):
        print("  %-16s = %s" % (k, q[k]))
    print(
        "  %-16s = OK=%d FAILED=%d（engine=%s，在树内执行；web/dist 存在=%s）"
        % ("TREE_MD5", q["TREE_MD5_OK"], q["TREE_MD5_FAILED"], q["TREE_ENGINE"], q["_tree_has_dist"])
    )
    if q["_missing"]:
        print("  **清单里 %d 个 src 作用域文件在树内不存在**：%s" % (len(q["_missing"]), q["_missing"][:6]))
    if q["SRC_MANIFEST_PRESENT"]:
        print("  %-16s = %d（期望 %d）" % ("SRC_MANIFEST_LINES", q["SRC_MANIFEST_LINES"], q["SRC_LINES"]))

    print("\n--- 作用域实测（真的在包产物里执行命令）---")
    for kind in ("prod", "src"):
        rec = q["_pkgs"].get(kind, {})
        path = rec.get("path")
        if not path:
            print("  %-4s 未发现当前版本的包产物（%s）⇒ 该作用域的 claim 为 SKIP" % (kind, rec.get("how")))
            continue
        top = rec.get("root", "")
        line = "  %-4s %s  files=%d" % (kind, path, rec.get("files", -1))
        if "md5_prod" in rec and rec["md5_prod"]:
            line += "  md5sum -c %s -> OK=%d FAILED=%d (engine=%s)" % (
                MANIFEST,
                rec["md5_prod"]["ok"],
                rec["md5_prod"]["failed"],
                rec["md5_prod"]["engine"],
            )
        if "md5_src" in rec and rec["md5_src"]:
            line += "  md5sum -c %s -> OK=%d FAILED=%d (engine=%s)" % (
                SRC_MANIFEST,
                rec["md5_src"]["ok"],
                rec["md5_src"]["failed"],
                rec["md5_src"]["engine"],
            )
        print(line + "  (root=%s)" % os.path.basename(top))
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
    "_md5_prod.txt": "_md5_prod.txt",
    "web/index.html": "web/dist/index.html",
    "web/app.js": "web/dist/app.js",
    "web/app_bg.wasm": "web/dist/app_bg.wasm",
    "web/style.css": "web/dist/style.css",
    "web/echarts.min.js": "web/dist/echarts.min.js",
    "web/favicon.svg": "web/dist/favicon.svg",
}


def build_fixture_pkg(root, kind, dest):
    """**仅用于 --selftest**：按交付链的映射从树里合成一个包布局。

    正常门禁走真实包产物；selftest 需要"可与文档数字对照"的稳定夹具，因此在这里用
    **与 `make_packages_221r2.sh` 相同的映射**合成（prod 摊平到 web/；src 取清单去掉
    web/dist 行）。这不是交付证据，只用于证明负向对照真的会红。
    """
    top = os.path.join(dest, "pkg")
    os.makedirs(top, exist_ok=True)
    if kind == "prod":
        for rel, src in FIXTURE_SRC_MAP.items():
            sp = os.path.join(root, src.replace("/", os.sep))
            dp = os.path.join(top, rel.replace("/", os.sep))
            os.makedirs(os.path.dirname(dp), exist_ok=True)
            if os.path.isfile(sp):
                shutil.copy2(sp, dp)
            else:
                open(dp, "wb").close()
        return top
    man = [l for l in io.open(os.path.join(root, MANIFEST), encoding="utf-8").read().splitlines() if l.strip()]
    keep = [l for l in man if not l.split("  ", 1)[1].startswith(DIST_PREFIX)]
    with io.open(os.path.join(top, MANIFEST), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(man) + "\n")
    with io.open(os.path.join(top, SRC_MANIFEST), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(keep) + "\n")
    for line in keep:
        rel = line.split("  ", 1)[1]
        sp = os.path.join(root, rel.replace("/", os.sep))
        dp = os.path.join(top, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dp), exist_ok=True)
        if os.path.isfile(sp):
            shutil.copy2(sp, dp)
    return top


SELFTEST_SKIP = False


def selftest(root, q):
    global SELFTEST_SKIP
    print("\n--- 负向对照（--selftest）---")
    # **2.1.30（登记项 6）**：源码包树按设计**没有 `web/dist`**。此前的 selftest 会拿
    # 空文件合成 prod 夹具 ⇒ md5 必然不匹配 ⇒ 基线假红。现在显式 SKIP（rc=0）：
    # "缺夹具"不等于"判据失效"；有 dist 的构建树上仍严格做全部负向对照。
    missing_dist = [src for rel, src in FIXTURE_SRC_MAP.items() if rel.startswith("web/") and not os.path.isfile(os.path.join(root, src))]
    if missing_dist:
        print("  SKIP  selftest-基线  **缺 web/dist 夹具**：%s" % missing_dist[:3])
        print("  SKIP  源码包树（无前端产物）不跑负向对照；构建树（含 web/dist）上严格校验")
        print("DOC_COUNTS_SELFTEST=SKIP（缺 web/dist 夹具；rc=0）")
        SELFTEST_SKIP = True
        return 0
    need = list(SCAN_FILES) + [MANIFEST, INTERFACE, "crates/ebpdns-proto/src/constants.rs"] + ([SRC_MANIFEST] if q["SRC_MANIFEST_PRESENT"] else [])
    tmp = tempfile.mkdtemp(prefix="doccnt-")
    rc = 0
    # 夹具包（selftest 专用；正常门禁用真实产物）
    fx = tempfile.mkdtemp(prefix="doccnt-fx-")
    try:
        for rel in need:
            dst = os.path.join(tmp, rel.replace("/", os.sep))
            d = os.path.dirname(dst)
            if d and not os.path.isdir(d):
                os.makedirs(d)
            shutil.copy2(os.path.join(root, rel.replace("/", os.sep)), dst)
        prod_fx = build_fixture_pkg(root, "prod", os.path.join(fx, "prod"))
        src_fx = build_fixture_pkg(root, "src", os.path.join(fx, "src"))
        qfx = dict(q)
        # selftest 假设"构建树"（含 web/dist）：树内行才可判定。否则在一棵刚从源码包解出来、
        # 还没有 dist 的树里，`--selftest` 会因 tree 作用域 SKIP 而测不到负向①。
        qfx["_tree_has_dist"] = True
        qfx["TREE_MD5_OK"] = qfx["MANIFEST_LINES"]
        qfx["TREE_MD5_FAILED"] = 0
        qfx["PROD_PKG_FILES"] = count_files(prod_fx)
        pm = run_md5_check(prod_fx, MANIFEST)
        qfx["PROD_MD5_OK"], qfx["PROD_MD5_FAILED"] = pm["ok"], pm["failed"]
        sm = run_md5_check(src_fx, SRC_MANIFEST)
        qfx["SRC_MD5_OK"], qfx["SRC_MD5_FAILED"] = sm["ok"], sm["failed"]
        pm2 = run_md5_check(src_fx, MANIFEST)
        qfx["SRC_PROD_OK"], qfx["SRC_PROD_FAILED"] = pm2["ok"], pm2["failed"]
        qfx["_scoped"] = {"prod": {"md5_prod": pm}, "src": {"md5_src": sm, "md5_prod": pm2}}
        qfx["_pkgs"] = {
            "prod": {"path": prod_fx, "root": prod_fx, "files": qfx["PROD_PKG_FILES"], "md5_prod": pm},
            "src": {"path": src_fx, "root": src_fx, "files": count_files(src_fx), "md5_src": sm, "md5_prod": pm2},
        }
        print(
            "  FIXTURE  prod files=%d md5_prod=%d/%d ; src md5_src=%d/%d md5_prod=%d/%d"
            % (
                qfx["PROD_PKG_FILES"],
                pm["ok"],
                pm["failed"],
                sm["ok"],
                sm["failed"],
                pm2["ok"],
                pm2["failed"],
            )
        )

        f0, _h, _s = check(tmp, qfx, verbose=False)
        if f0:
            print("  FAIL  selftest-基线  影子副本未通过：%s" % (f0[:2],))
            rc = 1
        else:
            print("  PASS  selftest-基线  影子副本 PASS")

        rel = "docs/PACKAGING.md"
        p = os.path.join(tmp, rel)
        orig = io.open(p, encoding="utf-8").read()
        n = qfx["MANIFEST_LINES"]
        needle = "**%d/%d OK**" % (n, n)
        if needle not in orig:
            print("  FAIL  selftest-定位  影子副本里找不到 `%s`（claim 与文档不同步）" % needle)
            rc = 1
        else:
            io.open(p, "w", encoding="utf-8", newline="\n").write(
                orig.replace(needle, "**%d/%d OK**" % (n - 1, n - 1), 1)
            )
            f1, _h, _s = check(tmp, qfx, verbose=False)
            if f1 and any(r[0] == rel and r[1] > 0 for r in f1):
                print("  PASS  selftest-负向①  树内行数字改小 1 后变红（file:line）：%s:%d" % (f1[0][0], f1[0][1]))
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

        # ---- 负向②（2.1.28）：把 prod 行**改回 2.1.27 的错误措辞**（199/199 OK）必须红 ----
        good_prod = "**%d OK / %d FAILED**" % (qfx["PROD_MD5_OK"], qfx["PROD_MD5_FAILED"])
        wrong_prod = "**%d/%d OK**（包内带 `web/`）" % (qfx["MANIFEST_LINES"], qfx["MANIFEST_LINES"])
        if good_prod not in orig:
            print("  FAIL  selftest-定位②  影子副本里找不到 prod 行的实测措辞 `%s`" % good_prod)
            rc = 1
        else:
            io.open(p, "w", encoding="utf-8", newline="\n").write(orig.replace(good_prod, wrong_prod, 1))
            f3, _h, _s = check(tmp, qfx, verbose=False)
            if f3 and any(r[0] == rel and r[1] > 0 for r in f3):
                print(
                    "  PASS  selftest-负向②  prod 行改回 2.1.27 的错误措辞后变红（file:line）：%s:%d"
                    % (f3[0][0], f3[0][1])
                )
            else:
                print("  FAIL  selftest-负向②  错误措辞**没有**变红（判据空转）：fails=%r" % (f3[:2],))
                rc = 1
            io.open(p, "w", encoding="utf-8", newline="\n").write(orig)

        # ---- 负向③（2.1.28）：把 src 包内跑 prod 清单的 FAILED 数改错必须红 ----
        good_srcp = "%d OK / %d FAILED" % (qfx["SRC_PROD_OK"], qfx["SRC_PROD_FAILED"])
        if good_srcp not in orig:
            print("  FAIL  selftest-定位③  影子副本里找不到 `%s`" % good_srcp)
            rc = 1
        else:
            io.open(p, "w", encoding="utf-8", newline="\n").write(
                orig.replace(good_srcp, "%d OK / %d FAILED" % (qfx["SRC_PROD_OK"], qfx["SRC_PROD_FAILED"] + 1), 1)
            )
            f4, _h, _s = check(tmp, qfx, verbose=False)
            if f4 and any(r[0] == rel and r[1] > 0 for r in f4):
                print("  PASS  selftest-负向③  src 包内 prod 清单 FAILED 数改错后变红：%s:%d" % (f4[0][0], f4[0][1]))
            else:
                print("  FAIL  selftest-负向③  改错后**没有**变红：fails=%r" % (f4[:2],))
                rc = 1
            io.open(p, "w", encoding="utf-8", newline="\n").write(orig)
            f5, _h, _s = check(tmp, qfx, verbose=False)
            if not f5:
                print("  PASS  selftest-回滚②  改回后变绿（rc=0）")
            else:
                print("  FAIL  selftest-回滚②  改回后仍红：%r" % (f5[:2],))
                rc = 1

        # ---- 负向④（2.1.30）：INTERFACE.md 的 status 键数改错必须红 ----
        pint = os.path.join(tmp, INTERFACE.replace("/", os.sep))
        orig_i = io.open(pint, encoding="utf-8").read()
        nstat = len(_marker_lines(orig_i, "STATUS_KEYS") or [])
        needle_i = "实测：%d 个键" % nstat
        if needle_i not in orig_i:
            print("  FAIL  selftest-定位④  影子副本里找不到 `%s`" % needle_i)
            rc = 1
        else:
            io.open(pint, "w", encoding="utf-8", newline="\n").write(
                orig_i.replace(needle_i, "实测：%d 个键" % (nstat - 1), 1)
            )
            f6, _h, _s = check(tmp, qfx, verbose=False)
            if f6 and any(r[0] == INTERFACE for r in f6):
                print("  PASS  selftest-负向④  INTERFACE status 键数改错后变红：%s:%d" % (f6[0][0], f6[0][1]))
            else:
                print("  FAIL  selftest-负向④  INTERFACE 键数改错**没有**变红：%r" % (f6[:2],))
                rc = 1
            io.open(pint, "w", encoding="utf-8", newline="\n").write(orig_i)
            f7, _h, _s = check(tmp, qfx, verbose=False)
            if not f7:
                print("  PASS  selftest-回滚③  改回后变绿（rc=0）")
            else:
                print("  FAIL  selftest-回滚③  改回后仍红：%r" % (f7[:2],))
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
    if q is None:
        print("DOC_COUNTS=FAIL (1)")
        return 1
    fails, _hits, skips = check(root, q, require_pkgs=require)
    # `_md5_src.txt` 只是"打包产物"：它由 `_manifest.py --src` 在打包第 4 步生成、随**源码包**
    # 交付，权威断言是包内 `_pack_verify.py`（"src 清单 == prod 清单去掉 dist 行"的字面比对）。
    # 因此树内这份**只作为信息项**打印：一棵刚从上一版源码包解出来的树里它必然还是旧值，
    # 那不代表本树的计数漂移（把它算失败会让"从源码包重建"这条路假红）。
    if q["ALLOWED_FILES"] <= 0:
        fails.append(("scripts/_pack_verify.py", 0, "无法从 ALLOWED 反算 prod 包文件数"))
    # 有真实 prod 包时，"包内实际文件数 == 白名单条目数"是硬断言（防"包里多/少文件"）。
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
        if not SELFTEST_SKIP:
            print("DOC_COUNTS_SELFTEST=PASS")
        # SKIP 时 selftest 已打印 `DOC_COUNTS_SELFTEST=SKIP（…；rc=0）`，这里不再改口径。
    else:
        print("DOC_COUNTS_GATE=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
