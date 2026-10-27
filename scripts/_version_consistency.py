#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Version-consistency hard gate (2.1.22, step 0/6 of the pack script).

**Seven** locations must carry **the same** version, and it must equal the workspace version in
the root `Cargo.toml` (`[workspace.package] version` = the single source of truth):

  1. root `Cargo.toml`                        `[workspace.package] version`
  2. `web/Cargo.toml`                         `[package] version`
  3. `packaging/systemd/ebpdns.service`       `Description=... (Rust vX)`
  4. `Makefile`                               `PKG := ebpdns-X`
  5. `packaging/install.sh`                   user-facing `ebpdns-X-prod.tar.gz` / `cd ebpdns-X`
  6. `docs/PACKAGING.md`                      `**适用范围：ebpdns X**` + example paths
  7. `README.md`                              first `**版本 vX`

Why this exists (2.1.22 measured): the 2.1.21 -> 2.1.22 bump only touched the three
`Cargo.toml` spots, leaving `(Rust v2.1.21)` in the shipped systemd unit and
`PKG := ebpdns-2.1.21` in the Makefile. `Makefile:8` itself says these places must be kept in
sync -> "keep it in sync by hand" is not a control. Non-zero exit => the pack script fails.


Usage: python3 scripts/_version_consistency.py <tree-root>
"""
import io
import os
import re
import sys

root = sys.argv[1] if len(sys.argv) > 1 else "."


def read(rel):
    p = os.path.join(root, rel)
    with io.open(p, encoding="utf-8") as fh:
        return fh.read()


def workspace_version():
    text = read("Cargo.toml")
    inside = False
    for line in text.splitlines():
        t = line.strip()
        if t.startswith("["):
            inside = t == "[workspace.package]"
            continue
        if inside:
            m = re.match(r'^version\s*=\s*"([^"]+)"', t)
            if m:
                return m.group(1)
    return None


def package_version(rel):
    text = read(rel)
    inside = False
    for line in text.splitlines():
        t = line.strip()
        if t.startswith("["):
            inside = t == "[package]"
            continue
        if inside:
            m = re.match(r'^version\s*=\s*"([^"]+)"', t)
            if m:
                return m.group(1)
    return None


V = workspace_version()
fails = []
notes = []


def ok(name, detail):
    print("  PASS  %-34s %s" % (name, detail))


def bad(name, detail):
    print("  FAIL  %-34s %s" % (name, detail))
    fails.append(name)


if not V:
    print("  FAIL  cannot parse [workspace.package] version from Cargo.toml")
    sys.exit(1)
print("  workspace version = %s" % V)
ok("Cargo.toml(workspace)", V)

wv = package_version("web/Cargo.toml")
(ok if wv == V else bad)("web/Cargo.toml", "version=%r want %r" % (wv, V))

svc = read("packaging/systemd/ebpdns.service")
m = re.search(r"^Description=.*?\(Rust v([0-9][^)]*)\)", svc, re.M)
got = m.group(1) if m else None
(ok if got == V else bad)("systemd Description", "(Rust v%s) want (Rust v%s)" % (got, V))

mk = read("Makefile")
m = re.search(r"^PKG\s*:=\s*ebpdns-([0-9][0-9.]*)", mk, re.M)
got = m.group(1) if m else None
(ok if got == V else bad)("Makefile PKG", "ebpdns-%s want ebpdns-%s" % (got, V))

# 只认**面向用户的包名/路径**三种形态（历史叙述不算，例如 README 里
# `-C metadata=ebpdns-2.1.19-repro` 的构建元数据串、或本文件引用缺陷原文的
# `PKG := ebpdns-2.1.21`）。判据窄而客观：装包指令指向错版本才是缺陷。
PKG_PATS = (
    re.compile(r"ebpdns-(\d+\.\d+\.\d+)-(?:prod|src)\.tar\.gz"),
    re.compile(r"cd ebpdns-(\d+\.\d+\.\d+)(?:[ \t]|$)"),
    re.compile(r"^[ \t]*ebpdns-(\d+\.\d+\.\d+)/", re.M),
)
for rel in ("packaging/install.sh", "docs/PACKAGING.md", "README.md"):
    text = read(rel)
    hits = sorted({m for pat in PKG_PATS for m in pat.findall(text)})
    (ok if hits == [V] else bad)("%s package names" % rel, "found=%s want=[%r]" % (hits, V))

md = read("docs/PACKAGING.md")
m = re.search(r"适用范围：ebpdns\s+([0-9][0-9.]*)", md)
got = m.group(1) if m else None
(ok if got == V else bad)("docs/PACKAGING.md scope", "ebpdns %s want ebpdns %s" % (got, V))

rm = read("README.md")
m = re.search(r"\*\*版本 v([0-9][0-9.]*)", rm)
got = m.group(1) if m else None
(ok if got == V else bad)("README.md version line", "v%s want v%s" % (got, V))

# The tree's own history must not smuggle a *stale* release literal into the shipped unit or
# Makefile (historical narrative comments elsewhere are legitimate and are not scanned).
for rel, pat in (("packaging/systemd/ebpdns.service", r"Rust v([0-9][0-9.]*)"),):
    stale = [x for x in re.findall(pat, read(rel)) if x != V]
    (ok if not stale else bad)("%s stale versions" % rel, "stale=%s" % stale)

# ---------------------------------------------------------------------------------------------
# **2.1.24：文档一致门禁** —— "单机单实例"约束的措辞必须在**四处**逐字出现
# ---------------------------------------------------------------------------------------------
# 背景（2.1.23 交付报告 ⑥/⑪ 的**唯一** FAIL，即 P0-3d）：权威规范 `CONVENTIONS §16.8`
# 已经把"单机单实例 / `state_dir` 独占"写清楚了，但 **README（部署段）、
# `web/INTERFACE.md`、`docs/PACKAGING.md` 三处一句都没复述** ⇒ 真正部署的人看不到，
# 而这条约束**已经**被违反过（隔离实例写进了生产 `state_dir`，把审查夹具的世代写进生产
# `history/`；见 DEF-222-03 实测）。"写在规范里"不等于"部署的人会看到"。
#
# 判据是**客观字符串**（不是关键词集合，避免"看起来写了"）：
#   去掉 Markdown 的 `**` 与反引号后，四处都必须逐字包含 DOC_MARKER。
# 允许写作者加粗/加行内代码（上面那步归一化会去掉它们），但**不允许**改词序/换标点。
# 打包脚本第 0 步（`make_packages_221r2.sh`）就是靠本文件的退出码当硬门。
DOC_MARKER = (
    "部署约束：单机单实例（state_dir 独占锁；第二实例会被拒；隔离实例必须显式 --state-dir）。"
)
DOC_FILES = ("README.md", "web/INTERFACE.md", "docs/PACKAGING.md", "CONVENTIONS.md")

# ---------------------------------------------------------------------------------------------
# **2.1.25：第二条文档契约** —— `GET /api/config.rules` 的**恒为数组**措辞必须在同四处逐字出现
# ---------------------------------------------------------------------------------------------
# 背景（2.1.24 交付报告 ⑬ 的登记项）：`web/INTERFACE.md:477-486` 仍在写 2.1.21 的口径
# （"`/api/config.rules` = 回显 `config.json.rules`"、"本轮不改接口形状"），
# 而实现（`ebpdns-server/src/api.rs::get_config` → `rules_admin::config_rules_view`）与
# `CONVENTIONS.md` §16.10（DEF-222-14）早已是"**任何情况下恒为数组、由真源派生**"。
# 两处口径相反，而两处都"看起来像权威文档" —— 排障时读到哪份纯看运气。
#
# 与第一条 marker 同型：**去掉 Markdown 的 `**` 与反引号**后，四处都必须逐字包含。
# 只有把措辞钉进机器门禁，"文档 ↔ 实现"才不会再一次各写各的。
RULES_MARKER = (
    "规则契约：/api/config.rules 在任何情况下都恒为数组，由真源派生（无规则时为 []，不是 null）。"
)


def plain(text):
    """归一化：去掉 Markdown 的强调符与行内代码符（只影响**排版**，不改字词）。"""
    return text.replace("`", "").replace("*", "")


doc_fails = []
for rel in DOC_FILES:
    try:
        body = plain(read(rel))
    except OSError as e:  # 文件缺失也算失败（"四处"是硬数目）
        print("  FAIL  %-34s unreadable: %s" % ("doc constraint " + rel, e))
        doc_fails.append(rel)
        continue
    if DOC_MARKER in body:
        print("  PASS  %-34s marker present" % ("doc constraint " + rel))
    else:
        print("  FAIL  %-34s missing marker: %s" % ("doc constraint " + rel, DOC_MARKER))
        doc_fails.append(rel)

# 第二条：`/api/config.rules` 恒为数组（2.1.25）。
rules_fails = []
for rel in DOC_FILES:
    try:
        body = plain(read(rel))
    except OSError as e:
        print("  FAIL  %-34s unreadable: %s" % ("rules contract " + rel, e))
        rules_fails.append(rel)
        continue
    if RULES_MARKER in body:
        print("  PASS  %-34s rules contract present" % ("rules contract " + rel))
    else:
        print("  FAIL  %-34s missing rules contract: %s" % ("rules contract " + rel, RULES_MARKER))
        rules_fails.append(rel)

# ---------------------------------------------------------------------------------------------
# **2.1.26：第三条文档契约（单文件）** —— 双清单作用域必须在 `docs/PACKAGING.md` 逐字出现
# ---------------------------------------------------------------------------------------------
# 背景（2.1.25 交付报告 §13① 的登记项）：`_md5_prod.txt` 的路径是**树根相对**，其行数
# 含 6 个 `web/dist/*`；源码包按设计不含 dist，于是在 src 包内跑 `md5sum -c _md5_prod.txt`
# **必然** 少那 6 行 —— "必然失败的校验"等于没有判据，而当时**任何文档都没写这件事**，
# 于是每个审阅者都会独立地把它当缺陷重报一次。
#
# 2.1.26 的修法是**双清单**（`_md5_prod.txt` + `_md5_src.txt`）。这条判据保证：只要有人
# 把 PACKAGING 里那段作用域说明改掉/删掉，`make check-all` 与打包第 0 步**立刻红**。
# 只作用于一个文件（另外三份文档与打包清单无关），因此不塞进 DOC_FILES 的四处合同。
MANIFEST_DOC_MARKER = (
    "清单作用域：树内用 _md5_prod.txt 自校验（含 web/dist），src 包内用 _md5_src.txt "
    "自校验（不含 web/dist）；src 包内跑 _md5_prod.txt 会缺 web/dist 那几行，属设计而非损坏。"
)
manifest_doc_fails = []
try:
    body = plain(read("docs/PACKAGING.md"))
    if MANIFEST_DOC_MARKER in body:
        print("  PASS  %-34s manifest scope contract present" % "docs/PACKAGING.md")
    else:
        print(
            "  FAIL  %-34s missing manifest scope contract: %s"
            % ("docs/PACKAGING.md", MANIFEST_DOC_MARKER)
        )
        manifest_doc_fails.append("docs/PACKAGING.md")
except OSError as e:
    print("  FAIL  %-34s unreadable: %s" % ("manifest scope docs/PACKAGING.md", e))
    manifest_doc_fails.append("docs/PACKAGING.md")

# ---------------------------------------------------------------------------------------------
# **2.1.28（A3）：提案文件与版本无关** —— `docs/PROPOSAL-*.md` 只写"仅提案、本版不实现"
# ---------------------------------------------------------------------------------------------
# 背景（2.1.27 交付实测）：`docs/PROPOSAL-domain_hits.md:1` 停在"仅提案，2.1.26 不实现"，
# `docs/PROPOSAL-cache-incremental.md:1` 写"仅提案，2.1.27 不实现" —— 两份提案各自把
# **一次性的版本号**写进标题，于是每次升版它们要么过期、要么被改得与"本版是否实现"矛盾。
# 提案是"供裁决的设计文档"，**与版本无关**；版本承诺只应出现在交付报告里。
#
# 判据（客观、可机检）：
#   ① 每份 `docs/PROPOSAL-*.md` 必须含**无版本**的状态措辞 `仅提案，本版不实现`；
#   ② **不得**出现"<版本号> 不实现 / 实现 / 采纳 / 落地"这类**版本锁定承诺**
#      （历史叙述如"2.1.25 B8 已量化"不受影响：它后面不是这些动词）。
# 本项**不是**七处版本门禁的一部分（提案不参与版本号一致），但它是同一脚本里的独立硬门。
PROPOSAL_MARKER = "仅提案，本版不实现"
PROPOSAL_FORBID = re.compile(r"(?<![\d.])2\.1\.\d+\s*(?:不实现|实现|采纳|落地)")
proposal_fails = []
proposal_files = []
_prop_dir = os.path.join(root, "docs")
if os.path.isdir(_prop_dir):
    proposal_files = sorted(
        "docs/" + n for n in os.listdir(_prop_dir) if n.startswith("PROPOSAL-") and n.endswith(".md")
    )
if not proposal_files:
    print("  FAIL  %-34s 找不到任何 docs/PROPOSAL-*.md（提案文件必须存在且无版本承诺）" % "proposal scope")
    proposal_fails.append("docs/PROPOSAL-*.md")
for _rel in proposal_files:
    body = plain(read(_rel))
    locked = PROPOSAL_FORBID.findall(body)
    if PROPOSAL_MARKER not in body or locked:
        print(
            "  FAIL  %-34s marker=%s version-locked=%s"
            % ("proposal scope " + _rel, PROPOSAL_MARKER in body, locked[:4])
        )
        proposal_fails.append(_rel)
    else:
        print("  PASS  %-34s 仅提案、本版不实现（无版本锁定承诺）" % ("proposal scope " + _rel))

if notes:
    print("\n".join(notes))
if fails:
    print("VERSION_CONSISTENCY=FAIL (%d): %s" % (len(fails), fails))
    sys.exit(1)
print("VERSION_CONSISTENCY=PASS (7 locations, all == %s)" % V)
if doc_fails or rules_fails or manifest_doc_fails or proposal_fails:
    if doc_fails:
        print("DOC_CONSTRAINTS=FAIL (%d): %s" % (len(doc_fails), doc_fails))
    if rules_fails:
        print("RULES_CONTRACT=FAIL (%d): %s" % (len(rules_fails), rules_fails))
    if manifest_doc_fails:
        print("MANIFEST_SCOPE_DOC=FAIL (%d): %s" % (len(manifest_doc_fails), manifest_doc_fails))
    if proposal_fails:
        print("PROPOSAL_SCOPE=FAIL (%d): %s" % (len(proposal_fails), proposal_fails))
    sys.exit(1)
print("DOC_CONSTRAINTS=PASS (%d files, 2 markers each)" % len(DOC_FILES))
print("RULES_CONTRACT=PASS (%d files)" % len(DOC_FILES))
print("MANIFEST_SCOPE_DOC=PASS (1 file)")
print("PROPOSAL_SCOPE=PASS (%d files, version-independent)" % len(proposal_files))

