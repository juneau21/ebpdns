#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pack-time self-verification (helper of `scripts/make_packages_221r2.sh`).

1. `md5sum -c _md5_prod.txt` must be 100% OK inside the tree;
2. the prod package must contain exactly the paths in `ALLOWED` (and nothing else);
3. **both** packages must carry a `_md5_prod.txt` byte-identical to the final manifest
   (DEF-220-08 / PACKAGING rule: exactly one manifest, same bytes everywhere);
4. **2.1.26（P3 清单作用域）** the src package must carry `_md5_src.txt` (the manifest
   minus the `web/dist/` lines) and **every row must match the bytes inside the package** —
   otherwise "self-check inside the src package" has no passing judgement at all
   (`md5sum -c _md5_prod.txt` there fails **exactly** on the `web/dist/` rows, *by design*).
   All counts are **derived** from the shipped manifest (never hardcoded), so a growing tree
   cannot make a stale number pass or fail spuriously; the row counts are printed at run time
   (`lines=` / `OK=` / `FAILED=`).
"""
import hashlib
import io
import os
import re
import subprocess
import sys
import tarfile

root, stage, prod, src = sys.argv[1:5]
man = os.path.join(root, "_md5_prod.txt")
man_bytes = open(man, "rb").read()
man_md5 = hashlib.md5(man_bytes).hexdigest()
print("  final manifest: %s (%d lines, %d bytes)" % (man_md5, man_bytes.count(b"\n"), len(man_bytes)))

r = subprocess.run(["md5sum", "-c", "_md5_prod.txt"], cwd=root, capture_output=True, text=True)
ok = sum(1 for l in r.stdout.splitlines() if l.endswith(": OK"))
bad = [l for l in r.stdout.splitlines() if not l.endswith(": OK")]
print("  md5sum -c: OK=%d FAILED=%d" % (ok, len(bad)))
if bad:
    print("\n".join(bad[:5]), file=sys.stderr)
    sys.exit(1)
# **2.1.26（P3 双清单硬门 ①）**：树内自校验必须**逐行全绿**，行数必须等于清单行数
# （= src 作用域行数 + `web/dist/*` 行数；两者的实际值在运行输出里打印）。
# 判据是**动态计数**，不是硬编码数字（2.1.25 的部署侧脚本硬编码过清单行数 ——
# 那类判据在文件数变化时会假红/假绿；2.1.27 起由 `scripts/_doc_counts.py` 反向兜底）。
man_lines = man_bytes.count(b"\n")
print("  tree manifest scope: lines=%d checked=%d FAILED=%d (must be equal / 0)" % (man_lines, ok, len(bad)))
if ok != man_lines:
    print(
        "  **树内自校验行数与清单行数不等**：checked=%d lines=%d" % (ok, man_lines),
        file=sys.stderr,
    )
    sys.exit(1)

ALLOWED = {
    "bin/ebpdns", "install.sh", "systemd/ebpdns.service",
    "etc/ebpdns/config.json", "LICENSE", "NOTICE", "_md5_prod.txt",
    "web/index.html", "web/app.js", "web/app_bg.wasm", "web/style.css",
    "web/echarts.min.js", "web/favicon.svg",
}
found = set()
for dp, _dn, fn in os.walk(stage):
    for f in fn:
        found.add(os.path.relpath(os.path.join(dp, f), stage).replace(os.sep, "/"))
extra, missing = sorted(found - ALLOWED), sorted(ALLOWED - found)
print("  prod package files=%d" % len(found))
if extra or missing:
    print("  prod allowlist FAILED extra=%s missing=%s" % (extra, missing), file=sys.stderr)
    sys.exit(1)

for label, tar in (("prod", prod), ("src", src)):
    with tarfile.open(tar) as t:
        cand = [m for m in t.getmembers() if m.name.endswith("/_md5_prod.txt") or m.name == "_md5_prod.txt"]
        if not cand:
            print("  %s package has NO _md5_prod.txt" % label, file=sys.stderr)
            sys.exit(1)
        blob = t.extractfile(cand[0]).read()
        names = t.getnames()
        # **2.1.26**：src 包的作用域清单要按**包内字节**逐行验证 ⇒ 需要成员内容。
        top = cand[0].name.rsplit("/_md5_prod.txt", 1)[0] if "/" in cand[0].name else ""
        members = {
            m.name: t.extractfile(m).read()
            for m in t.getmembers()
            if m.isfile()
        }
    same = blob == man_bytes
    print("  %s: manifest identical=%s  members=%d" % (label, same, len(names)))
    if not same:
        sys.exit(1)
    if label == "src":
        banned = [n for n in names if "_md5_219_only" in n]
        if banned:
            print("  src package still carries %s" % banned, file=sys.stderr)
            sys.exit(1)
        # ---- **2.1.22 硬断言（P5）**：源码包内**不得出现**字节码缓存 ----
        #
        # 为什么必须在这里再判一次（打包脚本已经 --exclude 了）：`scripts/__pycache__/`
        # 是**构建机上的真实残留**（打包脚本自己 import 过 `_manifest.py` 等模块）。
        # 一旦 `tar` 的排除规则被后人改动/打错，源码包里就会带上 `*.pyc` ——
        # 那种二进制是**解释器版本相关**的，在新机器上可能被当成有效缓存而
        # **改变脚本行为**（且不可审计）。排除规则可能失效，所以用"包内名单"
        # 再判一次；这是**硬断言**（退出码 1），不是提示。
        bad = [
            n
            for n in names
            if n.endswith(".pyc")
            or n.endswith(".pyo")
            or ("__pycache__" in n.split("/"))
        ]
        # ---- **2.1.26 硬断言（P3 清单作用域）**：src 包内必须带一份
        # `_md5_src.txt`，且**逐行与包内字节相符** ----
        #
        # 判据来源是**包内那份 `_md5_prod.txt`**（而不是重新调 `_manifest.py`）：
        # src 作用域清单按定义 = prod 清单里**去掉 `web/dist/` 行**（顺序不变，因为
        # 两份都由同一排序集合导出）。这样两条断言互相独立：
        #   ① 包内 `_md5_src.txt` == 由包内 `_md5_prod.txt` 派生的「源码作用域行」
        #      （行数 = 清单行数 − dist 行数；判据是**动态计数**，不硬编码数字）；
        #   ② 那 189 行里每一行都能在**包内**找到同名成员且 md5 相符（包内自校验等价）。
        man_lines = [l for l in man_bytes.decode("utf-8").splitlines() if l.strip()]
        dist_lines = [l for l in man_lines if l.split("  ", 1)[1].startswith("web/dist/")]
        want_src = [l for l in man_lines if not l.split("  ", 1)[1].startswith("web/dist/")]
        want_src_bytes = ("\n".join(want_src) + "\n").encode("utf-8")
        member_name = (top + "/_md5_src.txt") if top else "_md5_src.txt"
        got_src = members.get(member_name)
        print(
            "  src: _md5_src.txt present=%s lines=%d (prod %d - dist %d) identical_to_scope=%s"
            % (
                got_src is not None,
                got_src.count(b"\n") if got_src else 0,
                len(man_lines),
                len(dist_lines),
                got_src == want_src_bytes,
            )
        )
        if got_src is None:
            print(
                "  **源码包缺少 `_md5_src.txt`**（2.1.26 P3：包内自校验判据）", file=sys.stderr
            )
            sys.exit(1)
        if got_src != want_src_bytes:
            print(
                "  `_md5_src.txt` 与「prod 清单去掉 web/dist 行」**不逐字节相同** "
                "（两份清单必须同源导出）",
                file=sys.stderr,
            )
            sys.exit(1)
        if any("web/dist/" in l for l in got_src.decode("utf-8").splitlines()):
            print("  `_md5_src.txt` 不得包含 web/dist 行", file=sys.stderr)
            sys.exit(1)
        mismatched = []
        for line in got_src.decode("utf-8").splitlines():
            digest, rel = line.split("  ", 1)
            data = members.get((top + "/" + rel) if top else rel)
            if data is None:
                mismatched.append("MISSING " + rel)
            elif hashlib.md5(data).hexdigest() != digest:
                mismatched.append("MD5 " + rel)
        print(
            "  src: _md5_src.txt self-check OK=%d FAILED=%d (must be %d/0)"
            % (len(want_src) - len(mismatched), len(mismatched), len(want_src))
        )
        if mismatched:
            print("  **源码包内自校验失败**：%s" % mismatched[:8], file=sys.stderr)
            sys.exit(1)
        # ---- **2.1.26 双清单硬门 ③**：src 包内跑 `md5sum -c _md5_prod.txt` 必然
        # "src 行数 OK / dist 行数 FAILED"，缺的**必须恰好是** `web/dist/*` 那几条（按设计）----
        #
        # 这条断言把"按设计失败"变成**可判定的**：不能多缺一条（真丢文件）也不能少缺
        # 一条（说明 dist 混进了源码包）。判据同样是动态计数。
        misplaced = []
        for line in man_lines:
            _digest, rel = line.split("  ", 1)
            present = ((top + "/" + rel) if top else rel) in members
            if rel.startswith("web/dist/") and present:
                misplaced.append("DIST-IN-SRC " + rel)
            elif not rel.startswith("web/dist/") and not present:
                misplaced.append("MISSING " + rel)
        print(
            "  src: md5_prod scope inside package -> expect %d OK / %d FAILED (all %s dist), mismatches=%d"
            % (len(want_src), len(dist_lines), "web/dist", len(misplaced))
        )
        if misplaced:
            print(
                "  **源码包与清单作用域不符**（应为「src 行数 OK / dist 行数 FAILED」且缺的全是 web/dist）：%s"
                % misplaced[:8],
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            "  src: bytecode-cache members=%d (must be 0)  py_files=%d"
            % (len(bad), sum(1 for n in names if n.endswith(".py")))
        )
        if bad:
            print(
                "  **源码包内出现字节码缓存**（2.1.22 P5 硬断言失败）：%s" % bad[:10],
                file=sys.stderr,
            )
            sys.exit(1)

# ---- **2.1.22 交付链硬断言**：两个包都必须以 `ebpdns-<ver>/` 为**唯一顶层**，且源码包
# 里不得出现构建产物目录 `target/`（tar 已 --exclude，这里按**包内名单**再判一次）。
#
# **[2.1.23（`DEF-222-21`，本次新发现）修法]** 2.1.22 这里写的是
# `want_top = os.path.basename(root)`，也就是"**构建目录的名字**"。这条断言因此
# 只有在"构建目录恰好叫 `ebpdns-<ver>`"时才成立 —— 而那个前提**从未被声明**，
# 也没有任何地方强制它。实测：把同一棵树解到 `/root/f223/build` 里打包，
# 这条断言就在**最后一步**报
#   `prod package root must be exactly 'build', found ['ebpdns-2.1.23']`
# 并 `sys.exit(1)` ⇒ **整个交付链最后一步红**（包其实是对的，红的是判据）。
#
# 现在的判据取自**版本单一来源**（与 `scripts/_version_consistency.py`、
# `crates/ebpdns-resolver/tests/version_consistency.rs` 同一个来源：根 `Cargo.toml`
# 的 `[workspace.package] version`）⇒ 与构建目录名**解耦**，在任何目录名下都成立。
def workspace_version():
    with io.open(os.path.join(root, "Cargo.toml"), encoding="utf-8") as fh:
        text = fh.read()
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


V = workspace_version()
if not V:
    print("  无法从 Cargo.toml 解析 [workspace.package] version", file=sys.stderr)
    sys.exit(1)
want_top = "ebpdns-%s" % V
print("  expected package top-level = %s (from Cargo.toml; build dir=%r)" % (want_top, os.path.basename(root.rstrip("/"))))
for label, tar in (("prod", prod), ("src", src)):
    with tarfile.open(tar) as t:
        names = [n for n in t.getnames() if n not in (".", "./")]
    tops = sorted({n.split("/")[0] for n in names})
    if tops != [want_top]:
        print("  %s package root must be exactly %r, found %s" % (label, want_top, tops), file=sys.stderr)
        sys.exit(1)
    tgt = [n for n in names if "/target/" in n or n.startswith("target/") or "/target" == n[-7:]]
    if tgt:
        print("  %s package carries build output: %s" % (label, tgt[:5]), file=sys.stderr)
        sys.exit(1)
    print("  %s: root=%s target-members=0" % (label, want_top))

print("  PACK_VERIFY_OK")

