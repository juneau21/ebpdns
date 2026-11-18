#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pack-time self-verification (helper of `scripts/make_packages_221r2.sh`).

2.1.49 的交付口径：**只有包内 `_md5_package.txt` 一套清单**，源码树内不再保留 md5 清单。
本脚本按**包内实测**做硬断言（退出码 1 = 交付链红）：

1. prod stage 的文件集合 == `ALLOWED`，且 `md5sum -c _md5_package.txt` 逐行 OK；
2. prod / src 两个 tar 包的**唯一顶层目录**都等于 `ebpdns-<version>`；
3. 两个包内都带 `_md5_package.txt`，解包后 `md5sum -c` 逐行 OK；
4. 清单**不列自身**、无重复行、覆盖包内除自身外的**全部文件**（多一个/少一个都失败）；
5. 包内不得出现**其它** `_md5_*.txt` 清单、字节码缓存、`target/`、`web/dist/`。

所有行数都是**运行期动态计数**（`lines=` / `OK=` / `FAILED=`），脚本里没有"当前树有多少
文件"的常数。
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

MANIFEST = "_md5_package.txt"
ALLOWED = {
    "bin/ebpdns", "install.sh", "systemd/ebpdns.service",
    "etc/ebpdns/config.json", "LICENSE", "NOTICE", "BUILD_INFO.txt",
    "_md5_package.txt",
    "web/index.html", "web/app.js", "web/app_bg.wasm", "web/style.css",
    "web/echarts.min.js", "web/favicon.svg",
    # **2.2.0**：随包交付文档（`docs/*.md`）。集合大小 = 基础 12 + 文档 12
    # + `_md5_package.txt`；清单行数 = 集合大小 - 1（不列自身）。
    "docs/CACHE_POLICY_BENCH.md",
    "docs/CLIPPY.md",
    "docs/CONCURRENCY-SPEED-REVIEW.md",
    "docs/CONFIG-RECOMMENDED.md",
    "docs/FIX-2.1.49-p1.md",
    "docs/INTERFACE.md",
    "docs/MIGRATION-2.2.0.md",
    "docs/PACKAGING.md",
    "docs/PROPOSAL-cache-incremental.md",
    "docs/PROPOSAL-domain_hits.md",
    "docs/REVIEW-2.1.49-p1.md",
    "docs/TLS-POLICY.md",
}


def run_md5_check(pkg_root):
    """在 pkg_root 里执行 `md5sum -c _md5_package.txt`；无 md5sum 时用 hashlib 等价实现。"""
    man = os.path.join(pkg_root, MANIFEST)
    if not os.path.isfile(man):
        return None
    if shutil.which("md5sum"):
        r = subprocess.run(
            ["md5sum", "-c", MANIFEST], cwd=pkg_root, capture_output=True, text=True
        )
        ok = sum(1 for line in r.stdout.splitlines() if line.endswith(": OK"))
        bad = [line for line in r.stdout.splitlines() if line.strip() and not line.endswith(": OK")]
        return {"engine": "md5sum", "ok": ok, "failed": len(bad), "rc": r.returncode}
    ok = failed = 0
    with open(man, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            digest, rel = line.split("  ", 1)
            path = os.path.join(pkg_root, rel.replace("/", os.sep))
            got = None
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    got = hashlib.md5(f.read()).hexdigest()
            if got == digest:
                ok += 1
            else:
                failed += 1
    return {"engine": "hashlib", "ok": ok, "failed": failed, "rc": 0 if failed == 0 else 1}


def manifest_rows(pkg_root):
    """返回 (行数, 路径列表, 错误列表)。"""
    man = os.path.join(pkg_root, MANIFEST)
    errors = []
    paths = []
    with open(man, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            parts = line.split("  ")
            if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{32}", parts[0]):
                errors.append("bad line %d: %r" % (lineno, line))
                continue
            rel = parts[1]
            if rel == MANIFEST:
                errors.append("manifest lists itself: %s" % rel)
            if rel.startswith("/") or ".." in rel.split("/"):
                errors.append("absolute/escaping path: %s" % rel)
            paths.append(rel)
    if len(set(paths)) != len(paths):
        errors.append("duplicate manifest rows")
    if paths != sorted(paths):
        errors.append("manifest rows are not sorted by path")
    return len(paths), paths, errors


def package_files(top):
    found = []
    for dp, _dn, fn in os.walk(top):
        for f in fn:
            found.append(os.path.relpath(os.path.join(dp, f), top).replace(os.sep, "/"))
    return sorted(found)


def workspace_version(root):
    with open(os.path.join(root, "Cargo.toml"), encoding="utf-8") as fh:
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


def verify_package(label, tar_path, want_top):
    tmp = tempfile.mkdtemp(prefix="packverify-%s-" % label)
    try:
        with tarfile.open(tar_path) as t:
            names = [n for n in t.getnames() if n not in (".", "./")]
            try:
                t.extractall(tmp, filter="data")
            except TypeError:  # Python < 3.12
                t.extractall(tmp)
        tops = sorted({n.split("/")[0] for n in names})
        if tops != [want_top]:
            print("  %s package root must be exactly %r, found %s" % (label, want_top, tops), file=sys.stderr)
            return False
        top = os.path.join(tmp, want_top)
        files = package_files(top)
        old = [
            n
            for n in files
            if n.startswith("_md5_") and n.endswith(".txt") and n != MANIFEST
        ]
        if old:
            print("  %s package carries stale manifest(s): %s" % (label, old[:5]), file=sys.stderr)
            return False
        man = os.path.join(top, MANIFEST)
        if not os.path.isfile(man):
            print("  %s package has NO %s" % (label, MANIFEST), file=sys.stderr)
            return False
        rows, paths, errors = manifest_rows(top)
        if errors:
            print("  %s manifest invalid: %s" % (label, errors[:5]), file=sys.stderr)
            return False
        listed = set(paths)
        actual = set(files) - {MANIFEST}
        extra, missing = sorted(actual - listed), sorted(listed - actual)
        if extra or missing:
            print(
                "  %s manifest coverage FAILED extra=%s missing=%s" % (label, extra[:5], missing[:5]),
                file=sys.stderr,
            )
            return False
        chk = run_md5_check(top)
        print(
            "  %s: files=%d manifest_lines=%d md5sum -c OK=%d FAILED=%d (engine=%s)"
            % (label, len(files), rows, chk["ok"], chk["failed"], chk["engine"])
        )
        if chk["ok"] != rows or chk["failed"] != 0 or chk["rc"] != 0:
            print("  %s self-check FAILED (must be %d OK / 0)" % (label, rows), file=sys.stderr)
            return False
        if label == "src":
            bad = [
                n
                for n in files
                if n.endswith((".pyc", ".pyo")) or "__pycache__" in n.split("/")
            ]
            if bad:
                print("  src package carries bytecode cache: %s" % bad[:5], file=sys.stderr)
                return False
            if any(n.startswith("target/") or "/target/" in n for n in files):
                print("  src package carries build output (target/)", file=sys.stderr)
                return False
            if any(n.startswith("web/dist/") for n in files):
                print("  src package carries web/dist/", file=sys.stderr)
                return False
        return True
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if len(sys.argv) != 5:
        print("usage: _pack_verify.py <root> <stage> <prod.tar.gz> <src.tar.gz>", file=sys.stderr)
        return 2
    root, stage, prod, src = sys.argv[1:5]

    found = set(package_files(stage))
    extra, missing = sorted(found - ALLOWED), sorted(ALLOWED - found)
    print("  prod stage files=%d" % len(found))
    if extra or missing:
        print("  prod allowlist FAILED extra=%s missing=%s" % (extra, missing), file=sys.stderr)
        return 1
    chk = run_md5_check(stage)
    rows, _paths, errors = manifest_rows(stage)
    print(
        "  prod stage: %s lines=%d md5sum -c OK=%d FAILED=%d (engine=%s)"
        % (MANIFEST, rows, chk["ok"], chk["failed"], chk["engine"])
    )
    if errors:
        print("  prod stage manifest invalid: %s" % errors[:5], file=sys.stderr)
        return 1
    if chk["ok"] != rows or chk["failed"] != 0 or chk["rc"] != 0:
        print("  prod stage self-check FAILED (must be %d OK / 0)" % rows, file=sys.stderr)
        return 1

    version = workspace_version(root)
    if not version:
        print("  无法从 Cargo.toml 解析 [workspace.package] version", file=sys.stderr)
        return 1
    want_top = "ebpdns-%s" % version
    print("  expected package top-level = %s (from Cargo.toml)" % want_top)
    for label, tar in (("prod", prod), ("src", src)):
        if not verify_package(label, tar, want_top):
            return 1

    print("  PACK_VERIFY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
