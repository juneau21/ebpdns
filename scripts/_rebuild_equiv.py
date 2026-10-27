#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线重建等价门（**2.1.28 / A1**）：上一版源码包 + patch233_*.py == 本树（不跑 cargo）。

## 为什么有它

2.1.27 的交付物里，**"从 2.1.26 源码包一次性重建"这条路只有口头承诺**：交付目录里有
`patches/patch227_*.py`，但没有任何机器判据证明"解上一版 + 按序打补丁"得到的树与
**交付的源码包**逐文件相同。2.1.27 交付时实测到一处真实漂移：
`web/Cargo.lock` 里 `ebpdns-web` 的 `version` 行没进版本 part ⇒ 离线重建得到
`CHANGED=1`（重建树是 2.1.26 的 lock，交付树是 2.1.27 的 lock）。"补丁是否完备"必须
**逐文件比对**，不能靠人读 diff。

## 本文件的判据（全部客观、可复现）

1. 在**空目录**里解上一版**源码包**（`--prev-src`，只解包，不构建）；
2. 按**文件名排序**执行 `--patches` 目录下的 `patch233_*.py`（每个都必须 rc=0 且打印
   `PATCH_OK`）；
3. 与**交付的源码树**逐文件比对（`字节相等`，不跑 cargo、不跑任何构建）；
4. 打印 `CHANGED= / ADDED= / REMOVED=`，三者都必须为 0。

**排除白名单**（生成物，不参与比对）：`_md5_prod.txt`、`_md5_src.txt` —— 它们由打包流程
在**产物定稿后**生成（`scripts/_manifest.py` / `--src`），上一版源码包里带的是上一版的值；
把生成物当判据只会把"清单随文件数变化"误报成"补丁不完备"。白名单**只有这两项**，且以
`GENERATED` 常量列出（新增生成物必须同时改这里与本文件的说明）。

**不排除**任何源码/文档/脚本文件 —— 包括 `Cargo.lock`、`web/Cargo.lock`、`Makefile`。

## 用法

    python3 scripts/_rebuild_equiv.py <tree> --prev-src <tar.gz> --patches <dir>
    python3 scripts/_rebuild_equiv.py <tree> --prev-src ... --patches ... --keep   # 保留工作目录

退出码：0 = CHANGED=ADDED=REMOVED=0（等价）；1 = 有差异 / 补丁失败；2 = 用法或输入错误。
`scripts/_rebuild_equiv.sh` 负责发现输入并给出 `REBUILD_EQUIV=PASS/FAIL/SKIP` 口径。
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

GENERATED = ("_md5_prod.txt", "_md5_src.txt")
SKIP_DIRS = {"target", "dist-packages", ".git", "__pycache__", "web/target", "web/dist"}


def walk_files(root):
    """相对于 root 的**文件**路径（跳过构建产物/生成物目录）。"""
    out = set()
    for dp, dn, fn in os.walk(root):
        rel_dir = os.path.relpath(dp, root).replace(os.sep, "/")
        if rel_dir == ".":
            rel_dir = ""
        dn[:] = [
            d
            for d in dn
            if (rel_dir + "/" + d if rel_dir else d) not in SKIP_DIRS and d not in ("__pycache__", ".git")
        ]
        for f in fn:
            rel = (rel_dir + "/" + f) if rel_dir else f
            if rel in GENERATED:
                continue
            out.add(rel)
    return out


def md5_of(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def extract_prev(tar_path, dest):
    with tarfile.open(tar_path) as t:
        try:
            t.extractall(dest, filter="data")
        except TypeError:  # Python < 3.12
            t.extractall(dest)
    tops = [n for n in os.listdir(dest) if os.path.isdir(os.path.join(dest, n))]
    files = [n for n in os.listdir(dest) if os.path.isfile(os.path.join(dest, n))]
    if len(tops) == 1 and not files:
        return os.path.join(dest, tops[0])
    return dest


def apply_patches(prev_root, patch_dir):
    # **2.1.32**：补丁前缀随版本推进（patch231_* → patch233_*）。目录里若同时存在两代，
    # 只打**最新一代**（否则会把上一版的增量重复打一遍）。
    names = [f for f in os.listdir(patch_dir) if f.endswith(".py") and re.match(r"patch\d{3}_", f)]
    prefixes = sorted({re.match(r"patch\d{3}_", f).group(0) for f in names})
    chosen_prefix = prefixes[-1] if prefixes else None
    chosen = [f for f in names if chosen_prefix and f.startswith(chosen_prefix)]
    patches = sorted(os.path.join(patch_dir, f) for f in chosen)
    if not patches:
        print("  FAIL  %s 下没有 patchNNN_*.py（当前版本期望 patch233_*.py）" % patch_dir)
        return False
    print("  补丁（按文件名排序，共 %d 个）：" % len(patches))
    for p in patches:
        print("  ---- %s" % os.path.basename(p))
        r = subprocess.run([sys.executable, p, "."], cwd=prev_root, capture_output=True, text=True)
        # **2.1.29**：各补丁的 CLI 不统一（`patch233_cache*.py` 只认 `--tree`，收到位置参数会
        # rc=2 且**在改任何文件之前**返回）——这里只在"参数错误"(rc=2) 时按"无参数（默认
        # `tree='.'`）"重跑一次，其余退出码一律按原判据处理（不掩盖真实失败）。
        if r.returncode == 2:
            r = subprocess.run([sys.executable, p], cwd=prev_root, capture_output=True, text=True)
        for line in r.stdout.splitlines():
            print("    " + line)
        if r.returncode != 0:
            print("    **补丁失败 rc=%d**" % r.returncode)
            if r.stderr.strip():
                print("    " + r.stderr.strip()[:2000])
            return False
        # **2.1.29**：发布补丁集的 CLI/输出契约不统一 —— 2.1.29 的 6 组补丁来自不同作者：
        # qtype / noxdp 打印 `PATCH_OK`；docs / ui / webgate 打印 `*_RESULT ... rc=0`；
        # cache 的 4 个 part 打印 `... applied=N already=M failed=0 hash_mismatch=0`。
        # 判据因此改成"rc=0 + 至少一条**证明真的跑过**的证据"：命中 `PATCH_OK`，或
        # `applied...=N` 里出现 N>0（**不接受静默 no-op**），或 `*_RESULT ... rc=0`。
        applied_nums = [int(x) for x in re.findall(r"applied[a-z_]*=(\d+)", r.stdout)]
        ran = (
            "PATCH_OK" in r.stdout
            or any(n > 0 for n in applied_nums)
            or bool(re.search(r"_RESULT\b.*\brc=0\b", r.stdout))
        )
        if not ran:
            print("    **补丁没有留下\"真的跑过\"的证据（applied 全 0 且无 PATCH_OK/RESULT）**")
            return False
    return True


def main():
    args = sys.argv[1:]
    tree = None
    prev = patch_dir = None
    keep = "--keep" in args
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--prev-src" and i + 1 < len(args):
            prev = args[i + 1]
            i += 2
            continue
        if a == "--patches" and i + 1 < len(args):
            patch_dir = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if tree is None:
            tree = a
        i += 1
    tree = os.path.abspath(tree or ".")
    prev = os.path.abspath(prev) if prev else None
    patch_dir = os.path.abspath(patch_dir) if patch_dir else None
    print("=== REBUILD_EQUIV gate")
    print("  tree      = %s" % tree)
    print("  prev-src  = %s" % prev)
    print("  patches   = %s" % patch_dir)
    print("  generated excluded = %s" % (list(GENERATED),))
    if not prev or not os.path.isfile(prev):
        print("  FAIL  上一版源码包不存在：%r" % (prev,))
        return 2
    if not patch_dir or not os.path.isdir(patch_dir):
        print("  FAIL  补丁目录不存在：%r" % (patch_dir,))
        return 2
    if not os.path.isfile(os.path.join(tree, "Cargo.toml")):
        print("  FAIL  %s 不是源码树根（缺 Cargo.toml）" % tree)
        return 2

    work = tempfile.mkdtemp(prefix="rebuild-equiv-")
    try:
        print("  prev md5 = %s" % md5_of(prev))
        prev_root = extract_prev(prev, work)
        print("  解包到 %s（顶层 %s）" % (prev_root, os.path.basename(prev_root)))
        if not apply_patches(prev_root, patch_dir):
            return 1

        want = walk_files(tree)
        got = walk_files(prev_root)
        changed = sorted(p for p in (want & got) if md5_of(os.path.join(tree, p.replace("/", os.sep))) != md5_of(os.path.join(prev_root, p.replace("/", os.sep))))
        added = sorted(want - got)      # 交付树有、重建树没有
        removed = sorted(got - want)    # 重建树有、交付树没有
        print("\n  files: delivered=%d rebuilt=%d" % (len(want), len(got)))
        for label, lst in (("CHANGED", changed), ("ADDED", added), ("REMOVED", removed)):
            print("  %-8s = %d %s" % (label, len(lst), lst[:10] if lst else ""))
        ok = not (changed or added or removed)
        print("REBUILD_EQUIV=%s (CHANGED=%d ADDED=%d REMOVED=%d)" % ("PASS" if ok else "FAIL", len(changed), len(added), len(removed)))
        return 0 if ok else 1
    finally:
        if keep:
            print("  保留工作目录：%s" % work)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
