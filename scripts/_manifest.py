#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Recompute `_md5_prod.txt` (helper of the pack script) and its **src-package scope** twin.

**Path set rule (must not drift):** the manifest keeps exactly the path set it already has
(the 2.1.20 manifest plus files added by this round); files that appeared in the tree but were
never listed (`web/dist/**`, build outputs) stay unlisted, and files that were listed but are
gone are reported. This is what makes `md5sum -c` meaningful for the delivery.

Output format: `<md5>  <relpath>` sorted, LF, `md5sum -c` compatible.

Usage:

    python3 scripts/_manifest.py <tree-root>                 # 重算树内 `_md5_prod.txt`
    python3 scripts/_manifest.py --src <tree-root> <outfile> # 只算「src 包作用域」清单

# **2.1.26（P3：`_md5_prod.txt` 作用域口径）**

`_md5_prod.txt` 的路径是**树根相对**，其行数 = **源码文件数 + `web/dist/*` 的条数**
（两个数字都随树/产物变化，**不在本文件里写死**）。
而源码包按设计**不含** `web/dist`（它由打包第 1 步现编、随 prod 包交付），因此在**源码包内**
跑 `md5sum -c _md5_prod.txt` 必然少 dist 那几行 —— 那是**作用域**差异、不是损坏，
但"必然失败的校验"等于没有判据（2.1.25 交付报告 §13① 登记）。

修法（本文件）：用**同一份路径集合**再导出一份**只含源码文件**的清单
（`--src`，去掉 `web/dist/` 前缀的行），随**源码包**一并交付。

**唯一权威的"位置 × 命令 × 实测值"表在 `docs/PACKAGING.md`**（由 `scripts/_doc_counts.py`
带作用域逐行断言：`tree` / `prod` / `src` 的 claim 必须**真的在对应包产物里执行**那条
`md5sum -c`）。本文件**不复制**那张表 —— 复制一份数字就会在下次加文件时过期（2.1.27 的
prod 包行正是这么漂的：写了"包内全 OK"，而 prod 包只装白名单文件、资产摊平在 `web/`，
那条命令从没被执行过）。

**数字随树增长** ⇒ 所有判据（本文件、`_pack_verify.py`、部署侧脚本）一律**动态计数**，
不得硬编码行数（2.1.27 起 `scripts/_doc_counts.py` 会把文档里的数字与实测逐行比对）。

`_md5_src.txt` 由**同一函数**从**同一路径集合**导出 ⇒ 两份清单不可能各自漂移
（`scripts/_pack_verify.py` 的第 3 道门把这条钉成硬断言：src 包内每行都必须与**包内字节**相符）。
"""
import hashlib
import io
import os
import sys

SKIP_DIRS = {"target", ".git", "dist-packages", "__pycache__", "node_modules"}
SKIP_NAMES = {"_md5_prod.txt", "_md5_src.txt"}
# src 包按设计不含的路径前缀（第 1 步现编，只进 prod 包）。
SRC_EXCLUDED_PREFIXES = ("web/dist/",)


def md5_file(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def listed_paths(root):
    """现有 `_md5_prod.txt` 记录的路径集合（`keep` 规则的"想要的"一侧）。"""
    man = os.path.join(root, "_md5_prod.txt")
    wanted = set()
    if os.path.exists(man):
        for line in io.open(man, encoding="utf-8"):
            if line.strip():
                wanted.add(line.rstrip("\n").split("  ", 1)[1])
    return wanted


def present_paths(root):
    """树内实际存在、**应当**进清单的路径（与 SKIP_DIRS/SKIP_NAMES/字节码规则一致）。"""
    present = set()
    for dp, dn, fn in os.walk(root):
        dn[:] = [d for d in dn if d not in SKIP_DIRS]
        for f in fn:
            if f in SKIP_NAMES:
                continue
            # **2.1.22（P5）**：字节码缓存**绝不进清单**（也不进源码包）。
            # 这类文件由构建机上的解释器生成、带版本耦合，既不可审计也会在新机器上
            # 改变脚本行为；`_pack_verify.py` 还有一条"包内名单"硬断言兜底。
            if f.endswith((".pyc", ".pyo")):
                continue
            present.add(os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/"))
    return present


def keep_set(root):
    """最终清单的路径集合（= 已有记录 ∩ 现存 ∪ 新出现），并打印三条漂移统计。"""
    wanted = listed_paths(root)
    present = present_paths(root)
    newly = sorted(present - wanted)
    gone = sorted(wanted - present)
    print("  newly listed      : %d %s" % (len(newly), newly[:4]))
    print("  present but unlisted: %d %s" % (len(present - wanted - set(newly)), []))
    print("  listed but gone   : %d %s" % (len(gone), gone[:6]))
    return sorted((wanted & present) | (present - wanted))


def render(root, rels):
    return ("\n".join("%s  %s" % (md5_file(os.path.join(root, rel)), rel) for rel in rels) + "\n").encode(
        "utf-8"
    )


def write_manifest(root, out, rels, label):
    body = render(root, rels)
    with open(out, "wb") as fh:
        fh.write(body)
    print(
        "  %s lines=%d bytes=%d md5=%s"
        % (label, body.count(b"\n"), len(body), hashlib.md5(body).hexdigest())
    )
    return body


def main():
    args = sys.argv[1:]
    src_scope = bool(args) and args[0] == "--src"
    if src_scope:
        args = args[1:]
    root = args[0] if args else "."
    rels = keep_set(root)
    if not src_scope:
        write_manifest(root, os.path.join(root, "_md5_prod.txt"), rels, "manifest")
        return 0
    out = args[1] if len(args) > 1 else os.path.join(root, "_md5_src.txt")
    src_rels = [r for r in rels if not r.startswith(SRC_EXCLUDED_PREFIXES)]
    print(
        "  src-package scope  : kept=%d excluded(web/dist)=%d"
        % (len(src_rels), len(rels) - len(src_rels))
    )
    write_manifest(root, out, src_rels, "src manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
