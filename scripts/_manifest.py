#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the **package-internal** manifest `_md5_package.txt`（打包脚本的现算帮手）。

## 唯一一套清单

2.1.49 起不再有树内 md5 清单：**清单是包产物，不是树文件**。
每个交付包（prod / src）在**包内容定稿后**，于包根生成一份 `_md5_package.txt`：

* 路径**相对包根**（`bin/ebpdns`、`web/app.js`、`crates/...`），按路径排序；
* 每行 `<md5>  <relpath>`，UTF-8 + LF，`md5sum -c _md5_package.txt` 兼容；
* **不列清单自身**（否则自校验文件无法包含自己的 md5）；
* 不列构建产物/解释器缓存（`target/`、`__pycache__/`、`*.pyc` …）。

## 用法

    python3 scripts/_manifest.py <package-root>

输出固定写到 `<package-root>/_md5_package.txt`。源码树不是包根 —— 不要在树根调用它；
打包脚本只在 stage 目录（prod）与临时 src stage（src）上调用。
"""
import hashlib
import os
import sys

MANIFEST_NAME = "_md5_package.txt"
SKIP_DIRS = {"target", ".git", "dist-packages", "__pycache__", "node_modules"}


def md5_file(path):
    with open(path, "rb") as fh:
        return hashlib.md5(fh.read()).hexdigest()


def present_paths(root):
    """包根下应进清单的文件（相对路径、`/` 分隔、排序）。"""
    rels = []
    for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if d not in SKIP_DIRS)
        for f in fn:
            if f == MANIFEST_NAME:
                continue
            if f.endswith((".pyc", ".pyo")):
                continue
            rel = os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/")
            rels.append(rel)
    return sorted(rels)


def render(root, rels):
    body = "\n".join("%s  %s" % (md5_file(os.path.join(root, rel)), rel) for rel in rels) + "\n"
    return body.encode("utf-8")


def main():
    if len(sys.argv) != 2:
        print("usage: _manifest.py <package-root>", file=sys.stderr)
        return 2
    root = os.path.abspath(sys.argv[1])
    if not os.path.isdir(root):
        print("not a directory: %s" % root, file=sys.stderr)
        return 2
    rels = present_paths(root)
    body = render(root, rels)
    out = os.path.join(root, MANIFEST_NAME)
    with open(out, "wb") as fh:
        fh.write(body)
    os.chmod(out, 0o644)
    print(
        "  package manifest: %s lines=%d bytes=%d md5=%s"
        % (MANIFEST_NAME, len(rels), len(body), hashlib.md5(body).hexdigest())
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
