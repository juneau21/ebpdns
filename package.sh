#!/bin/bash
# ebpdns 通用打包脚本（剔除测试文件）
# 用法: ./package.sh <version>
set -e

VERSION="${1:?用法: $0 <version>}"
WORKDIR="/home/user/.super_doubao/super-doubao-runtime/workspace/ebpdns-v1931"
DISTDIR="$WORKDIR/dist"

mkdir -p "$DISTDIR"

echo "=== 打包 ebpdns-python-v${VERSION}.tar.gz（生产包，仅运行时文件）==="
cd "$WORKDIR"
tar czf "$DISTDIR/ebpdns-python-v${VERSION}.tar.gz" \
    ebpdns/__init__.py \
    ebpdns/__main__.py \
    ebpdns/api.py \
    ebpdns/cache.py \
    ebpdns/cli.py \
    ebpdns/config.py \
    ebpdns/dnsmsg.py \
    ebpdns/probe.py \
    ebpdns/quic_upstream.py \
    ebpdns/resolver.py \
    ebpdns/server.py \
    ebpdns/telemetry.py \
    ebpdns/upstream.py \
    bin/ebpdns \
    web/echarts.min.js \
    web/index.html \
    etc/ebpdns.conf.json \
    systemd/ebpdns.service \
    systemd/ebpdns-restart.service \
    systemd/ebpdns-restart.timer \
    install.sh \
    Makefile \
    LICENSE \
    README.md

echo "=== 打包 ebpdns-git-v${VERSION}.tar.gz（完整源码，剔除测试/报告/缓存，仅保留 README.md/CONTRIBUTING.md）==="
cd /home/user/.super_doubao/super-doubao-runtime/workspace
TMPPKG="/tmp/ebpdns-git-v${VERSION}.tar.gz"
rm -f "$TMPPKG"
find ebpdns-v1931 \
    \( -path 'ebpdns-v1931/dist' -o -path 'ebpdns-v1931/test' -o -path 'ebpdns-v1931/ebpdns/__pycache__' \) -prune -o \
    -not -name '*.pyc' \
    \( -not -name '*.md' -o -name 'README.md' -o -name 'CONTRIBUTING.md' \) \
    -print0 | tar czf "$TMPPKG" --no-recursion --null -T -
mv "$TMPPKG" "$DISTDIR/ebpdns-git-v${VERSION}.tar.gz"

echo "=== 打包完成 ==="
ls -lh "$DISTDIR/ebpdns-python-v${VERSION}.tar.gz" "$DISTDIR/ebpdns-git-v${VERSION}.tar.gz"
