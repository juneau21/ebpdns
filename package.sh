#!/bin/bash
# ebpdns 通用打包脚本（剔除测试文件）
# 用法: ./package.sh <version>
set -e

VERSION="${1:?用法: $0 <version>}"

# 自动定位项目根目录（脚本所在目录），不再硬编码
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR="$SCRIPT_DIR"
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
    web/favicon.svg \
    etc/ebpdns.conf.json \
    etc/rules_local.json \
    bpf/Makefile \
    bpf/load.sh \
    bpf/ebpdns_xdp.bpf.c \
    bpf/ebpdns_xdp.h \
    bpf/README.md \
    systemd/ebpdns.service \
    systemd/ebpdns-restart.service \
    systemd/ebpdns-restart.timer \
    install.sh \
    Makefile \
    LICENSE \
    README.md \
    CONTRIBUTING.md

echo "=== 打包 ebpdns-git-v${VERSION}.tar.gz（完整源码，剔除测试/报告/缓存/本地配置）==="
TMPPKG="/tmp/ebpdns-git-v${VERSION}.tar.gz"
rm -f "$TMPPKG"

cd "$WORKDIR/.."
# 项目目录名（打包时用顶层目录名作为 tar 内顶层）
PROJNAME="$(basename "$WORKDIR")"

find "$PROJNAME" \
    \( -path "$PROJNAME/.git" \
       -o -path "$PROJNAME/dist" \
       -o -path "$PROJNAME/test" \
       -o -path "$PROJNAME/tests" \
       -o -path "$PROJNAME/tests_cache" \
       -o -path "$PROJNAME/artifacts" \
       -o -path "$PROJNAME/ebpdns/artifacts" \
       -o -path "$PROJNAME/ebpdns/__pycache__" \
       -o -path "$PROJNAME/rules_local.json" \) -prune -o \
    -not -name '*.pyc' \
    -not -name '__pycache__' \
    -not -name '*_test.py' \
    -not -name 'full_log_test.py' \
    -not -name 'profile_test.py' \
    -not -name 'stress_test.py' \
    -not -name 'v1931.local.json' \
    -not -name '.gitignore' \
    -not -name '.git' \
    \( -not -name '*.md' -o -name 'README.md' -o -name 'CONTRIBUTING.md' \) \
    -print0 | tar czf "$TMPPKG" --no-recursion --null --transform "s,^$PROJNAME,ebpdns-v${VERSION}," -T -

mv "$TMPPKG" "$DISTDIR/ebpdns-git-v${VERSION}.tar.gz"

echo "=== 打包完成 ==="
ls -lh "$DISTDIR/ebpdns-python-v${VERSION}.tar.gz" "$DISTDIR/ebpdns-git-v${VERSION}.tar.gz"
