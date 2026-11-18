#!/usr/bin/env bash
# 构建 ebpdns Web 控制台前端到 web/dist（wasm-bindgen 手动流水线，非 trunk）。
#
# 产物（供 `cargo build --features embed-frontend` 经 rust-embed 嵌入二进制）：
#   dist/index.html      页面外壳（挂载 Leptos）
#   dist/app.js          wasm-bindgen 胶水代码
#   dist/app_bg.wasm     Leptos 前端本体
#   dist/style.css       v1.9.162 原样式（与 web/style.css 同源）
#   dist/echarts.min.js  ECharts 5（遥测页图表，v1.9.162 同款）
#   dist/favicon.svg     站点图标
#
# **2.1.19（2.1.18 遗留修复项 2；2.1.19 起生效）：输出目录与 target 目录都可重定向 —— 供隔离/可复现构建使用。**
#
#   WEB_DIST_DIR   输出目录（默认 `<web>/dist`）
#   WEB_TARGET_DIR cargo target 目录（默认 `<web>/target`）
#
# 为什么加这两个开关：`scripts/f218-repro-build.sh` 的 wasm 复现模式会注入
# `--remap-path-prefix` 等规范化标志，产出的 wasm **与交付链的 dist 不是同一份字节**
# （交付链 = 普通构建 = 冻结 dist；remap 模式 = 仅用于度量"可复现性"）。
# 2.1.18 的脚本直接跑本脚本 ⇒ **会把冻结的 `web/dist` 覆盖成 remap 版**
# （实测 `d08c17e5…` → `5996e590…`，破坏了交付链一致性与 `EMBEDDED == DIST` 门禁）。
# 现在 repro 脚本把这两个变量指向自己的 `REPRO_OUT_DIR`，**物理上不可能**写到 `web/dist`。
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"
cd "$(dirname "$0")"

OUT_DIR="${WEB_DIST_DIR:-dist}"
TARGET_DIR="${WEB_TARGET_DIR:-target}"

# 安全闸：拒绝把输出目录指到根/家目录/上级目录（`rm -rf` 前的最后一道防线）。
case "$OUT_DIR" in
  ""|/|.|..|./|../|"$HOME"|"$HOME"/) 
    echo "WEB_DIST_DIR 取值不安全：'$OUT_DIR'（拒绝 rm -rf）" >&2
    exit 2
    ;;
esac

cargo build --release --target wasm32-unknown-unknown --target-dir "$TARGET_DIR"

# 二进制 crate 名 ebpdns-web：cargo 产物文件名保留连字符（Linux/Windows 均如此），
# 旧 Makefile 写的 app.wasm 不存在。两种拼写都探测一遍。
WASM="$TARGET_DIR/wasm32-unknown-unknown/release/ebpdns-web.wasm"
[ -f "$WASM" ] || WASM="$TARGET_DIR/wasm32-unknown-unknown/release/ebpdns_web.wasm"
if [ ! -f "$WASM" ]; then
  echo "找不到 wasm 产物（期望 $TARGET_DIR/wasm32-unknown-unknown/release/ebpdns-web.wasm）" >&2
  ls -l "$TARGET_DIR/wasm32-unknown-unknown/release/" >&2 || true
  exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
wasm-bindgen --target web --no-typescript --out-dir "$OUT_DIR" --out-name app "$WASM"
cp -f index.html style.css echarts.min.js favicon.svg "$OUT_DIR/"
echo "---- $OUT_DIR ----"
ls -l "$OUT_DIR"
