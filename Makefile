# ebpdns Makefile（Rust 版；以 Python v1.9.162 为行为参照，对照状态见 README.md）
# **2.1.27**：本行**刻意不写版本号** —— 版本单一来源见下面的 `PKG`（此前的 `v2.1.25`
# 从 2.1.26 起就是旧值，而任何门禁都没扫这一行，属同一类"注释漂移"）。
# 在源码树中：make build / wasm / test / package / check-all
# 在预编译包中：make install / uninstall
SHELL := /bin/bash
export PATH := $(HOME)/.cargo/bin:$(PATH)

# 版本单一来源 = 根 Cargo.toml 的 [workspace.package] version（见 README「版本」）。
# 改版本时本行、packaging/install.sh、systemd Description、README 必须同步。
PKG      := ebpdns-2.1.49
WEB_DIR  := web
DIST     := $(WEB_DIR)/dist

.PHONY: help build wasm test clippy fmt check check-all check-all-selftest install uninstall package clean

help:
	@echo "build     构建 release 二进制（嵌入前端）"
	@echo "wasm      构建 WASM 前端到 $(DIST)"
	@echo "test      cargo test 全量"
	@echo "check     clippy(-D warnings) + fmt --check + test"
	@echo "check-all 一次跑完全部门禁（scripts/check_all.sh：版本+文档门禁 / fmt / clippy / test / dist 新鲜度）"
	@echo "check-all-selftest 门禁自己的门禁（scripts/check_all_selftest.sh：开关组合 + 负向对照）"
	@echo "install   预编译包安装（等价 ./install.sh）"
	@echo "package   生成预编译包与源码包"

# ---- 源码构建 ----
# **2.1.27（B3）+ 2.1.28（B1）**：release 构建注入 `--remap-path-prefix`。单一来源 =
# `scripts/_repro_flags.sh`（与 `scripts/make_packages_221r2.sh` 同一个脚本，两处不会漂）。
# 目的：交付二进制不泄漏构建机绝对路径；**交付链**（`make_packages_221r2.sh`）还会把源码
# 播种到**固定构建路径** `/build/ebpdns` 再构建 —— ThinLTO 的 `llvm.<module-hash>` 对物理
# 构建路径敏感，remap 改不到它（2.1.27 实测残差 700 B）。
# `make build` / `make wasm` 是**开发构建**（就地构建），产出字节**不承诺**等于交付字节；
# 交付/可复现口径见 `docs/PACKAGING.md §6d`。
# **不动 `[profile.release]`**（lto / codegen-units / opt-level）。
# 预编译包里没有 `scripts/` ⇒ `$(shell …)` 用 `[ -f ]` 兜底，缺文件时静默为空。
REPRO_FLAGS := $(shell [ -f scripts/_repro_flags.sh ] && bash scripts/_repro_flags.sh "$(CURDIR)")
REPRO_FLAGS_WASM := $(shell [ -f scripts/_repro_flags.sh ] && bash scripts/_repro_flags.sh "$(CURDIR)" --wasm)

# **2.1.28（B1 根因）**：`rust-embed` 把 `web/dist` 文件的 `created`/`last_modified` 编进二进制
# （`SOURCE_DATE_EPOCH` 可覆盖）。开发构建也钉住它，避免"同一棵树重编 dist 就换一份字节"。
SOURCE_DATE_EPOCH := $(shell cat BUILD_EPOCH 2>/dev/null)

build: wasm
	SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" RUSTFLAGS="$(REPRO_FLAGS)" cargo build --release --bin ebpdns --features embed-frontend

wasm:
	SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" RUSTFLAGS="$(REPRO_FLAGS_WASM)" ./$(WEB_DIR)/build.sh

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all --check

check: fmt clippy test

# **2.1.24**：单一入口跑完所有门禁（含版本/文档一致门禁与 web/dist 新鲜度）。
check-all:
	bash scripts/check_all.sh

# **2.1.25**：门禁**自己**的门禁 —— `SKIP_TEST=1` / `OFFLINE=1` 两条开关组合必须 PASS，
# 外加"把 `--offline` 放回 `--` 之后必须变红"的负向对照（2.1.24 的 P3 缺陷就是这么漏掉的）。
check-all-selftest:
	bash scripts/check_all_selftest.sh

# ---- 预编译包安装 ----
install:
	./install.sh start

uninstall:
	./install.sh uninstall

# ---- 打包（在源码树根目录执行）----
package:
	./scripts/make_packages_221r2.sh

clean:
	cargo clean
	rm -rf $(WEB_DIR)/target $(DIST)
