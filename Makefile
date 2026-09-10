# ebpdns 顶层 Makefile —— 开发辅助
PY ?= python3

.PHONY: all test console install bpf clean

all: console test

## 从 tools/ 模板重新生成 web/index.html（保留原 CSS 设计）
console:
	$(PY) tools/build_console.py

## 单元测试
test:
	$(PY) -m unittest discover -s tests -v

## 安装（需 root）
install:
	sudo ./install.sh

## 本地以非特权端口运行（调试）
run:
	$(PY) -m ebpdns run --dns-udp 127.0.0.1:1053 --dns-tcp 127.0.0.1:1053 --api-port 8081

bpf:
	$(MAKE) -C bpf

clean:
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	rm -f .coverage
