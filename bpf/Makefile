# ============================================================
# ebpdns XDP 数据面编译 (Debian 13)
#   依赖: clang llvm libbpf-dev linux-libc-dev bpftool
#   sudo apt install clang llvm libbpf-dev linux-libc-dev linux-tools-common bpftool
# ============================================================

CLANG ?= clang
BPF_TARGET ?= bpfel
PREFIX ?= /usr
BPF_CFLAGS := -O2 -g -Wall -Werror \
	-target $(BPF_TARGET) \
	-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include

# 安装目录: .o 放到 $(PREFIX)/lib/ebpdns/ 供用户态 loader 查找
INSTALL_DIR ?= $(DESTDIR)$(PREFIX)/lib/ebpdns

all: ebpdns_xdp.o ebpdns_xdp.skel.h

ebpdns_xdp.o: ebpdns_xdp.bpf.c ebpdns_xdp.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpdns_xdp.skel.h: ebpdns_xdp.o
	bpftool gen skeleton ebpdns_xdp.o > ebpdns_xdp.skel.h

# 安装: 把预编译 .o (与 .skel.h) 拷到系统库目录, 供 ebpdns/bpf_loader.py 加载
#   loader 查找顺序: ../bpf/ebpdns_xdp.o -> /usr/lib/ebpdns/ebpdns_xdp.o
install: ebpdns_xdp.o
	install -d $(INSTALL_DIR)
	install -m 0644 ebpdns_xdp.o $(INSTALL_DIR)/
	@echo "已安装 ebpdns_xdp.o 到 $(INSTALL_DIR)/"
	@echo "用户态 loader 启动时会自动从该目录加载; 需要 root/CAP_BPF + 网卡支持原生 XDP。"

clean:
	rm -f ebpdns_xdp.o ebpdns_xdp.skel.h

.PHONY: all clean install
