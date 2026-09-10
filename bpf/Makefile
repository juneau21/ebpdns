# ============================================================
# ebpdns XDP 数据面编译 (Debian 13)
#   依赖: clang llvm libbpf-dev linux-libc-dev bpftool
#   sudo apt install clang llvm libbpf-dev linux-libc-dev linux-tools-common bpftool
# ============================================================

CLANG ?= clang
BPF_TARGET ?= bpfel
BPF_CFLAGS := -O2 -g -Wall -Werror \
	-target $(BPF_TARGET) \
	-D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/') \
	-I/usr/include/$(shell uname -m)-linux-gnu \
	-I/usr/include

all: ebpdns_xdp.o ebpdns_xdp.skel.h

ebpdns_xdp.o: ebpdns_xdp.bpf.c ebpdns_xdp.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ebpdns_xdp.skel.h: ebpdns_xdp.o
	bpftool gen skeleton ebpdns_xdp.o > ebpdns_xdp.skel.h

clean:
	rm -f ebpdns_xdp.o ebpdns_xdp.skel.h

.PHONY: all clean
