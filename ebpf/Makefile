CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    := $(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -I.

SRC := $(wildcard src/*.bpf.c)
OBJ := $(patsubst src/%.bpf.c,build/%.bpf.o,$(SRC))

.PHONY: all vmlinux clean

all: vmlinux.h $(OBJ)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

build/%.bpf.o: src/%.bpf.c vmlinux.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

clean:
	rm -rf build vmlinux.h
