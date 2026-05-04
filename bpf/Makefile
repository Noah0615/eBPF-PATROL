BPF_CLANG ?= clang
ARCH := $(shell uname -m)

ifeq ($(ARCH),x86_64)
TARGET_ARCH := x86
else ifeq ($(ARCH),aarch64)
TARGET_ARCH := arm64
else
$(error unsupported arch $(ARCH))
endif

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(TARGET_ARCH)

all: ../gen/patrol_bpfel.o

../gen/patrol_bpfel.o: patrol.bpf.c common.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I. -c patrol.bpf.c -o ../gen/patrol_bpfel.o

clean:
	rm -f ../gen/*.o