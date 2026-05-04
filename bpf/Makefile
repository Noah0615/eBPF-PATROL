CLANG ?= clang
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

INCLUDES := -I.
CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

OUTPUT := ../gen

.PHONY: all clean

all: $(OUTPUT)/patrol_bpfel.o

$(OUTPUT)/patrol_bpfel.o: patrol.bpf.c vmlinux.h common.h
	@mkdir -p $(OUTPUT)
	$(CLANG) $(CFLAGS) -c patrol.bpf.c -o $@

clean:
	rm -f $(OUTPUT)/patrol_bpfel.o