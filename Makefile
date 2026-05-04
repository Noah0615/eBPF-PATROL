.PHONY: all bpf build clean run

all: bpf build

bpf:
	$(MAKE) -C bpf

build: bpf
	go build -o bin/patrold ./cmd/patrold

run: build
	sudo ./bin/patrold

clean:
	$(MAKE) -C bpf clean
	rm -rf bin/ gen/*.o