.PHONY: build build-ebpf run-agent run-audit test clean

build: build-ebpf
	go build ./...

build-ebpf:
	$(MAKE) -C ebpf

run-agent:
	go run ./cmd/agent

run-audit:
	go run ./cmd/audit

test:
	go test ./...

clean:
	$(MAKE) -C ebpf clean
