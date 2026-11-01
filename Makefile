.PHONY: build build-ebpf run-server run-agent run-audit test clean

GO ?= go

build: build-ebpf
	$(GO) build ./...

build-ebpf:
	$(MAKE) -C ebpf

run-server:
	$(GO) run ./cmd/adr server

run-agent:
	$(GO) run ./cmd/adr agent

run-audit:
	$(GO) run ./cmd/adr audit

test:
	$(GO) test ./...

clean:
	$(MAKE) -C ebpf clean
