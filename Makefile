.PHONY: build test integration run clean fmt lint install-service uninstall-service

BINARY_NAME=telegram-proxy
GO ?= go
export GOTOOLCHAIN=local

build:
	$(GO) build -o $(BINARY_NAME) ./cmd/proxy

test:
	$(GO) test -v -race ./...

integration:
	$(GO) test -v -race -tags=integration ./internal/proxy/...

run: build
	./$(BINARY_NAME) -config configs/config.yaml

clean:
	rm -f $(BINARY_NAME)
	$(GO) clean -testcache

lint:
	golangci-lint run ./...

fmt:
	$(GO) fmt ./...

ci: test integration build

install-service:
	sudo bash deploy/install.sh

uninstall-service:
	sudo bash deploy/uninstall.sh
