.PHONY: build test integration run clean

BINARY_NAME=telegram-proxy

build:
	go build -o $(BINARY_NAME) ./cmd/proxy

test:
	go test -v -race ./...

integration:
	go test -v -race -tags=integration ./internal/proxy/...

run: build
	./$(BINARY_NAME) -config configs/config.yaml

clean:
	rm -f $(BINARY_NAME)
	go clean -testcache

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...