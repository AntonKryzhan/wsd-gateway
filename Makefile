GO ?= go
.PHONY: test vet build cross
test:
	$(GO) test -race ./...
vet:
	$(GO) vet ./...
build:
	$(GO) build -o wsd-gateway .
cross:
	mkdir -p bin
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/wsd-gateway-freebsd-amd64 .
	GOOS=freebsd GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/wsd-gateway-freebsd-arm64 .
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/wsd-gateway-linux-amd64 .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/wsd-gateway-linux-arm64 .
