.PHONY: all build test clean run-api run-gateway run-worker

all: build test

build:
	go build -o bin/clm-api ./cmd/api
	go build -o bin/clm-gateway ./cmd/gateway
	go build -o bin/clm-worker ./cmd/worker
	go build -o bin/clm ./cmd/clm

test:
	go test -v ./internal/... ./test/...

clean:
	rm -rf bin/ clm.db *.exe

run-api:
	go run ./cmd/api

run-gateway:
	go run ./cmd/gateway

run-worker:
	go run ./cmd/worker
