.PHONY: build test bench fuzz fuzz-dsl fuzz-window lint

build:
	go build ./...

test:
	go test ./...

bench:
	@echo "=== DSL Pipeline ==="
	go test -bench=. -benchmem ./internal/policy/dsl/
	@echo ""
	@echo "=== Sliding Window ==="
	go test -bench=. -benchmem ./internal/streaming/
	@echo ""
	@echo "=== Input Scanner ==="
	go test -bench=. -benchmem ./internal/guardrails/input/

fuzz: fuzz-dsl fuzz-window

fuzz-dsl:
	go test -fuzz=FuzzLexer -fuzztime=30s ./internal/policy/dsl/
	go test -fuzz=FuzzParser -fuzztime=30s ./internal/policy/dsl/
	go test -fuzz=FuzzCompile -fuzztime=30s ./internal/policy/dsl/

fuzz-window:
	go test -fuzz=FuzzWindow -fuzztime=30s ./internal/streaming/

load:
	go run ./tests/load -rate 100 -duration 10s -workers 10
