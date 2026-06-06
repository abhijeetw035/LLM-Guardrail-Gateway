# Benchmark Report

## How to Run

### Go Micro-benchmarks

```bash
# All benchmarks
go test -bench=. -benchmem ./internal/...

# DSL pipeline only
go test -bench=. -benchmem ./internal/policy/dsl/

# Sliding window only
go test -bench=. -benchmem ./internal/streaming/

# Input scanner only
go test -bench=. -benchmem ./internal/guardrails/input/
```

### Fuzz Tests

```bash
# DSL lexer — run for 30 seconds
go test -fuzz=FuzzLexer -fuzztime=30s ./internal/policy/dsl/

# DSL parser — run for 30 seconds
go test -fuzz=FuzzParser -fuzztime=30s ./internal/policy/dsl/

# DSL full pipeline (lex → parse → compile → evaluate)
go test -fuzz=FuzzCompile -fuzztime=30s ./internal/policy/dsl/

# Sliding window scanner
go test -fuzz=FuzzWindow -fuzztime=30s ./internal/streaming/
```

### Load Test

Requires the gateway and mock LLM to be running.

```bash
# Terminal 1 — mock LLM
go run ./cmd/mockllm

# Terminal 2 — gateway (without Redis for baseline)
go run ./cmd/gateway

# Terminal 3 — load test
go run ./tests/load -rate 100 -duration 10s -workers 10
```

---

## Micro-benchmark Results

> Run on: Apple M-series / go 1.25  
> Fill in after running `go test -bench=. -benchmem ./internal/...`

### DSL Pipeline

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| BenchmarkLex | | | | |
| BenchmarkParse | | | | |
| BenchmarkCompile | | | | |
| BenchmarkEvaluate | | | | |
| BenchmarkEvaluateLargePolicy (100 rules) | | | | |

**Key insight**: `BenchmarkEvaluate` should show **0 allocs/op** because the compiled closures are pre-built — no AST traversal or parsing happens on the hot path.

### Input Scanner

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| BenchmarkScanClean | | | | |
| BenchmarkScanMalicious | | | | |
| BenchmarkScanLargePrompt (4KB) | | | | |

### Sliding Window

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| BenchmarkWindowFlush/window_32 | | | | |
| BenchmarkWindowFlush/window_64 | | | | |
| BenchmarkWindowFlush/window_128 | | | | |
| BenchmarkWindowFlush/window_256 | | | | |
| BenchmarkWindowFlush/window_512 | | | | |
| BenchmarkWindowFlush/window_1024 | | | | |
| BenchmarkWindowAbort | | | | |
| BenchmarkOutScanner/clean_128 | | | | |
| BenchmarkOutScanner/clean_512 | | | | |
| BenchmarkOutScanner/clean_2048 | | | | |
| BenchmarkOutScanner/clean_8192 | | | | |

**Key question**: How does window size affect throughput? Larger windows = more data scanned per flush = higher ns/op, but better safety coverage.

---

## Load Test Results

> Fill in after running `go run ./tests/load -rate 100 -duration 10s`

| Metric | Value |
|---|---|
| Target Rate | 100 req/s |
| Duration | 10s |
| Workers | 10 |
| Total Requests | |
| Success | |
| Errors | |
| Throughput | req/s |
| P50 Latency | |
| P95 Latency | |
| P99 Latency | |
| Max Latency | |

---

## Fuzz Test Results

> Fill in after running each fuzz test for 30-60 seconds

| Fuzz Target | Duration | Executions | Crashes |
|---|---|---|---|
| FuzzLexer | 30s | | |
| FuzzParser | 30s | | |
| FuzzCompile | 30s | | |
| FuzzWindow | 30s | | |

**Goal**: Zero crashes. Any crash = a bug to fix and add as a regression test.

---

## Analysis

### Per-stage overhead

| Stage | Estimated overhead |
|---|---|
| Auth + tenant resolution | |
| Input guardrail scan | |
| Policy evaluation (4 rules) | |
| Policy evaluation (100 rules) | |
| Sliding window (512 bytes) | |
| Total gateway overhead vs direct proxy | |

### Window size trade-off

| Window Size | Throughput | Safety | Recommendation |
|---|---|---|---|
| 32 bytes | Highest | Low — short patterns may span chunks | Testing only |
| 128 bytes | High | Medium | Low-risk applications |
| 512 bytes | Medium | High | **Default** |
| 1024 bytes | Lower | Very high | High-security applications |

---

## How to Reproduce

```bash
# Full benchmark suite in one command
make bench
```

Or manually:

```bash
go test -bench=. -benchmem -count=5 ./internal/policy/dsl/ > results_dsl.txt
go test -bench=. -benchmem -count=5 ./internal/streaming/ > results_window.txt
go test -bench=. -benchmem -count=5 ./internal/guardrails/input/ > results_scanner.txt
```

Run each benchmark 5 times (`-count=5`) for statistical stability.
