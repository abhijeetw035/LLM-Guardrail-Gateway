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

> Run on: Macbook Air M4 / go 1.25  
> Completed. Results recorded from Go micro-benchmarks.

### DSL Pipeline

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| BenchmarkLex | 877,249 | 1,372 | 19 | 4,584 |
| BenchmarkParse | 702,135 | 1,723 | 34 | 5,248 |
| BenchmarkCompile | 601,276 | 2,019 | 41 | 5,824 |
| BenchmarkEvaluate | 154,187,565 | 7.772 | 0 | 0 |
| BenchmarkEvaluateLargePolicy (100 rules) | 5,650,279 | 212.4 | 0 | 0 |

**Key insight**: `BenchmarkEvaluate` should show **0 allocs/op** because the compiled closures are pre-built — no AST traversal or parsing happens on the hot path.

### Input Scanner

| Benchmark | ops/sec | ns/op | allocs/op | B/op |
|---|---|---|---|---|
| BenchmarkScanClean | 66,823 | 16,901 | 20 | 2,136 |
| BenchmarkScanMalicious | 43,345 | 28,762 | 41 | 5,601 |
| BenchmarkScanLargePrompt (4KB) | 1,776 | 706,345 | 21 | 13,314 |

### Sliding Window

| Benchmark                        | ops/sec |     ns/op | allocs/op |   B/op |
| -------------------------------- | ------: | --------: | --------: | -----: |
| BenchmarkWindowFlush/window_32   |   1,720 |   713,156 |        13 | 16,993 |
| BenchmarkWindowFlush/window_64   |   1,303 |   927,493 |        13 | 17,072 |
| BenchmarkWindowFlush/window_128  |     865 | 1,373,506 |        14 | 17,571 |
| BenchmarkWindowFlush/window_256  |     535 | 2,239,343 |        15 | 18,621 |
| BenchmarkWindowFlush/window_512  |     306 | 3,951,609 |        15 | 19,634 |
| BenchmarkWindowFlush/window_1024 |     172 | 6,877,883 |        16 | 22,935 |
| BenchmarkWindowAbort             |  42,025 |    28,648 |        15 | 10,240 |
| BenchmarkOutScanner/clean_128    |  96,346 |    12,379 |         0 |      0 |
| BenchmarkOutScanner/clean_512    |  22,386 |    49,955 |         0 |      1 |
| BenchmarkOutScanner/clean_2048   |   5,829 |   202,954 |         0 |      6 |
| BenchmarkOutScanner/clean_8192   |   1,369 |   859,914 |         0 |     33 |

**Key insight:** Memory allocations in the streaming path were reduced from over 500 allocations per operation to approximately 13–16 allocations per operation through buffer reuse and allocation elimination. The benchmark now scales primarily with window size rather than allocation overhead.

**Key question**: How does window size affect throughput? Larger windows = more data scanned per flush = higher ns/op, but better safety coverage.

---

## Load Test Results

> Completed. Results collected from Vegeta load test with rate 100 over 10s.

| Metric | Value |
|---|---|
| Target Rate | 100 req/s |
| Duration | 10s |
| Workers | 10 |
| Total Requests | 999 |
| Success | 999 |
| Errors | 0 |
| Throughput | 99.4 req/s |
| P50 Latency | 51.71ms |
| P95 Latency | 52.24ms |
| P99 Latency | 53.77ms |
| Max Latency | 77.46ms |

---

## Fuzz Test Results

> Completed. Ran each fuzz test for 30 seconds without finding any crashes.

| Fuzz Target | Duration | Executions | Crashes |
|---|---|---|---|
| FuzzLexer | 30s | 13,876,921 | 0 |
| FuzzParser | 30s | 12,384,463 | 0 |
| FuzzCompile | 30s | 11,549,171 | 0 |
| FuzzWindow | 30s | 45,278 | 0 |

**Goal**: Zero crashes. Any crash = a bug to fix and add as a regression test.

---

## Analysis

### Per-stage overhead

| Stage | Estimated overhead |
|---|---|
| Auth + tenant resolution | ~1ms (Redis lookup) |
| Input guardrail scan | 16.9µs |
| Policy evaluation (4 rules) | 7.7ns |
| Policy evaluation (100 rules) | 212.4ns |
| Sliding window (512 bytes) | 3.95ms |
| Total gateway overhead vs direct proxy | ~5ms (requires direct-proxy baseline measurement) |

### Window size trade-off

| Window Size | Throughput | Safety                               | Recommendation             |
| ----------- | ---------- | ------------------------------------ | -------------------------- |
| 32 bytes    | Highest    | Low — short patterns may span chunks | Testing only               |
| 128 bytes   | High       | Medium                               | Low-risk applications      |
| 512 bytes   | Medium     | High                                 | **Default**                |
| 1024 bytes  | Lower      | Very high                            | High-security applications |

---


## Optimization Results

### Streaming Interceptor Memory Optimization

| Metric    |  Before |  After | Improvement |
| --------- | ------: | -----: | ----------: |
| allocs/op |     518 |     15 |      -97.1% |
| B/op      | 112,712 | 19,634 |      -82.6% |

### Changes

* Reused buffers instead of repeatedly allocating new ones
* Reduced temporary slice allocations in the sliding window path
* Eliminated unnecessary intermediate objects during scanning and flushing
* Improved memory locality within the streaming interceptor

### Result

* ~97% reduction in allocations per operation
* ~83% reduction in memory allocated per operation
* Lower GC pressure during sustained streaming workloads
* More predictable latency under concurrent load

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

