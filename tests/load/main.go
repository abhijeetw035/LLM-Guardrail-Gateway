// Package main implements a simple load testing tool for the gateway.
//
// Usage:
//   go run ./tests/load -url http://localhost:8080/v1/complete \
//       -rate 100 -duration 10s -workers 10
//
// It sends POST requests at the configured rate and reports:
//   - Total requests sent
//   - Success / error count
//   - P50 / P95 / P99 latency
//   - Throughput (req/s)
//
// This is a self-contained tool with no external dependencies (no vegeta/k6).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	url := flag.String("url", "http://localhost:8080/v1/complete", "Target URL")
	rate := flag.Int("rate", 50, "Requests per second")
	duration := flag.Duration("duration", 10*time.Second, "Test duration")
	workers := flag.Int("workers", 10, "Concurrent workers")
	token := flag.String("token", "key-dev-local", "API key for Authorization header")
	prompt := flag.String("prompt", "What is the capital of France?", "Prompt to send")
	flag.Parse()

	body := []byte(fmt.Sprintf(`{"prompt":%q}`, *prompt))
	interval := time.Second / time.Duration(*rate)

	fmt.Printf("Load test: %s\n", *url)
	fmt.Printf("  rate=%d req/s  duration=%s  workers=%d\n\n", *rate, *duration, *workers)

	var (
		totalSent   int64
		totalOK     int64
		totalErr    int64
		latencies   []time.Duration
		latenciesMu sync.Mutex
	)

	// Work channel for requests.
	work := make(chan struct{}, *workers*2)
	var wg sync.WaitGroup

	// Spawn workers.
	client := &http.Client{Timeout: 30 * time.Second}
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range work {
				start := time.Now()
				req, _ := http.NewRequest(http.MethodPost, *url, bytes.NewReader(body))
				req.Header.Set("Authorization", "Bearer "+*token)
				req.Header.Set("Content-Type", "application/json")

				resp, err := client.Do(req)
				elapsed := time.Since(start)

				if err != nil {
					atomic.AddInt64(&totalErr, 1)
				} else {
					resp.Body.Close()
					if resp.StatusCode >= 200 && resp.StatusCode < 300 {
						atomic.AddInt64(&totalOK, 1)
					} else {
						atomic.AddInt64(&totalErr, 1)
					}
				}

				latenciesMu.Lock()
				latencies = append(latencies, elapsed)
				latenciesMu.Unlock()
			}
		}()
	}

	// Ticker to send requests at the configured rate.
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	deadline := time.After(*duration)

	testStart := time.Now()
loop:
	for {
		select {
		case <-deadline:
			break loop
		case <-ticker.C:
			atomic.AddInt64(&totalSent, 1)
			work <- struct{}{}
		}
	}
	close(work)
	wg.Wait()
	testDuration := time.Since(testStart)

	// Sort latencies for percentile calculation.
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	fmt.Println("--- Results ---")
	fmt.Printf("Duration:    %s\n", testDuration.Round(time.Millisecond))
	fmt.Printf("Requests:    %d sent, %d ok, %d errors\n", totalSent, totalOK, totalErr)
	if testDuration.Seconds() > 0 {
		fmt.Printf("Throughput:  %.1f req/s\n", float64(totalOK)/testDuration.Seconds())
	}

	if len(latencies) > 0 {
		fmt.Printf("Latency P50: %s\n", percentile(latencies, 0.50))
		fmt.Printf("Latency P95: %s\n", percentile(latencies, 0.95))
		fmt.Printf("Latency P99: %s\n", percentile(latencies, 0.99))
		fmt.Printf("Latency Max: %s\n", latencies[len(latencies)-1])
	}

	// Exit with error if more than 5% of requests failed.
	errorRate := float64(totalErr) / float64(totalSent)
	if errorRate > 0.05 {
		fmt.Printf("\nWARNING: %.1f%% error rate exceeds 5%% threshold\n", errorRate*100)
		os.Exit(1)
	}
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}
