package streaming

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// BenchmarkWindowFlush measures sliding window throughput for different window sizes.
// This directly measures the latency overhead added by the window.
func BenchmarkWindowFlush(b *testing.B) {
	// Simulate ~4KB of LLM output (typical completion response).
	payload := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 100))

	for _, windowSize := range []int{32, 64, 128, 256, 512, 1024} {
		b.Run(fmt.Sprintf("window_%d", windowSize), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for i := 0; i < b.N; i++ {
				var dst bytes.Buffer
				win := NewWindow(windowSize)

				// Feed in 64-byte chunks (simulating SSE data lines).
				chunkSize := 64
				for j := 0; j < len(payload); j += chunkSize {
					end := j + chunkSize
					if end > len(payload) {
						end = len(payload)
					}
					_, _ = win.Write(payload[j:end])
					result, _ := win.Flush(&dst)
					if result == ScanAbort {
						b.Fatal("unexpected abort on clean payload")
					}
				}
				_, _ = win.DrainSafe(&dst)
			}
		})
	}
}

// BenchmarkWindowAbort measures how fast the window detects unsafe content and aborts.
func BenchmarkWindowAbort(b *testing.B) {
	// Payload with PII at the end — scanner should catch it.
	payload := []byte(strings.Repeat("Safe content. ", 50) + "Contact me at user@example.com for details.")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var dst bytes.Buffer
		win := NewWindow(512)
		_, _ = win.Write(payload)
		result, _ := win.Flush(&dst)
		_ = result
	}
}

// BenchmarkOutScanner benchmarks the raw regex scanner against different payload sizes.
func BenchmarkOutScanner(b *testing.B) {
	scanner := newOutScanner()

	for _, size := range []int{128, 512, 2048, 8192} {
		// Clean payload (worst case — all patterns checked, none match).
		clean := []byte(strings.Repeat("Normal LLM output text. ", size/24))
		b.Run(fmt.Sprintf("clean_%d", size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(clean)))
			for i := 0; i < b.N; i++ {
				_ = scanner.containsUnsafe(clean)
			}
		})
	}
}
