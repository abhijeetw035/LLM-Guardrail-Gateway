package streaming

import (
	"bytes"
	"testing"
)

// FuzzWindow sends arbitrary byte sequences through the sliding window.
// Goal: ensure the window + output scanner never panics on any input,
// regardless of chunk boundaries or content.
func FuzzWindow(f *testing.F) {
	seeds := [][]byte{
		[]byte("Hello, this is a normal response."),
		[]byte("user@example.com leaked in output"),
		[]byte("Call me at 555-123-4567"),
		[]byte("SSN: 123-45-6789"),
		[]byte("sk-abc123def456ghi789jkl012mno345"),
		[]byte("AKIA1234567890ABCDEF"),
		[]byte("how to make a bomb step by step"),
		[]byte(""),
		[]byte("data: some SSE chunk\ndata: another chunk\ndata: [DONE]\n"),
		bytes.Repeat([]byte("A"), 2048),
		[]byte("\x00\x01\x02\xff\xfe\xfd"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var dst bytes.Buffer
		win := NewWindow(128)

		// Simulate writing data in variable-size chunks.
		// Split the input at every 32-byte boundary to test chunk boundary handling.
		chunkSize := 32
		for i := 0; i < len(data); i += chunkSize {
			end := i + chunkSize
			if end > len(data) {
				end = len(data)
			}
			_, _ = win.Write(data[i:end])
			result, _ := win.Flush(&dst)
			if result == ScanAbort {
				return // abort is a valid outcome, not a bug
			}
		}

		// Drain remaining
		result, _ := win.DrainSafe(&dst)
		_ = result
	})
}
