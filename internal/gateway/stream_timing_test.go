package gateway

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/streaming"
)

func TestWindowWriter_TimingAndMetrics(t *testing.T) {
	win := streaming.NewWindow(64) // 64-byte window for testing
	recorder := httptest.NewRecorder()
	log := logger.New(logger.LevelError)

	start := time.Now()
	ww := &windowWriter{
		win:         win,
		dst:         recorder,
		flusher:     recorder,
		canFlush:    true,
		reqID:       "test-req-1",
		tenantID:    "test-tenant",
		log:         log,
		streamStart: start,
	}

	// 1. Send small chunk (< 64 bytes) -> should buffer, not flush to recorder
	chunk1 := []byte("data: hello world\n\n")
	n, err := ww.Write(chunk1)
	if err != nil {
		t.Fatalf("unexpected write error: %v", err)
	}
	if n != len(chunk1) {
		t.Errorf("expected %d written, got %d", len(chunk1), n)
	}
	if recorder.Body.Len() > 0 {
		t.Errorf("expected 0 bytes emitted to client before window is full, got %d", recorder.Body.Len())
	}
	if !ww.firstChunkSentAt.IsZero() {
		t.Errorf("firstChunkSentAt should be zero before first flush")
	}

	// 2. Send large chunk to exceed window size -> should flush safe prefix
	chunk2 := []byte("data: this is a longer chunk that easily pushes the total buffer size past the 64 byte window threshold!\n\n")
	_, err = ww.Write(chunk2)
	if err != nil {
		t.Fatalf("unexpected write error on chunk 2: %v", err)
	}
	if recorder.Body.Len() == 0 {
		t.Errorf("expected bytes to be flushed to client")
	}
	if ww.firstChunkSentAt.IsZero() {
		t.Errorf("firstChunkSentAt should be recorded")
	}

	// 3. Send another chunk -> should record inter-chunk latency
	chunk3 := []byte("data: another chunk arriving after small interval\n\n")
	time.Sleep(5 * time.Millisecond)
	_, err = ww.Write(chunk3)
	if err != nil {
		t.Fatalf("unexpected write error on chunk 3: %v", err)
	}
	if ww.chunksSentCount == 0 {
		t.Errorf("expected chunksSentCount > 0, got %d", ww.chunksSentCount)
	}
	if ww.totalInterChunk <= 0 {
		t.Errorf("expected totalInterChunk > 0, got %v", ww.totalInterChunk)
	}
	if ww.totalCheckTime <= 0 {
		t.Errorf("expected totalCheckTime > 0, got %v", ww.totalCheckTime)
	}

	// 4. Drain remaining buffer
	cw := &countWriter{dst: recorder}
	res, err := win.DrainSafe(cw)
	if err != nil || res != streaming.ScanOK {
		t.Fatalf("drain failed: res=%v, err=%v", res, err)
	}
	if !bytes.Contains(recorder.Body.Bytes(), []byte("hello world")) {
		t.Errorf("expected recorder to have buffered content")
	}
}
