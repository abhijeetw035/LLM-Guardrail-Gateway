package streaming_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/streaming"
)

func TestWindow_CleanContent_ForwardedAfterWindowFills(t *testing.T) {
	win := streaming.NewWindow(10) // tiny 10-byte window for test speed
	var out bytes.Buffer

	// Write 20 bytes of safe content — more than the window size.
	win.Write([]byte("hello world safe content"))
	result, err := win.Flush(&out)
	if err != nil {
		t.Fatal(err)
	}
	if result != streaming.ScanOK {
		t.Errorf("expected ScanOK, got %v", result)
	}
	// Some bytes should have been forwarded (buffer > window size).
	if out.Len() == 0 {
		t.Error("expected some bytes forwarded after buffer exceeds window size")
	}
}

func TestWindow_UnsafeContent_Aborted(t *testing.T) {
	win := streaming.NewWindow(512)
	var out bytes.Buffer

	// Write content containing an email address (PII).
	win.Write([]byte("Here is the info: contact@leaked-internal.com — please call us"))
	result, err := win.Flush(&out)
	if err != nil {
		t.Fatal(err)
	}
	if result != streaming.ScanAbort {
		t.Errorf("expected ScanAbort for PII content, got %v", result)
	}
	// Nothing must have been written to the client.
	if out.Len() != 0 {
		t.Errorf("expected 0 bytes forwarded on abort, got %d", out.Len())
	}
}

func TestWindow_DrainSafe_CleanContent(t *testing.T) {
	win := streaming.NewWindow(512)
	var out bytes.Buffer

	win.Write([]byte("This is a completely safe response with no PII."))
	result, err := win.DrainSafe(&out)
	if err != nil {
		t.Fatal(err)
	}
	if result != streaming.ScanOK {
		t.Errorf("expected ScanOK on drain, got %v", result)
	}
	if out.Len() == 0 {
		t.Error("expected content in output after drain")
	}
}

func TestWindow_DrainSafe_UnsafeContent_Aborted(t *testing.T) {
	win := streaming.NewWindow(512)
	var out bytes.Buffer

	win.Write([]byte("Call us at 555-123-4567 to learn more"))
	result, _ := win.DrainSafe(&out)
	if result != streaming.ScanAbort {
		t.Errorf("expected ScanAbort for phone number in drain, got %v", result)
	}
	if out.Len() != 0 {
		t.Errorf("no bytes should be forwarded on abort, got %d", out.Len())
	}
}

func TestReadSSEChunks_ParsesDataLines(t *testing.T) {
	sse := "data: hello\n\ndata: world\n\ndata: [DONE]\n\n"
	r := strings.NewReader(sse)

	var collected []string
	err := streaming.ReadSSEChunks(r, func(data []byte) bool {
		collected = append(collected, string(data))
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(collected) != 2 { // [DONE] is consumed, not passed to callback
		t.Errorf("expected 2 chunks, got %d: %v", len(collected), collected)
	}
	if collected[0] != "hello" {
		t.Errorf("expected 'hello', got %q", collected[0])
	}
}
