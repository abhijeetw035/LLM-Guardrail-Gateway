// Package streaming implements the sliding window buffer and FSM output scanner.
//
// The core problem: once bytes are flushed to the HTTP client they cannot be
// recalled. If we scan each chunk and immediately forward it, unsafe content
// reaches the client before we can stop it.
//
// Solution: hold a rolling buffer of the last N bytes between the LLM stream
// and the client write path. Only forward bytes once the scanner has cleared
// them. If unsafe content is detected, abort — nothing unsafe has left the
// gateway yet.
//
// Trade-off: clients see a small delay (proportional to window size) before
// the first bytes arrive. For a 512-byte window at typical LLM speeds this is
// well under 200ms.
package streaming

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
)

// ScanResult is the outcome of an output scan.
type ScanResult int

const (
	ScanOK    ScanResult = iota // buffer prefix is safe, forward it
	ScanAbort                   // unsafe content detected, abort stream
)

// Window holds the rolling buffer and drives the scan-then-forward loop.
type Window struct {
	size    int        // max bytes to hold before forwarding the safe prefix
	scanner *outScanner
	buf     bytes.Buffer
}

// NewWindow returns a Window with the given buffer size (bytes).
func NewWindow(size int) *Window {
	if size <= 0 {
		size = 512
	}
	return &Window{
		size:    size,
		scanner: globalOutScanner,
	}
}

// Write appends p to the internal buffer (satisfies io.Writer so it can be
// used with io.Copy from the LLM response body).
func (w *Window) Write(p []byte) (int, error) {
	return w.buf.Write(p)
}

// Flush scans the current buffer contents and writes the safe prefix to dst.
//
// Returns ScanOK if all content so far is clean and the safe prefix was written.
// Returns ScanAbort if unsafe content was detected — dst is NOT written to.
//
// Call this after each Write() to drive the forward loop.
func (w *Window) Flush(dst io.Writer) (ScanResult, error) {
	data := w.buf.Bytes()
	if len(data) == 0 {
		return ScanOK, nil
	}

	// Run the FSM scanner over the entire current buffer.
	if w.scanner.containsUnsafe(data) {
		return ScanAbort, nil
	}

	// If buffer hasn't reached window size yet, hold it — don't forward.
	// This ensures we always have at least `size` bytes of lookahead.
	if w.buf.Len() <= w.size {
		return ScanOK, nil
	}

	// Forward the safe prefix (everything except the last `size` bytes).
	safe := w.buf.Len() - w.size
	_, err := dst.Write(data[:safe])
	if err != nil {
		return ScanOK, err
	}

	// Consume the forwarded bytes from the buffer.
	// bytes.Buffer will automatically shift the remaining tail to the front
	// when needed, avoiding slice allocations on every flush.
	w.buf.Next(safe)

	return ScanOK, nil
}

// DrainSafe forwards whatever is left in the buffer after the LLM stream ends,
// provided the scanner passes it. Call once after the source stream is exhausted.
func (w *Window) DrainSafe(dst io.Writer) (ScanResult, error) {
	data := w.buf.Bytes()
	if len(data) == 0 {
		return ScanOK, nil
	}
	if w.scanner.containsUnsafe(data) {
		return ScanAbort, nil
	}
	_, err := dst.Write(data)
	w.buf.Reset()
	return ScanOK, err
}

// --- FSM output scanner ---
//
// Scans buffered bytes for patterns that should never reach a client:
//   - PII: email addresses, phone numbers, SSNs, credit card numbers
//   - Secrets: AWS keys, generic API key patterns
//   - Unsafe content markers
//
// The FSM here is implemented as compiled regexes that run over the buffered
// window. Because the buffer always contains the full unforwarded tail, a
// pattern split across two SSE chunks is still detected correctly — the
// dangerous bytes are never forwarded before the scan completes.

type outScanner struct {
	patterns []*regexp.Regexp
}

var globalOutScanner *outScanner

func init() {
	raw := []string{
		// Email addresses
		`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		// US phone numbers (various formats)
		`(\+1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}`,
		// US Social Security Numbers
		`\b\d{3}[\s\-]\d{2}[\s\-]\d{4}\b`,
		// Credit card numbers (Visa, MC, Amex, Discover — 13-19 digits with optional separators)
		`\b(?:\d[ \-]?){13,19}\b`,
		// AWS access key IDs
		`\bAKIA[0-9A-Z]{16}\b`,
		// Generic "sk-" style secret keys (OpenAI, Stripe, etc.)
		`\bsk-[a-zA-Z0-9]{20,}\b`,
		// Unsafe instruction patterns in output
		`(?i)(how\s+to\s+(make|build|synthesize)\s+(a\s+)?(bomb|weapon|explosive|poison|malware|virus))`,
		// Self-harm content
		`(?i)(step[s]?\s+(to|for)\s+(commit\s+suicide|self[\s\-]harm|end\s+(your|my)\s+life))`,
	}

	compiled := make([]*regexp.Regexp, 0, len(raw))
	for _, p := range raw {
		compiled = append(compiled, regexp.MustCompile(p))
	}
	globalOutScanner = &outScanner{patterns: compiled}
}

// containsUnsafe returns true if any pattern matches in data.
func (s *outScanner) containsUnsafe(data []byte) bool {
	for _, re := range s.patterns {
		if re.Match(data) {
			return true
		}
	}
	return false
}

// --- SSE helpers ---

// ReadSSEChunks reads an SSE stream from r, calling onChunk for each data line.
// Stops on io.EOF or when onChunk returns false.
func ReadSSEChunks(r io.Reader, onChunk func(data []byte) bool) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		// SSE data lines start with "data: "
		if bytes.HasPrefix(line, []byte("data: ")) {
			payload := line[len("data: "):]
			// [DONE] is the SSE terminator sentinel
			if bytes.Equal(payload, []byte("[DONE]")) {
				break
			}
			if !onChunk(payload) {
				break
			}
		}
	}
	return scanner.Err()
}
