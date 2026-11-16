package streaming

import (
	"bytes"
	"testing"
)

func TestContainsUnsafe_Sync(t *testing.T) {
	cases := []struct {
		name string
		text string
		want bool
	}{
		{"key followed by newline", "ID: AKIAIOSFODNN7EXAMPLE\nAWS Secret", true},
		{"key at end of text", "ID: AKIAIOSFODNN7EXAMPLE", true},
		{"email followed by newline", "contact a@b.com\nNext", true},
		{"clean multi-line text", "Hello there.\nThis is a clean answer.\nGoodbye.", false},
	}
	for _, c := range cases {
		if got := ContainsUnsafe(c.text); got != c.want {
			t.Errorf("%s: ContainsUnsafe(%q) = %v, want %v", c.name, c.text, got, c.want)
		}
	}
}

func TestWindow_StreamDetectsUnsafe(t *testing.T) {
	cases := []struct {
		name string
		sse  string
	}{
		{"subword tokens", "data: AK\n\ndata: IA\n\ndata: IOSFODNN7EXAMPLE\n\n"},
		{"key then empty chunk then next word", "data: AKIAIOSFODNN7EXAMPLE\n\ndata: \n\n\ndata: AWS\n\n"},
	}
	for _, c := range cases {
		w := NewWindow(512)
		w.Write([]byte(c.sse))
		var dst bytes.Buffer
		if res, _ := w.Flush(&dst); res != ScanAbort {
			t.Errorf("%s: Flush = %v, want ScanAbort", c.name, res)
		}
		w = NewWindow(512)
		w.Write([]byte(c.sse))
		if res, _ := w.DrainSafe(&dst); res != ScanAbort {
			t.Errorf("%s: DrainSafe = %v, want ScanAbort", c.name, res)
		}
		if dst.Len() != 0 {
			t.Errorf("%s: unsafe bytes were forwarded", c.name)
		}
	}
}
