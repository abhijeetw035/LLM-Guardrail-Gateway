// Package provider defines the Adapter interface and factory for pluggable LLM backends.
//
// The gateway uses this abstraction to forward requests to any compatible
// LLM provider (Groq, Gemini, OpenAI, or the local mock) without changing
// the core request pipeline. Switching providers is a one-line env-var change.
package provider

import (
	"context"
	"io"
)

// GenerateResult holds the response from a non-streaming LLM call.
type GenerateResult struct {
	Text         string
	InputTokens  int
	OutputTokens int
	Model        string
}

// Adapter is the interface every LLM backend must satisfy.
//
// Generate performs a blocking (non-streaming) completion and returns the
// response text plus token usage metadata.
//
// StreamTo performs a streaming completion and writes raw SSE bytes to dst.
// The caller is responsible for scanning the bytes through the sliding window
// before forwarding to the HTTP client. The method returns when the LLM stream
// is exhausted or the context is cancelled.
type Adapter interface {
	Generate(ctx context.Context, prompt string) (GenerateResult, error)
	StreamTo(ctx context.Context, prompt string, dst io.Writer) error
}
