package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// MockAdapter wraps the local mock LLM server. It is the default adapter used
// when LLM_PROVIDER is unset or "mock", preserving backward-compatibility with
// all existing tests and the Docker Compose development stack.
type MockAdapter struct {
	baseURL string
	client  *http.Client
}

// NewMockAdapter creates an adapter that forwards requests to the mock LLM
// server at baseURL (e.g. "http://localhost:9090").
func NewMockAdapter(baseURL string) *MockAdapter {
	return &MockAdapter{
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// mockRequest is the JSON payload the mock LLM expects.
type mockRequest struct {
	Prompt string `json:"prompt"`
}

// mockResponse is what the mock LLM returns for non-streaming calls.
type mockResponse struct {
	Response    string `json:"response"`
	Model       string `json:"model"`
	InputTokens int    `json:"input_tokens"`
	OutTokens   int    `json:"output_tokens"`
}

// Generate calls POST /generate on the mock LLM and returns the response.
func (a *MockAdapter) Generate(ctx context.Context, prompt string) (GenerateResult, error) {
	body, err := json.Marshal(mockRequest{Prompt: prompt})
	if err != nil {
		return GenerateResult{}, fmt.Errorf("mock: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/generate", bytes.NewReader(body))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("mock: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("mock: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return GenerateResult{}, fmt.Errorf("mock: provider returned %d", resp.StatusCode)
	}

	var llmResp mockResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return GenerateResult{}, fmt.Errorf("mock: decode response: %w", err)
	}

	return GenerateResult{
		Text:         llmResp.Response,
		InputTokens:  llmResp.InputTokens,
		OutputTokens: llmResp.OutTokens,
		Model:        llmResp.Model,
	}, nil
}

// StreamTo calls POST /stream on the mock LLM and pipes the raw SSE bytes to dst.
// The caller (gateway) is responsible for scanning through the sliding window.
func (a *MockAdapter) StreamTo(ctx context.Context, prompt string, dst io.Writer) error {
	body, err := json.Marshal(mockRequest{Prompt: prompt})
	if err != nil {
		return fmt.Errorf("mock: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/stream", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("mock: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("mock: do request: %w", err)
	}
	defer resp.Body.Close()

	_, err = io.Copy(dst, resp.Body)
	return err
}
