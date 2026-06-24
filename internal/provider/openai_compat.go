package provider

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OpenAICompatAdapter handles any LLM provider that exposes an OpenAI-compatible
// chat completions API. This includes:
//   - Groq  (api.groq.com/openai/v1)
//   - Gemini (generativelanguage.googleapis.com/v1beta/openai/)
//   - OpenAI (api.openai.com/v1)
//   - Any local/custom deployment (Ollama, LM Studio, vLLM, etc.)
//
// All of the above accept the same JSON request format and produce the same
// SSE streaming format, so a single adapter handles them all.
type OpenAICompatAdapter struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewOpenAICompatAdapter creates an adapter for any OpenAI-compatible provider.
//
//   - baseURL: the API base, e.g. "https://api.groq.com/openai/v1"
//   - apiKey:  the bearer token / API key
//   - model:   the model name, e.g. "llama-3.3-70b-versatile"
func NewOpenAICompatAdapter(baseURL, apiKey, model string) *OpenAICompatAdapter {
	return &OpenAICompatAdapter{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{Timeout: 60 * time.Second},
	}
}

// --- OpenAI wire types ---

type oaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type oaiRequest struct {
	Model    string       `json:"model"`
	Messages []oaiMessage `json:"messages"`
	Stream   bool         `json:"stream"`
}

type oaiChoice struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
	// streaming delta
	Delta struct {
		Content string `json:"content"`
	} `json:"delta"`
}

type oaiResponse struct {
	Model   string      `json:"model"`
	Choices []oaiChoice `json:"choices"`
	Usage   struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Generate performs a non-streaming (blocking) chat completion.
func (a *OpenAICompatAdapter) Generate(ctx context.Context, prompt string) (GenerateResult, error) {
	reqBody := oaiRequest{
		Model:    a.model,
		Stream:   false,
		Messages: []oaiMessage{{Role: "user", Content: prompt}},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("openai_compat: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return GenerateResult{}, fmt.Errorf("openai_compat: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return GenerateResult{}, fmt.Errorf("openai_compat: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return GenerateResult{}, fmt.Errorf("openai_compat: provider returned %d: %s", resp.StatusCode, string(errBody))
	}

	var oaiResp oaiResponse
	if err := json.NewDecoder(resp.Body).Decode(&oaiResp); err != nil {
		return GenerateResult{}, fmt.Errorf("openai_compat: decode response: %w", err)
	}

	text := ""
	if len(oaiResp.Choices) > 0 {
		text = oaiResp.Choices[0].Message.Content
	}

	return GenerateResult{
		Text:         text,
		InputTokens:  oaiResp.Usage.PromptTokens,
		OutputTokens: oaiResp.Usage.CompletionTokens,
		Model:        oaiResp.Model,
	}, nil
}

// StreamTo performs a streaming chat completion and writes the raw SSE bytes
// (in OpenAI SSE format: "data: <json>\n\n") to dst.
//
// The gateway's sliding window scanner reads these bytes through dst — it does
// NOT need to understand the JSON structure; it scans the raw text. The gateway
// will detect and abort the stream if unsafe content is found.
//
// We translate the LLM's SSE chunks into a format the existing sliding window
// already understands: raw text appended line by line, each prefixed with
// "data: " so the mock-LLM-compatible ReadSSEChunks helper can parse them.
func (a *OpenAICompatAdapter) StreamTo(ctx context.Context, prompt string, dst io.Writer) error {
	reqBody := oaiRequest{
		Model:    a.model,
		Stream:   true,
		Messages: []oaiMessage{{Role: "user", Content: prompt}},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("openai_compat: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("openai_compat: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+a.apiKey)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("openai_compat: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("openai_compat: provider returned %d: %s", resp.StatusCode, string(errBody))
	}

	// Read the provider's SSE stream, extract text deltas, and re-emit them
	// as plain "data: <word>\n\n" lines that the sliding window expects.
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()

		// SSE lines look like: "data: <json_object>" or "data: [DONE]"
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := line[len("data: "):]
		if payload == "[DONE]" {
			// Emit the SSE terminator so the gateway's drain loop exits cleanly.
			fmt.Fprintf(dst, "data: [DONE]\n\n")
			break
		}

		// Parse the streaming chunk JSON.
		var chunk oaiResponse
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			// Malformed chunk — skip rather than crash.
			continue
		}
		if len(chunk.Choices) == 0 {
			continue
		}

		delta := chunk.Choices[0].Delta.Content
		if delta == "" {
			continue
		}

		// Re-emit as a plain text SSE event for the sliding window to scan.
		// Format: "data: <token>\n\n"
		// The scanner in window.go reads lines with this prefix.
		fmt.Fprintf(dst, "data: %s\n\n", delta)
	}

	return scanner.Err()
}
