// cmd/mockllm runs a tiny HTTP server that pretends to be an LLM.
// It accepts POST /generate with {"prompt":"..."} and returns a deterministic
// fake response. Used exclusively for local development and testing.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type generateRequest struct {
	Prompt string `json:"prompt"`
}

type generateResponse struct {
	Response    string `json:"response"`
	Model       string `json:"model"`
	InputTokens int    `json:"input_tokens"`
	OutputTokens int   `json:"output_tokens"`
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate", handleGenerate)
	mux.HandleFunc("/stream", handleStream)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	addr := ":9090"
	log.Printf("[mock-llm] listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[mock-llm] fatal: %v", err)
	}
}

func handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req generateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Simulate a small processing delay so latency logs look realistic.
	time.Sleep(50 * time.Millisecond)

	words := strings.Fields(req.Prompt)
	resp := generateResponse{
		Response:     fmt.Sprintf("Mock response to: %q. This is a simulated LLM reply for local development.", req.Prompt),
		Model:        "mock-llm-v1",
		InputTokens:  len(words),
		OutputTokens: 45,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleStream sends the mock response as SSE chunks (one word per chunk).
// It sets the SSE headers and flushes after every chunk to simulate real streaming.
//
// Query param ?unsafe=true injects a fake email address mid-stream so the
// gateway output scanner can be tested against a real unsafe payload.
func handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req generateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Build the words to stream.
	response := fmt.Sprintf("Mock streaming response to: %q. This is a simulated token-by-token reply.", req.Prompt)

	// If the caller wants to test unsafe content interception, inject a fake email.
	if r.URL.Query().Get("unsafe") == "true" {
		response += " Contact us at leaked.secret@internal-corp.com for more info."
	}

	words := strings.Fields(response)

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	flusher, canFlush := w.(http.Flusher)

	for _, word := range words {
		// Each SSE event: "data: <word>\n\n"
		fmt.Fprintf(w, "data: %s \n\n", word)
		if canFlush {
			flusher.Flush()
		}
		time.Sleep(20 * time.Millisecond) // simulate token generation speed
	}

	// SSE terminator
	fmt.Fprintf(w, "data: [DONE]\n\n")
	if canFlush {
		flusher.Flush()
	}
}
