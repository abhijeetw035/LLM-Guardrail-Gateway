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
