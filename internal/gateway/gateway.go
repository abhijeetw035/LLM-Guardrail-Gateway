// Package gateway implements the HTTP server and request handler.
//
//   - Accept POST /v1/complete with a JSON prompt body
//   - Enforce request body size limit (MaxBytesReader)
//   - Forward prompt to the mock LLM and return its response
//   - Structured JSON logging for every request
//   - GET /healthz for liveness checks
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
)

// CompletionRequest is the JSON body the client sends to the gateway.
type CompletionRequest struct {
	Prompt string `json:"prompt"`
}

// CompletionResponse is what the gateway returns to the client.
type CompletionResponse struct {
	RequestID string `json:"request_id"`
	Response  string `json:"response"`
}

// errorResponse is the standard JSON error shape.
type errorResponse struct {
	Error     string `json:"error"`
	RequestID string `json:"request_id"`
}

// Server wraps the HTTP mux and shared dependencies.
type Server struct {
	cfg    config.Config
	log    *logger.Logger
	client *http.Client
	mux    *http.ServeMux
}

// New creates a Server and registers all routes.
func New(cfg config.Config, log *logger.Logger) *Server {
	s := &Server{
		cfg: cfg,
		log: log,
		// Shared HTTP client used to forward requests to the mock LLM.
		// Timeout is generous for Phase 1; will be tunable in later phases.
		client: &http.Client{Timeout: 30 * time.Second},
		mux:    http.NewServeMux(),
	}
	s.mux.HandleFunc("/v1/complete", s.handleComplete)
	s.mux.HandleFunc("/healthz", s.handleHealth)
	return s
}

// Handler returns the http.Handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

// withMiddleware wraps the mux with request-ID injection and request/response logging.
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := newRequestID()

		// Attach request ID to context so handlers can read it.
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		r = r.WithContext(ctx)

		// Surface the request ID to the caller as a response header.
		w.Header().Set("X-Request-ID", reqID)

		s.log.Info("request_started", map[string]any{
			"request_id": reqID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
		})

		// Wrap ResponseWriter to capture status code for logging.
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.log.Info("request_completed", map[string]any{
			"request_id":  reqID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.status,
			"duration_ms": time.Since(start).Milliseconds(),
		})
	})
}

// handleHealth is a simple liveness probe — always returns 200.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleComplete processes POST /v1/complete.
//
// Flow:
//  1. Enforce body size limit (MaxBytesReader) — reject 413 before any parsing.
//  2. Decode JSON prompt from request body.
//  3. Forward prompt to mock LLM.
//  4. Return mock LLM response to client.
func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromCtx(r.Context())

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", reqID)
		return
	}

	// --- Step 1: Enforce body size limit before reading any bytes ---
	// MaxBytesReader wraps the body so that reading beyond MaxBodyBytes
	// returns an error immediately. This prevents large payloads from being
	// fully read into memory before we can reject them.
	if r.ContentLength > s.cfg.MaxBodyBytes {
		s.log.Warn("request_body_too_large", map[string]any{
			"request_id":     reqID,
			"content_length": r.ContentLength,
			"remote":         r.RemoteAddr,
		})
		s.writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", reqID)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)

	// --- Step 2: Decode the prompt ---
	var req CompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}
	if req.Prompt == "" {
		s.writeError(w, http.StatusBadRequest, "prompt_required", reqID)
		return
	}

	// --- Step 3: Forward to mock LLM ---
	llmResp, err := s.callMockLLM(r.Context(), reqID, req.Prompt)
	if err != nil {
		s.log.Error("mock_llm_error", map[string]any{
			"request_id": reqID,
			"error":      err.Error(),
		})
		s.writeError(w, http.StatusBadGateway, "provider_error", reqID)
		return
	}

	// --- Step 4: Return response ---
	s.writeJSON(w, http.StatusOK, CompletionResponse{
		RequestID: reqID,
		Response:  llmResp,
	})
}

// mockLLMRequest is the payload sent to the mock LLM server.
type mockLLMRequest struct {
	Prompt string `json:"prompt"`
}

// mockLLMResponse is what the mock LLM server returns.
type mockLLMResponse struct {
	Response    string `json:"response"`
	Model       string `json:"model"`
	InputTokens int    `json:"input_tokens"`
	OutTokens   int    `json:"output_tokens"`
}

// callMockLLM POSTs the prompt to the mock LLM and returns the response text.
func (s *Server) callMockLLM(ctx context.Context, reqID, prompt string) (string, error) {
	body, err := json.Marshal(mockLLMRequest{Prompt: prompt})
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.MockLLMAddr+"/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := s.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("provider returned %d", resp.StatusCode)
	}

	var llmResp mockLLMResponse
	if err := json.NewDecoder(resp.Body).Decode(&llmResp); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	s.log.Info("provider_response_ok", map[string]any{
		"request_id":   reqID,
		"model":        llmResp.Model,
		"input_tokens": llmResp.InputTokens,
		"output_tokens": llmResp.OutTokens,
		"duration_ms":  time.Since(start).Milliseconds(),
	})

	return llmResp.Response, nil
}

// writeJSON encodes v as JSON and writes it with the given status code.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes a standard JSON error response.
func (s *Server) writeError(w http.ResponseWriter, status int, code, reqID string) {
	s.writeJSON(w, status, errorResponse{Error: code, RequestID: reqID})
}

// --- Helpers ---

type ctxKeyRequestID struct{}

func requestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(ctxKeyRequestID{}).(string); ok {
		return id
	}
	return "unknown"
}

// newRequestID generates a UUID v4 request ID.
func newRequestID() string {
	return uuid.NewString()
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}

// ReadFrom is needed to propagate io.Copy calls through the wrapper.
func (rw *responseWriter) ReadFrom(src io.Reader) (int64, error) {
	return io.Copy(rw.ResponseWriter, src)
}
