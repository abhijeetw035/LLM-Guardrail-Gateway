// Package gateway implements the HTTP server and request handler.
//
package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/auth"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/guardrails/input"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/streaming"
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
	cfg       config.Config
	log       *logger.Logger
	client    *http.Client
	mux       *http.ServeMux
	authStore *auth.Store
	scanner   *input.Scanner
}

// New creates a Server and registers all routes.
func New(cfg config.Config, log *logger.Logger) *Server {
	s := &Server{
		cfg:       cfg,
		log:       log,
		client:    &http.Client{Timeout: 30 * time.Second},
		mux:       http.NewServeMux(),
		authStore: auth.DefaultStore(),
		scanner:   input.NewScanner(),
	}
	s.mux.HandleFunc("/v1/complete", s.handleComplete)
	s.mux.HandleFunc("/v1/stream", s.handleStream)
	s.mux.HandleFunc("/healthz", s.handleHealth)
	return s
}

// Handler returns the http.Handler for use with http.ListenAndServe.
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

// withMiddleware chains: request-ID injection → auth → logging.
func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		reqID := newRequestID()

		// 1. Attach request ID to context and response header.
		ctx := context.WithValue(r.Context(), ctxKeyRequestID{}, reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)

		// 2. Authenticate — /healthz is exempt.
		var tenantID string
		if r.URL.Path != "/healthz" {
			tenant, err := s.authStore.Authenticate(r.Header.Get("Authorization"))
			if err != nil {
				s.log.Warn("auth_failed", map[string]any{
					"request_id": reqID,
					"remote":     r.RemoteAddr,
				})
				s.writeJSON(w, http.StatusUnauthorized,
					errorResponse{Error: "unauthorized", RequestID: reqID})
				return
			}
			// Store resolved tenant in context for downstream handlers.
			r = r.WithContext(auth.WithTenant(r.Context(), tenant))
			tenantID = tenant.ID
		}

		// 3. Log request start (after auth so tenant_id is known).
		s.log.Info("request_started", map[string]any{
			"request_id": reqID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
			"tenant_id":  tenantID,
		})

		// 4. Delegate to handler, capture status for logging.
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		s.log.Info("request_completed", map[string]any{
			"request_id":  reqID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.status,
			"duration_ms": time.Since(start).Milliseconds(),
			"tenant_id":   tenantID,
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
//  1. Enforce body size limit — reject 413 before any parsing.
//  2. Decode JSON prompt.
//  3. Run input guardrail scan — block or tag based on composite risk score.
//  4. Forward to mock LLM.
//  5. Return response.
func (s *Server) handleComplete(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromCtx(r.Context())
	tenant, _ := auth.TenantFromCtx(r.Context())

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", reqID)
		return
	}

	// --- Enforce body size limit ---
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

	// --- Decode the prompt ---
	var req CompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}
	if req.Prompt == "" {
		s.writeError(w, http.StatusBadRequest, "prompt_required", reqID)
		return
	}

	// --- Input guardrail scan ---
	result := s.scanner.Scan(r.Context(), req.Prompt)
	s.log.Info("guardrail_scan", map[string]any{
		"request_id":  reqID,
		"tenant_id":   tenant.ID,
		"score":       result.Score,
		"verdict":     string(result.Verdict),
		"signals":     result.Signals,
	})

	if result.Verdict == input.VerdictBlock {
		s.log.Warn("guardrail_blocked", map[string]any{
			"request_id": reqID,
			"tenant_id":  tenant.ID,
			"score":      result.Score,
		})
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "guardrail_block",
			"reason":     "Request blocked by input safety policy",
			"score":      result.Score,
			"request_id": reqID,
		})
		return
	}

	// VerdictTag: allow through but the scan log above already records it.
	// --- Forward to mock LLM ---
	llmResp, err := s.callMockLLM(r.Context(), reqID, req.Prompt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.log.Error("mock_llm_timeout", map[string]any{"request_id": reqID})
			s.writeError(w, http.StatusGatewayTimeout, "provider_timeout", reqID)
			return
		}
		s.log.Error("mock_llm_error", map[string]any{
			"request_id": reqID,
			"error":      err.Error(),
		})
		s.writeError(w, http.StatusBadGateway, "provider_error", reqID)
		return
	}

	// --- Return response ---
	s.writeJSON(w, http.StatusOK, CompletionResponse{
		RequestID: reqID,
		Response:  llmResp,
	})
}

// handleStream processes POST /v1/stream.
//
// It forwards the prompt to the mock LLM's SSE stream endpoint and pipes
// the raw SSE bytes through the sliding window buffer. The window holds N bytes
// before forwarding so the output scanner always has lookahead — unsafe
// content is detected before it reaches the client.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	reqID := requestIDFromCtx(r.Context())
	tenant, _ := auth.TenantFromCtx(r.Context())

	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", reqID)
		return
	}

	// Body size guard.
	if r.ContentLength > s.cfg.MaxBodyBytes {
		s.writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large", reqID)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)

	// Decode prompt.
	var req CompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_request_body", reqID)
		return
	}
	if req.Prompt == "" {
		s.writeError(w, http.StatusBadRequest, "prompt_required", reqID)
		return
	}

	// Input guardrail scan.
	scanResult := s.scanner.Scan(r.Context(), req.Prompt)
	s.log.Info("guardrail_scan", map[string]any{
		"request_id": reqID,
		"tenant_id":  tenant.ID,
		"score":      scanResult.Score,
		"verdict":    string(scanResult.Verdict),
	})
	if scanResult.Verdict == input.VerdictBlock {
		s.log.Warn("guardrail_blocked", map[string]any{"request_id": reqID, "score": scanResult.Score})
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "guardrail_block",
			"reason":     "Request blocked by input safety policy",
			"score":      scanResult.Score,
			"request_id": reqID,
		})
		return
	}

	// Build mock LLM URL, forwarding any query params from the client request
	// (e.g. ?unsafe=true used in testing to trigger the unsafe payload path).
	streamURL := s.cfg.MockLLMAddr + "/stream"
	if q := r.URL.RawQuery; q != "" {
		streamURL += "?" + q
	}

	body, _ := json.Marshal(mockLLMRequest{Prompt: req.Prompt})
	llmReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, streamURL, bytes.NewReader(body))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "internal_error", reqID)
		return
	}
	llmReq.Header.Set("Content-Type", "application/json")

	llmResp, err := s.client.Do(llmReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.writeError(w, http.StatusGatewayTimeout, "provider_timeout", reqID)
			return
		}
		s.log.Error("stream_llm_error", map[string]any{"request_id": reqID, "error": err.Error()})
		s.writeError(w, http.StatusBadGateway, "provider_error", reqID)
		return
	}
	defer llmResp.Body.Close()

	// Set SSE response headers before writing the first byte.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(http.StatusOK)
	flusher, canFlush := w.(http.Flusher)

	win := streaming.NewWindow(s.cfg.WindowSize)
	start := time.Now()
	chunk := make([]byte, 256)

	// Read raw SSE bytes from the mock LLM and push them through the window.
	// Raw bytes include "data: word\n\n" — the window forwards them unchanged,
	// so the client receives proper SSE format. The scanner sees the full text
	// (including any PII embedded in the payload) and can match across chunk
	// boundaries because the window tail is never discarded until cleared.
	for {
		n, readErr := llmResp.Body.Read(chunk)
		if n > 0 {
			win.Write(chunk[:n])
			result, werr := win.Flush(w)
			if werr != nil {
				break
			}
			if result == streaming.ScanAbort {
				s.log.Warn("stream_aborted_unsafe_output", map[string]any{
					"request_id":  reqID,
					"tenant_id":   tenant.ID,
					"duration_ms": time.Since(start).Milliseconds(),
				})
				fmt.Fprintf(w, "data: {\"error\":\"output_policy_violation\",\"request_id\":%q}\n\n", reqID)
				if canFlush {
					flusher.Flush()
				}
				return
			}
			if canFlush {
				flusher.Flush()
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			s.log.Error("stream_read_error", map[string]any{"request_id": reqID, "error": readErr.Error()})
			return
		}
	}

	// Drain the remaining window buffer after the stream ends.
	result, _ := win.DrainSafe(w)
	if result == streaming.ScanAbort {
		s.log.Warn("stream_aborted_unsafe_output_drain", map[string]any{"request_id": reqID})
		fmt.Fprintf(w, "data: {\"error\":\"output_policy_violation\",\"request_id\":%q}\n\n", reqID)
		if canFlush {
			flusher.Flush()
		}
		return
	}
	if canFlush {
		flusher.Flush()
	}

	s.log.Info("stream_completed", map[string]any{
		"request_id":  reqID,
		"tenant_id":   tenant.ID,
		"duration_ms": time.Since(start).Milliseconds(),
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
