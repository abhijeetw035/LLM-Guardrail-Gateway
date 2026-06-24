// Package gateway implements the HTTP server and request handler.
//
package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/auth"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/cache"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/guardrails/input"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/metrics"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/policy"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/policy/dsl"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/provider"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/ratelimit"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/redisclient"
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
	cfg         config.Config
	log         *logger.Logger
	mux         *http.ServeMux
	authStore   *auth.Store
	scanner     *input.Scanner
	policy      *policy.Watcher        // nil when no policy file configured
	limiter     *ratelimit.Limiter      // nil when Redis not configured
	quota       *ratelimit.QuotaCounter // nil when Redis not configured
	policyCache *cache.PolicyCache      // nil when Redis not configured
	llm         provider.Adapter        // pluggable LLM backend
}

// New creates a Server and registers all routes.
func New(cfg config.Config, log *logger.Logger) *Server {
	s := &Server{
		cfg:       cfg,
		log:       log,
		mux:       http.NewServeMux(),
		authStore: auth.DefaultStore(),
		scanner:   input.NewScanner(),
	}

	// Initialise the LLM provider adapter.
	llmAdapter, err := provider.New(cfg)
	if err != nil {
		log.Error("provider_init_failed", map[string]any{"error": err.Error()})
		// Fall back to mock so the gateway doesn't crash on startup.
		llmAdapter = provider.NewMockAdapter(cfg.MockLLMAddr)
	}
	s.llm = llmAdapter
	log.Info("provider_selected", map[string]any{"provider": cfg.LLMProvider})

	// Initialise Redis-backed features when RedisAddr is set.
	if cfg.RedisAddr != "" {
		rdb, err := redisclient.New(cfg.RedisAddr, cfg.RedisPassword, 0)
		if err != nil {
			log.Error("redis_connect_failed", map[string]any{
				"addr":  cfg.RedisAddr,
				"error": err.Error(),
			})
			// Non-fatal: gateway starts without rate limiting and caching.
		} else {
			log.Info("redis_connected", map[string]any{"addr": cfg.RedisAddr})
			s.limiter     = ratelimit.NewLimiter(rdb, cfg.RateLimitPerMinute, time.Minute)
			s.quota       = ratelimit.NewQuotaCounter(rdb, cfg.DailyTokenQuota)
			s.policyCache = cache.NewPolicyCache(rdb)
		}
	}

	if cfg.PolicyFile != "" {
		w, err := policy.NewWatcher(cfg.PolicyFile, log, s.policyCache)
		if err != nil {
			log.Error("policy_load_failed", map[string]any{
				"path":  cfg.PolicyFile,
				"error": err.Error(),
			})
		} else {
			s.policy = w
		}
	}

	s.mux.HandleFunc("/v1/complete", s.handleComplete)
	s.mux.HandleFunc("/v1/stream", s.handleStream)
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.Handle("/metrics", promhttp.Handler())
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

		// 2. Authenticate — /healthz and /metrics are exempt.
		var tenantID string
		if r.URL.Path != "/healthz" && r.URL.Path != "/metrics" {
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

			// Rate limit check — per-tenant sliding window.
			if s.limiter != nil {
				allowed, remaining, err := s.limiter.Allow(r.Context(), tenantID)
				if err != nil {
					s.log.Error("rate_limit_error", map[string]any{
						"request_id": reqID,
						"tenant_id":  tenantID,
						"error":      err.Error(),
					})
					// On Redis error: fail open (allow the request through).
				} else if !allowed {
					s.log.Warn("rate_limited", map[string]any{
						"request_id": reqID,
						"tenant_id":  tenantID,
					})
					metrics.RateLimitHitsTotal.WithLabelValues(tenantID, "rate").Inc()
					w.Header().Set("Retry-After", "60")
					s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
						"error":      "rate_limit_exceeded",
						"request_id": reqID,
					})
					return
				} else {
					w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
				}
			}

			// Daily token quota check.
			if s.quota != nil {
				_, underLimit, err := s.quota.Check(r.Context(), tenantID)
				if err != nil {
					s.log.Error("quota_check_error", map[string]any{
						"request_id": reqID,
						"tenant_id":  tenantID,
						"error":      err.Error(),
					})
					// On Redis error: fail open.
				} else if !underLimit {
					s.log.Warn("quota_exceeded", map[string]any{
						"request_id": reqID,
						"tenant_id":  tenantID,
					})
					metrics.RateLimitHitsTotal.WithLabelValues(tenantID, "quota").Inc()
					s.writeJSON(w, http.StatusTooManyRequests, map[string]any{
						"error":      "daily_quota_exceeded",
						"request_id": reqID,
					})
					return
				}
			}
		}

		// 3. Log request start (after auth so tenant_id is known).
		s.log.Info("request_started", map[string]any{
			"request_id": reqID,
			"method":     r.Method,
			"path":       r.URL.Path,
			"remote":     r.RemoteAddr,
			"tenant_id":  tenantID,
		})

		// 4. Delegate to handler, capture status for logging and metrics.
		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		s.log.Info("request_completed", map[string]any{
			"request_id":  reqID,
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.status,
			"duration_ms": duration.Milliseconds(),
			"tenant_id":   tenantID,
		})

		// Record Prometheus metrics for every completed request.
		if r.URL.Path != "/metrics" && r.URL.Path != "/healthz" {
			metrics.RequestsTotal.WithLabelValues(
				tenantID,
				strconv.Itoa(rw.status),
				r.URL.Path,
			).Inc()
			metrics.RequestDuration.WithLabelValues(tenantID, r.URL.Path).Observe(duration.Seconds())
		}
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
		metrics.GuardrailBlocksTotal.WithLabelValues(tenant.ID, "input").Inc()
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "guardrail_block",
			"reason":     "Request blocked by input safety policy",
			"score":      result.Score,
			"request_id": reqID,
		})
		return
	}

	// VerdictTag: allow through but the scan log above already records it.

	// --- Policy engine evaluation ---
	if verdict := s.evalPolicy(r.Context(), tenant.ID, result.Score, "mock-llm-v1"); verdict.Matched && verdict.Action == dsl.ActionBlock {
		s.log.Warn("policy_blocked", map[string]any{
			"request_id": reqID,
			"tenant_id":  tenant.ID,
			"rule":       verdict.RuleName,
			"reason":     verdict.Reason,
		})
		metrics.PolicyEvaluationsTotal.WithLabelValues(tenant.ID, "block").Inc()
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "policy_block",
			"rule":       verdict.RuleName,
			"reason":     verdict.Reason,
			"request_id": reqID,
		})
		return
	}

	// --- Forward to LLM provider ---
	provResult, err := s.llm.Generate(r.Context(), req.Prompt)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			s.log.Error("provider_timeout", map[string]any{"request_id": reqID})
			s.writeError(w, http.StatusGatewayTimeout, "provider_timeout", reqID)
			return
		}
		s.log.Error("provider_error", map[string]any{
			"request_id": reqID,
			"error":      err.Error(),
		})
		s.writeError(w, http.StatusBadGateway, "provider_error", reqID)
		return
	}

	s.log.Info("provider_response_ok", map[string]any{
		"request_id":    reqID,
		"model":         provResult.Model,
		"input_tokens":  provResult.InputTokens,
		"output_tokens": provResult.OutputTokens,
	})

	// --- Return response ---
	s.writeJSON(w, http.StatusOK, CompletionResponse{
		RequestID: reqID,
		Response:  provResult.Text,
	})

	// Track token usage. Use real token counts when available (from provider),
	// otherwise fall back to the 1-token-per-4-chars heuristic.
	if s.quota != nil {
		tokens := int64(provResult.InputTokens + provResult.OutputTokens)
		if tokens < 1 {
			tokens = int64((len(req.Prompt) + len(provResult.Text)) / 4)
		}
		if tokens < 1 {
			tokens = 1
		}
		if _, _, err := s.quota.Add(r.Context(), tenant.ID, tokens); err != nil {
			s.log.Error("quota_add_error", map[string]any{
				"request_id": reqID,
				"error":      err.Error(),
			})
		}
	}
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
		metrics.GuardrailBlocksTotal.WithLabelValues(tenant.ID, "input").Inc()
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "guardrail_block",
			"reason":     "Request blocked by input safety policy",
			"score":      scanResult.Score,
			"request_id": reqID,
		})
		return
	}

	// --- Policy engine evaluation ---
	if verdict := s.evalPolicy(r.Context(), tenant.ID, scanResult.Score, "mock-llm-v1"); verdict.Matched && verdict.Action == dsl.ActionBlock {
		s.log.Warn("policy_blocked", map[string]any{
			"request_id": reqID,
			"tenant_id":  tenant.ID,
			"rule":       verdict.RuleName,
			"reason":     verdict.Reason,
		})
		metrics.PolicyEvaluationsTotal.WithLabelValues(tenant.ID, "block").Inc()
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error":      "policy_block",
			"rule":       verdict.RuleName,
			"reason":     verdict.Reason,
			"request_id": reqID,
		})
		return
	}

	// Set SSE response headers before writing the first byte.
	// We set these BEFORE calling StreamTo so that if the provider fails
	// immediately, we can still return a proper HTTP error code.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Request-ID", reqID)
	w.WriteHeader(http.StatusOK)
	flusher, canFlush := w.(http.Flusher)

	win := streaming.NewWindow(s.cfg.WindowSize)
	start := time.Now()

	// winWriter wraps the sliding window flush+abort logic as an io.Writer.
	// The provider adapter writes SSE bytes to this writer; we scan each chunk
	// through the window before forwarding safe prefixes to the HTTP client.
	winWriter := &windowWriter{
		win:      win,
		dst:      w,
		flusher:  flusher,
		canFlush: canFlush,
		reqID:    reqID,
		tenantID: tenant.ID,
		log:      s.log,
	}

	if err := s.llm.StreamTo(r.Context(), req.Prompt, winWriter); err != nil {
		if !winWriter.aborted {
			if errors.Is(err, context.DeadlineExceeded) {
				s.log.Error("stream_provider_timeout", map[string]any{"request_id": reqID})
			} else {
				s.log.Error("stream_provider_error", map[string]any{"request_id": reqID, "error": err.Error()})
			}
		}
		return
	}

	if winWriter.aborted {
		metrics.StreamAbortsTotal.WithLabelValues(tenant.ID).Inc()
		fmt.Fprintf(w, "data: {\"error\":\"output_policy_violation\",\"request_id\":%q}\n\n", reqID)
		if canFlush {
			flusher.Flush()
		}
		return
	}

	// Drain the remaining window buffer after the stream ends.
	result, _ := win.DrainSafe(w)
	if result == streaming.ScanAbort {
		s.log.Warn("stream_aborted_unsafe_output_drain", map[string]any{"request_id": reqID})
		metrics.StreamAbortsTotal.WithLabelValues(tenant.ID).Inc()
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

// evalPolicy builds the context and evaluates the compiled policy bundle.
func (s *Server) evalPolicy(ctx context.Context, tenantID string, inputRiskScore float64, reqModel string) dsl.Verdict {
	if s.policy == nil {
		return dsl.Verdict{}
	}

	// Read the real daily token count from Redis when available.
	var dailyTokens float64
	if s.quota != nil {
		total, err := s.quota.Total(ctx, tenantID)
		if err == nil {
			dailyTokens = float64(total)
		}
	}

	evalCtx := dsl.EvalContext{
		InputRiskScore:    inputRiskScore,
		RequestModel:      reqModel,
		TenantDailyTokens: dailyTokens,
	}

	b := s.policy.Bundle()
	if b == nil || b.TenantID != tenantID {
		return dsl.Verdict{}
	}

	return b.Evaluate(evalCtx)
}

// windowWriter is an io.Writer that feeds bytes from the LLM provider through
// the sliding window scanner. It is used by handleStream to connect the
// provider.Adapter.StreamTo call to the safety scanning layer.
type windowWriter struct {
	win      *streaming.Window
	dst      io.Writer
	flusher  http.Flusher
	canFlush bool
	reqID    string
	tenantID string
	log      *logger.Logger
	aborted  bool
}

func (ww *windowWriter) Write(p []byte) (int, error) {
	if ww.aborted {
		// Once aborted, stop accepting bytes so the provider call returns.
		return 0, fmt.Errorf("stream aborted: unsafe content detected")
	}
	ww.win.Write(p)
	result, err := ww.win.Flush(ww.dst)
	if err != nil {
		return len(p), err
	}
	if result == streaming.ScanAbort {
		ww.aborted = true
		ww.log.Warn("stream_aborted_unsafe_output", map[string]any{
			"request_id": ww.reqID,
			"tenant_id":  ww.tenantID,
		})
		return 0, fmt.Errorf("stream aborted: unsafe content detected")
	}
	if ww.canFlush {
		ww.flusher.Flush()
	}
	return len(p), nil
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
