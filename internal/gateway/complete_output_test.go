package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/auth"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/guardrails/input"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/provider"
)

type fakeAdapter struct{ text string }

func (f fakeAdapter) Generate(context.Context, string) (provider.GenerateResult, error) {
	return provider.GenerateResult{Text: f.text, Model: "fake"}, nil
}
func (f fakeAdapter) StreamTo(context.Context, string, io.Writer) error { return nil }

func completeWith(t *testing.T, llmText string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{
		cfg:     config.Config{MaxBodyBytes: 1 << 20},
		log:     logger.New(logger.LevelError),
		scanner: input.NewScanner(),
		llm:     fakeAdapter{text: llmText},
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/complete", strings.NewReader(`{"prompt":"say hello"}`))
	req = req.WithContext(auth.WithTenant(req.Context(), auth.Tenant{ID: "t1", Name: "T1"}))
	rec := httptest.NewRecorder()
	s.handleComplete(rec, req)
	return rec
}

func TestHandleComplete_BlocksUnsafeOutput(t *testing.T) {
	rec := completeWith(t, "key AKIAIOSFODNN7EXAMPLE")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "output_policy_violation" {
		t.Errorf("want output_policy_violation, got %q", body["error"])
	}
	if strings.Contains(rec.Body.String(), "AKIA") {
		t.Error("unsafe text leaked in response body")
	}
}

func TestHandleComplete_AllowsCleanOutput(t *testing.T) {
	rec := completeWith(t, "Hello there, nice to meet you.")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Hello there") {
		t.Errorf("clean text missing from response: %s", rec.Body.String())
	}
}
