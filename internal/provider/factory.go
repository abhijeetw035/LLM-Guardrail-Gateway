package provider

import (
	"fmt"
	"strings"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
)

// providerDefaults holds the default base URL and model for each supported provider.
var providerDefaults = map[string]struct{ baseURL, model string }{
	"groq":   {"https://api.groq.com/openai/v1", "llama-3.3-70b-versatile"},
	"gemini": {"https://generativelanguage.googleapis.com/v1beta/openai/", "gemini-2.0-flash"},
	"openai": {"https://api.openai.com/v1", "gpt-4o-mini"},
}

// New reads LLMProvider (and related fields) from cfg and returns the
// appropriate Adapter. The default is MockAdapter so that local development
// and all existing tests work without any env vars set.
//
// Supported LLM_PROVIDER values:
//
//	"mock"   (default) – local mock LLM server
//	"groq"             – Groq cloud API (free tier available)
//	"gemini"           – Google Gemini via OpenAI-compatible endpoint
//	"openai"           – OpenAI API
//	"custom"           – any OpenAI-compatible API; requires LLM_BASE_URL
func New(cfg config.Config) (Adapter, error) {
	p := strings.ToLower(strings.TrimSpace(cfg.LLMProvider))
	if p == "" || p == "mock" {
		return NewMockAdapter(cfg.MockLLMAddr), nil
	}

	if p == "custom" {
		if cfg.LLMBaseURL == "" {
			return nil, fmt.Errorf("provider: LLM_BASE_URL is required when LLM_PROVIDER=custom")
		}
		if cfg.LLMAPIKey == "" {
			return nil, fmt.Errorf("provider: LLM_API_KEY is required when LLM_PROVIDER=custom")
		}
		model := cfg.LLMModel
		if model == "" {
			model = "default"
		}
		return NewOpenAICompatAdapter(cfg.LLMBaseURL, cfg.LLMAPIKey, model), nil
	}

	defaults, ok := providerDefaults[p]
	if !ok {
		return nil, fmt.Errorf("provider: unknown LLM_PROVIDER %q (valid: mock, groq, gemini, openai, custom)", p)
	}

	if cfg.LLMAPIKey == "" {
		return nil, fmt.Errorf("provider: LLM_API_KEY is required for provider %q", p)
	}

	baseURL := cfg.LLMBaseURL
	if baseURL == "" {
		baseURL = defaults.baseURL
	}
	model := cfg.LLMModel
	if model == "" {
		model = defaults.model
	}

	return NewOpenAICompatAdapter(baseURL, cfg.LLMAPIKey, model), nil
}
