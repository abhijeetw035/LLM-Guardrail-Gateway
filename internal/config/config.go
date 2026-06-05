// Package config holds gateway configuration loaded from environment variables.
// All fields have sensible defaults so the gateway runs without any env vars set.
package config

import (
	"os"
	"strconv"
)

// Config holds all tunable gateway settings.
type Config struct {
	// ListenAddr is the address the gateway HTTP server binds to.
	ListenAddr string

	// MockLLMAddr is the base URL of the mock LLM server.
	MockLLMAddr string

	// MaxBodyBytes is the hard cap on request body size (default 512 KB).
	// Requests exceeding this are rejected with 413 before any parsing.
	MaxBodyBytes int64

	// LogLevel controls minimum log verbosity ("info", "warn", "error").
	LogLevel string

	// WindowSize is the number of bytes the sliding window buffer holds before
	// forwarding a prefix to the client. Larger = more safety latency.
	// Default 512 bytes (~a few sentences).
	WindowSize int

	// PolicyFile is the path to the .policy file loaded at startup.
	// Leave empty to disable policy evaluation.
	PolicyFile string

	// RedisAddr is the Redis server address ("host:port").
	// Leave empty to disable all Redis-backed features (rate limiting, quota, policy cache).
	RedisAddr string

	// RedisPassword is the optional Redis AUTH password.
	RedisPassword string

	// RateLimitPerMinute is the max requests a single tenant may make per minute.
	RateLimitPerMinute int

	// DailyTokenQuota is the maximum tokens a tenant may consume in one UTC day.
	DailyTokenQuota int64
}

// Load reads config from environment variables, applying defaults where unset.
func Load() Config {
	return Config{
		ListenAddr:         getEnv("GATEWAY_LISTEN_ADDR", ":8080"),
		MockLLMAddr:        getEnv("MOCK_LLM_ADDR", "http://localhost:9090"),
		MaxBodyBytes:       getEnvInt64("GATEWAY_MAX_BODY_BYTES", 512*1024),
		LogLevel:           getEnv("GATEWAY_LOG_LEVEL", "info"),
		WindowSize:         getEnvInt("GATEWAY_WINDOW_SIZE", 512),
		PolicyFile:         getEnv("GATEWAY_POLICY_FILE", "configs/dev.policy"),
		RedisAddr:          getEnv("REDIS_ADDR", ""),
		RedisPassword:      getEnv("REDIS_PASSWORD", ""),
		RateLimitPerMinute: getEnvInt("RATE_LIMIT_PER_MINUTE", 60),
		DailyTokenQuota:    getEnvInt64("DAILY_TOKEN_QUOTA", 100000),
	}
}




func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt64(key string, fallback int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
