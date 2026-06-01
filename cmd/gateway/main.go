package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/config"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/gateway"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
)

func main() {
	cfg := config.Load()
	log := logger.New(logger.Level(cfg.LogLevel))

	log.Info("gateway_starting", map[string]any{
		"listen_addr":   cfg.ListenAddr,
		"mock_llm_addr": cfg.MockLLMAddr,
		"max_body_bytes": cfg.MaxBodyBytes,
		"log_level":     cfg.LogLevel,
	})

	srv := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      gateway.New(cfg, log).Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine so we can listen for shutdown signals.
	errCh := make(chan error, 1)
	go func() {
		log.Info("gateway_listening", map[string]any{"addr": cfg.ListenAddr})
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
		close(errCh)
	}()

	// Wait for SIGINT / SIGTERM or a fatal server error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		log.Info("gateway_shutdown_initiated", map[string]any{"signal": sig.String()})
	case err := <-errCh:
		log.Error("gateway_fatal_error", map[string]any{"error": err.Error()})
		os.Exit(1)
	}

	// Graceful shutdown: give in-flight requests up to 10 seconds to finish.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("gateway_shutdown_error", map[string]any{"error": err.Error()})
	}
	log.Info("gateway_stopped", nil)
}
