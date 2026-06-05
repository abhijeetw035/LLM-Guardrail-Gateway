// Package policy manages policy bundles: loading from .policy files, compiling,
// and hot-reloading when the file changes on disk.
//
// Hot-reload race condition handling:
// When fsnotify fires, the new file is compiled on a background goroutine.
// The old compiled bundle stays active for all in-flight requests that already
// hold a pointer to it. Once compilation succeeds, the bundle is atomically
// swapped under a sync.RWMutex. In-flight requests complete with old rules;
// new requests get new rules. No request ever sees a partially-compiled state.
package policy

import (
	"fmt"
	"os"
	"sync"

	"github.com/fsnotify/fsnotify"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/logger"
	"github.com/abhijeetw035/llm-guardrail-gateway/internal/policy/dsl"
)

// Bundle is a compiled, ready-to-evaluate policy for one tenant.
type Bundle struct {
	TenantID string
	Rules    []dsl.CompiledRule
}

// Evaluate runs the bundle's rules against ctx and returns the first match.
func (b *Bundle) Evaluate(ctx dsl.EvalContext) dsl.Verdict {
	return dsl.Evaluate(b.Rules, ctx)
}

// Watcher loads a policy file, compiles it, and recompiles on every file change.
// The active bundle is always available through Bundle() with no lock held by callers.
type Watcher struct {
	path string
	log  *logger.Logger

	mu     sync.RWMutex
	bundle *Bundle // protected by mu

	done chan struct{}
}

// NewWatcher creates a Watcher for the given policy file path and compiles the
// initial bundle. Returns an error if the file cannot be read or compiled.
func NewWatcher(path string, log *logger.Logger) (*Watcher, error) {
	w := &Watcher{
		path: path,
		log:  log,
		done: make(chan struct{}),
	}

	b, err := w.load()
	if err != nil {
		return nil, fmt.Errorf("initial policy load: %w", err)
	}
	w.bundle = b

	go w.watch()
	return w, nil
}

// Bundle returns the current compiled bundle. Safe to call from many goroutines.
// Callers should not store the returned pointer — call Bundle() on each request
// to always get the latest compiled version after a hot reload.
func (w *Watcher) Bundle() *Bundle {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.bundle
}

// Close stops the background watcher goroutine.
func (w *Watcher) Close() {
	close(w.done)
}

// load reads the policy file, lexes, parses, and compiles it.
func (w *Watcher) load() (*Bundle, error) {
	src, err := os.ReadFile(w.path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", w.path, err)
	}

	ast, err := dsl.Parse(string(src))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	rules, err := dsl.Compile(ast)
	if err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}

	return &Bundle{TenantID: ast.TenantID, Rules: rules}, nil
}

// watch runs fsnotify in a background goroutine and recompiles on Write events.
func (w *Watcher) watch() {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		w.log.Error("policy_watcher_init_failed", map[string]any{"error": err.Error()})
		return
	}
	defer fsw.Close()

	if err := fsw.Add(w.path); err != nil {
		w.log.Error("policy_watcher_add_failed", map[string]any{
			"path":  w.path,
			"error": err.Error(),
		})
		return
	}

	w.log.Info("policy_watcher_started", map[string]any{"path": w.path})

	for {
		select {
		case <-w.done:
			return

		case event, ok := <-fsw.Events:
			if !ok {
				return
			}
			// Only recompile on write events (also catches rename/create for editors
			// that save atomically by writing to a temp file then renaming).
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				w.reload()
			}

		case err, ok := <-fsw.Errors:
			if !ok {
				return
			}
			w.log.Error("policy_watcher_error", map[string]any{"error": err.Error()})
		}
	}
}

// reload compiles a new bundle and atomically swaps it in.
// If compilation fails, the old bundle remains active and the error is logged.
func (w *Watcher) reload() {
	b, err := w.load()
	if err != nil {
		// Compilation failure: keep old bundle. Log the error so the operator
		// can fix the syntax without the gateway dropping to no-policy state.
		w.log.Error("policy_reload_failed", map[string]any{
			"path":  w.path,
			"error": err.Error(),
		})
		return
	}

	w.mu.Lock()
	w.bundle = b
	w.mu.Unlock()

	w.log.Info("policy_reloaded", map[string]any{
		"path":      w.path,
		"tenant_id": b.TenantID,
		"rules":     len(b.Rules),
	})
}
