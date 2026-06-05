// Package auth validates API keys and resolves tenant identities.
//
// In production this would be backed by Redis or a DB, but the interface
// stays the same — the gateway only calls Authenticate() and never touches
// the store directly.
//
// Tenant isolation: every downstream pipeline stage receives the tenant_id
// from the request context. No request can proceed past this layer without
// a resolved tenant.
package auth

import (
	"context"
	"errors"
	"strings"
)

// ErrUnauthorized is returned when the API key is missing or invalid.
var ErrUnauthorized = errors.New("unauthorized")

// Tenant holds the resolved identity attached to an API key.
type Tenant struct {
	ID   string // e.g. "acme-corp"
	Name string // human-readable label
}

// Store holds the known API key → Tenant mappings.
// Keys are stored as-is (no hashing) for simplicity.
type Store struct {
	keys map[string]Tenant
}

// NewStore returns a Store pre-loaded with the given key map.
func NewStore(keys map[string]Tenant) *Store {
	return &Store{keys: keys}
}

// DefaultStore returns a hard-coded store suitable for local development.
func DefaultStore() *Store {
	return NewStore(map[string]Tenant{
		"key-acme-1234":  {ID: "acme-corp", Name: "Acme Corp"},
		"key-beta-5678":  {ID: "beta-inc", Name: "Beta Inc"},
		"key-dev-local":  {ID: "dev", Name: "Local Dev"},
	})
}

// Authenticate extracts and validates the API key from the Authorization header.
// Expected format: "Bearer <api-key>"
// Returns the resolved Tenant on success, ErrUnauthorized on failure.
func (s *Store) Authenticate(authHeader string) (Tenant, error) {
	if authHeader == "" {
		return Tenant{}, ErrUnauthorized
	}

	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return Tenant{}, ErrUnauthorized
	}

	key := strings.TrimSpace(authHeader[len(prefix):])
	if key == "" {
		return Tenant{}, ErrUnauthorized
	}

	tenant, ok := s.keys[key]
	if !ok {
		return Tenant{}, ErrUnauthorized
	}
	return tenant, nil
}

// --- Context helpers ---

type ctxKeyTenant struct{}

// WithTenant stores the resolved tenant in the context.
func WithTenant(ctx context.Context, t Tenant) context.Context {
	return context.WithValue(ctx, ctxKeyTenant{}, t)
}

// TenantFromCtx retrieves the tenant stored by WithTenant.
// Returns the zero value and false if not present.
func TenantFromCtx(ctx context.Context) (Tenant, bool) {
	t, ok := ctx.Value(ctxKeyTenant{}).(Tenant)
	return t, ok
}
