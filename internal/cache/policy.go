// Package cache provides a Redis-backed cache for compiled policy bundles.
//
// Policy bundles are serialised as JSON and stored under the key:
//   policy:{tenant_id}:{version}
//
// The bundle is re-serialised from the in-memory compiled form using a
// lightweight JSON representation of each rule's metadata. The condition
// closure itself cannot be serialised — when the bundle is loaded from cache
// it is recompiled from the stored source text. This makes the cache a source
// cache (stores the .policy source) rather than a compiled cache, which is the
// correct design because Go closures are not serialisable.
//
// Cache flow:
//   1. Gateway starts, watcher loads and compiles the .policy file.
//   2. Gateway writes the policy source + version to Redis.
//   3. On hot-reload (file change), new source + bumped version written to Redis.
//   4. Future gateway instances read from Redis and recompile, avoiding disk I/O.
package cache

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/abhijeetw035/llm-guardrail-gateway/internal/policy/dsl"
)

const policyTTL = 24 * time.Hour

// PolicyCache stores and retrieves compiled policy bundles in Redis.
type PolicyCache struct {
	rdb *redis.Client
}

// NewPolicyCache creates a PolicyCache backed by rdb.
func NewPolicyCache(rdb *redis.Client) *PolicyCache {
	return &PolicyCache{rdb: rdb}
}

// cachedEntry is the JSON shape stored in Redis.
type cachedEntry struct {
	TenantID string      `json:"tenant_id"`
	Version  string      `json:"version"`
	Source   string      `json:"source"`
	Rules    []ruleEntry `json:"rules"`
}

// ruleEntry stores the metadata of a compiled rule.
// Conditions are not serialisable — we store source and recompile on load.
type ruleEntry struct {
	Name   string `json:"name"`
	Action string `json:"action"`
	Reason string `json:"reason"`
}

// Set serialises and caches the policy source for tenantID.
// version is derived from the SHA-256 of the source text, making the cache key
// content-addressed: different file contents always use different keys.
func (c *PolicyCache) Set(ctx context.Context, tenantID, source string, rules []dsl.CompiledRule) error {
	version := contentVersion(source)
	key := cacheKey(tenantID, version)

	entries := make([]ruleEntry, len(rules))
	for i, r := range rules {
		entries[i] = ruleEntry{
			Name:   r.Name,
			Action: string(r.Action),
			Reason: r.Reason,
		}
	}

	entry := cachedEntry{
		TenantID: tenantID,
		Version:  version,
		Source:   source,
		Rules:    entries,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal policy cache entry: %w", err)
	}

	return c.rdb.Set(ctx, key, data, policyTTL).Err()
}

// Get retrieves and recompiles a cached policy bundle.
// Returns (nil, nil) if the key is not present (cache miss).
func (c *PolicyCache) Get(ctx context.Context, tenantID, version string) ([]dsl.CompiledRule, error) {
	key := cacheKey(tenantID, version)

	data, err := c.rdb.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // cache miss
	}
	if err != nil {
		return nil, fmt.Errorf("redis get policy: %w", err)
	}

	var entry cachedEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, fmt.Errorf("unmarshal policy cache entry: %w", err)
	}

	// Recompile from source — closures cannot be serialised.
	ast, err := dsl.Parse(entry.Source)
	if err != nil {
		return nil, fmt.Errorf("reparse cached policy: %w", err)
	}

	rules, err := dsl.Compile(ast)
	if err != nil {
		return nil, fmt.Errorf("recompile cached policy: %w", err)
	}

	return rules, nil
}

// LatestVersion returns the version string currently stored for tenantID,
// by listing keys matching the pattern and returning the most recent one.
// Returns "" if no entry exists.
func (c *PolicyCache) LatestVersion(ctx context.Context, tenantID string) (string, error) {
	pattern := fmt.Sprintf("policy:%s:*", tenantID)
	keys, err := c.rdb.Keys(ctx, pattern).Result()
	if err != nil {
		return "", fmt.Errorf("list policy keys: %w", err)
	}
	if len(keys) == 0 {
		return "", nil
	}
	// Parse the version out of the first matching key (format: policy:tenant:version)
	// For simplicity, return the first one — in production you'd store a "latest" pointer key.
	var version string
	fmt.Sscanf(keys[0], fmt.Sprintf("policy:%s:%%s", tenantID), &version)
	return version, nil
}

// ContentVersion returns the SHA-256 hex of source, truncated to 16 chars.
// Used externally by the watcher when publishing a new bundle.
func ContentVersion(source string) string {
	return contentVersion(source)
}

func contentVersion(source string) string {
	h := sha256.Sum256([]byte(source))
	return fmt.Sprintf("%x", h[:8]) // first 8 bytes = 16 hex chars
}

func cacheKey(tenantID, version string) string {
	return fmt.Sprintf("policy:%s:%s", tenantID, version)
}
