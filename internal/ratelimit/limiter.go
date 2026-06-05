// Package ratelimit implements a Redis-backed sliding window rate limiter.
//
// Algorithm: Redis sorted set per (tenant, window).
// Each member is a unique request timestamp (nanoseconds as a string score).
// On every request:
//  1. Remove entries older than the window duration (ZREMRANGEBYSCORE).
//  2. Count remaining entries (ZCARD).
//  3. If count >= limit → reject 429.
//  4. Otherwise add current timestamp (ZADD) and set TTL.
//
// All four operations are wrapped in a Lua script so they execute atomically
// in a single Redis round-trip. This prevents TOCTOU races where two concurrent
// requests both read count=limit-1 and both proceed.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter performs per-tenant sliding window rate limiting backed by Redis.
type Limiter struct {
	rdb    *redis.Client
	limit  int           // max requests per window
	window time.Duration // window size (e.g. 1 minute)
}

// NewLimiter creates a Limiter.
// limit = max allowed requests in window. window = duration of the window.
func NewLimiter(rdb *redis.Client, limit int, window time.Duration) *Limiter {
	return &Limiter{rdb: rdb, limit: limit, window: window}
}

// Allow checks whether tenantID is within its rate limit.
// Returns (true, remaining) if the request is allowed.
// Returns (false, 0) if the limit is exceeded.
func (l *Limiter) Allow(ctx context.Context, tenantID string) (bool, int, error) {
	key := fmt.Sprintf("ratelimit:%s", tenantID)
	now := time.Now()
	windowStart := now.Add(-l.window).UnixNano()
	nowNano := now.UnixNano()

	// Lua script runs atomically in Redis — prevents concurrent bypass.
	// Returns the count of requests in the window AFTER adding this one.
	script := redis.NewScript(`
local key    = KEYS[1]
local wstart = tonumber(ARGV[1])
local now    = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local ttl    = tonumber(ARGV[4])

-- Remove timestamps older than the window start
redis.call("ZREMRANGEBYSCORE", key, "-inf", wstart)

-- Count current requests in window
local count = redis.call("ZCARD", key)

if count >= limit then
  return -1  -- rate limited
end

-- Add this request (score = timestamp, member = timestamp string for uniqueness)
redis.call("ZADD", key, now, tostring(now))
redis.call("EXPIRE", key, ttl)

return redis.call("ZCARD", key)
`)

	ttlSecs := int(l.window.Seconds()) + 1
	result, err := script.Run(ctx, l.rdb,
		[]string{key},
		windowStart, nowNano, l.limit, ttlSecs,
	).Int()

	if err != nil {
		return false, 0, fmt.Errorf("rate limit script: %w", err)
	}

	if result == -1 {
		return false, 0, nil
	}

	remaining := l.limit - result
	return true, remaining, nil
}
