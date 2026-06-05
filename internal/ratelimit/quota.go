// Package ratelimit — token quota counter.
//
// Each tenant has a daily token budget stored as a Redis counter.
// The key is keyed to the current UTC day so the counter resets automatically
// at midnight without any cron job or background cleanup.
//
// Key format: quota:{tenant_id}:{YYYY-MM-DD}
// TTL: 25 hours so the key always expires before the next daily key could conflict.
package ratelimit

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// QuotaCounter tracks per-tenant daily token consumption in Redis.
type QuotaCounter struct {
	rdb   *redis.Client
	limit int64 // max tokens per day
}

// NewQuotaCounter creates a QuotaCounter.
func NewQuotaCounter(rdb *redis.Client, dailyLimit int64) *QuotaCounter {
	return &QuotaCounter{rdb: rdb, limit: dailyLimit}
}

// dailyKey returns the Redis key for today's quota for the given tenant.
// Using UTC date means the counter resets at midnight UTC regardless of server timezone.
func dailyKey(tenantID string) string {
	day := time.Now().UTC().Format("2006-01-02")
	return fmt.Sprintf("quota:%s:%s", tenantID, day)
}

// Check reads the current token count for tenantID today.
// Returns the count and whether it is under the daily limit.
func (q *QuotaCounter) Check(ctx context.Context, tenantID string) (int64, bool, error) {
	key := dailyKey(tenantID)
	val, err := q.rdb.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, true, nil // no usage yet today → under limit
	}
	if err != nil {
		return 0, false, fmt.Errorf("quota check: %w", err)
	}
	return val, val < q.limit, nil
}

// Add increments the token count for tenantID by n tokens.
// Sets a 25-hour TTL on first use so the key auto-expires.
// Returns the new total and whether the tenant is still under limit.
func (q *QuotaCounter) Add(ctx context.Context, tenantID string, n int64) (int64, bool, error) {
	key := dailyKey(tenantID)

	// INCRBY returns the new value atomically.
	newVal, err := q.rdb.IncrBy(ctx, key, n).Result()
	if err != nil {
		return 0, false, fmt.Errorf("quota add: %w", err)
	}

	// Set TTL only when the key is newly created (newVal == n).
	// For existing keys the TTL is already set; avoid overwriting it.
	if newVal == n {
		q.rdb.Expire(ctx, key, 25*time.Hour)
	}

	return newVal, newVal <= q.limit, nil
}

// Total returns the current token count without modifying it.
func (q *QuotaCounter) Total(ctx context.Context, tenantID string) (int64, error) {
	key := dailyKey(tenantID)
	val, err := q.rdb.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return val, err
}
