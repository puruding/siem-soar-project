// Package consumer provides Kafka consumer for ML-enriched alerts.
package consumer

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// IdempotencyChecker prevents duplicate alert processing using Redis.
type IdempotencyChecker struct {
	redis *redis.Client
	ttl   time.Duration
}

// IdempotencyConfig holds the configuration for the idempotency checker.
type IdempotencyConfig struct {
	RedisAddr     string        `json:"redis_addr"`
	RedisPassword string        `json:"redis_password"`
	RedisDB       int           `json:"redis_db"`
	TTL           time.Duration `json:"ttl"` // default 30 minutes
}

// DefaultIdempotencyConfig returns default configuration.
func DefaultIdempotencyConfig() IdempotencyConfig {
	return IdempotencyConfig{
		RedisAddr:     "localhost:6379",
		RedisPassword: "",
		RedisDB:       0,
		TTL:           30 * time.Minute,
	}
}

// NewIdempotencyChecker creates a new IdempotencyChecker instance.
func NewIdempotencyChecker(cfg IdempotencyConfig) (*IdempotencyChecker, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	ttl := cfg.TTL
	if ttl == 0 {
		ttl = 30 * time.Minute
	}

	return &IdempotencyChecker{
		redis: client,
		ttl:   ttl,
	}, nil
}

// NewIdempotencyCheckerWithClient creates a new IdempotencyChecker with an existing Redis client.
func NewIdempotencyCheckerWithClient(client *redis.Client, ttl time.Duration) *IdempotencyChecker {
	if ttl == 0 {
		ttl = 30 * time.Minute
	}

	return &IdempotencyChecker{
		redis: client,
		ttl:   ttl,
	}
}

// buildKey builds the Redis key for idempotency check.
// Key format: "soar:processed:{alert_id}:{ml_analysis_hash}"
func (c *IdempotencyChecker) buildKey(alertID string, mlHash string) string {
	return fmt.Sprintf("soar:processed:%s:%s", alertID, mlHash)
}

// IsProcessed checks if an alert has already been processed.
func (c *IdempotencyChecker) IsProcessed(ctx context.Context, alertID string, mlHash string) (bool, error) {
	key := c.buildKey(alertID, mlHash)

	exists, err := c.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check idempotency key: %w", err)
	}

	return exists > 0, nil
}

// MarkProcessed marks an alert as processed.
func (c *IdempotencyChecker) MarkProcessed(ctx context.Context, alertID string, mlHash string) error {
	key := c.buildKey(alertID, mlHash)

	// Store processing timestamp
	value := time.Now().UTC().Format(time.RFC3339)

	err := c.redis.Set(ctx, key, value, c.ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set idempotency key: %w", err)
	}

	return nil
}

// MarkProcessedWithInfo marks an alert as processed with additional info.
func (c *IdempotencyChecker) MarkProcessedWithInfo(ctx context.Context, alertID string, mlHash string, info ProcessedInfo) error {
	key := c.buildKey(alertID, mlHash)

	// Store as JSON
	data := fmt.Sprintf(`{"processed_at":"%s","execution_ids":%q,"playbook_ids":%q}`,
		info.ProcessedAt.UTC().Format(time.RFC3339),
		info.ExecutionIDs,
		info.PlaybookIDs,
	)

	err := c.redis.Set(ctx, key, data, c.ttl).Err()
	if err != nil {
		return fmt.Errorf("failed to set idempotency key: %w", err)
	}

	return nil
}

// ProcessedInfo contains information about a processed alert.
type ProcessedInfo struct {
	ProcessedAt  time.Time `json:"processed_at"`
	ExecutionIDs []string  `json:"execution_ids,omitempty"`
	PlaybookIDs  []string  `json:"playbook_ids,omitempty"`
}

// GetProcessedInfo retrieves information about a processed alert.
func (c *IdempotencyChecker) GetProcessedInfo(ctx context.Context, alertID string, mlHash string) (*ProcessedInfo, error) {
	key := c.buildKey(alertID, mlHash)

	val, err := c.redis.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get idempotency key: %w", err)
	}

	// Try to parse as timestamp first (simple format)
	if t, err := time.Parse(time.RFC3339, val); err == nil {
		return &ProcessedInfo{ProcessedAt: t}, nil
	}

	// Otherwise return raw value
	return &ProcessedInfo{ProcessedAt: time.Now()}, nil
}

// Clear removes the idempotency marker for an alert.
// Use this when an alert needs to be reprocessed.
func (c *IdempotencyChecker) Clear(ctx context.Context, alertID string) error {
	// Use pattern matching to clear all ML hash variants
	pattern := fmt.Sprintf("soar:processed:%s:*", alertID)

	var cursor uint64
	var deletedCount int64

	for {
		keys, nextCursor, err := c.redis.Scan(ctx, cursor, pattern, 100).Result()
		if err != nil {
			return fmt.Errorf("failed to scan keys: %w", err)
		}

		if len(keys) > 0 {
			deleted, err := c.redis.Del(ctx, keys...).Result()
			if err != nil {
				return fmt.Errorf("failed to delete keys: %w", err)
			}
			deletedCount += deleted
		}

		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return nil
}

// ClearSpecific removes a specific idempotency marker.
func (c *IdempotencyChecker) ClearSpecific(ctx context.Context, alertID string, mlHash string) error {
	key := c.buildKey(alertID, mlHash)

	_, err := c.redis.Del(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to delete idempotency key: %w", err)
	}

	return nil
}

// Close closes the Redis connection.
func (c *IdempotencyChecker) Close() error {
	if c.redis != nil {
		return c.redis.Close()
	}
	return nil
}

// IdempotencyStats returns statistics about idempotency keys.
type IdempotencyStats struct {
	TotalKeys       int64 `json:"total_keys"`
	ConnectedStatus bool  `json:"connected_status"`
}

// GetStats returns statistics about idempotency keys.
func (c *IdempotencyChecker) GetStats(ctx context.Context) (*IdempotencyStats, error) {
	// Test connection
	if err := c.redis.Ping(ctx).Err(); err != nil {
		return &IdempotencyStats{ConnectedStatus: false}, nil
	}

	// Count keys with pattern
	pattern := "soar:processed:*"
	var count int64
	var cursor uint64

	for {
		keys, nextCursor, err := c.redis.Scan(ctx, cursor, pattern, 1000).Result()
		if err != nil {
			return nil, fmt.Errorf("failed to scan keys: %w", err)
		}

		count += int64(len(keys))
		cursor = nextCursor
		if cursor == 0 {
			break
		}
	}

	return &IdempotencyStats{
		TotalKeys:       count,
		ConnectedStatus: true,
	}, nil
}
