package client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/go-redis/redis/v8"
)

// RedisClient wraps Redis client for ML Gateway caching.
type RedisClient struct {
	client *redis.Client
}

// NewRedisClient creates a new Redis client.
func NewRedisClient(redisURL string) (*RedisClient, error) {
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis url: %w", err)
	}

	client := redis.NewClient(opt)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping: %w", err)
	}

	slog.Info("redis connected", "url", redisURL)

	return &RedisClient{client: client}, nil
}

// CacheKey generates a cache key from request data.
func CacheKey(prefix string, data interface{}) string {
	jsonBytes, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonBytes)
	return fmt.Sprintf("%s:%s", prefix, hex.EncodeToString(hash[:8]))
}

// Get retrieves a cached value.
func (r *RedisClient) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := r.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil // Cache miss
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

// GetJSON retrieves and unmarshals a cached JSON value.
func (r *RedisClient) GetJSON(ctx context.Context, key string, dest interface{}) (bool, error) {
	val, err := r.Get(ctx, key)
	if err != nil {
		return false, err
	}
	if val == nil {
		return false, nil // Cache miss
	}

	if err := json.Unmarshal(val, dest); err != nil {
		return false, fmt.Errorf("unmarshal cached value: %w", err)
	}

	return true, nil
}

// Set stores a value in cache with TTL.
func (r *RedisClient) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

// SetJSON marshals and stores a value in cache.
func (r *RedisClient) SetJSON(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	jsonBytes, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshal value: %w", err)
	}
	return r.Set(ctx, key, jsonBytes, ttl)
}

// Delete removes a key from cache.
func (r *RedisClient) Delete(ctx context.Context, keys ...string) error {
	return r.client.Del(ctx, keys...).Err()
}

// DeletePattern removes all keys matching a pattern.
func (r *RedisClient) DeletePattern(ctx context.Context, pattern string) error {
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	for iter.Next(ctx) {
		if err := r.client.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}
	return iter.Err()
}

// Exists checks if a key exists.
func (r *RedisClient) Exists(ctx context.Context, key string) (bool, error) {
	result, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// TTL returns the remaining TTL for a key.
func (r *RedisClient) TTL(ctx context.Context, key string) (time.Duration, error) {
	return r.client.TTL(ctx, key).Result()
}

// Incr increments a counter.
func (r *RedisClient) Incr(ctx context.Context, key string) (int64, error) {
	return r.client.Incr(ctx, key).Result()
}

// IncrBy increments a counter by a specific value.
func (r *RedisClient) IncrBy(ctx context.Context, key string, value int64) (int64, error) {
	return r.client.IncrBy(ctx, key, value).Result()
}

// Close closes the Redis connection.
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Ping checks Redis connectivity.
func (r *RedisClient) Ping(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// Stats returns cache statistics.
type CacheStats struct {
	Hits        int64
	Misses      int64
	KeyCount    int64
	MemoryUsed  int64
	HitRate     float64
	Connections int
}

// GetStats returns cache statistics.
func (r *RedisClient) GetStats(ctx context.Context) (*CacheStats, error) {
	info, err := r.client.Info(ctx, "stats", "memory", "clients").Result()
	if err != nil {
		return nil, err
	}

	// Parse info (simplified)
	stats := &CacheStats{}

	// Count keys
	keyCount, err := r.client.DBSize(ctx).Result()
	if err == nil {
		stats.KeyCount = keyCount
	}

	_ = info // Would parse detailed stats from info string

	return stats, nil
}

// Pipeline returns a Redis pipeline for batch operations.
func (r *RedisClient) Pipeline() redis.Pipeliner {
	return r.client.Pipeline()
}

// BatchGet retrieves multiple keys at once.
func (r *RedisClient) BatchGet(ctx context.Context, keys []string) (map[string][]byte, error) {
	results := make(map[string][]byte)

	if len(keys) == 0 {
		return results, nil
	}

	values, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	for i, key := range keys {
		if values[i] != nil {
			if str, ok := values[i].(string); ok {
				results[key] = []byte(str)
			}
		}
	}

	return results, nil
}

// BatchSet stores multiple key-value pairs at once.
func (r *RedisClient) BatchSet(ctx context.Context, items map[string][]byte, ttl time.Duration) error {
	if len(items) == 0 {
		return nil
	}

	pipe := r.client.Pipeline()
	for key, value := range items {
		pipe.Set(ctx, key, value, ttl)
	}

	_, err := pipe.Exec(ctx)
	return err
}
