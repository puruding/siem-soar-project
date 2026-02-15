package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ============================================================================
// Redis Configuration
// ============================================================================

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Addresses        []string      `json:"addresses" yaml:"addresses"`
	Password         string        `json:"password" yaml:"password"`
	DB               int           `json:"db" yaml:"db"`
	MaxRetries       int           `json:"max_retries" yaml:"max_retries"`
	PoolSize         int           `json:"pool_size" yaml:"pool_size"`
	MinIdleConns     int           `json:"min_idle_conns" yaml:"min_idle_conns"`
	DialTimeout      time.Duration `json:"dial_timeout" yaml:"dial_timeout"`
	ReadTimeout      time.Duration `json:"read_timeout" yaml:"read_timeout"`
	WriteTimeout     time.Duration `json:"write_timeout" yaml:"write_timeout"`
	PoolTimeout      time.Duration `json:"pool_timeout" yaml:"pool_timeout"`
	IdleTimeout      time.Duration `json:"idle_timeout" yaml:"idle_timeout"`
	ClusterMode      bool          `json:"cluster_mode" yaml:"cluster_mode"`
	EnableTracing    bool          `json:"enable_tracing" yaml:"enable_tracing"`
	MasterName       string        `json:"master_name" yaml:"master_name"` // For Sentinel mode
	SentinelPassword string        `json:"sentinel_password" yaml:"sentinel_password"`
}

// DefaultRedisConfig returns default Redis configuration.
func DefaultRedisConfig() RedisConfig {
	return RedisConfig{
		Addresses:     []string{"localhost:6379"},
		DB:            0,
		MaxRetries:    3,
		PoolSize:      10,
		MinIdleConns:  2,
		DialTimeout:   5 * time.Second,
		ReadTimeout:   3 * time.Second,
		WriteTimeout:  3 * time.Second,
		PoolTimeout:   4 * time.Second,
		IdleTimeout:   5 * time.Minute,
		ClusterMode:   false,
		EnableTracing: false,
	}
}

// ============================================================================
// Redis Connection
// ============================================================================

// RedisConn represents a Redis connection wrapper.
type RedisConn struct {
	client        redis.UniversalClient
	config        RedisConfig
	pubsubClients map[string]*redis.PubSub
}

// NewRedisConn creates a new Redis connection.
func NewRedisConn(cfg RedisConfig) (*RedisConn, error) {
	var client redis.UniversalClient

	if cfg.ClusterMode {
		// Cluster mode
		client = redis.NewClusterClient(&redis.ClusterOptions{
			Addrs:        cfg.Addresses,
			Password:     cfg.Password,
			MaxRetries:   cfg.MaxRetries,
			PoolSize:     cfg.PoolSize,
			MinIdleConns: cfg.MinIdleConns,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			PoolTimeout:  cfg.PoolTimeout,
		})
	} else if cfg.MasterName != "" {
		// Sentinel mode
		client = redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:       cfg.MasterName,
			SentinelAddrs:    cfg.Addresses,
			SentinelPassword: cfg.SentinelPassword,
			Password:         cfg.Password,
			DB:               cfg.DB,
			MaxRetries:       cfg.MaxRetries,
			PoolSize:         cfg.PoolSize,
			MinIdleConns:     cfg.MinIdleConns,
			DialTimeout:      cfg.DialTimeout,
			ReadTimeout:      cfg.ReadTimeout,
			WriteTimeout:     cfg.WriteTimeout,
			PoolTimeout:      cfg.PoolTimeout,
		})
	} else {
		// Standalone mode
		client = redis.NewClient(&redis.Options{
			Addr:         cfg.Addresses[0],
			Password:     cfg.Password,
			DB:           cfg.DB,
			MaxRetries:   cfg.MaxRetries,
			PoolSize:     cfg.PoolSize,
			MinIdleConns: cfg.MinIdleConns,
			DialTimeout:  cfg.DialTimeout,
			ReadTimeout:  cfg.ReadTimeout,
			WriteTimeout: cfg.WriteTimeout,
			PoolTimeout:  cfg.PoolTimeout,
		})
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), cfg.DialTimeout)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to ping redis: %w", err)
	}

	return &RedisConn{
		client:        client,
		config:        cfg,
		pubsubClients: make(map[string]*redis.PubSub),
	}, nil
}

// Close closes the Redis connection.
func (c *RedisConn) Close() error {
	// Close all pubsub clients
	for _, ps := range c.pubsubClients {
		ps.Close()
	}
	return c.client.Close()
}

// Ping tests the connection.
func (c *RedisConn) Ping(ctx context.Context) error {
	return c.client.Ping(ctx).Err()
}

// IsHealthy returns true if the connection is healthy.
func (c *RedisConn) IsHealthy(ctx context.Context) bool {
	return c.Ping(ctx) == nil
}

// Client returns the underlying Redis client.
func (c *RedisConn) Client() redis.UniversalClient {
	return c.client
}

// ============================================================================
// Cache Operations
// ============================================================================

// RedisCache implements caching operations.
type RedisCache struct {
	conn   *RedisConn
	prefix string
}

// NewRedisCache creates a new Redis cache instance.
func NewRedisCache(conn *RedisConn, prefix string) *RedisCache {
	return &RedisCache{
		conn:   conn,
		prefix: prefix,
	}
}

// key prefixes the key with namespace.
func (c *RedisCache) key(key string) string {
	if c.prefix == "" {
		return key
	}
	return c.prefix + ":" + key
}

// Set sets a cache value with optional TTL.
func (c *RedisCache) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("failed to marshal value: %w", err)
	}

	return c.conn.client.Set(ctx, c.key(key), data, ttl).Err()
}

// Get retrieves a cache value.
func (c *RedisCache) Get(ctx context.Context, key string, dest interface{}) error {
	data, err := c.conn.client.Get(ctx, c.key(key)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("key not found: %s", key)
		}
		return fmt.Errorf("failed to get value: %w", err)
	}

	if err := json.Unmarshal(data, dest); err != nil {
		return fmt.Errorf("failed to unmarshal value: %w", err)
	}

	return nil
}

// GetString retrieves a string value.
func (c *RedisCache) GetString(ctx context.Context, key string) (string, error) {
	val, err := c.conn.client.Get(ctx, c.key(key)).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("key not found: %s", key)
	}
	return val, err
}

// SetString sets a string value.
func (c *RedisCache) SetString(ctx context.Context, key, value string, ttl time.Duration) error {
	return c.conn.client.Set(ctx, c.key(key), value, ttl).Err()
}

// Delete deletes a cache key.
func (c *RedisCache) Delete(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	prefixedKeys := make([]string, len(keys))
	for i, k := range keys {
		prefixedKeys[i] = c.key(k)
	}

	return c.conn.client.Del(ctx, prefixedKeys...).Err()
}

// Exists checks if a key exists.
func (c *RedisCache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := c.conn.client.Exists(ctx, c.key(key)).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Expire sets TTL on a key.
func (c *RedisCache) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return c.conn.client.Expire(ctx, c.key(key), ttl).Err()
}

// TTL returns the remaining TTL for a key.
func (c *RedisCache) TTL(ctx context.Context, key string) (time.Duration, error) {
	return c.conn.client.TTL(ctx, c.key(key)).Result()
}

// Increment atomically increments a counter.
func (c *RedisCache) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	return c.conn.client.IncrBy(ctx, c.key(key), delta).Result()
}

// Decrement atomically decrements a counter.
func (c *RedisCache) Decrement(ctx context.Context, key string, delta int64) (int64, error) {
	return c.conn.client.DecrBy(ctx, c.key(key), delta).Result()
}

// MGet retrieves multiple values at once.
func (c *RedisCache) MGet(ctx context.Context, keys ...string) ([]interface{}, error) {
	prefixedKeys := make([]string, len(keys))
	for i, k := range keys {
		prefixedKeys[i] = c.key(k)
	}

	return c.conn.client.MGet(ctx, prefixedKeys...).Result()
}

// MSet sets multiple values at once.
func (c *RedisCache) MSet(ctx context.Context, pairs map[string]interface{}) error {
	if len(pairs) == 0 {
		return nil
	}

	values := make([]interface{}, 0, len(pairs)*2)
	for k, v := range pairs {
		data, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal value for key %s: %w", k, err)
		}
		values = append(values, c.key(k), data)
	}

	return c.conn.client.MSet(ctx, values...).Err()
}

// FlushAll deletes all keys with the prefix.
func (c *RedisCache) FlushAll(ctx context.Context) error {
	pattern := c.key("*")
	iter := c.conn.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		if err := c.conn.client.Del(ctx, iter.Val()).Err(); err != nil {
			return err
		}
	}

	return iter.Err()
}

// ============================================================================
// Session Store
// ============================================================================

// Session represents a user session.
type Session struct {
	SessionID  string                 `json:"session_id"`
	UserID     string                 `json:"user_id"`
	TenantID   string                 `json:"tenant_id"`
	Username   string                 `json:"username"`
	Role       string                 `json:"role"`
	IPAddress  string                 `json:"ip_address"`
	UserAgent  string                 `json:"user_agent"`
	CreatedAt  time.Time              `json:"created_at"`
	ExpiresAt  time.Time              `json:"expires_at"`
	LastAccess time.Time              `json:"last_access"`
	Data       map[string]interface{} `json:"data,omitempty"`
}

// RedisSessionStore implements session storage.
type RedisSessionStore struct {
	cache      *RedisCache
	defaultTTL time.Duration
}

// NewRedisSessionStore creates a new session store.
func NewRedisSessionStore(conn *RedisConn, defaultTTL time.Duration) *RedisSessionStore {
	return &RedisSessionStore{
		cache:      NewRedisCache(conn, "session"),
		defaultTTL: defaultTTL,
	}
}

// Create creates a new session.
func (s *RedisSessionStore) Create(ctx context.Context, session *Session) error {
	session.CreatedAt = time.Now()
	session.ExpiresAt = session.CreatedAt.Add(s.defaultTTL)
	session.LastAccess = session.CreatedAt

	return s.cache.Set(ctx, session.SessionID, session, s.defaultTTL)
}

// Get retrieves a session by ID.
func (s *RedisSessionStore) Get(ctx context.Context, sessionID string) (*Session, error) {
	var session Session
	if err := s.cache.Get(ctx, sessionID, &session); err != nil {
		return nil, err
	}

	// Update last access time
	session.LastAccess = time.Now()
	if err := s.cache.Set(ctx, sessionID, &session, s.defaultTTL); err != nil {
		return &session, err // Return session but log error
	}

	return &session, nil
}

// Update updates an existing session.
func (s *RedisSessionStore) Update(ctx context.Context, session *Session) error {
	session.LastAccess = time.Now()
	return s.cache.Set(ctx, session.SessionID, session, s.defaultTTL)
}

// Delete deletes a session.
func (s *RedisSessionStore) Delete(ctx context.Context, sessionID string) error {
	return s.cache.Delete(ctx, sessionID)
}

// DeleteByUser deletes all sessions for a user.
func (s *RedisSessionStore) DeleteByUser(ctx context.Context, userID string) error {
	pattern := s.cache.key("*")
	iter := s.cache.conn.client.Scan(ctx, 0, pattern, 0).Iterator()

	for iter.Next(ctx) {
		var session Session
		if err := s.cache.Get(ctx, iter.Val(), &session); err != nil {
			continue
		}
		if session.UserID == userID {
			s.cache.Delete(ctx, iter.Val())
		}
	}

	return iter.Err()
}

// Exists checks if a session exists.
func (s *RedisSessionStore) Exists(ctx context.Context, sessionID string) (bool, error) {
	return s.cache.Exists(ctx, sessionID)
}

// Refresh extends the session TTL.
func (s *RedisSessionStore) Refresh(ctx context.Context, sessionID string) error {
	return s.cache.Expire(ctx, sessionID, s.defaultTTL)
}

// ListByUser retrieves all sessions for a user.
func (s *RedisSessionStore) ListByUser(ctx context.Context, userID string) ([]*Session, error) {
	pattern := s.cache.key("*")
	iter := s.cache.conn.client.Scan(ctx, 0, pattern, 0).Iterator()

	var sessions []*Session
	for iter.Next(ctx) {
		var session Session
		if err := s.cache.Get(ctx, iter.Val(), &session); err != nil {
			continue
		}
		if session.UserID == userID {
			sessions = append(sessions, &session)
		}
	}

	return sessions, iter.Err()
}

// ============================================================================
// Distributed Lock
// ============================================================================

// RedisLock implements distributed locking using Redis.
type RedisLock struct {
	conn       *RedisConn
	prefix     string
	defaultTTL time.Duration
}

// NewRedisLock creates a new distributed lock manager.
func NewRedisLock(conn *RedisConn) *RedisLock {
	return &RedisLock{
		conn:       conn,
		prefix:     "lock",
		defaultTTL: 30 * time.Second,
	}
}

// key generates the lock key.
func (l *RedisLock) key(name string) string {
	return l.prefix + ":" + name
}

// Acquire attempts to acquire a lock.
func (l *RedisLock) Acquire(ctx context.Context, name string, ttl time.Duration) (bool, error) {
	if ttl == 0 {
		ttl = l.defaultTTL
	}

	ok, err := l.conn.client.SetNX(ctx, l.key(name), time.Now().Unix(), ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}

	return ok, nil
}

// Release releases a lock.
func (l *RedisLock) Release(ctx context.Context, name string) error {
	return l.conn.client.Del(ctx, l.key(name)).Err()
}

// Refresh extends the lock TTL.
func (l *RedisLock) Refresh(ctx context.Context, name string, ttl time.Duration) error {
	if ttl == 0 {
		ttl = l.defaultTTL
	}
	return l.conn.client.Expire(ctx, l.key(name), ttl).Err()
}

// IsLocked checks if a lock is currently held.
func (l *RedisLock) IsLocked(ctx context.Context, name string) (bool, error) {
	count, err := l.conn.client.Exists(ctx, l.key(name)).Result()
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// WithLock executes a function while holding a lock.
func (l *RedisLock) WithLock(ctx context.Context, name string, ttl time.Duration, fn func() error) error {
	acquired, err := l.Acquire(ctx, name, ttl)
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("failed to acquire lock: %s", name)
	}

	defer l.Release(ctx, name)

	return fn()
}

// ============================================================================
// Pub/Sub
// ============================================================================

// RedisPubSub implements publish/subscribe operations.
type RedisPubSub struct {
	conn *RedisConn
}

// NewRedisPubSub creates a new pub/sub manager.
func NewRedisPubSub(conn *RedisConn) *RedisPubSub {
	return &RedisPubSub{conn: conn}
}

// Publish publishes a message to a channel.
func (p *RedisPubSub) Publish(ctx context.Context, channel string, message interface{}) error {
	data, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	return p.conn.client.Publish(ctx, channel, data).Err()
}

// PublishString publishes a string message.
func (p *RedisPubSub) PublishString(ctx context.Context, channel, message string) error {
	return p.conn.client.Publish(ctx, channel, message).Err()
}

// Subscribe subscribes to channels.
func (p *RedisPubSub) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	return p.conn.client.Subscribe(ctx, channels...)
}

// PSubscribe subscribes to channels matching patterns.
func (p *RedisPubSub) PSubscribe(ctx context.Context, patterns ...string) *redis.PubSub {
	return p.conn.client.PSubscribe(ctx, patterns...)
}

// ============================================================================
// Rate Limiter
// ============================================================================

// RedisRateLimiter implements rate limiting using sliding window.
type RedisRateLimiter struct {
	conn   *RedisConn
	prefix string
}

// NewRedisRateLimiter creates a new rate limiter.
func NewRedisRateLimiter(conn *RedisConn) *RedisRateLimiter {
	return &RedisRateLimiter{
		conn:   conn,
		prefix: "ratelimit",
	}
}

// key generates the rate limit key.
func (r *RedisRateLimiter) key(identifier string) string {
	return r.prefix + ":" + identifier
}

// Allow checks if an action is allowed under the rate limit.
func (r *RedisRateLimiter) Allow(ctx context.Context, identifier string, limit int64, window time.Duration) (bool, error) {
	key := r.key(identifier)
	now := time.Now().UnixNano()
	windowStart := now - window.Nanoseconds()

	pipe := r.conn.client.Pipeline()

	// Remove old entries
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))

	// Count current entries
	countCmd := pipe.ZCard(ctx, key)

	// Add new entry
	pipe.ZAdd(ctx, key, redis.Z{Score: float64(now), Member: now})

	// Set expiration
	pipe.Expire(ctx, key, window)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return false, err
	}

	count := countCmd.Val()
	return count < limit, nil
}

// Count returns the current count for an identifier.
func (r *RedisRateLimiter) Count(ctx context.Context, identifier string, window time.Duration) (int64, error) {
	key := r.key(identifier)
	now := time.Now().UnixNano()
	windowStart := now - window.Nanoseconds()

	// Remove old entries and count
	pipe := r.conn.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
	countCmd := pipe.ZCard(ctx, key)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	return countCmd.Val(), nil
}

// Reset resets the rate limit for an identifier.
func (r *RedisRateLimiter) Reset(ctx context.Context, identifier string) error {
	return r.conn.client.Del(ctx, r.key(identifier)).Err()
}

// ============================================================================
// Helper Functions
// ============================================================================

// SetWithRetry attempts to set a value with retries.
func SetWithRetry(ctx context.Context, cache *RedisCache, key string, value interface{}, ttl time.Duration, maxRetries int) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = cache.Set(ctx, key, value, ttl)
		if err == nil {
			return nil
		}
		time.Sleep(time.Millisecond * time.Duration(100*(i+1)))
	}
	return fmt.Errorf("failed after %d retries: %w", maxRetries, err)
}

// GetWithFallback gets a value or returns a fallback if not found.
func GetWithFallback(ctx context.Context, cache *RedisCache, key string, dest interface{}, fallback func() (interface{}, error)) error {
	err := cache.Get(ctx, key, dest)
	if err == nil {
		return nil
	}

	// Cache miss - use fallback
	value, err := fallback()
	if err != nil {
		return err
	}

	// Store in cache for next time
	cache.Set(ctx, key, value, 5*time.Minute)

	// Copy to destination
	data, _ := json.Marshal(value)
	return json.Unmarshal(data, dest)
}
