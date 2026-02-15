// Package ratelimit provides rate limiting for the API gateway.
package ratelimit

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// RateLimitConfig holds rate limiter configuration.
type RateLimitConfig struct {
	// Global limits
	GlobalRPS     int `json:"global_rps"`
	GlobalBurst   int `json:"global_burst"`

	// Per-tenant limits
	TenantRPS     int `json:"tenant_rps"`
	TenantBurst   int `json:"tenant_burst"`

	// Per-IP limits
	IPRPS         int `json:"ip_rps"`
	IPBurst       int `json:"ip_burst"`

	// Per-API-key limits
	APIKeyRPS     int `json:"api_key_rps"`
	APIKeyBurst   int `json:"api_key_burst"`

	// Window settings
	WindowSize    time.Duration `json:"window_size"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// DefaultRateLimitConfig returns default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GlobalRPS:      10000,
		GlobalBurst:    20000,
		TenantRPS:      1000,
		TenantBurst:    2000,
		IPRPS:          100,
		IPBurst:        200,
		APIKeyRPS:      500,
		APIKeyBurst:    1000,
		WindowSize:     time.Second,
		CleanupInterval: 5 * time.Minute,
	}
}

// RateLimitResult represents the result of a rate limit check.
type RateLimitResult struct {
	Allowed      bool          `json:"allowed"`
	Remaining    int           `json:"remaining"`
	Limit        int           `json:"limit"`
	ResetAt      time.Time     `json:"reset_at"`
	RetryAfter   time.Duration `json:"retry_after,omitempty"`
	LimitedBy    string        `json:"limited_by,omitempty"` // global, tenant, ip, api_key
}

// Limiter interface for different rate limiting algorithms.
type Limiter interface {
	Allow(key string) *RateLimitResult
	AllowN(key string, n int) *RateLimitResult
}

// TokenBucket implements a token bucket rate limiter.
type TokenBucket struct {
	rate       float64 // tokens per second
	burst      int     // maximum tokens
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket.
func NewTokenBucket(rate float64, burst int) *TokenBucket {
	return &TokenBucket{
		rate:       rate,
		burst:      burst,
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

// Allow checks if a request is allowed.
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// AllowN checks if n requests are allowed.
func (tb *TokenBucket) AllowN(n int) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Add tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tb.tokens += elapsed * tb.rate
	if tb.tokens > float64(tb.burst) {
		tb.tokens = float64(tb.burst)
	}
	tb.lastUpdate = now

	// Check if we have enough tokens
	if tb.tokens >= float64(n) {
		tb.tokens -= float64(n)
		return true
	}

	return false
}

// Tokens returns the current number of tokens.
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Add tokens based on elapsed time
	now := time.Now()
	elapsed := now.Sub(tb.lastUpdate).Seconds()
	tokens := tb.tokens + elapsed*tb.rate
	if tokens > float64(tb.burst) {
		tokens = float64(tb.burst)
	}

	return tokens
}

// SlidingWindow implements a sliding window rate limiter.
type SlidingWindow struct {
	windowSize time.Duration
	limit      int
	windows    sync.Map // map[int64]int (timestamp bucket -> count)
}

// NewSlidingWindow creates a new sliding window limiter.
func NewSlidingWindow(windowSize time.Duration, limit int) *SlidingWindow {
	return &SlidingWindow{
		windowSize: windowSize,
		limit:      limit,
	}
}

// Allow checks if a request is allowed.
func (sw *SlidingWindow) Allow() *RateLimitResult {
	return sw.AllowN(1)
}

// AllowN checks if n requests are allowed.
func (sw *SlidingWindow) AllowN(n int) *RateLimitResult {
	now := time.Now()
	currentBucket := now.UnixNano() / int64(sw.windowSize)
	previousBucket := currentBucket - 1

	// Get counts from current and previous buckets
	currentCount := sw.getCount(currentBucket)
	previousCount := sw.getCount(previousBucket)

	// Calculate weighted count
	elapsedRatio := float64(now.UnixNano()%int64(sw.windowSize)) / float64(sw.windowSize)
	weightedCount := int(float64(previousCount)*(1-elapsedRatio)) + currentCount

	// Check if allowed
	allowed := weightedCount+n <= sw.limit

	if allowed {
		sw.increment(currentBucket, n)
	}

	remaining := sw.limit - weightedCount - n
	if remaining < 0 {
		remaining = 0
	}

	return &RateLimitResult{
		Allowed:   allowed,
		Remaining: remaining,
		Limit:     sw.limit,
		ResetAt:   time.Unix(0, (currentBucket+1)*int64(sw.windowSize)),
	}
}

func (sw *SlidingWindow) getCount(bucket int64) int {
	if val, ok := sw.windows.Load(bucket); ok {
		return val.(int)
	}
	return 0
}

func (sw *SlidingWindow) increment(bucket int64, n int) {
	for {
		val, loaded := sw.windows.LoadOrStore(bucket, n)
		if !loaded {
			return
		}
		current := val.(int)
		if sw.windows.CompareAndSwap(bucket, current, current+n) {
			return
		}
	}
}

// RateLimiter provides multi-level rate limiting.
type RateLimiter struct {
	config      RateLimitConfig
	global      *TokenBucket
	tenants     sync.Map // map[string]*TokenBucket
	ips         sync.Map // map[string]*TokenBucket
	apiKeys     sync.Map // map[string]*TokenBucket
	logger      *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Metrics
	totalRequests atomic.Uint64
	totalAllowed  atomic.Uint64
	totalDenied   atomic.Uint64
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(cfg RateLimitConfig, logger *slog.Logger) *RateLimiter {
	ctx, cancel := context.WithCancel(context.Background())

	rl := &RateLimiter{
		config:  cfg,
		global:  NewTokenBucket(float64(cfg.GlobalRPS), cfg.GlobalBurst),
		logger:  logger.With("component", "rate-limiter"),
		ctx:     ctx,
		cancel:  cancel,
	}

	// Start cleanup goroutine
	rl.wg.Add(1)
	go rl.cleanupLoop()

	return rl
}

// Check checks rate limits for a request.
func (rl *RateLimiter) Check(tenantID, ip, apiKey string) *RateLimitResult {
	rl.totalRequests.Add(1)

	// Check global limit
	if !rl.global.Allow() {
		rl.totalDenied.Add(1)
		return &RateLimitResult{
			Allowed:   false,
			Limit:     rl.config.GlobalRPS,
			LimitedBy: "global",
		}
	}

	// Check tenant limit
	if tenantID != "" {
		tenantBucket := rl.getTenantBucket(tenantID)
		if !tenantBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     rl.config.TenantRPS,
				LimitedBy: "tenant",
			}
		}
	}

	// Check IP limit
	if ip != "" {
		ipBucket := rl.getIPBucket(ip)
		if !ipBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     rl.config.IPRPS,
				LimitedBy: "ip",
			}
		}
	}

	// Check API key limit
	if apiKey != "" {
		apiKeyBucket := rl.getAPIKeyBucket(apiKey)
		if !apiKeyBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     rl.config.APIKeyRPS,
				LimitedBy: "api_key",
			}
		}
	}

	rl.totalAllowed.Add(1)

	return &RateLimitResult{
		Allowed:   true,
		Limit:     rl.config.GlobalRPS,
	}
}

// CheckWithCustomLimit checks rate limits with a custom limit for API key.
func (rl *RateLimiter) CheckWithCustomLimit(tenantID, ip, apiKey string, customRPS int) *RateLimitResult {
	if customRPS <= 0 {
		return rl.Check(tenantID, ip, apiKey)
	}

	rl.totalRequests.Add(1)

	// Check global limit
	if !rl.global.Allow() {
		rl.totalDenied.Add(1)
		return &RateLimitResult{
			Allowed:   false,
			Limit:     rl.config.GlobalRPS,
			LimitedBy: "global",
		}
	}

	// Check tenant limit
	if tenantID != "" {
		tenantBucket := rl.getTenantBucket(tenantID)
		if !tenantBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     rl.config.TenantRPS,
				LimitedBy: "tenant",
			}
		}
	}

	// Check IP limit
	if ip != "" {
		ipBucket := rl.getIPBucket(ip)
		if !ipBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     rl.config.IPRPS,
				LimitedBy: "ip",
			}
		}
	}

	// Check API key with custom limit
	if apiKey != "" {
		apiKeyBucket := rl.getOrCreateAPIKeyBucket(apiKey, customRPS)
		if !apiKeyBucket.Allow() {
			rl.totalDenied.Add(1)
			return &RateLimitResult{
				Allowed:   false,
				Remaining: 0,
				Limit:     customRPS,
				LimitedBy: "api_key",
			}
		}
	}

	rl.totalAllowed.Add(1)

	return &RateLimitResult{
		Allowed: true,
		Limit:   customRPS,
	}
}

func (rl *RateLimiter) getTenantBucket(tenantID string) *TokenBucket {
	if bucket, ok := rl.tenants.Load(tenantID); ok {
		return bucket.(*TokenBucket)
	}

	bucket := NewTokenBucket(float64(rl.config.TenantRPS), rl.config.TenantBurst)
	actual, _ := rl.tenants.LoadOrStore(tenantID, bucket)
	return actual.(*TokenBucket)
}

func (rl *RateLimiter) getIPBucket(ip string) *TokenBucket {
	if bucket, ok := rl.ips.Load(ip); ok {
		return bucket.(*TokenBucket)
	}

	bucket := NewTokenBucket(float64(rl.config.IPRPS), rl.config.IPBurst)
	actual, _ := rl.ips.LoadOrStore(ip, bucket)
	return actual.(*TokenBucket)
}

func (rl *RateLimiter) getAPIKeyBucket(apiKey string) *TokenBucket {
	if bucket, ok := rl.apiKeys.Load(apiKey); ok {
		return bucket.(*TokenBucket)
	}

	bucket := NewTokenBucket(float64(rl.config.APIKeyRPS), rl.config.APIKeyBurst)
	actual, _ := rl.apiKeys.LoadOrStore(apiKey, bucket)
	return actual.(*TokenBucket)
}

func (rl *RateLimiter) getOrCreateAPIKeyBucket(apiKey string, rps int) *TokenBucket {
	if bucket, ok := rl.apiKeys.Load(apiKey); ok {
		return bucket.(*TokenBucket)
	}

	bucket := NewTokenBucket(float64(rps), rps*2)
	actual, _ := rl.apiKeys.LoadOrStore(apiKey, bucket)
	return actual.(*TokenBucket)
}

func (rl *RateLimiter) cleanupLoop() {
	defer rl.wg.Done()

	ticker := time.NewTicker(rl.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.ctx.Done():
			return
		case <-ticker.C:
			rl.cleanup()
		}
	}
}

func (rl *RateLimiter) cleanup() {
	// Clean up IP buckets (keep only recently active)
	var ipCount int
	rl.ips.Range(func(key, value interface{}) bool {
		bucket := value.(*TokenBucket)
		// If bucket is full (no recent activity), remove it
		if bucket.Tokens() >= float64(rl.config.IPBurst) {
			rl.ips.Delete(key)
		} else {
			ipCount++
		}
		return true
	})

	// Clean up API key buckets
	var apiKeyCount int
	rl.apiKeys.Range(func(key, value interface{}) bool {
		bucket := value.(*TokenBucket)
		if bucket.Tokens() >= float64(rl.config.APIKeyBurst) {
			rl.apiKeys.Delete(key)
		} else {
			apiKeyCount++
		}
		return true
	})

	rl.logger.Debug("rate limiter cleanup", "ip_buckets", ipCount, "api_key_buckets", apiKeyCount)
}

// Stop stops the rate limiter.
func (rl *RateLimiter) Stop() {
	rl.cancel()
	rl.wg.Wait()
}

// Stats returns rate limiter statistics.
func (rl *RateLimiter) Stats() map[string]interface{} {
	var tenantCount, ipCount, apiKeyCount int

	rl.tenants.Range(func(k, v interface{}) bool {
		tenantCount++
		return true
	})

	rl.ips.Range(func(k, v interface{}) bool {
		ipCount++
		return true
	})

	rl.apiKeys.Range(func(k, v interface{}) bool {
		apiKeyCount++
		return true
	})

	return map[string]interface{}{
		"total_requests":  rl.totalRequests.Load(),
		"total_allowed":   rl.totalAllowed.Load(),
		"total_denied":    rl.totalDenied.Load(),
		"global_tokens":   rl.global.Tokens(),
		"tenant_buckets":  tenantCount,
		"ip_buckets":      ipCount,
		"api_key_buckets": apiKeyCount,
	}
}

// GetRateLimitHeaders returns HTTP headers for rate limiting.
func GetRateLimitHeaders(result *RateLimitResult) map[string]string {
	headers := map[string]string{
		"X-RateLimit-Limit":     fmt.Sprintf("%d", result.Limit),
		"X-RateLimit-Remaining": fmt.Sprintf("%d", result.Remaining),
		"X-RateLimit-Reset":     fmt.Sprintf("%d", result.ResetAt.Unix()),
	}

	if !result.Allowed {
		headers["Retry-After"] = fmt.Sprintf("%d", int(result.RetryAfter.Seconds())+1)
	}

	return headers
}
