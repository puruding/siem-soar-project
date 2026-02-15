package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for ML Gateway service.
type Config struct {
	// Server settings
	Port        string
	Environment string
	Debug       bool

	// Service URLs
	ClassifyServiceURL string
	DGAServiceURL      string
	PriorityServiceURL string

	// Redis settings
	RedisURL         string
	CacheTTL         time.Duration
	CacheEnabled     bool
	CacheMaxSize     int

	// Load balancing
	LoadBalanceStrategy string // round-robin, least-connections, random
	HealthCheckInterval time.Duration

	// Rate limiting
	RateLimitEnabled    bool
	RateLimitPerSecond  int
	RateLimitBurst      int

	// Async inference
	AsyncEnabled      bool
	AsyncQueueSize    int
	AsyncWorkers      int

	// Timeouts
	ClassifyTimeout time.Duration
	DGATimeout      time.Duration
	PriorityTimeout time.Duration

	// Model versioning
	DefaultModelVersion string
	EnableModelRouting  bool

	// Metrics
	MetricsEnabled bool
	TracingEnabled bool
}

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnvOrDefault("PORT", "8090"),
		Environment: getEnvOrDefault("ENVIRONMENT", "development"),
		Debug:       getEnvOrDefault("DEBUG", "false") == "true",

		// Service URLs
		ClassifyServiceURL: getEnvOrDefault("CLASSIFY_SERVICE_URL", "http://localhost:8000"),
		DGAServiceURL:      getEnvOrDefault("DGA_SERVICE_URL", "http://localhost:8000"),
		PriorityServiceURL: getEnvOrDefault("PRIORITY_SERVICE_URL", "http://localhost:8000"),

		// Redis
		RedisURL:     getEnvOrDefault("REDIS_URL", "redis://localhost:6379/0"),
		CacheTTL:     getDurationOrDefault("CACHE_TTL", 5*time.Minute),
		CacheEnabled: getEnvOrDefault("CACHE_ENABLED", "true") == "true",
		CacheMaxSize: getIntOrDefault("CACHE_MAX_SIZE", 10000),

		// Load balancing
		LoadBalanceStrategy: getEnvOrDefault("LOAD_BALANCE_STRATEGY", "round-robin"),
		HealthCheckInterval: getDurationOrDefault("HEALTH_CHECK_INTERVAL", 30*time.Second),

		// Rate limiting
		RateLimitEnabled:   getEnvOrDefault("RATE_LIMIT_ENABLED", "true") == "true",
		RateLimitPerSecond: getIntOrDefault("RATE_LIMIT_PER_SECOND", 1000),
		RateLimitBurst:     getIntOrDefault("RATE_LIMIT_BURST", 2000),

		// Async
		AsyncEnabled:   getEnvOrDefault("ASYNC_ENABLED", "true") == "true",
		AsyncQueueSize: getIntOrDefault("ASYNC_QUEUE_SIZE", 10000),
		AsyncWorkers:   getIntOrDefault("ASYNC_WORKERS", 10),

		// Timeouts
		ClassifyTimeout: getDurationOrDefault("CLASSIFY_TIMEOUT", 30*time.Second),
		DGATimeout:      getDurationOrDefault("DGA_TIMEOUT", 10*time.Second),
		PriorityTimeout: getDurationOrDefault("PRIORITY_TIMEOUT", 15*time.Second),

		// Model versioning
		DefaultModelVersion: getEnvOrDefault("DEFAULT_MODEL_VERSION", "v1.0.0"),
		EnableModelRouting:  getEnvOrDefault("ENABLE_MODEL_ROUTING", "true") == "true",

		// Observability
		MetricsEnabled: getEnvOrDefault("METRICS_ENABLED", "true") == "true",
		TracingEnabled: getEnvOrDefault("TRACING_ENABLED", "false") == "true",
	}

	return cfg, nil
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

// ModelEndpoint represents a model service endpoint.
type ModelEndpoint struct {
	URL      string
	Version  string
	Weight   int
	Healthy  bool
	LastPing time.Time
}

// ServiceEndpoints holds multiple endpoints for load balancing.
type ServiceEndpoints struct {
	Classify []ModelEndpoint
	DGA      []ModelEndpoint
	Priority []ModelEndpoint
}
