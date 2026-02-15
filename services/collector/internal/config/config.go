// Package config provides configuration for the collector service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the collector service configuration.
type Config struct {
	// Service settings
	ServiceName string
	HTTPPort    int
	GRPCPort    int
	MetricsPort int

	// Syslog receiver
	Syslog SyslogConfig

	// HTTP receiver
	HTTP HTTPReceiverConfig

	// Kafka settings
	Kafka KafkaConfig

	// Polling sources
	Polling PollingConfig

	// Performance settings
	BatchSize       int
	FlushInterval   time.Duration
	WorkerCount     int
	ChannelBuffer   int
	BackpressureMax int
}

// SyslogConfig holds syslog receiver settings.
type SyslogConfig struct {
	Enabled     bool
	UDPAddr     string
	TCPAddr     string
	TLSAddr     string
	TLSCertPath string
	TLSKeyPath  string
	MaxMsgSize  int
	ParseRFC    bool // Auto-detect RFC3164/RFC5424
}

// HTTPReceiverConfig holds HTTP receiver settings.
type HTTPReceiverConfig struct {
	Enabled       bool
	ListenAddr    string
	TLSEnabled    bool
	TLSCertPath   string
	TLSKeyPath    string
	MaxBodySize   int64
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	APIKeyHeader  string
	APIKeys       map[string]string // key -> tenant mapping
	RateLimitRPS  int
	RateLimitBurst int
}

// KafkaConfig holds Kafka connection settings.
type KafkaConfig struct {
	Brokers        []string
	Topic          string
	RequiredAcks   int
	MaxMessageSize int
	Compression    string
	BatchSize      int
	LingerMs       int
	Retries        int
	RetryBackoff   time.Duration
	TLSEnabled     bool
	TLSCertPath    string
	TLSKeyPath     string
	TLSCAPath      string
	SASLEnabled    bool
	SASLMechanism  string
	SASLUsername   string
	SASLPassword   string
}

// PollingConfig holds polling source settings.
type PollingConfig struct {
	// API polling
	APISources []APISourceConfig

	// S3 polling
	S3Sources []S3SourceConfig

	// File watching
	FileSources []FileSourceConfig
}

// APISourceConfig holds API polling source settings.
type APISourceConfig struct {
	Name            string
	Enabled         bool
	URL             string
	Method          string
	Headers         map[string]string
	AuthType        string // none, basic, bearer, oauth2
	AuthCredentials map[string]string
	PollInterval    time.Duration
	PageSize        int
	MaxPages        int
	RateLimitRPS    int
	TenantID        string
	SourceType      string
}

// S3SourceConfig holds S3 polling source settings.
type S3SourceConfig struct {
	Name         string
	Enabled      bool
	Region       string
	Bucket       string
	Prefix       string
	Endpoint     string
	AccessKey    string
	SecretKey    string
	PollInterval time.Duration
	BatchSize    int
	DeleteAfter  bool
	TenantID     string
	SourceType   string
}

// FileSourceConfig holds file watching source settings.
type FileSourceConfig struct {
	Name       string
	Enabled    bool
	Paths      []string
	Patterns   []string
	Recursive  bool
	TenantID   string
	SourceType string
}

// Load creates a new Config from environment variables.
func Load() *Config {
	return &Config{
		ServiceName: getEnv("SERVICE_NAME", "collector"),
		HTTPPort:    getEnvAsInt("HTTP_PORT", 8086),
		GRPCPort:    getEnvAsInt("GRPC_PORT", 9086),
		MetricsPort: getEnvAsInt("METRICS_PORT", 9186),

		Syslog: SyslogConfig{
			Enabled:    getEnvAsBool("SYSLOG_ENABLED", true),
			UDPAddr:    getEnv("SYSLOG_UDP_ADDR", ":514"),
			TCPAddr:    getEnv("SYSLOG_TCP_ADDR", ":514"),
			TLSAddr:    getEnv("SYSLOG_TLS_ADDR", ":6514"),
			MaxMsgSize: getEnvAsInt("SYSLOG_MAX_MSG_SIZE", 65536),
			ParseRFC:   getEnvAsBool("SYSLOG_PARSE_RFC", true),
		},

		HTTP: HTTPReceiverConfig{
			Enabled:       getEnvAsBool("HTTP_RECEIVER_ENABLED", true),
			ListenAddr:    getEnv("HTTP_RECEIVER_ADDR", ":8087"),
			TLSEnabled:    getEnvAsBool("HTTP_RECEIVER_TLS", false),
			MaxBodySize:   int64(getEnvAsInt("HTTP_RECEIVER_MAX_BODY", 10485760)),
			ReadTimeout:   getEnvAsDuration("HTTP_RECEIVER_READ_TIMEOUT", 30*time.Second),
			WriteTimeout:  getEnvAsDuration("HTTP_RECEIVER_WRITE_TIMEOUT", 30*time.Second),
			APIKeyHeader:  getEnv("HTTP_RECEIVER_API_KEY_HEADER", "X-API-Key"),
			RateLimitRPS:  getEnvAsInt("HTTP_RECEIVER_RATE_LIMIT_RPS", 10000),
			RateLimitBurst: getEnvAsInt("HTTP_RECEIVER_RATE_LIMIT_BURST", 20000),
		},

		Kafka: KafkaConfig{
			Brokers:        getEnvAsSlice("KAFKA_BROKERS", []string{"localhost:9092"}),
			Topic:          getEnv("KAFKA_TOPIC", "raw-logs"),
			RequiredAcks:   getEnvAsInt("KAFKA_REQUIRED_ACKS", -1),
			MaxMessageSize: getEnvAsInt("KAFKA_MAX_MESSAGE_SIZE", 10485760),
			Compression:    getEnv("KAFKA_COMPRESSION", "lz4"),
			BatchSize:      getEnvAsInt("KAFKA_BATCH_SIZE", 16384),
			LingerMs:       getEnvAsInt("KAFKA_LINGER_MS", 5),
			Retries:        getEnvAsInt("KAFKA_RETRIES", 3),
			RetryBackoff:   getEnvAsDuration("KAFKA_RETRY_BACKOFF", 100*time.Millisecond),
			TLSEnabled:     getEnvAsBool("KAFKA_TLS_ENABLED", false),
			SASLEnabled:    getEnvAsBool("KAFKA_SASL_ENABLED", false),
			SASLMechanism:  getEnv("KAFKA_SASL_MECHANISM", "PLAIN"),
		},

		BatchSize:       getEnvAsInt("BATCH_SIZE", 1000),
		FlushInterval:   getEnvAsDuration("FLUSH_INTERVAL", 100*time.Millisecond),
		WorkerCount:     getEnvAsInt("WORKER_COUNT", 8),
		ChannelBuffer:   getEnvAsInt("CHANNEL_BUFFER", 100000),
		BackpressureMax: getEnvAsInt("BACKPRESSURE_MAX", 500000),
	}
}

// Helper functions
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getEnvAsSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		parts := strings.Split(value, ",")
		result := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				result = append(result, trimmed)
			}
		}
		if len(result) > 0 {
			return result
		}
	}
	return defaultValue
}
