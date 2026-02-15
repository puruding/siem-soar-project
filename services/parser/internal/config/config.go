// Package config provides configuration management for the parser service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds parser service configuration.
type Config struct {
	// Service
	ServiceName string
	Port        string
	LogLevel    string

	// Kafka
	KafkaBrokers       []string
	KafkaInputTopic    string
	KafkaOutputTopic   string
	KafkaDLQTopic      string
	KafkaConsumerGroup string

	// Parser
	Workers          int
	BatchSize        int
	BatchTimeout     time.Duration
	ParseTimeout     time.Duration
	MaxFieldSize     int
	MaxFields        int
	EnableAutoDetect bool
	EnableGrokCache  bool
	GrokCacheSize    int

	// Hot Reload
	RedisAddr       string
	RedisPassword   string
	RedisDB         int
	ReloadChannel   string

	// Metrics
	MetricsEnabled bool
	MetricsPort    string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		// Service
		ServiceName: getEnv("SERVICE_NAME", "parser"),
		Port:        getEnv("PORT", "8088"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),

		// Kafka
		KafkaBrokers:       strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		KafkaInputTopic:    getEnv("KAFKA_INPUT_TOPIC", "logs.raw"),
		KafkaOutputTopic:   getEnv("KAFKA_OUTPUT_TOPIC", "logs.parsed"),
		KafkaDLQTopic:      getEnv("KAFKA_DLQ_TOPIC", "logs.dlq.parser"),
		KafkaConsumerGroup: getEnv("KAFKA_CONSUMER_GROUP", "parser-service"),

		// Parser
		Workers:          getEnvInt("PARSER_WORKERS", 8),
		BatchSize:        getEnvInt("PARSER_BATCH_SIZE", 1000),
		BatchTimeout:     getEnvDuration("PARSER_BATCH_TIMEOUT", "100ms"),
		ParseTimeout:     getEnvDuration("PARSER_PARSE_TIMEOUT", "5s"),
		MaxFieldSize:     getEnvInt("PARSER_MAX_FIELD_SIZE", 65536),
		MaxFields:        getEnvInt("PARSER_MAX_FIELDS", 500),
		EnableAutoDetect: getEnvBool("PARSER_AUTO_DETECT", true),
		EnableGrokCache:  getEnvBool("PARSER_GROK_CACHE", true),
		GrokCacheSize:    getEnvInt("PARSER_GROK_CACHE_SIZE", 10000),

		// Hot Reload
		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvInt("REDIS_DB", 0),
		ReloadChannel: getEnv("REDIS_RELOAD_CHANNEL", "parser:reload"),

		// Metrics
		MetricsEnabled: getEnvBool("METRICS_ENABLED", true),
		MetricsPort:    getEnv("METRICS_PORT", "9090"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getEnvDuration(key, defaultValue string) time.Duration {
	value := getEnv(key, defaultValue)
	d, err := time.ParseDuration(value)
	if err != nil {
		d, _ = time.ParseDuration(defaultValue)
	}
	return d
}
