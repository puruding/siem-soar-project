// Package config provides configuration management for the router service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds router service configuration.
type Config struct {
	// Service
	ServiceName string
	Port        string
	LogLevel    string

	// Kafka Consumer
	KafkaBrokers    []string
	KafkaGroupID    string
	KafkaInputTopic string // logs.enriched
	KafkaDLQTopic   string // logs.dlq.router

	// Kafka Output Topics
	KafkaOutputTopic    string // logs.routed
	KafkaDetectionTopic string // detection.events
	KafkaAlertTopic     string // alerts.events

	// ClickHouse
	ClickHouseHosts    []string
	ClickHouseDatabase string
	ClickHouseTable    string
	ClickHouseUsername string
	ClickHousePassword string
	ClickHouseBatchSize int
	ClickHouseFlushInterval time.Duration

	// S3
	S3Region      string
	S3Bucket      string
	S3Prefix      string
	S3Endpoint    string // Custom endpoint for S3-compatible storage
	S3AccessKey   string
	S3SecretKey   string
	S3Compression bool
	S3BatchSize   int
	S3FlushInterval time.Duration

	// Router
	DefaultDestination string
	MaxConcurrent      int
	Workers            int
	BatchSize          int
	BatchTimeout       time.Duration

	// Metrics
	MetricsEnabled bool
	MetricsPort    string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		// Service
		ServiceName: getEnv("SERVICE_NAME", "router"),
		Port:        getEnv("PORT", "8091"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),

		// Kafka Consumer
		KafkaBrokers:    strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		KafkaGroupID:    getEnv("KAFKA_GROUP_ID", "router-service"),
		KafkaInputTopic: getEnv("KAFKA_INPUT_TOPIC", "logs.enriched"),
		KafkaDLQTopic:   getEnv("KAFKA_DLQ_TOPIC", "logs.dlq.router"),

		// Kafka Output Topics
		KafkaOutputTopic:    getEnv("KAFKA_OUTPUT_TOPIC", "logs.routed"),
		KafkaDetectionTopic: getEnv("KAFKA_DETECTION_TOPIC", "detection.events"),
		KafkaAlertTopic:     getEnv("KAFKA_ALERT_TOPIC", "alerts.events"),

		// ClickHouse
		ClickHouseHosts:    strings.Split(getEnv("CLICKHOUSE_HOSTS", "localhost:9000"), ","),
		ClickHouseDatabase: getEnv("CLICKHOUSE_DATABASE", "siem"),
		ClickHouseTable:    getEnv("CLICKHOUSE_TABLE", "events"),
		ClickHouseUsername: getEnv("CLICKHOUSE_USERNAME", "default"),
		ClickHousePassword: getEnv("CLICKHOUSE_PASSWORD", ""),
		ClickHouseBatchSize: getEnvInt("CLICKHOUSE_BATCH_SIZE", 1000),
		ClickHouseFlushInterval: getEnvDuration("CLICKHOUSE_FLUSH_INTERVAL", "100ms"),

		// S3
		S3Region:      getEnv("S3_REGION", "us-east-1"),
		S3Bucket:      getEnv("S3_BUCKET", "siem-events"),
		S3Prefix:      getEnv("S3_PREFIX", "archive"),
		S3Endpoint:    getEnv("S3_ENDPOINT", ""),
		S3AccessKey:   getEnv("S3_ACCESS_KEY", ""),
		S3SecretKey:   getEnv("S3_SECRET_KEY", ""),
		S3Compression: getEnvBool("S3_COMPRESSION", true),
		S3BatchSize:   getEnvInt("S3_BATCH_SIZE", 10000),
		S3FlushInterval: getEnvDuration("S3_FLUSH_INTERVAL", "1m"),

		// Router
		DefaultDestination: getEnv("DEFAULT_DESTINATION", "clickhouse-main"),
		MaxConcurrent:      getEnvInt("ROUTER_MAX_CONCURRENT", 100),
		Workers:            getEnvInt("ROUTER_WORKERS", 8),
		BatchSize:          getEnvInt("ROUTER_BATCH_SIZE", 500),
		BatchTimeout:       getEnvDuration("ROUTER_BATCH_TIMEOUT", "100ms"),

		// Metrics
		MetricsEnabled: getEnvBool("METRICS_ENABLED", true),
		MetricsPort:    getEnv("METRICS_PORT", "9091"),
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
