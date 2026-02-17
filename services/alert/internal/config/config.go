// Package config provides configuration management for the alert service.
package config

import (
	"crypto/tls"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/alert/internal/dedup"
	"github.com/siem-soar-platform/services/alert/internal/enricher"
	"github.com/siem-soar-platform/services/alert/internal/generator"
)

// Config holds all configuration for the alert service.
type Config struct {
	Service   ServiceConfig   `json:"service"`
	Kafka     KafkaConfig     `json:"kafka"`
	Generator generator.GeneratorConfig `json:"generator"`
	Dedup     dedup.DedupConfig         `json:"dedup"`
	Enricher  enricher.EnricherConfig   `json:"enricher"`
	Publisher PublisherConfig `json:"publisher"`
}

// ServiceConfig holds service-level configuration.
type ServiceConfig struct {
	Name     string `json:"name"`
	Port     string `json:"port"`
	LogLevel string `json:"log_level"`
}

// KafkaConfig holds Kafka consumer configuration.
type KafkaConfig struct {
	Brokers       []string      `json:"brokers"`
	ConsumerGroup string        `json:"consumer_group"`
	InputTopic    string        `json:"input_topic"`
	BatchSize     int           `json:"batch_size"`
	BatchTimeout  time.Duration `json:"batch_timeout"`

	// Security
	SASL SASLConfig `json:"sasl"`
	TLS  TLSConfig  `json:"tls"`

	// Consumer settings
	SessionTimeout time.Duration `json:"session_timeout"`
	HeartbeatInterval time.Duration `json:"heartbeat_interval"`
	MaxPollRecords int           `json:"max_poll_records"`
}

// SASLConfig holds SASL authentication configuration.
type SASLConfig struct {
	Enabled   bool   `json:"enabled"`
	Mechanism string `json:"mechanism"` // PLAIN, SCRAM-SHA-256, SCRAM-SHA-512
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enabled            bool   `json:"enabled"`
	CertFile           string `json:"cert_file"`
	KeyFile            string `json:"key_file"`
	CAFile             string `json:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// PublisherConfig holds publisher configuration.
type PublisherConfig struct {
	Webhook   WebhookConfig   `json:"webhook"`
	Slack     SlackConfig     `json:"slack"`
	PagerDuty PagerDutyConfig `json:"pagerduty"`
	Kafka     KafkaPublisherConfig `json:"kafka"`
}

// WebhookConfig holds webhook publisher configuration.
type WebhookConfig struct {
	Enabled      bool              `json:"enabled"`
	Endpoints    []string          `json:"endpoints"`
	Headers      map[string]string `json:"headers"`
	Timeout      time.Duration     `json:"timeout"`
	RetryCount   int               `json:"retry_count"`
	RetryDelay   time.Duration     `json:"retry_delay"`
}

// SlackConfig holds Slack publisher configuration.
type SlackConfig struct {
	Enabled    bool   `json:"enabled"`
	WebhookURL string `json:"webhook_url"`
	Channel    string `json:"channel"`
	Timeout    time.Duration `json:"timeout"`
}

// PagerDutyConfig holds PagerDuty publisher configuration.
type PagerDutyConfig struct {
	Enabled     bool   `json:"enabled"`
	RoutingKey  string `json:"routing_key"`
	Timeout     time.Duration `json:"timeout"`
}

// KafkaPublisherConfig holds Kafka publisher configuration.
type KafkaPublisherConfig struct {
	Enabled bool   `json:"enabled"`
	Topic   string `json:"topic"`
}

// EnricherProviderConfig holds enricher provider configuration.
type EnricherProviderConfig struct {
	GeoIP GeoIPConfig `json:"geoip"`
	TI    TIConfig    `json:"ti"`
	Asset AssetConfig `json:"asset"`
	User  UserConfig  `json:"user"`
}

// GeoIPConfig holds GeoIP configuration.
type GeoIPConfig struct {
	Enabled  bool   `json:"enabled"`
	DBPath   string `json:"db_path"`
	CacheTTL time.Duration `json:"cache_ttl"`
}

// TIConfig holds Threat Intelligence configuration.
type TIConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	APIKey   string `json:"api_key"`
	Timeout  time.Duration `json:"timeout"`
	CacheTTL time.Duration `json:"cache_ttl"`
}

// AssetConfig holds Asset lookup configuration.
type AssetConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	Timeout  time.Duration `json:"timeout"`
}

// UserConfig holds User lookup configuration.
type UserConfig struct {
	Enabled  bool   `json:"enabled"`
	Endpoint string `json:"endpoint"`
	Timeout  time.Duration `json:"timeout"`
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		Service: ServiceConfig{
			Name:     "alert",
			Port:     "8084",
			LogLevel: "info",
		},
		Kafka: KafkaConfig{
			Brokers:           []string{"localhost:9092"},
			ConsumerGroup:     "alert-service",
			InputTopic:        "alerts",
			BatchSize:         100,
			BatchTimeout:      5 * time.Second,
			SessionTimeout:    30 * time.Second,
			HeartbeatInterval: 3 * time.Second,
			MaxPollRecords:    500,
		},
		Generator: generator.DefaultGeneratorConfig(),
		Dedup:     dedup.DefaultDedupConfig(),
		Enricher:  enricher.DefaultEnricherConfig(),
		Publisher: PublisherConfig{
			Webhook: WebhookConfig{
				Enabled:    false,
				Timeout:    10 * time.Second,
				RetryCount: 3,
				RetryDelay: 1 * time.Second,
			},
			Slack: SlackConfig{
				Enabled: false,
				Timeout: 10 * time.Second,
			},
			PagerDuty: PagerDutyConfig{
				Enabled: false,
				Timeout: 10 * time.Second,
			},
			Kafka: KafkaPublisherConfig{
				Enabled: false,
				Topic:   "processed-alerts",
			},
		},
	}
}

// LoadFromEnv loads configuration from environment variables.
func LoadFromEnv() *Config {
	cfg := DefaultConfig()

	// Service configuration
	if v := os.Getenv("SERVICE_NAME"); v != "" {
		cfg.Service.Name = v
	}
	if v := os.Getenv("PORT"); v != "" {
		cfg.Service.Port = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		cfg.Service.LogLevel = v
	}

	// Kafka configuration
	if v := os.Getenv("KAFKA_BROKERS"); v != "" {
		cfg.Kafka.Brokers = strings.Split(v, ",")
	}
	if v := os.Getenv("KAFKA_CONSUMER_GROUP"); v != "" {
		cfg.Kafka.ConsumerGroup = v
	}
	if v := os.Getenv("KAFKA_INPUT_TOPIC"); v != "" {
		cfg.Kafka.InputTopic = v
	}
	if v := os.Getenv("KAFKA_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Kafka.BatchSize = n
		}
	}
	if v := os.Getenv("KAFKA_BATCH_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Kafka.BatchTimeout = d
		}
	}

	// Kafka SASL
	if v := os.Getenv("KAFKA_SASL_ENABLED"); v == "true" {
		cfg.Kafka.SASL.Enabled = true
	}
	if v := os.Getenv("KAFKA_SASL_MECHANISM"); v != "" {
		cfg.Kafka.SASL.Mechanism = v
	}
	if v := os.Getenv("KAFKA_SASL_USERNAME"); v != "" {
		cfg.Kafka.SASL.Username = v
	}
	if v := os.Getenv("KAFKA_SASL_PASSWORD"); v != "" {
		cfg.Kafka.SASL.Password = v
	}

	// Kafka TLS
	if v := os.Getenv("KAFKA_TLS_ENABLED"); v == "true" {
		cfg.Kafka.TLS.Enabled = true
	}
	if v := os.Getenv("KAFKA_TLS_CERT_FILE"); v != "" {
		cfg.Kafka.TLS.CertFile = v
	}
	if v := os.Getenv("KAFKA_TLS_KEY_FILE"); v != "" {
		cfg.Kafka.TLS.KeyFile = v
	}
	if v := os.Getenv("KAFKA_TLS_CA_FILE"); v != "" {
		cfg.Kafka.TLS.CAFile = v
	}
	if v := os.Getenv("KAFKA_TLS_INSECURE_SKIP_VERIFY"); v == "true" {
		cfg.Kafka.TLS.InsecureSkipVerify = true
	}

	// Generator configuration
	if v := os.Getenv("GENERATOR_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Generator.MaxConcurrent = n
		}
	}
	if v := os.Getenv("GENERATOR_BATCH_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Generator.BatchSize = n
		}
	}
	if v := os.Getenv("GENERATOR_ENABLE_DEDUP"); v == "true" {
		cfg.Generator.EnableDedup = true
	}
	if v := os.Getenv("GENERATOR_ENABLE_ENRICHMENT"); v == "true" {
		cfg.Generator.EnableEnrichment = true
	}

	// Dedup configuration
	if v := os.Getenv("DEDUP_STRATEGY"); v != "" {
		cfg.Dedup.Strategy = dedup.DedupStrategy(v)
	}
	if v := os.Getenv("DEDUP_ACTION"); v != "" {
		cfg.Dedup.Action = dedup.DedupAction(v)
	}
	if v := os.Getenv("DEDUP_WINDOW_DURATION"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Dedup.WindowDuration = d
		}
	}
	if v := os.Getenv("DEDUP_MAX_GROUP_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Dedup.MaxGroupSize = n
		}
	}

	// Enricher configuration
	if v := os.Getenv("ENRICHER_ENABLE_GEOIP"); v == "false" {
		cfg.Enricher.EnableGeoIP = false
	}
	if v := os.Getenv("ENRICHER_ENABLE_ASN"); v == "false" {
		cfg.Enricher.EnableASN = false
	}
	if v := os.Getenv("ENRICHER_ENABLE_THREAT_INTEL"); v == "false" {
		cfg.Enricher.EnableThreatIntel = false
	}
	if v := os.Getenv("ENRICHER_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Enricher.MaxConcurrent = n
		}
	}
	if v := os.Getenv("ENRICHER_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Enricher.CacheTTL = d
		}
	}

	// Publisher - Webhook
	if v := os.Getenv("PUBLISHER_WEBHOOK_ENABLED"); v == "true" {
		cfg.Publisher.Webhook.Enabled = true
	}
	if v := os.Getenv("PUBLISHER_WEBHOOK_ENDPOINTS"); v != "" {
		cfg.Publisher.Webhook.Endpoints = strings.Split(v, ",")
	}
	if v := os.Getenv("PUBLISHER_WEBHOOK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Publisher.Webhook.Timeout = d
		}
	}
	if v := os.Getenv("PUBLISHER_WEBHOOK_RETRY_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Publisher.Webhook.RetryCount = n
		}
	}

	// Publisher - Slack
	if v := os.Getenv("PUBLISHER_SLACK_ENABLED"); v == "true" {
		cfg.Publisher.Slack.Enabled = true
	}
	if v := os.Getenv("PUBLISHER_SLACK_WEBHOOK_URL"); v != "" {
		cfg.Publisher.Slack.WebhookURL = v
	}
	if v := os.Getenv("PUBLISHER_SLACK_CHANNEL"); v != "" {
		cfg.Publisher.Slack.Channel = v
	}

	// Publisher - PagerDuty
	if v := os.Getenv("PUBLISHER_PAGERDUTY_ENABLED"); v == "true" {
		cfg.Publisher.PagerDuty.Enabled = true
	}
	if v := os.Getenv("PUBLISHER_PAGERDUTY_ROUTING_KEY"); v != "" {
		cfg.Publisher.PagerDuty.RoutingKey = v
	}

	// Publisher - Kafka
	if v := os.Getenv("PUBLISHER_KAFKA_ENABLED"); v == "true" {
		cfg.Publisher.Kafka.Enabled = true
	}
	if v := os.Getenv("PUBLISHER_KAFKA_TOPIC"); v != "" {
		cfg.Publisher.Kafka.Topic = v
	}

	return cfg
}

// GetEnvOrDefault returns the environment variable value or a default.
func GetEnvOrDefault(key, defaultValue string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultValue
}

// GetEnvIntOrDefault returns the environment variable as int or a default.
func GetEnvIntOrDefault(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultValue
}

// GetEnvDurationOrDefault returns the environment variable as duration or a default.
func GetEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

// GetEnvBoolOrDefault returns the environment variable as bool or a default.
func GetEnvBoolOrDefault(key string, defaultValue bool) bool {
	if v := os.Getenv(key); v != "" {
		return strings.ToLower(v) == "true"
	}
	return defaultValue
}

// BuildTLSConfig builds a TLS config from the configuration.
func (c *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	if !c.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.InsecureSkipVerify,
	}

	// Load client certificate if provided
	if c.CertFile != "" && c.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
