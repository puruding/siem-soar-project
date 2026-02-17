// Package config provides configuration management for the enricher service.
package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds enricher service configuration.
type Config struct {
	// Service
	ServiceName string
	Port        string
	LogLevel    string

	// Kafka
	KafkaBrokers       []string
	KafkaGroupID       string
	KafkaInputTopic    string // logs.normalized
	KafkaOutputTopic   string // logs.enriched
	KafkaDLQTopic      string // logs.dlq.enricher

	// GeoIP
	GeoIPCityDB    string
	GeoIPASNDB     string
	GeoIPAnonDB    string
	GeoIPCacheSize int
	GeoIPCacheTTL  time.Duration

	// Asset (CMDB)
	CMDBEndpoint   string
	CMDBAPIKey     string
	AssetCacheSize int
	AssetCacheTTL  time.Duration

	// User (LDAP)
	LDAPEndpoint     string
	LDAPBaseDN       string
	LDAPBindDN       string
	LDAPBindPassword string
	LDAPUseTLS       bool
	UserCacheSize    int
	UserCacheTTL     time.Duration

	// Threat Intel
	MISPEndpoint    string
	MISPAPIKey      string
	OTXEndpoint     string
	OTXAPIKey       string
	VirusTotalKey   string
	AbuseIPDBKey    string
	ThreatCacheSize int
	ThreatCacheTTL  time.Duration

	// Worker settings
	Workers          int
	BatchSize        int
	BatchTimeout     time.Duration
	RequestTimeout   time.Duration

	// Enrichment settings
	EnableGeoIP     bool
	EnableAsset     bool
	EnableUser      bool
	EnableThreat    bool
	SkipPrivateIPs  bool

	// Metrics
	MetricsEnabled bool
	MetricsPort    string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		// Service
		ServiceName: getEnv("SERVICE_NAME", "enricher"),
		Port:        getEnv("PORT", "8090"),
		LogLevel:    getEnv("LOG_LEVEL", "info"),

		// Kafka
		KafkaBrokers:     strings.Split(getEnv("KAFKA_BROKERS", "localhost:9092"), ","),
		KafkaGroupID:     getEnv("KAFKA_GROUP_ID", "enricher-service"),
		KafkaInputTopic:  getEnv("KAFKA_INPUT_TOPIC", "logs.normalized"),
		KafkaOutputTopic: getEnv("KAFKA_OUTPUT_TOPIC", "logs.enriched"),
		KafkaDLQTopic:    getEnv("KAFKA_DLQ_TOPIC", "logs.dlq.enricher"),

		// GeoIP
		GeoIPCityDB:    getEnv("GEOIP_CITY_DB", ""),
		GeoIPASNDB:     getEnv("GEOIP_ASN_DB", ""),
		GeoIPAnonDB:    getEnv("GEOIP_ANON_DB", ""),
		GeoIPCacheSize: getEnvInt("GEOIP_CACHE_SIZE", 100000),
		GeoIPCacheTTL:  getEnvDuration("GEOIP_CACHE_TTL", "24h"),

		// Asset (CMDB)
		CMDBEndpoint:   getEnv("CMDB_ENDPOINT", ""),
		CMDBAPIKey:     getEnv("CMDB_API_KEY", ""),
		AssetCacheSize: getEnvInt("ASSET_CACHE_SIZE", 50000),
		AssetCacheTTL:  getEnvDuration("ASSET_CACHE_TTL", "5m"),

		// User (LDAP)
		LDAPEndpoint:     getEnv("LDAP_ENDPOINT", ""),
		LDAPBaseDN:       getEnv("LDAP_BASE_DN", ""),
		LDAPBindDN:       getEnv("LDAP_BIND_DN", ""),
		LDAPBindPassword: getEnv("LDAP_BIND_PASSWORD", ""),
		LDAPUseTLS:       getEnvBool("LDAP_USE_TLS", true),
		UserCacheSize:    getEnvInt("USER_CACHE_SIZE", 50000),
		UserCacheTTL:     getEnvDuration("USER_CACHE_TTL", "5m"),

		// Threat Intel
		MISPEndpoint:    getEnv("MISP_ENDPOINT", ""),
		MISPAPIKey:      getEnv("MISP_API_KEY", ""),
		OTXEndpoint:     getEnv("OTX_ENDPOINT", "https://otx.alienvault.com"),
		OTXAPIKey:       getEnv("OTX_API_KEY", ""),
		VirusTotalKey:   getEnv("VIRUSTOTAL_API_KEY", ""),
		AbuseIPDBKey:    getEnv("ABUSEIPDB_API_KEY", ""),
		ThreatCacheSize: getEnvInt("THREAT_CACHE_SIZE", 100000),
		ThreatCacheTTL:  getEnvDuration("THREAT_CACHE_TTL", "1h"),

		// Worker settings
		Workers:        getEnvInt("ENRICHER_WORKERS", 8),
		BatchSize:      getEnvInt("ENRICHER_BATCH_SIZE", 500),
		BatchTimeout:   getEnvDuration("ENRICHER_BATCH_TIMEOUT", "100ms"),
		RequestTimeout: getEnvDuration("ENRICHER_REQUEST_TIMEOUT", "5s"),

		// Enrichment settings
		EnableGeoIP:    getEnvBool("ENRICHER_ENABLE_GEOIP", true),
		EnableAsset:    getEnvBool("ENRICHER_ENABLE_ASSET", true),
		EnableUser:     getEnvBool("ENRICHER_ENABLE_USER", true),
		EnableThreat:   getEnvBool("ENRICHER_ENABLE_THREAT", true),
		SkipPrivateIPs: getEnvBool("ENRICHER_SKIP_PRIVATE_IPS", true),

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
