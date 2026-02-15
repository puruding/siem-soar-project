// Package elastic provides Elasticsearch connector implementation.
package elastic

import (
	"fmt"
	"time"

	"siem-soar-project/pkg/connector"
)

// Config holds Elasticsearch-specific configuration.
type Config struct {
	// Base configuration
	Base connector.SIEMConfig `json:"base"`

	// Elasticsearch addresses (can be multiple for cluster)
	Addresses []string `json:"addresses"`

	// Cloud configuration
	CloudID string `json:"cloud_id,omitempty"`

	// API Key authentication
	APIKey string `json:"api_key,omitempty"`

	// Index settings
	Index IndexConfig `json:"index"`

	// Query settings
	Query QueryConfig `json:"query"`

	// Bulk settings
	Bulk BulkConfig `json:"bulk"`

	// Connection settings
	MaxRetries            int           `json:"max_retries,omitempty"`
	RetryOnStatus         []int         `json:"retry_on_status,omitempty"`
	DisableRetry          bool          `json:"disable_retry,omitempty"`
	EnableMetrics         bool          `json:"enable_metrics,omitempty"`
	EnableDebugLogger     bool          `json:"enable_debug_logger,omitempty"`
	CompressRequestBody   bool          `json:"compress_request_body,omitempty"`
	DiscoverNodesOnStart  bool          `json:"discover_nodes_on_start,omitempty"`
	DiscoverNodesInterval time.Duration `json:"discover_nodes_interval,omitempty"`
}

// IndexConfig holds index-related configuration.
type IndexConfig struct {
	DefaultIndex      string `json:"default_index,omitempty"`
	IndexPattern      string `json:"index_pattern,omitempty"` // e.g., "logs-*"
	DataStream        string `json:"data_stream,omitempty"`   // For data streams
	Shards            int    `json:"shards,omitempty"`
	Replicas          int    `json:"replicas,omitempty"`
	RefreshInterval   string `json:"refresh_interval,omitempty"`
	ILMPolicy         string `json:"ilm_policy,omitempty"`
}

// QueryConfig holds query-related configuration.
type QueryConfig struct {
	DefaultSize      int           `json:"default_size,omitempty"`
	MaxSize          int           `json:"max_size,omitempty"`
	ScrollTimeout    time.Duration `json:"scroll_timeout,omitempty"`
	RequestTimeout   time.Duration `json:"request_timeout,omitempty"`
	TrackTotalHits   bool          `json:"track_total_hits,omitempty"`
	AllowPartialResults bool       `json:"allow_partial_results,omitempty"`
}

// BulkConfig holds bulk operation configuration.
type BulkConfig struct {
	BatchSize      int           `json:"batch_size,omitempty"`
	FlushInterval  time.Duration `json:"flush_interval,omitempty"`
	FlushBytes     int           `json:"flush_bytes,omitempty"`
	Workers        int           `json:"workers,omitempty"`
	Pipeline       string        `json:"pipeline,omitempty"`
	RefreshPolicy  string        `json:"refresh_policy,omitempty"` // "true", "false", "wait_for"
}

// DefaultConfig returns a default Elasticsearch configuration.
func DefaultConfig() *Config {
	return &Config{
		Base: connector.SIEMConfig{
			Type:    connector.SIEMElastic,
			Enabled: true,
			Timeout: 30 * time.Second,
			Retry:   connector.DefaultRetryConfig(),
		},
		Index: IndexConfig{
			DefaultIndex:    "logs",
			Shards:          1,
			Replicas:        1,
			RefreshInterval: "1s",
		},
		Query: QueryConfig{
			DefaultSize:      100,
			MaxSize:          10000,
			ScrollTimeout:    5 * time.Minute,
			RequestTimeout:   30 * time.Second,
			TrackTotalHits:   true,
		},
		Bulk: BulkConfig{
			BatchSize:     1000,
			FlushInterval: 30 * time.Second,
			FlushBytes:    5 * 1024 * 1024, // 5MB
			Workers:       2,
			RefreshPolicy: "false",
		},
		MaxRetries:           3,
		RetryOnStatus:        []int{502, 503, 504},
		CompressRequestBody:  true,
	}
}

// Validate validates the Elasticsearch configuration.
func (c *Config) Validate() error {
	if len(c.Addresses) == 0 && c.CloudID == "" {
		return fmt.Errorf("at least one elasticsearch address or cloud_id is required")
	}

	// Validate credentials
	creds := c.Base.Credentials
	hasAuth := false

	if creds.Type == "basic" {
		if creds.Username == "" || creds.Password == "" {
			return fmt.Errorf("username and password required for basic auth")
		}
		hasAuth = true
	}

	if creds.Type == "api_key" || c.APIKey != "" {
		hasAuth = true
	}

	if creds.Type == "token" && creds.Token != "" {
		hasAuth = true
	}

	if !hasAuth && c.CloudID != "" {
		return fmt.Errorf("authentication required for cloud deployment")
	}

	// Validate query settings
	if c.Query.MaxSize > 0 && c.Query.DefaultSize > c.Query.MaxSize {
		return fmt.Errorf("default_size cannot exceed max_size")
	}

	return nil
}

// GetAddresses returns the Elasticsearch addresses.
func (c *Config) GetAddresses() []string {
	if c.CloudID != "" {
		return nil // Cloud ID is handled separately
	}
	return c.Addresses
}

// GetIndexName returns the index name for a given event type.
func (c *Config) GetIndexName(eventType string, timestamp time.Time) string {
	if c.Index.DataStream != "" {
		return c.Index.DataStream
	}

	if c.Index.IndexPattern != "" {
		// Apply date pattern
		return timestamp.Format(c.Index.IndexPattern)
	}

	if eventType != "" {
		return fmt.Sprintf("%s-%s", c.Index.DefaultIndex, eventType)
	}

	return c.Index.DefaultIndex
}
