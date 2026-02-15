// Package splunk provides Splunk connector implementation.
package splunk

import (
	"fmt"
	"time"

	"siem-soar-project/pkg/connector"
)

// Config holds Splunk-specific configuration.
type Config struct {
	// Base configuration
	Base connector.SIEMConfig `json:"base"`

	// Splunk-specific settings
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Scheme     string `json:"scheme"` // "http" or "https"

	// Management API settings
	ManagementPort int    `json:"management_port,omitempty"` // Default: 8089
	App            string `json:"app,omitempty"`             // Splunk app context

	// HEC (HTTP Event Collector) settings
	HEC HECConfig `json:"hec,omitempty"`

	// Search settings
	Search SearchConfig `json:"search"`

	// Connection pool settings
	MaxIdleConns        int           `json:"max_idle_conns,omitempty"`
	MaxConnsPerHost     int           `json:"max_conns_per_host,omitempty"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout,omitempty"`
}

// HECConfig holds HEC-specific configuration.
type HECConfig struct {
	Enabled      bool   `json:"enabled"`
	Endpoint     string `json:"endpoint,omitempty"` // Default: /services/collector
	Token        string `json:"token"`
	Index        string `json:"index,omitempty"`
	Source       string `json:"source,omitempty"`
	SourceType   string `json:"sourcetype,omitempty"`
	Host         string `json:"host,omitempty"`
	UseAck       bool   `json:"use_ack,omitempty"`
	Channel      string `json:"channel,omitempty"`
	BatchSize    int    `json:"batch_size,omitempty"`    // Events per batch
	BatchTimeout time.Duration `json:"batch_timeout,omitempty"` // Flush timeout
}

// SearchConfig holds search-specific configuration.
type SearchConfig struct {
	DefaultIndex    string        `json:"default_index,omitempty"`
	DefaultEarliest string        `json:"default_earliest,omitempty"` // e.g., "-24h"
	DefaultLatest   string        `json:"default_latest,omitempty"`   // e.g., "now"
	MaxResults      int           `json:"max_results,omitempty"`      // Default: 10000
	SearchTimeout   time.Duration `json:"search_timeout,omitempty"`
	StatusInterval  time.Duration `json:"status_interval,omitempty"` // Polling interval for async searches
	OutputMode      string        `json:"output_mode,omitempty"`     // "json", "json_rows", "csv", "xml"
}

// DefaultConfig returns a default Splunk configuration.
func DefaultConfig() *Config {
	return &Config{
		Base: connector.SIEMConfig{
			Type:    connector.SIEMSplunk,
			Enabled: true,
			Timeout: 30 * time.Second,
			Retry:   connector.DefaultRetryConfig(),
		},
		Scheme:         "https",
		Port:           8089,
		ManagementPort: 8089,
		App:            "search",
		HEC: HECConfig{
			Endpoint:     "/services/collector",
			BatchSize:    100,
			BatchTimeout: 5 * time.Second,
		},
		Search: SearchConfig{
			DefaultEarliest: "-24h",
			DefaultLatest:   "now",
			MaxResults:      10000,
			SearchTimeout:   300 * time.Second,
			StatusInterval:  1 * time.Second,
			OutputMode:      "json",
		},
		MaxIdleConns:    10,
		MaxConnsPerHost: 10,
		IdleConnTimeout: 90 * time.Second,
	}
}

// Validate validates the Splunk configuration.
func (c *Config) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("splunk host is required")
	}

	if c.Port <= 0 || c.Port > 65535 {
		return fmt.Errorf("invalid splunk port: %d", c.Port)
	}

	if c.Scheme != "http" && c.Scheme != "https" {
		return fmt.Errorf("invalid scheme: %s (must be http or https)", c.Scheme)
	}

	// Validate credentials
	creds := c.Base.Credentials
	if creds.Type == "basic" {
		if creds.Username == "" || creds.Password == "" {
			return fmt.Errorf("username and password required for basic auth")
		}
	} else if creds.Type == "token" {
		if creds.Token == "" {
			return fmt.Errorf("token required for token auth")
		}
	}

	// Validate HEC config if enabled
	if c.HEC.Enabled {
		if c.HEC.Token == "" {
			return fmt.Errorf("HEC token is required when HEC is enabled")
		}
	}

	return nil
}

// GetManagementURL returns the Splunk management API URL.
func (c *Config) GetManagementURL() string {
	port := c.ManagementPort
	if port == 0 {
		port = c.Port
	}
	return fmt.Sprintf("%s://%s:%d", c.Scheme, c.Host, port)
}

// GetHECURL returns the HEC endpoint URL.
func (c *Config) GetHECURL() string {
	endpoint := c.HEC.Endpoint
	if endpoint == "" {
		endpoint = "/services/collector"
	}
	// HEC typically uses port 8088
	return fmt.Sprintf("%s://%s:8088%s", c.Scheme, c.Host, endpoint)
}

// GetSearchURL returns the search API URL.
func (c *Config) GetSearchURL() string {
	return fmt.Sprintf("%s/servicesNS/%s/%s/search/jobs",
		c.GetManagementURL(),
		"-", // owner (use - for all)
		c.App,
	)
}
