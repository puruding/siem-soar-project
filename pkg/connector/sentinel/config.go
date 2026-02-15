// Package sentinel provides Microsoft Sentinel connector implementation.
package sentinel

import (
	"fmt"
	"time"

	"siem-soar-project/pkg/connector"
)

// Config holds Sentinel-specific configuration.
type Config struct {
	// Base configuration
	Base connector.SIEMConfig `json:"base"`

	// Azure subscription and resource details
	SubscriptionID string `json:"subscription_id"`
	ResourceGroup  string `json:"resource_group"`
	WorkspaceName  string `json:"workspace_name"`
	WorkspaceID    string `json:"workspace_id"` // Log Analytics workspace ID

	// Azure AD authentication
	TenantID     string `json:"tenant_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	// Managed Identity (alternative to client credentials)
	UseManagedIdentity bool `json:"use_managed_identity"`

	// Event Hub configuration (for data ingestion)
	EventHub EventHubConfig `json:"event_hub,omitempty"`

	// Data Collection configuration
	DataCollection DataCollectionConfig `json:"data_collection,omitempty"`

	// Query settings
	Query QueryConfig `json:"query"`

	// API settings
	APIVersion string `json:"api_version,omitempty"`
}

// EventHubConfig holds Event Hub configuration.
type EventHubConfig struct {
	Enabled           bool   `json:"enabled"`
	Namespace         string `json:"namespace"`
	Name              string `json:"name"`
	ConnectionString  string `json:"connection_string,omitempty"`
	ConsumerGroup     string `json:"consumer_group,omitempty"`
	CheckpointStore   string `json:"checkpoint_store,omitempty"` // Storage account for checkpoints
}

// DataCollectionConfig holds Data Collection Rule configuration.
type DataCollectionConfig struct {
	Enabled         bool   `json:"enabled"`
	Endpoint        string `json:"endpoint"`        // DCE endpoint
	RuleID          string `json:"rule_id"`         // DCR immutable ID
	StreamName      string `json:"stream_name"`     // Custom log stream
}

// QueryConfig holds query-related configuration.
type QueryConfig struct {
	DefaultTimespan string        `json:"default_timespan,omitempty"` // e.g., "P1D", "PT1H"
	MaxResults      int           `json:"max_results,omitempty"`
	Timeout         time.Duration `json:"timeout,omitempty"`
	ServerTimeout   string        `json:"server_timeout,omitempty"` // ISO 8601 duration
}

// DefaultConfig returns a default Sentinel configuration.
func DefaultConfig() *Config {
	return &Config{
		Base: connector.SIEMConfig{
			Type:    connector.SIEMSentinel,
			Enabled: true,
			Timeout: 60 * time.Second,
			Retry:   connector.DefaultRetryConfig(),
		},
		Query: QueryConfig{
			DefaultTimespan: "P1D",
			MaxResults:      10000,
			Timeout:         5 * time.Minute,
			ServerTimeout:   "PT5M",
		},
		APIVersion: "2023-02-01",
	}
}

// Validate validates the Sentinel configuration.
func (c *Config) Validate() error {
	if c.SubscriptionID == "" {
		return fmt.Errorf("subscription_id is required")
	}
	if c.ResourceGroup == "" {
		return fmt.Errorf("resource_group is required")
	}
	if c.WorkspaceName == "" && c.WorkspaceID == "" {
		return fmt.Errorf("workspace_name or workspace_id is required")
	}
	if c.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}

	// Validate authentication
	if !c.UseManagedIdentity {
		if c.ClientID == "" {
			return fmt.Errorf("client_id is required when not using managed identity")
		}
		if c.ClientSecret == "" {
			return fmt.Errorf("client_secret is required when not using managed identity")
		}
	}

	// Validate Event Hub config if enabled
	if c.EventHub.Enabled {
		if c.EventHub.Namespace == "" || c.EventHub.Name == "" {
			return fmt.Errorf("event_hub namespace and name are required when enabled")
		}
	}

	// Validate Data Collection config if enabled
	if c.DataCollection.Enabled {
		if c.DataCollection.Endpoint == "" || c.DataCollection.RuleID == "" {
			return fmt.Errorf("data_collection endpoint and rule_id are required when enabled")
		}
	}

	return nil
}

// GetAzureResourceManagerURL returns the Azure Resource Manager base URL.
func (c *Config) GetAzureResourceManagerURL() string {
	return "https://management.azure.com"
}

// GetLogAnalyticsURL returns the Log Analytics query URL.
func (c *Config) GetLogAnalyticsURL() string {
	return "https://api.loganalytics.io"
}

// GetSentinelResourceID returns the Sentinel workspace resource ID.
func (c *Config) GetSentinelResourceID() string {
	return fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.OperationalInsights/workspaces/%s",
		c.SubscriptionID,
		c.ResourceGroup,
		c.WorkspaceName,
	)
}

// GetIncidentsURL returns the URL for incident operations.
func (c *Config) GetIncidentsURL() string {
	return fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/incidents?api-version=%s",
		c.GetAzureResourceManagerURL(),
		c.GetSentinelResourceID(),
		c.APIVersion,
	)
}

// GetAlertRulesURL returns the URL for alert rule operations.
func (c *Config) GetAlertRulesURL() string {
	return fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/alertRules?api-version=%s",
		c.GetAzureResourceManagerURL(),
		c.GetSentinelResourceID(),
		c.APIVersion,
	)
}

// GetQueryURL returns the URL for Log Analytics queries.
func (c *Config) GetQueryURL() string {
	return fmt.Sprintf(
		"%s/v1/workspaces/%s/query",
		c.GetLogAnalyticsURL(),
		c.WorkspaceID,
	)
}
