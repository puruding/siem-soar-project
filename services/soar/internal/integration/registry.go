// Package integration provides connector registry and factory functionality.
package integration

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/siem-soar-platform/services/soar/internal/connector"
	"github.com/siem-soar-platform/services/soar/internal/connector/actions"
)

// ConnectorFactory creates connectors from configuration.
type ConnectorFactory interface {
	Create(config *connector.ConnectorConfig) (connector.ActionConnector, error)
}

// DefaultConnectorFactory is the default implementation of ConnectorFactory.
type DefaultConnectorFactory struct {
	logger *slog.Logger
}

// NewDefaultConnectorFactory creates a new default connector factory.
func NewDefaultConnectorFactory(logger *slog.Logger) *DefaultConnectorFactory {
	return &DefaultConnectorFactory{
		logger: logger,
	}
}

// Create creates a connector from configuration.
func (f *DefaultConnectorFactory) Create(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	switch config.Type {
	case "email":
		return actions.NewEmailConnector(config)
	case "slack":
		return actions.NewSlackConnector(config)
	case "jira":
		return actions.NewJiraConnector(config)
	case "firewall":
		return actions.NewFirewallConnector(config)
	case "edr":
		return actions.NewEDRConnector(config)
	case "active_directory", "ad":
		return actions.NewADConnector(config)
	default:
		return nil, fmt.Errorf("unknown connector type: %s", config.Type)
	}
}

// Registry provides connector registration and lookup.
type Registry struct {
	hub     *Hub
	factory ConnectorFactory
	logger  *slog.Logger
}

// NewRegistry creates a new connector registry.
func NewRegistry(hub *Hub, factory ConnectorFactory, logger *slog.Logger) *Registry {
	return &Registry{
		hub:     hub,
		factory: factory,
		logger:  logger,
	}
}

// LoadConnectors loads connectors from configuration.
func (r *Registry) LoadConnectors(ctx context.Context, configs []*connector.ConnectorConfig) error {
	for _, config := range configs {
		if err := r.RegisterConnector(ctx, config); err != nil {
			r.logger.Error("Failed to register connector",
				"name", config.Name,
				"type", config.Type,
				"error", err,
			)
			continue
		}
	}

	return nil
}

// RegisterConnector registers a connector from configuration.
func (r *Registry) RegisterConnector(ctx context.Context, config *connector.ConnectorConfig) error {
	conn, err := r.factory.Create(config)
	if err != nil {
		return fmt.Errorf("failed to create connector %s: %w", config.Name, err)
	}

	if err := r.hub.RegisterConnector(config.Name, conn, config); err != nil {
		return fmt.Errorf("failed to register connector %s: %w", config.Name, err)
	}

	r.logger.Info("Registered connector",
		"name", config.Name,
		"type", config.Type,
		"enabled", config.Enabled,
	)

	return nil
}

// GetConnector returns a connector by name.
func (r *Registry) GetConnector(name string) (connector.ActionConnector, error) {
	return r.hub.GetConnector(name)
}

// ListConnectors returns all registered connectors.
func (r *Registry) ListConnectors() []string {
	connectors := r.hub.ListConnectors()
	names := make([]string, len(connectors))
	for i, c := range connectors {
		names[i] = c.Name
	}
	return names
}

// DefaultConnectorConfigs returns default connector configurations.
func DefaultConnectorConfigs() []*connector.ConnectorConfig {
	return []*connector.ConnectorConfig{
		{
			Name:        "email",
			Type:        "email",
			Description: "Email connector for sending notifications",
			Enabled:     true,
			Endpoint:    "smtp.example.com:587",
			Credentials: connector.Credentials{
				Username: "soar@example.com",
				Password: "${SMTP_PASSWORD}",
			},
			Extra: map[string]string{
				"from": "soar@example.com",
			},
		},
		{
			Name:        "slack",
			Type:        "slack",
			Description: "Slack connector for notifications and alerts",
			Enabled:     true,
			Credentials: connector.Credentials{
				APIKey: "${SLACK_BOT_TOKEN}",
			},
		},
		{
			Name:        "jira",
			Type:        "jira",
			Description: "Jira connector for ticket management",
			Enabled:     true,
			Endpoint:    "https://company.atlassian.net",
			Credentials: connector.Credentials{
				Username: "jira-service@example.com",
				Password: "${JIRA_API_TOKEN}",
			},
			Extra: map[string]string{
				"project": "SEC",
			},
		},
		{
			Name:        "palo_alto",
			Type:        "firewall",
			Description: "Palo Alto Networks firewall connector",
			Enabled:     true,
			Endpoint:    "https://firewall.example.com",
			Credentials: connector.Credentials{
				APIKey: "${PALO_ALTO_API_KEY}",
			},
			Extra: map[string]string{
				"vendor": "palo_alto",
			},
		},
		{
			Name:        "crowdstrike",
			Type:        "edr",
			Description: "CrowdStrike Falcon EDR connector",
			Enabled:     true,
			Endpoint:    "https://api.crowdstrike.com",
			Credentials: connector.Credentials{
				ClientID:     "${CROWDSTRIKE_CLIENT_ID}",
				ClientSecret: "${CROWDSTRIKE_CLIENT_SECRET}",
			},
			Extra: map[string]string{
				"vendor": "crowdstrike",
			},
		},
		{
			Name:        "active_directory",
			Type:        "active_directory",
			Description: "Active Directory connector for user management",
			Enabled:     true,
			Endpoint:    "ldaps://dc.example.com:636",
			Credentials: connector.Credentials{
				Username: "CN=SOAR Service,OU=Service Accounts,DC=example,DC=com",
				Password: "${AD_SERVICE_PASSWORD}",
			},
			Extra: map[string]string{
				"base_dn": "DC=example,DC=com",
			},
			TLS: &connector.TLSConfig{
				Enabled: true,
			},
		},
	}
}

// ConnectorTypeInfo contains information about a connector type.
type ConnectorTypeInfo struct {
	Type        string   `json:"type"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Category    string   `json:"category"`
	Actions     []string `json:"actions"`
	Required    []string `json:"required_fields"`
	Optional    []string `json:"optional_fields"`
}

// GetConnectorTypes returns information about all available connector types.
func GetConnectorTypes() []ConnectorTypeInfo {
	return []ConnectorTypeInfo{
		{
			Type:        "email",
			Name:        "Email",
			Description: "Send emails via SMTP",
			Category:    "notification",
			Actions:     []string{"send_email", "send_html_email", "send_template"},
			Required:    []string{"endpoint", "username", "password"},
			Optional:    []string{"from", "use_tls"},
		},
		{
			Type:        "slack",
			Name:        "Slack",
			Description: "Send messages to Slack channels",
			Category:    "notification",
			Actions:     []string{"send_message", "send_alert", "create_channel", "update_message"},
			Required:    []string{"api_key"},
			Optional:    []string{"default_channel"},
		},
		{
			Type:        "jira",
			Name:        "Jira",
			Description: "Create and manage Jira tickets",
			Category:    "ticketing",
			Actions:     []string{"create_issue", "update_issue", "add_comment", "search_issues", "get_issue"},
			Required:    []string{"endpoint", "username", "api_key"},
			Optional:    []string{"project", "default_assignee"},
		},
		{
			Type:        "firewall",
			Name:        "Firewall",
			Description: "Manage firewall rules",
			Category:    "containment",
			Actions:     []string{"block_ip", "unblock_ip", "block_domain", "unblock_domain", "list_rules", "create_rule"},
			Required:    []string{"endpoint", "api_key", "vendor"},
			Optional:    []string{"verify_ssl"},
		},
		{
			Type:        "edr",
			Name:        "EDR",
			Description: "Endpoint Detection and Response",
			Category:    "containment",
			Actions:     []string{"isolate_host", "unisolate_host", "kill_process", "scan_host", "get_host_info", "search_hosts"},
			Required:    []string{"endpoint", "client_id", "client_secret", "vendor"},
			Optional:    []string{"verify_ssl"},
		},
		{
			Type:        "active_directory",
			Name:        "Active Directory",
			Description: "Manage AD users and groups",
			Category:    "identity",
			Actions:     []string{"disable_user", "enable_user", "reset_password", "get_user_info", "add_to_group", "remove_from_group"},
			Required:    []string{"endpoint", "username", "password", "base_dn"},
			Optional:    []string{"use_tls"},
		},
	}
}

// ValidateConnectorConfig validates a connector configuration.
func ValidateConnectorConfig(config *connector.ConnectorConfig) error {
	if config.Name == "" {
		return fmt.Errorf("connector name is required")
	}
	if config.Type == "" {
		return fmt.Errorf("connector type is required")
	}

	// Get type info
	typeInfos := GetConnectorTypes()
	var typeInfo *ConnectorTypeInfo
	for _, ti := range typeInfos {
		if ti.Type == config.Type {
			typeInfo = &ti
			break
		}
	}

	if typeInfo == nil {
		return fmt.Errorf("unknown connector type: %s", config.Type)
	}

	// Validate required fields
	for _, field := range typeInfo.Required {
		switch field {
		case "endpoint":
			if config.Endpoint == "" {
				return fmt.Errorf("endpoint is required for %s connector", config.Type)
			}
		case "username":
			if config.Credentials.Username == "" {
				return fmt.Errorf("username is required for %s connector", config.Type)
			}
		case "password":
			if config.Credentials.Password == "" {
				return fmt.Errorf("password is required for %s connector", config.Type)
			}
		case "api_key":
			if config.Credentials.APIKey == "" {
				return fmt.Errorf("api_key is required for %s connector", config.Type)
			}
		case "client_id":
			if config.Credentials.ClientID == "" {
				return fmt.Errorf("client_id is required for %s connector", config.Type)
			}
		case "client_secret":
			if config.Credentials.ClientSecret == "" {
				return fmt.Errorf("client_secret is required for %s connector", config.Type)
			}
		case "vendor":
			if config.Extra == nil || config.Extra["vendor"] == "" {
				return fmt.Errorf("vendor is required for %s connector", config.Type)
			}
		case "base_dn":
			if config.Extra == nil || config.Extra["base_dn"] == "" {
				return fmt.Errorf("base_dn is required for %s connector", config.Type)
			}
		}
	}

	return nil
}
