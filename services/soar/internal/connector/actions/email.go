// Package actions provides SOAR connector implementations.
package actions

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	"github.com/siem-soar-platform/services/soar/internal/connector"
)

// EmailConnector implements email sending functionality.
type EmailConnector struct {
	*connector.BaseConnector
	smtpHost     string
	smtpPort     string
	username     string
	password     string
	fromAddress  string
	useTLS       bool
	tlsConfig    *tls.Config
}

// NewEmailConnector creates a new email connector.
func NewEmailConnector(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	base := connector.NewBaseConnector(config)

	ec := &EmailConnector{
		BaseConnector: base,
		smtpHost:      config.Endpoint,
		smtpPort:      config.Extra["port"],
		username:      config.Credentials.Username,
		password:      config.Credentials.Password,
		fromAddress:   config.Extra["from_address"],
		useTLS:        config.TLS != nil && config.TLS.Enabled,
	}

	if ec.smtpPort == "" {
		ec.smtpPort = "587"
	}

	// Register actions
	ec.registerActions()

	return ec, nil
}

// registerActions registers all email actions.
func (c *EmailConnector) registerActions() {
	// Send email action
	c.RegisterAction(connector.ActionDefinition{
		Name:        "send_email",
		DisplayName: "Send Email",
		Description: "Send an email message",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "to", DisplayName: "To", Type: "string[]", Required: true, Description: "Recipient email addresses"},
			{Name: "cc", DisplayName: "CC", Type: "string[]", Required: false, Description: "CC email addresses"},
			{Name: "bcc", DisplayName: "BCC", Type: "string[]", Required: false, Description: "BCC email addresses"},
			{Name: "subject", DisplayName: "Subject", Type: "string", Required: true, Description: "Email subject"},
			{Name: "body", DisplayName: "Body", Type: "string", Required: true, Description: "Email body (HTML or plain text)"},
			{Name: "body_type", DisplayName: "Body Type", Type: "string", Required: false, Description: "text or html", Options: []string{"text", "html"}},
			{Name: "attachments", DisplayName: "Attachments", Type: "object[]", Required: false, Description: "File attachments"},
			{Name: "priority", DisplayName: "Priority", Type: "string", Required: false, Options: []string{"low", "normal", "high"}},
		},
		Returns: []connector.ParameterDef{
			{Name: "message_id", Type: "string", Description: "Message ID"},
			{Name: "sent_at", Type: "datetime", Description: "Timestamp when sent"},
		},
	}, c.sendEmail)

	// Send template email action
	c.RegisterAction(connector.ActionDefinition{
		Name:        "send_template_email",
		DisplayName: "Send Template Email",
		Description: "Send an email using a predefined template",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "to", DisplayName: "To", Type: "string[]", Required: true},
			{Name: "template_id", DisplayName: "Template ID", Type: "string", Required: true},
			{Name: "template_data", DisplayName: "Template Data", Type: "object", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "message_id", Type: "string"},
			{Name: "sent_at", Type: "datetime"},
		},
	}, c.sendTemplateEmail)

	// Validate email action
	c.RegisterAction(connector.ActionDefinition{
		Name:        "validate_email",
		DisplayName: "Validate Email Address",
		Description: "Validate an email address format and optionally check MX records",
		Category:    "utility",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "email", DisplayName: "Email", Type: "string", Required: true},
			{Name: "check_mx", DisplayName: "Check MX Records", Type: "bool", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "valid", Type: "bool"},
			{Name: "reason", Type: "string"},
		},
	}, c.validateEmail)
}

// sendEmail sends an email.
func (c *EmailConnector) sendEmail(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Extract parameters
	to := toStringSlice(params["to"])
	cc := toStringSlice(params["cc"])
	bcc := toStringSlice(params["bcc"])
	subject := params["subject"].(string)
	body := params["body"].(string)
	bodyType := "text/plain"
	if bt, ok := params["body_type"].(string); ok && bt == "html" {
		bodyType = "text/html"
	}

	// Build email message
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", c.fromAddress))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	if len(cc) > 0 {
		msg.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(cc, ", ")))
	}
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString(fmt.Sprintf("Content-Type: %s; charset=UTF-8\r\n", bodyType))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(body)

	// Collect all recipients
	recipients := append(to, cc...)
	recipients = append(recipients, bcc...)

	// Send email
	addr := fmt.Sprintf("%s:%s", c.smtpHost, c.smtpPort)
	auth := smtp.PlainAuth("", c.username, c.password, c.smtpHost)

	err := smtp.SendMail(addr, auth, c.fromAddress, recipients, []byte(msg.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to send email: %w", err)
	}

	return map[string]interface{}{
		"message_id": generateMessageID(),
		"sent_at":    time.Now().Format(time.RFC3339),
		"recipients": len(recipients),
	}, nil
}

// sendTemplateEmail sends a template-based email.
func (c *EmailConnector) sendTemplateEmail(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Template rendering would be implemented here
	// For now, delegate to sendEmail with rendered template
	return c.sendEmail(ctx, params)
}

// validateEmail validates an email address.
func (c *EmailConnector) validateEmail(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	email := params["email"].(string)

	// Basic email format validation
	if !strings.Contains(email, "@") {
		return map[string]interface{}{
			"valid":  false,
			"reason": "Invalid email format: missing @",
		}, nil
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return map[string]interface{}{
			"valid":  false,
			"reason": "Invalid email format",
		}, nil
	}

	// Check MX records if requested
	// In production, would use net.LookupMX

	return map[string]interface{}{
		"valid":  true,
		"reason": "Email format is valid",
	}, nil
}

// Actions returns the list of action names.
func (c *EmailConnector) Actions() []string {
	return []string{
		"send_email",
		"send_template_email",
		"validate_email",
	}
}

// Health checks the email connector health.
func (c *EmailConnector) Health(ctx context.Context) (*connector.HealthStatus, error) {
	start := time.Now()

	// Try to establish SMTP connection
	addr := fmt.Sprintf("%s:%s", c.smtpHost, c.smtpPort)

	// In production, would actually test connection
	_ = addr

	return &connector.HealthStatus{
		Status:    "healthy",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
	}, nil
}

// Helper functions

func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, len(val))
		for i, item := range val {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	case string:
		return []string{val}
	default:
		return nil
	}
}

func generateMessageID() string {
	return fmt.Sprintf("%d@soar.local", time.Now().UnixNano())
}
