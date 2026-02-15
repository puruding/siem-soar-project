// Package actions provides Slack connector implementation.
package actions

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/siem-soar-platform/services/soar/internal/connector"
)

// SlackConnector implements Slack integration.
type SlackConnector struct {
	*connector.BaseConnector
	botToken   string
	webhookURL string
	httpClient *http.Client
}

// NewSlackConnector creates a new Slack connector.
func NewSlackConnector(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	base := connector.NewBaseConnector(config)

	sc := &SlackConnector{
		BaseConnector: base,
		botToken:      config.Credentials.Token,
		webhookURL:    config.Extra["webhook_url"],
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}

	sc.registerActions()
	return sc, nil
}

// registerActions registers all Slack actions.
func (c *SlackConnector) registerActions() {
	// Send message action
	c.RegisterAction(connector.ActionDefinition{
		Name:        "send_message",
		DisplayName: "Send Message",
		Description: "Send a message to a Slack channel",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "channel", DisplayName: "Channel", Type: "string", Required: true, Description: "Channel ID or name (#channel)"},
			{Name: "text", DisplayName: "Text", Type: "string", Required: true, Description: "Message text"},
			{Name: "blocks", DisplayName: "Blocks", Type: "object[]", Required: false, Description: "Block Kit blocks"},
			{Name: "attachments", DisplayName: "Attachments", Type: "object[]", Required: false, Description: "Message attachments"},
			{Name: "thread_ts", DisplayName: "Thread TS", Type: "string", Required: false, Description: "Thread timestamp for replies"},
			{Name: "unfurl_links", DisplayName: "Unfurl Links", Type: "bool", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "ts", Type: "string", Description: "Message timestamp"},
			{Name: "channel", Type: "string", Description: "Channel ID"},
		},
	}, c.sendMessage)

	// Send webhook message
	c.RegisterAction(connector.ActionDefinition{
		Name:        "send_webhook",
		DisplayName: "Send Webhook Message",
		Description: "Send a message via incoming webhook",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "text", DisplayName: "Text", Type: "string", Required: true},
			{Name: "blocks", DisplayName: "Blocks", Type: "object[]", Required: false},
			{Name: "attachments", DisplayName: "Attachments", Type: "object[]", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.sendWebhook)

	// Send alert notification
	c.RegisterAction(connector.ActionDefinition{
		Name:        "send_alert",
		DisplayName: "Send Alert Notification",
		Description: "Send a formatted security alert notification",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "channel", DisplayName: "Channel", Type: "string", Required: true},
			{Name: "alert_id", DisplayName: "Alert ID", Type: "string", Required: true},
			{Name: "title", DisplayName: "Title", Type: "string", Required: true},
			{Name: "severity", DisplayName: "Severity", Type: "string", Required: true, Options: []string{"critical", "high", "medium", "low", "informational"}},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
			{Name: "source", DisplayName: "Source", Type: "string", Required: false},
			{Name: "entities", DisplayName: "Entities", Type: "object[]", Required: false},
			{Name: "case_url", DisplayName: "Case URL", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "ts", Type: "string"},
			{Name: "channel", Type: "string"},
		},
	}, c.sendAlert)

	// Update message
	c.RegisterAction(connector.ActionDefinition{
		Name:        "update_message",
		DisplayName: "Update Message",
		Description: "Update an existing Slack message",
		Category:    "notification",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "channel", DisplayName: "Channel", Type: "string", Required: true},
			{Name: "ts", DisplayName: "Timestamp", Type: "string", Required: true},
			{Name: "text", DisplayName: "Text", Type: "string", Required: true},
			{Name: "blocks", DisplayName: "Blocks", Type: "object[]", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "ts", Type: "string"},
		},
	}, c.updateMessage)

	// Add reaction
	c.RegisterAction(connector.ActionDefinition{
		Name:        "add_reaction",
		DisplayName: "Add Reaction",
		Description: "Add an emoji reaction to a message",
		Category:    "utility",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "channel", DisplayName: "Channel", Type: "string", Required: true},
			{Name: "ts", DisplayName: "Timestamp", Type: "string", Required: true},
			{Name: "emoji", DisplayName: "Emoji", Type: "string", Required: true, Description: "Emoji name without colons"},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.addReaction)

	// Create channel
	c.RegisterAction(connector.ActionDefinition{
		Name:        "create_channel",
		DisplayName: "Create Channel",
		Description: "Create a new Slack channel",
		Category:    "management",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "name", DisplayName: "Name", Type: "string", Required: true},
			{Name: "is_private", DisplayName: "Is Private", Type: "bool", Required: false},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "channel_id", Type: "string"},
			{Name: "channel_name", Type: "string"},
		},
	}, c.createChannel)

	// Lookup user
	c.RegisterAction(connector.ActionDefinition{
		Name:        "lookup_user",
		DisplayName: "Lookup User",
		Description: "Look up a Slack user by email",
		Category:    "utility",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "email", DisplayName: "Email", Type: "string", Required: true},
		},
		Returns: []connector.ParameterDef{
			{Name: "user_id", Type: "string"},
			{Name: "display_name", Type: "string"},
			{Name: "real_name", Type: "string"},
		},
	}, c.lookupUser)
}

// sendMessage sends a message to a Slack channel.
func (c *SlackConnector) sendMessage(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"channel": params["channel"],
		"text":    params["text"],
	}

	if blocks, ok := params["blocks"]; ok {
		payload["blocks"] = blocks
	}
	if attachments, ok := params["attachments"]; ok {
		payload["attachments"] = attachments
	}
	if threadTS, ok := params["thread_ts"]; ok {
		payload["thread_ts"] = threadTS
	}

	result, err := c.slackAPI(ctx, "chat.postMessage", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ts":      result["ts"],
		"channel": result["channel"],
	}, nil
}

// sendWebhook sends a message via webhook.
func (c *SlackConnector) sendWebhook(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	if c.webhookURL == "" {
		return nil, fmt.Errorf("webhook URL not configured")
	}

	payload, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.webhookURL, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("webhook failed with status %d: %s", resp.StatusCode, string(body))
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// sendAlert sends a formatted security alert.
func (c *SlackConnector) sendAlert(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	severity := params["severity"].(string)
	title := params["title"].(string)
	alertID := params["alert_id"].(string)

	// Build blocks for formatted alert
	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type": "plain_text",
				"text": fmt.Sprintf(":rotating_light: Security Alert: %s", title),
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Alert ID:*\n%s", alertID),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Severity:*\n%s %s", severityEmoji(severity), severity),
				},
			},
		},
	}

	if desc, ok := params["description"].(string); ok && desc != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Description:*\n%s", desc),
			},
		})
	}

	if caseURL, ok := params["case_url"].(string); ok && caseURL != "" {
		blocks = append(blocks, map[string]interface{}{
			"type": "actions",
			"elements": []map[string]interface{}{
				{
					"type": "button",
					"text": map[string]interface{}{
						"type": "plain_text",
						"text": "View Case",
					},
					"url":   caseURL,
					"style": "primary",
				},
			},
		})
	}

	return c.sendMessage(ctx, map[string]interface{}{
		"channel": params["channel"],
		"text":    fmt.Sprintf("Security Alert: %s [%s]", title, severity),
		"blocks":  blocks,
	})
}

// updateMessage updates an existing message.
func (c *SlackConnector) updateMessage(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"channel": params["channel"],
		"ts":      params["ts"],
		"text":    params["text"],
	}

	if blocks, ok := params["blocks"]; ok {
		payload["blocks"] = blocks
	}

	result, err := c.slackAPI(ctx, "chat.update", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"ts": result["ts"],
	}, nil
}

// addReaction adds a reaction to a message.
func (c *SlackConnector) addReaction(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"channel":   params["channel"],
		"timestamp": params["ts"],
		"name":      params["emoji"],
	}

	_, err := c.slackAPI(ctx, "reactions.add", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// createChannel creates a new channel.
func (c *SlackConnector) createChannel(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"name": params["name"],
	}

	if isPrivate, ok := params["is_private"].(bool); ok && isPrivate {
		payload["is_private"] = true
	}

	result, err := c.slackAPI(ctx, "conversations.create", payload)
	if err != nil {
		return nil, err
	}

	channel := result["channel"].(map[string]interface{})
	return map[string]interface{}{
		"channel_id":   channel["id"],
		"channel_name": channel["name"],
	}, nil
}

// lookupUser looks up a user by email.
func (c *SlackConnector) lookupUser(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"email": params["email"],
	}

	result, err := c.slackAPI(ctx, "users.lookupByEmail", payload)
	if err != nil {
		return nil, err
	}

	user := result["user"].(map[string]interface{})
	profile := user["profile"].(map[string]interface{})

	return map[string]interface{}{
		"user_id":      user["id"],
		"display_name": profile["display_name"],
		"real_name":    profile["real_name"],
	}, nil
}

// slackAPI makes a Slack API request.
func (c *SlackConnector) slackAPI(ctx context.Context, method string, payload map[string]interface{}) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://slack.com/api/%s", method)

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.botToken))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	if ok, _ := result["ok"].(bool); !ok {
		errMsg, _ := result["error"].(string)
		return nil, fmt.Errorf("Slack API error: %s", errMsg)
	}

	return result, nil
}

// Actions returns the list of action names.
func (c *SlackConnector) Actions() []string {
	return []string{
		"send_message",
		"send_webhook",
		"send_alert",
		"update_message",
		"add_reaction",
		"create_channel",
		"lookup_user",
	}
}

// Health checks the Slack connector health.
func (c *SlackConnector) Health(ctx context.Context) (*connector.HealthStatus, error) {
	start := time.Now()

	// Test API connection
	result, err := c.slackAPI(ctx, "auth.test", map[string]interface{}{})
	if err != nil {
		return &connector.HealthStatus{
			Status:    "unhealthy",
			Message:   err.Error(),
			LastCheck: time.Now(),
			Latency:   time.Since(start),
		}, nil
	}

	return &connector.HealthStatus{
		Status:    "healthy",
		LastCheck: time.Now(),
		Latency:   time.Since(start),
		Details: map[string]interface{}{
			"team":    result["team"],
			"user":    result["user"],
			"bot_id":  result["bot_id"],
		},
	}, nil
}

// severityEmoji returns an emoji for a severity level.
func severityEmoji(severity string) string {
	switch severity {
	case "critical":
		return ":red_circle:"
	case "high":
		return ":large_orange_circle:"
	case "medium":
		return ":large_yellow_circle:"
	case "low":
		return ":large_blue_circle:"
	default:
		return ":white_circle:"
	}
}
