// Package approval provides notification services for approvals.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"
)

// EmailNotifier sends email notifications for approvals.
type EmailNotifier struct {
	smtpHost     string
	smtpPort     int
	fromEmail    string
	fromName     string
	webBaseURL   string
	slackWebhook string
	teamsWebhook string
	templates    *template.Template
}

// EmailConfig contains email notification configuration.
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     int
	FromEmail    string
	FromName     string
	WebBaseURL   string
	SlackWebhook string
	TeamsWebhook string
}

// NewEmailNotifier creates a new email notifier.
func NewEmailNotifier(config EmailConfig) *EmailNotifier {
	return &EmailNotifier{
		smtpHost:     config.SMTPHost,
		smtpPort:     config.SMTPPort,
		fromEmail:    config.FromEmail,
		fromName:     config.FromName,
		webBaseURL:   config.WebBaseURL,
		slackWebhook: config.SlackWebhook,
		teamsWebhook: config.TeamsWebhook,
		templates:    loadEmailTemplates(),
	}
}

// SendApprovalRequest sends an approval request notification.
func (n *EmailNotifier) SendApprovalRequest(ctx context.Context, approver string, request *Request) error {
	// Build approval URL
	approvalURL := fmt.Sprintf("%s/approvals/%s", n.webBaseURL, request.ID)

	// Send email
	subject := fmt.Sprintf("Approval Required: %s", request.Title)
	body := n.buildApprovalRequestEmail(request, approvalURL)

	if err := n.sendEmail(ctx, approver, subject, body); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	// Send Slack notification if configured
	if n.slackWebhook != "" {
		if err := n.sendSlackNotification(ctx, request, approvalURL); err != nil {
			fmt.Printf("Failed to send Slack notification: %v\n", err)
		}
	}

	// Send Teams notification if configured
	if n.teamsWebhook != "" {
		if err := n.sendTeamsNotification(ctx, request, approvalURL); err != nil {
			fmt.Printf("Failed to send Teams notification: %v\n", err)
		}
	}

	return nil
}

// SendApprovalReminder sends a reminder for pending approvals.
func (n *EmailNotifier) SendApprovalReminder(ctx context.Context, approver string, request *Request) error {
	approvalURL := fmt.Sprintf("%s/approvals/%s", n.webBaseURL, request.ID)

	subject := fmt.Sprintf("Reminder: Approval Required - %s", request.Title)
	body := n.buildReminderEmail(request, approvalURL)

	return n.sendEmail(ctx, approver, subject, body)
}

// SendApprovalResult sends the final approval result.
func (n *EmailNotifier) SendApprovalResult(ctx context.Context, request *Request) error {
	approvalURL := fmt.Sprintf("%s/approvals/%s", n.webBaseURL, request.ID)

	var subject string
	if request.Status == StatusApproved {
		subject = fmt.Sprintf("Approved: %s", request.Title)
	} else {
		subject = fmt.Sprintf("Rejected: %s", request.Title)
	}

	body := n.buildResultEmail(request, approvalURL)

	// Send to all approvers
	for _, approver := range request.Approvers {
		if err := n.sendEmail(ctx, approver, subject, body); err != nil {
			fmt.Printf("Failed to send result email to %s: %v\n", approver, err)
		}
	}

	return nil
}

// SendEscalationNotice sends escalation notifications.
func (n *EmailNotifier) SendEscalationNotice(ctx context.Context, escalators []string, request *Request) error {
	approvalURL := fmt.Sprintf("%s/approvals/%s", n.webBaseURL, request.ID)

	subject := fmt.Sprintf("Escalated: Approval Required - %s", request.Title)
	body := n.buildEscalationEmail(request, approvalURL)

	for _, escalator := range escalators {
		if err := n.sendEmail(ctx, escalator, subject, body); err != nil {
			fmt.Printf("Failed to send escalation email to %s: %v\n", escalator, err)
		}
	}

	return nil
}

// Email template builders

func (n *EmailNotifier) buildApprovalRequestEmail(request *Request, approvalURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { background-color: #f9f9f9; padding: 20px; }
        .info-row { margin: 10px 0; }
        .label { font-weight: bold; color: #666; }
        .button { display: inline-block; padding: 12px 30px; margin: 10px 5px;
                  text-decoration: none; border-radius: 5px; font-weight: bold; }
        .approve-btn { background-color: #4CAF50; color: white; }
        .reject-btn { background-color: #f44336; color: white; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Approval Required</h2>
        </div>
        <div class="content">
            <h3>%s</h3>
            <p>%s</p>

            <div class="info-row">
                <span class="label">Priority:</span> %s
            </div>
            <div class="info-row">
                <span class="label">Type:</span> %s
            </div>
            <div class="info-row">
                <span class="label">Expires:</span> %s
            </div>

            %s

            <div style="text-align: center; margin-top: 30px;">
                <a href="%s" class="button approve-btn">Review & Approve</a>
            </div>
        </div>
        <div class="footer">
            <p>This approval request expires at %s</p>
            <p>If you did not expect this request, please contact your security team.</p>
        </div>
    </div>
</body>
</html>
	`, request.Title, request.Description, request.Priority, request.Type,
		request.ExpiresAt.Format("2006-01-02 15:04 MST"),
		n.buildContextInfo(request),
		approvalURL,
		request.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
}

func (n *EmailNotifier) buildReminderEmail(request *Request, approvalURL string) string {
	timeRemaining := time.Until(request.ExpiresAt)
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #ff9800; color: white; padding: 15px;">
            <h2>⏰ Approval Reminder</h2>
        </div>
        <div style="padding: 20px; background-color: #f9f9f9;">
            <h3>%s</h3>
            <p>This approval request is still pending your response.</p>
            <p><strong>Time Remaining:</strong> %s</p>
            <div style="text-align: center; margin-top: 20px;">
                <a href="%s" style="display: inline-block; padding: 12px 30px;
                   background-color: #ff9800; color: white; text-decoration: none;
                   border-radius: 5px; font-weight: bold;">
                   Review Now
                </a>
            </div>
        </div>
    </div>
</body>
</html>
	`, request.Title, formatDuration(timeRemaining), approvalURL)
}

func (n *EmailNotifier) buildResultEmail(request *Request, approvalURL string) string {
	var headerColor, statusText string
	if request.Status == StatusApproved {
		headerColor = "#4CAF50"
		statusText = "✅ Approved"
	} else {
		headerColor = "#f44336"
		statusText = "❌ Rejected"
	}

	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: %s; color: white; padding: 15px;">
            <h2>%s</h2>
        </div>
        <div style="padding: 20px; background-color: #f9f9f9;">
            <h3>%s</h3>
            <p><strong>Status:</strong> %s</p>
            <p><strong>Approved:</strong> %d</p>
            <p><strong>Rejected:</strong> %d</p>
            <p><strong>Completed:</strong> %s</p>

            <h4>Responses:</h4>
            %s

            <div style="text-align: center; margin-top: 20px;">
                <a href="%s" style="display: inline-block; padding: 10px 25px;
                   background-color: #2196F3; color: white; text-decoration: none;
                   border-radius: 5px;">
                   View Details
                </a>
            </div>
        </div>
    </div>
</body>
</html>
	`, headerColor, statusText, request.Title, request.Status,
		request.ApprovedCount, request.RejectedCount,
		request.CompletedAt.Format("2006-01-02 15:04:05 MST"),
		n.buildResponsesList(request.Responses),
		approvalURL)
}

func (n *EmailNotifier) buildEscalationEmail(request *Request, approvalURL string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background-color: #ff5722; color: white; padding: 15px;">
            <h2>🚨 Escalated Approval Request</h2>
        </div>
        <div style="padding: 20px; background-color: #f9f9f9;">
            <h3>%s</h3>
            <p>This approval request has been escalated to you due to timeout.</p>
            <p><strong>Escalation Level:</strong> %d</p>
            <p><strong>Original Approvers:</strong> %d</p>
            <p><strong>Expires:</strong> %s</p>

            <div style="text-align: center; margin-top: 30px;">
                <a href="%s" style="display: inline-block; padding: 12px 30px;
                   background-color: #ff5722; color: white; text-decoration: none;
                   border-radius: 5px; font-weight: bold;">
                   Review & Respond
                </a>
            </div>
        </div>
    </div>
</body>
</html>
	`, request.Title, request.EscalationLevel, len(request.Approvers),
		request.ExpiresAt.Format("2006-01-02 15:04:05 MST"), approvalURL)
}

func (n *EmailNotifier) buildContextInfo(request *Request) string {
	var html bytes.Buffer

	if request.AlertID != "" {
		html.WriteString(fmt.Sprintf(`<div class="info-row"><span class="label">Alert ID:</span> %s</div>`, request.AlertID))
	}
	if request.CaseID != "" {
		html.WriteString(fmt.Sprintf(`<div class="info-row"><span class="label">Case ID:</span> %s</div>`, request.CaseID))
	}
	if request.PlaybookName != "" {
		html.WriteString(fmt.Sprintf(`<div class="info-row"><span class="label">Playbook:</span> %s</div>`, request.PlaybookName))
	}

	return html.String()
}

func (n *EmailNotifier) buildResponsesList(responses []Response) string {
	var html bytes.Buffer
	html.WriteString(`<ul style="list-style: none; padding: 0;">`)

	for _, resp := range responses {
		icon := "✅"
		if !resp.Approved {
			icon = "❌"
		}
		html.WriteString(fmt.Sprintf(`
			<li style="margin: 10px 0; padding: 10px; background-color: white; border-left: 3px solid %s;">
				%s <strong>%s</strong> - %s
				<br><small>%s</small>
				%s
			</li>
		`, n.getResponseColor(resp.Approved), icon, resp.Approver, resp.Action,
			resp.Timestamp.Format("2006-01-02 15:04:05 MST"),
			n.formatComment(resp.Comment)))
	}

	html.WriteString(`</ul>`)
	return html.String()
}

func (n *EmailNotifier) getResponseColor(approved bool) string {
	if approved {
		return "#4CAF50"
	}
	return "#f44336"
}

func (n *EmailNotifier) formatComment(comment string) string {
	if comment == "" {
		return ""
	}
	return fmt.Sprintf(`<br><span style="color: #666; font-style: italic;">"%s"</span>`, comment)
}

// Communication methods

func (n *EmailNotifier) sendEmail(ctx context.Context, to, subject, body string) error {
	// In production, this would use an SMTP library or email service
	fmt.Printf("Sending email to %s: %s\n", to, subject)
	return nil
}

func (n *EmailNotifier) sendSlackNotification(ctx context.Context, request *Request, approvalURL string) error {
	payload := map[string]interface{}{
		"blocks": []map[string]interface{}{
			{
				"type": "header",
				"text": map[string]string{
					"type": "plain_text",
					"text": "🔔 Approval Required",
				},
			},
			{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*%s*\n%s", request.Title, request.Description),
				},
			},
			{
				"type": "section",
				"fields": []map[string]string{
					{"type": "mrkdwn", "text": fmt.Sprintf("*Priority:*\n%s", request.Priority)},
					{"type": "mrkdwn", "text": fmt.Sprintf("*Expires:*\n%s", request.ExpiresAt.Format("2006-01-02 15:04"))},
				},
			},
			{
				"type": "actions",
				"elements": []map[string]interface{}{
					{
						"type": "button",
						"text": map[string]string{"type": "plain_text", "text": "Review & Approve"},
						"url":   approvalURL,
						"style": "primary",
					},
				},
			},
		},
	}

	return n.sendWebhook(ctx, n.slackWebhook, payload)
}

func (n *EmailNotifier) sendTeamsNotification(ctx context.Context, request *Request, approvalURL string) error {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    "Approval Required",
		"themeColor": "FFA500",
		"title":      "🔔 Approval Required",
		"sections": []map[string]interface{}{
			{
				"activityTitle": request.Title,
				"activityText":  request.Description,
				"facts": []map[string]string{
					{"name": "Priority", "value": request.Priority},
					{"name": "Type", "value": string(request.Type)},
					{"name": "Expires", "value": request.ExpiresAt.Format("2006-01-02 15:04")},
				},
			},
		},
		"potentialAction": []map[string]interface{}{
			{
				"@type": "OpenUri",
				"name":  "Review & Approve",
				"targets": []map[string]string{
					{"os": "default", "uri": approvalURL},
				},
			},
		},
	}

	return n.sendWebhook(ctx, n.teamsWebhook, payload)
}

func (n *EmailNotifier) sendWebhook(ctx context.Context, webhookURL string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", webhookURL, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

func loadEmailTemplates() *template.Template {
	// In production, load from files
	return template.New("email")
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "Expired"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}
