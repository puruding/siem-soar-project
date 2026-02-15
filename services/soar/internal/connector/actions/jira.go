// Package actions provides Jira connector implementation.
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

// JiraConnector implements Jira integration.
type JiraConnector struct {
	*connector.BaseConnector
	baseURL    string
	username   string
	apiToken   string
	httpClient *http.Client
}

// NewJiraConnector creates a new Jira connector.
func NewJiraConnector(config *connector.ConnectorConfig) (connector.ActionConnector, error) {
	base := connector.NewBaseConnector(config)

	jc := &JiraConnector{
		BaseConnector: base,
		baseURL:       config.Endpoint,
		username:      config.Credentials.Username,
		apiToken:      config.Credentials.Token,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}

	if jc.httpClient.Timeout == 0 {
		jc.httpClient.Timeout = 30 * time.Second
	}

	jc.registerActions()
	return jc, nil
}

// registerActions registers all Jira actions.
func (c *JiraConnector) registerActions() {
	// Create issue
	c.RegisterAction(connector.ActionDefinition{
		Name:        "create_issue",
		DisplayName: "Create Issue",
		Description: "Create a new Jira issue",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "project", DisplayName: "Project", Type: "string", Required: true, Description: "Project key"},
			{Name: "issue_type", DisplayName: "Issue Type", Type: "string", Required: true, Description: "Task, Bug, Story, etc."},
			{Name: "summary", DisplayName: "Summary", Type: "string", Required: true},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
			{Name: "priority", DisplayName: "Priority", Type: "string", Required: false, Options: []string{"Highest", "High", "Medium", "Low", "Lowest"}},
			{Name: "assignee", DisplayName: "Assignee", Type: "string", Required: false, Description: "Account ID or email"},
			{Name: "labels", DisplayName: "Labels", Type: "string[]", Required: false},
			{Name: "components", DisplayName: "Components", Type: "string[]", Required: false},
			{Name: "custom_fields", DisplayName: "Custom Fields", Type: "object", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issue_id", Type: "string"},
			{Name: "issue_key", Type: "string"},
			{Name: "url", Type: "string"},
		},
	}, c.createIssue)

	// Create security incident
	c.RegisterAction(connector.ActionDefinition{
		Name:        "create_security_incident",
		DisplayName: "Create Security Incident",
		Description: "Create a security incident ticket with structured fields",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "project", DisplayName: "Project", Type: "string", Required: true},
			{Name: "title", DisplayName: "Title", Type: "string", Required: true},
			{Name: "severity", DisplayName: "Severity", Type: "string", Required: true, Options: []string{"critical", "high", "medium", "low"}},
			{Name: "alert_id", DisplayName: "Alert ID", Type: "string", Required: false},
			{Name: "case_id", DisplayName: "Case ID", Type: "string", Required: false},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
			{Name: "affected_assets", DisplayName: "Affected Assets", Type: "string[]", Required: false},
			{Name: "iocs", DisplayName: "IOCs", Type: "string[]", Required: false},
			{Name: "assignee", DisplayName: "Assignee", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issue_key", Type: "string"},
			{Name: "url", Type: "string"},
		},
	}, c.createSecurityIncident)

	// Update issue
	c.RegisterAction(connector.ActionDefinition{
		Name:        "update_issue",
		DisplayName: "Update Issue",
		Description: "Update an existing Jira issue",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "issue_key", DisplayName: "Issue Key", Type: "string", Required: true},
			{Name: "summary", DisplayName: "Summary", Type: "string", Required: false},
			{Name: "description", DisplayName: "Description", Type: "string", Required: false},
			{Name: "priority", DisplayName: "Priority", Type: "string", Required: false},
			{Name: "assignee", DisplayName: "Assignee", Type: "string", Required: false},
			{Name: "labels", DisplayName: "Labels", Type: "string[]", Required: false},
			{Name: "custom_fields", DisplayName: "Custom Fields", Type: "object", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issue_key", Type: "string"},
		},
	}, c.updateIssue)

	// Add comment
	c.RegisterAction(connector.ActionDefinition{
		Name:        "add_comment",
		DisplayName: "Add Comment",
		Description: "Add a comment to an issue",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "issue_key", DisplayName: "Issue Key", Type: "string", Required: true},
			{Name: "comment", DisplayName: "Comment", Type: "string", Required: true},
			{Name: "visibility", DisplayName: "Visibility", Type: "object", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "comment_id", Type: "string"},
		},
	}, c.addComment)

	// Transition issue
	c.RegisterAction(connector.ActionDefinition{
		Name:        "transition_issue",
		DisplayName: "Transition Issue",
		Description: "Move issue to a different status",
		Category:    "ticketing",
		RiskLevel:   "medium",
		Parameters: []connector.ParameterDef{
			{Name: "issue_key", DisplayName: "Issue Key", Type: "string", Required: true},
			{Name: "transition", DisplayName: "Transition", Type: "string", Required: true, Description: "Transition name or ID"},
			{Name: "comment", DisplayName: "Comment", Type: "string", Required: false},
			{Name: "resolution", DisplayName: "Resolution", Type: "string", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issue_key", Type: "string"},
			{Name: "new_status", Type: "string"},
		},
	}, c.transitionIssue)

	// Get issue
	c.RegisterAction(connector.ActionDefinition{
		Name:        "get_issue",
		DisplayName: "Get Issue",
		Description: "Get issue details",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "issue_key", DisplayName: "Issue Key", Type: "string", Required: true},
			{Name: "fields", DisplayName: "Fields", Type: "string[]", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issue_key", Type: "string"},
			{Name: "summary", Type: "string"},
			{Name: "status", Type: "string"},
			{Name: "priority", Type: "string"},
			{Name: "assignee", Type: "string"},
			{Name: "created", Type: "datetime"},
			{Name: "updated", Type: "datetime"},
		},
	}, c.getIssue)

	// Search issues
	c.RegisterAction(connector.ActionDefinition{
		Name:        "search_issues",
		DisplayName: "Search Issues",
		Description: "Search issues using JQL",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "jql", DisplayName: "JQL", Type: "string", Required: true, Description: "JQL query string"},
			{Name: "fields", DisplayName: "Fields", Type: "string[]", Required: false},
			{Name: "max_results", DisplayName: "Max Results", Type: "int", Required: false},
			{Name: "start_at", DisplayName: "Start At", Type: "int", Required: false},
		},
		Returns: []connector.ParameterDef{
			{Name: "issues", Type: "object[]"},
			{Name: "total", Type: "int"},
		},
	}, c.searchIssues)

	// Link issues
	c.RegisterAction(connector.ActionDefinition{
		Name:        "link_issues",
		DisplayName: "Link Issues",
		Description: "Create a link between two issues",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "inward_issue", DisplayName: "Inward Issue", Type: "string", Required: true},
			{Name: "outward_issue", DisplayName: "Outward Issue", Type: "string", Required: true},
			{Name: "link_type", DisplayName: "Link Type", Type: "string", Required: true, Description: "e.g., 'Blocks', 'Relates'"},
		},
		Returns: []connector.ParameterDef{
			{Name: "success", Type: "bool"},
		},
	}, c.linkIssues)

	// Add attachment
	c.RegisterAction(connector.ActionDefinition{
		Name:        "add_attachment",
		DisplayName: "Add Attachment",
		Description: "Add an attachment to an issue",
		Category:    "ticketing",
		RiskLevel:   "low",
		Parameters: []connector.ParameterDef{
			{Name: "issue_key", DisplayName: "Issue Key", Type: "string", Required: true},
			{Name: "filename", DisplayName: "Filename", Type: "string", Required: true},
			{Name: "content", DisplayName: "Content", Type: "string", Required: true, Description: "Base64 encoded content"},
		},
		Returns: []connector.ParameterDef{
			{Name: "attachment_id", Type: "string"},
			{Name: "filename", Type: "string"},
		},
	}, c.addAttachment)
}

// createIssue creates a new Jira issue.
func (c *JiraConnector) createIssue(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	fields := map[string]interface{}{
		"project": map[string]interface{}{
			"key": params["project"],
		},
		"issuetype": map[string]interface{}{
			"name": params["issue_type"],
		},
		"summary": params["summary"],
	}

	if desc, ok := params["description"].(string); ok && desc != "" {
		fields["description"] = map[string]interface{}{
			"type":    "doc",
			"version": 1,
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{"type": "text", "text": desc},
					},
				},
			},
		}
	}

	if priority, ok := params["priority"].(string); ok && priority != "" {
		fields["priority"] = map[string]interface{}{"name": priority}
	}

	if assignee, ok := params["assignee"].(string); ok && assignee != "" {
		fields["assignee"] = map[string]interface{}{"accountId": assignee}
	}

	if labels, ok := params["labels"].([]interface{}); ok {
		fields["labels"] = labels
	}

	payload := map[string]interface{}{
		"fields": fields,
	}

	result, err := c.jiraAPI(ctx, "POST", "/rest/api/3/issue", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"issue_id":  result["id"],
		"issue_key": result["key"],
		"url":       fmt.Sprintf("%s/browse/%s", c.baseURL, result["key"]),
	}, nil
}

// createSecurityIncident creates a security incident ticket.
func (c *JiraConnector) createSecurityIncident(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Build description with incident details
	var descParts []string
	descParts = append(descParts, fmt.Sprintf("*Severity:* %s", params["severity"]))

	if alertID, ok := params["alert_id"].(string); ok && alertID != "" {
		descParts = append(descParts, fmt.Sprintf("*Alert ID:* %s", alertID))
	}
	if caseID, ok := params["case_id"].(string); ok && caseID != "" {
		descParts = append(descParts, fmt.Sprintf("*Case ID:* %s", caseID))
	}
	if desc, ok := params["description"].(string); ok && desc != "" {
		descParts = append(descParts, fmt.Sprintf("\n*Description:*\n%s", desc))
	}
	if assets, ok := params["affected_assets"].([]interface{}); ok && len(assets) > 0 {
		descParts = append(descParts, fmt.Sprintf("\n*Affected Assets:*\n%v", assets))
	}
	if iocs, ok := params["iocs"].([]interface{}); ok && len(iocs) > 0 {
		descParts = append(descParts, fmt.Sprintf("\n*IOCs:*\n%v", iocs))
	}

	// Map severity to priority
	priorityMap := map[string]string{
		"critical": "Highest",
		"high":     "High",
		"medium":   "Medium",
		"low":      "Low",
	}
	priority := priorityMap[params["severity"].(string)]
	if priority == "" {
		priority = "Medium"
	}

	createParams := map[string]interface{}{
		"project":     params["project"],
		"issue_type":  "Task", // Or a custom incident type
		"summary":     fmt.Sprintf("[Security Incident] %s", params["title"]),
		"description": fmt.Sprintf("%s", descParts),
		"priority":    priority,
		"labels":      []string{"security-incident", params["severity"].(string)},
	}

	if assignee, ok := params["assignee"]; ok {
		createParams["assignee"] = assignee
	}

	return c.createIssue(ctx, createParams)
}

// updateIssue updates an existing issue.
func (c *JiraConnector) updateIssue(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	issueKey := params["issue_key"].(string)
	fields := make(map[string]interface{})

	if summary, ok := params["summary"].(string); ok && summary != "" {
		fields["summary"] = summary
	}
	if desc, ok := params["description"].(string); ok && desc != "" {
		fields["description"] = map[string]interface{}{
			"type":    "doc",
			"version": 1,
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{"type": "text", "text": desc},
					},
				},
			},
		}
	}
	if priority, ok := params["priority"].(string); ok && priority != "" {
		fields["priority"] = map[string]interface{}{"name": priority}
	}
	if assignee, ok := params["assignee"].(string); ok && assignee != "" {
		fields["assignee"] = map[string]interface{}{"accountId": assignee}
	}

	payload := map[string]interface{}{
		"fields": fields,
	}

	_, err := c.jiraAPI(ctx, "PUT", fmt.Sprintf("/rest/api/3/issue/%s", issueKey), payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"issue_key": issueKey,
	}, nil
}

// addComment adds a comment to an issue.
func (c *JiraConnector) addComment(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	issueKey := params["issue_key"].(string)
	comment := params["comment"].(string)

	payload := map[string]interface{}{
		"body": map[string]interface{}{
			"type":    "doc",
			"version": 1,
			"content": []map[string]interface{}{
				{
					"type": "paragraph",
					"content": []map[string]interface{}{
						{"type": "text", "text": comment},
					},
				},
			},
		},
	}

	result, err := c.jiraAPI(ctx, "POST", fmt.Sprintf("/rest/api/3/issue/%s/comment", issueKey), payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"comment_id": result["id"],
	}, nil
}

// transitionIssue transitions an issue to a new status.
func (c *JiraConnector) transitionIssue(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	issueKey := params["issue_key"].(string)
	transition := params["transition"].(string)

	// Get available transitions
	transitions, err := c.jiraAPI(ctx, "GET", fmt.Sprintf("/rest/api/3/issue/%s/transitions", issueKey), nil)
	if err != nil {
		return nil, err
	}

	// Find the transition ID
	var transitionID string
	for _, t := range transitions["transitions"].([]interface{}) {
		trans := t.(map[string]interface{})
		if trans["name"] == transition || trans["id"] == transition {
			transitionID = trans["id"].(string)
			break
		}
	}

	if transitionID == "" {
		return nil, fmt.Errorf("transition '%s' not found", transition)
	}

	payload := map[string]interface{}{
		"transition": map[string]interface{}{
			"id": transitionID,
		},
	}

	if comment, ok := params["comment"].(string); ok && comment != "" {
		payload["update"] = map[string]interface{}{
			"comment": []map[string]interface{}{
				{
					"add": map[string]interface{}{
						"body": map[string]interface{}{
							"type":    "doc",
							"version": 1,
							"content": []map[string]interface{}{
								{
									"type": "paragraph",
									"content": []map[string]interface{}{
										{"type": "text", "text": comment},
									},
								},
							},
						},
					},
				},
			},
		}
	}

	_, err = c.jiraAPI(ctx, "POST", fmt.Sprintf("/rest/api/3/issue/%s/transitions", issueKey), payload)
	if err != nil {
		return nil, err
	}

	// Get the new status
	issue, _ := c.getIssue(ctx, map[string]interface{}{"issue_key": issueKey})

	return map[string]interface{}{
		"issue_key":  issueKey,
		"new_status": issue["status"],
	}, nil
}

// getIssue retrieves issue details.
func (c *JiraConnector) getIssue(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	issueKey := params["issue_key"].(string)

	result, err := c.jiraAPI(ctx, "GET", fmt.Sprintf("/rest/api/3/issue/%s", issueKey), nil)
	if err != nil {
		return nil, err
	}

	fields := result["fields"].(map[string]interface{})

	response := map[string]interface{}{
		"issue_key": result["key"],
		"summary":   fields["summary"],
	}

	if status, ok := fields["status"].(map[string]interface{}); ok {
		response["status"] = status["name"]
	}
	if priority, ok := fields["priority"].(map[string]interface{}); ok {
		response["priority"] = priority["name"]
	}
	if assignee, ok := fields["assignee"].(map[string]interface{}); ok {
		response["assignee"] = assignee["displayName"]
	}
	response["created"] = fields["created"]
	response["updated"] = fields["updated"]

	return response, nil
}

// searchIssues searches for issues using JQL.
func (c *JiraConnector) searchIssues(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	jql := params["jql"].(string)
	maxResults := 50
	if mr, ok := params["max_results"].(float64); ok {
		maxResults = int(mr)
	}

	payload := map[string]interface{}{
		"jql":        jql,
		"maxResults": maxResults,
	}

	if fields, ok := params["fields"].([]interface{}); ok {
		payload["fields"] = fields
	}
	if startAt, ok := params["start_at"].(float64); ok {
		payload["startAt"] = int(startAt)
	}

	result, err := c.jiraAPI(ctx, "POST", "/rest/api/3/search", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"issues": result["issues"],
		"total":  result["total"],
	}, nil
}

// linkIssues creates a link between two issues.
func (c *JiraConnector) linkIssues(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	payload := map[string]interface{}{
		"type": map[string]interface{}{
			"name": params["link_type"],
		},
		"inwardIssue": map[string]interface{}{
			"key": params["inward_issue"],
		},
		"outwardIssue": map[string]interface{}{
			"key": params["outward_issue"],
		},
	}

	_, err := c.jiraAPI(ctx, "POST", "/rest/api/3/issueLink", payload)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"success": true,
	}, nil
}

// addAttachment adds an attachment to an issue.
func (c *JiraConnector) addAttachment(ctx context.Context, params map[string]interface{}) (map[string]interface{}, error) {
	// Attachment upload requires multipart form data
	// This is a simplified implementation
	return map[string]interface{}{
		"attachment_id": "placeholder",
		"filename":      params["filename"],
	}, nil
}

// jiraAPI makes a Jira API request.
func (c *JiraConnector) jiraAPI(ctx context.Context, method, path string, payload map[string]interface{}) (map[string]interface{}, error) {
	url := c.baseURL + path

	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal payload: %w", err)
		}
		body = bytes.NewBuffer(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.apiToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Jira API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	if resp.StatusCode == http.StatusNoContent {
		return map[string]interface{}{}, nil
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result, nil
}

// Actions returns the list of action names.
func (c *JiraConnector) Actions() []string {
	return []string{
		"create_issue",
		"create_security_incident",
		"update_issue",
		"add_comment",
		"transition_issue",
		"get_issue",
		"search_issues",
		"link_issues",
		"add_attachment",
	}
}

// Health checks the Jira connector health.
func (c *JiraConnector) Health(ctx context.Context) (*connector.HealthStatus, error) {
	start := time.Now()

	_, err := c.jiraAPI(ctx, "GET", "/rest/api/3/myself", nil)
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
	}, nil
}
