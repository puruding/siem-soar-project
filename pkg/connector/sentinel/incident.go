// Package sentinel provides Sentinel incident management implementation.
package sentinel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"

	"siem-soar-project/pkg/connector"
)

// Incident represents a Sentinel incident.
type Incident struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Etag       string            `json:"etag,omitempty"`
	Properties IncidentProperties `json:"properties"`
}

// IncidentProperties holds incident properties.
type IncidentProperties struct {
	Title             string        `json:"title"`
	Description       string        `json:"description,omitempty"`
	Severity          string        `json:"severity"`
	Status            string        `json:"status"`
	Classification    string        `json:"classification,omitempty"`
	ClassificationReason string     `json:"classificationReason,omitempty"`
	ClassificationComment string    `json:"classificationComment,omitempty"`
	Owner             *IncidentOwner `json:"owner,omitempty"`
	Labels            []IncidentLabel `json:"labels,omitempty"`
	IncidentNumber    int           `json:"incidentNumber"`
	IncidentURL       string        `json:"incidentUrl"`
	CreatedTimeUtc    time.Time     `json:"createdTimeUtc"`
	LastModifiedTimeUtc time.Time   `json:"lastModifiedTimeUtc"`
	FirstActivityTimeUtc time.Time  `json:"firstActivityTimeUtc,omitempty"`
	LastActivityTimeUtc time.Time   `json:"lastActivityTimeUtc,omitempty"`
	ProviderName      string        `json:"providerName,omitempty"`
	ProviderIncidentID string       `json:"providerIncidentId,omitempty"`
	RelatedAnalyticRuleIDs []string `json:"relatedAnalyticRuleIds,omitempty"`
	AdditionalData    *IncidentAdditionalData `json:"additionalData,omitempty"`
}

// IncidentOwner represents incident owner information.
type IncidentOwner struct {
	AssignedTo          string `json:"assignedTo,omitempty"`
	Email               string `json:"email,omitempty"`
	ObjectID            string `json:"objectId,omitempty"`
	OwnerType           string `json:"ownerType,omitempty"`
	UserPrincipalName   string `json:"userPrincipalName,omitempty"`
}

// IncidentLabel represents an incident label.
type IncidentLabel struct {
	LabelName string `json:"labelName"`
	LabelType string `json:"labelType,omitempty"`
}

// IncidentAdditionalData holds additional incident data.
type IncidentAdditionalData struct {
	AlertProductNames []string `json:"alertProductNames,omitempty"`
	AlertsCount       int      `json:"alertsCount"`
	BookmarksCount    int      `json:"bookmarksCount"`
	CommentsCount     int      `json:"commentsCount"`
	Tactics           []string `json:"tactics,omitempty"`
	Techniques        []string `json:"techniques,omitempty"`
}

// IncidentListResponse represents a list of incidents response.
type IncidentListResponse struct {
	Value    []Incident `json:"value"`
	NextLink string     `json:"nextLink,omitempty"`
}

// GetIncidents retrieves incidents from Sentinel.
func (c *Client) GetIncidents(ctx context.Context, filter *connector.IncidentFilter) ([]connector.Incident, error) {
	incidentsURL := c.config.GetIncidentsURL()

	// Build filter query
	params := url.Values{}
	if filter != nil {
		if len(filter.Statuses) > 0 {
			// Build OData filter
			filterStr := ""
			for i, status := range filter.Statuses {
				if i > 0 {
					filterStr += " or "
				}
				filterStr += fmt.Sprintf("properties/status eq '%s'", status)
			}
			params.Set("$filter", filterStr)
		}
		if filter.Limit > 0 {
			params.Set("$top", fmt.Sprintf("%d", filter.Limit))
		}
	}

	if len(params) > 0 {
		incidentsURL += "&" + params.Encode()
	}

	resp, err := c.doRequest(ctx, "GET", incidentsURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get incidents failed: %s - %s", resp.Status, string(body))
	}

	var listResp IncidentListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}

	// Convert to common format
	incidents := make([]connector.Incident, len(listResp.Value))
	for i, inc := range listResp.Value {
		incidents[i] = convertToCommonIncident(&inc)
	}

	return incidents, nil
}

// GetIncident retrieves a specific incident.
func (c *Client) GetIncident(ctx context.Context, incidentID string) (*connector.Incident, error) {
	incidentURL := fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/incidents/%s?api-version=%s",
		c.config.GetAzureResourceManagerURL(),
		c.config.GetSentinelResourceID(),
		url.PathEscape(incidentID),
		c.config.APIVersion,
	)

	resp, err := c.doRequest(ctx, "GET", incidentURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("incident %s not found", incidentID)
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get incident failed: %s - %s", resp.Status, string(body))
	}

	var inc Incident
	if err := json.NewDecoder(resp.Body).Decode(&inc); err != nil {
		return nil, err
	}

	result := convertToCommonIncident(&inc)
	return &result, nil
}

// UpdateIncident updates an incident.
func (c *Client) UpdateIncident(ctx context.Context, incidentID string, update *connector.IncidentUpdate) error {
	// First, get the current incident
	incidentURL := fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/incidents/%s?api-version=%s",
		c.config.GetAzureResourceManagerURL(),
		c.config.GetSentinelResourceID(),
		url.PathEscape(incidentID),
		c.config.APIVersion,
	)

	getResp, err := c.doRequest(ctx, "GET", incidentURL, nil)
	if err != nil {
		return err
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != 200 {
		body, _ := io.ReadAll(getResp.Body)
		return fmt.Errorf("get incident for update failed: %s - %s", getResp.Status, string(body))
	}

	var inc Incident
	if err := json.NewDecoder(getResp.Body).Decode(&inc); err != nil {
		return err
	}

	// Apply updates
	if update.Status != nil {
		inc.Properties.Status = string(*update.Status)
	}
	if update.Severity != nil {
		inc.Properties.Severity = string(*update.Severity)
	}
	if update.Owner != nil {
		inc.Properties.Owner = &IncidentOwner{
			AssignedTo:        update.Owner.AssignedTo,
			Email:             update.Owner.Email,
			ObjectID:          update.Owner.ObjectID,
			UserPrincipalName: update.Owner.UserPrincipalName,
			OwnerType:         update.Owner.OwnerType,
		}
	}
	if len(update.Labels) > 0 {
		inc.Properties.Labels = make([]IncidentLabel, len(update.Labels))
		for i, label := range update.Labels {
			inc.Properties.Labels[i] = IncidentLabel{
				LabelName: label.Name,
				LabelType: label.Type,
			}
		}
	}
	if update.Classification != "" {
		inc.Properties.Classification = update.Classification
	}
	if update.ClassificationReason != "" {
		inc.Properties.ClassificationReason = update.ClassificationReason
	}

	// Send update
	putResp, err := c.doJSONRequest(ctx, "PUT", incidentURL, inc)
	if err != nil {
		return err
	}
	defer putResp.Body.Close()

	if putResp.StatusCode != 200 && putResp.StatusCode != 201 {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("update incident failed: %s - %s", putResp.Status, string(body))
	}

	return nil
}

// AddIncidentComment adds a comment to an incident.
func (c *Client) AddIncidentComment(ctx context.Context, incidentID string, comment string) error {
	commentURL := fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/incidents/%s/comments/%s?api-version=%s",
		c.config.GetAzureResourceManagerURL(),
		c.config.GetSentinelResourceID(),
		url.PathEscape(incidentID),
		fmt.Sprintf("comment-%d", time.Now().UnixNano()),
		c.config.APIVersion,
	)

	body := map[string]interface{}{
		"properties": map[string]interface{}{
			"message": comment,
		},
	}

	resp, err := c.doJSONRequest(ctx, "PUT", commentURL, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("add comment failed: %s - %s", resp.Status, string(body))
	}

	return nil
}

// GetIncidentAlerts retrieves alerts associated with an incident.
func (c *Client) GetIncidentAlerts(ctx context.Context, incidentID string) ([]connector.Alert, error) {
	alertsURL := fmt.Sprintf(
		"%s%s/providers/Microsoft.SecurityInsights/incidents/%s/alerts?api-version=%s",
		c.config.GetAzureResourceManagerURL(),
		c.config.GetSentinelResourceID(),
		url.PathEscape(incidentID),
		c.config.APIVersion,
	)

	resp, err := c.doRequest(ctx, "POST", alertsURL, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("get incident alerts failed: %s - %s", resp.Status, string(body))
	}

	var alertsResp struct {
		Value []SentinelAlert `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&alertsResp); err != nil {
		return nil, err
	}

	alerts := make([]connector.Alert, len(alertsResp.Value))
	for i, alert := range alertsResp.Value {
		alerts[i] = convertToCommonAlert(&alert)
	}

	return alerts, nil
}

// SentinelAlert represents a Sentinel alert.
type SentinelAlert struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Properties AlertProperties `json:"properties"`
}

// AlertProperties holds alert properties.
type AlertProperties struct {
	AlertDisplayName      string    `json:"alertDisplayName"`
	Description           string    `json:"description,omitempty"`
	Severity              string    `json:"severity"`
	Status                string    `json:"status"`
	ProviderAlertID       string    `json:"providerAlertId"`
	VendorName            string    `json:"vendorName,omitempty"`
	ProductName           string    `json:"productName,omitempty"`
	ProductComponentName  string    `json:"productComponentName,omitempty"`
	AlertType             string    `json:"alertType,omitempty"`
	ConfidenceLevel       string    `json:"confidenceLevel,omitempty"`
	ConfidenceScore       float64   `json:"confidenceScore,omitempty"`
	ConfidenceReasons     []string  `json:"confidenceReasons,omitempty"`
	TimeGenerated         time.Time `json:"timeGenerated"`
	StartTimeUtc          time.Time `json:"startTimeUtc,omitempty"`
	EndTimeUtc            time.Time `json:"endTimeUtc,omitempty"`
	ProcessingEndTime     time.Time `json:"processingEndTime,omitempty"`
	Tactics               []string  `json:"tactics,omitempty"`
	Techniques            []string  `json:"techniques,omitempty"`
	Intent                string    `json:"intent,omitempty"`
	RemediationSteps      []string  `json:"remediationSteps,omitempty"`
	ExtendedLinks         []string  `json:"extendedLinks,omitempty"`
	Entities              []Entity  `json:"entities,omitempty"`
}

// Entity represents an entity in an alert.
type Entity struct {
	Kind       string                 `json:"kind"`
	Properties map[string]interface{} `json:"properties"`
}

// convertToCommonIncident converts a Sentinel incident to the common format.
func convertToCommonIncident(inc *Incident) connector.Incident {
	common := connector.Incident{
		ID:          inc.Name,
		Name:        inc.Properties.Title,
		Title:       inc.Properties.Title,
		Description: inc.Properties.Description,
		AlertCount:  inc.Properties.AdditionalData.AlertsCount,
		CreatedTime: inc.Properties.CreatedTimeUtc,
		LastModifiedTime: inc.Properties.LastModifiedTimeUtc,
		FirstActivityTime: inc.Properties.FirstActivityTimeUtc,
		LastActivityTime: inc.Properties.LastActivityTimeUtc,
		Classification:    inc.Properties.Classification,
		ClassificationReason: inc.Properties.ClassificationReason,
	}

	// Map severity
	switch inc.Properties.Severity {
	case "Informational":
		common.Severity = connector.AlertSeverityInformational
	case "Low":
		common.Severity = connector.AlertSeverityLow
	case "Medium":
		common.Severity = connector.AlertSeverityMedium
	case "High":
		common.Severity = connector.AlertSeverityHigh
	case "Critical":
		common.Severity = connector.AlertSeverityCritical
	}

	// Map status
	switch inc.Properties.Status {
	case "New":
		common.Status = connector.IncidentStatusNew
	case "Active":
		common.Status = connector.IncidentStatusActive
	case "Closed":
		common.Status = connector.IncidentStatusClosed
	}

	// Map owner
	if inc.Properties.Owner != nil {
		common.Owner = &connector.IncidentOwner{
			AssignedTo:        inc.Properties.Owner.AssignedTo,
			Email:             inc.Properties.Owner.Email,
			ObjectID:          inc.Properties.Owner.ObjectID,
			UserPrincipalName: inc.Properties.Owner.UserPrincipalName,
			OwnerType:         inc.Properties.Owner.OwnerType,
		}
	}

	// Map labels
	if len(inc.Properties.Labels) > 0 {
		common.Labels = make([]connector.IncidentLabel, len(inc.Properties.Labels))
		for i, label := range inc.Properties.Labels {
			common.Labels[i] = connector.IncidentLabel{
				Name: label.LabelName,
				Type: label.LabelType,
			}
		}
	}

	// Map additional data
	if inc.Properties.AdditionalData != nil {
		common.BookmarkCount = inc.Properties.AdditionalData.BookmarksCount
		common.CommentCount = inc.Properties.AdditionalData.CommentsCount
		common.Tactics = inc.Properties.AdditionalData.Tactics
	}

	return common
}

// convertToCommonAlert converts a Sentinel alert to the common format.
func convertToCommonAlert(alert *SentinelAlert) connector.Alert {
	common := connector.Alert{
		ID:          alert.Name,
		Name:        alert.Properties.AlertDisplayName,
		Description: alert.Properties.Description,
		Source:      connector.SIEMSentinel,
		Timestamp:   alert.Properties.TimeGenerated,
		Tactics:     alert.Properties.Tactics,
		Techniques:  alert.Properties.Techniques,
	}

	// Map severity
	switch alert.Properties.Severity {
	case "Informational":
		common.Severity = connector.AlertSeverityInformational
	case "Low":
		common.Severity = connector.AlertSeverityLow
	case "Medium":
		common.Severity = connector.AlertSeverityMedium
	case "High":
		common.Severity = connector.AlertSeverityHigh
	}

	// Map status
	switch alert.Properties.Status {
	case "New":
		common.Status = connector.AlertStatusNew
	case "InProgress":
		common.Status = connector.AlertStatusInProgress
	case "Resolved":
		common.Status = connector.AlertStatusResolved
	case "Closed":
		common.Status = connector.AlertStatusClosed
	}

	// Convert entities
	for _, entity := range alert.Properties.Entities {
		alertEntity := connector.AlertEntity{
			Type: entity.Kind,
		}
		if val, ok := entity.Properties["address"].(string); ok {
			alertEntity.Value = val
		} else if val, ok := entity.Properties["hostName"].(string); ok {
			alertEntity.Value = val
		} else if val, ok := entity.Properties["accountName"].(string); ok {
			alertEntity.Value = val
		}
		common.Entities = append(common.Entities, alertEntity)
	}

	return common
}
