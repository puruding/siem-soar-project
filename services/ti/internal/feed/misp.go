// Package feed provides MISP integration for threat intelligence.
package feed

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// MISPEvent represents a MISP event.
type MISPEvent struct {
	ID            string           `json:"id"`
	UUID          string           `json:"uuid"`
	Info          string           `json:"info"`
	Date          string           `json:"date"`
	ThreatLevelID string           `json:"threat_level_id"`
	Published     bool             `json:"published"`
	Analysis      string           `json:"analysis"`
	Orgc          *MISPOrg         `json:"Orgc,omitempty"`
	Org           *MISPOrg         `json:"Org,omitempty"`
	Tags          []MISPTag        `json:"Tag,omitempty"`
	Attributes    []MISPAttribute  `json:"Attribute,omitempty"`
	Objects       []MISPObject     `json:"Object,omitempty"`
	Galaxy        []MISPGalaxy     `json:"Galaxy,omitempty"`
}

// MISPOrg represents a MISP organization.
type MISPOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

// MISPTag represents a MISP tag.
type MISPTag struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Color string `json:"colour"`
}

// MISPAttribute represents a MISP attribute (IOC).
type MISPAttribute struct {
	ID               string     `json:"id"`
	EventID          string     `json:"event_id"`
	UUID             string     `json:"uuid"`
	Type             string     `json:"type"`
	Category         string     `json:"category"`
	Value            string     `json:"value"`
	Value1           string     `json:"value1,omitempty"`
	Value2           string     `json:"value2,omitempty"`
	Comment          string     `json:"comment,omitempty"`
	ToIDS            bool       `json:"to_ids"`
	FirstSeen        string     `json:"first_seen,omitempty"`
	LastSeen         string     `json:"last_seen,omitempty"`
	Timestamp        string     `json:"timestamp"`
	Distribution     string     `json:"distribution"`
	Tags             []MISPTag  `json:"Tag,omitempty"`
	Galaxy           []MISPGalaxy `json:"Galaxy,omitempty"`
}

// MISPObject represents a MISP object.
type MISPObject struct {
	ID         string          `json:"id"`
	UUID       string          `json:"uuid"`
	Name       string          `json:"name"`
	Comment    string          `json:"comment,omitempty"`
	Attributes []MISPAttribute `json:"Attribute,omitempty"`
}

// MISPGalaxy represents a MISP galaxy (e.g., MITRE ATT&CK).
type MISPGalaxy struct {
	ID          string           `json:"id"`
	UUID        string           `json:"uuid"`
	Name        string           `json:"name"`
	Type        string           `json:"type"`
	Description string           `json:"description,omitempty"`
	GalaxyCluster []MISPCluster `json:"GalaxyCluster,omitempty"`
}

// MISPCluster represents a MISP galaxy cluster.
type MISPCluster struct {
	ID          string `json:"id"`
	UUID        string `json:"uuid"`
	Type        string `json:"type"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source,omitempty"`
}

// MISPSearchRequest represents a MISP search request.
type MISPSearchRequest struct {
	ReturnFormat string      `json:"returnFormat"`
	Value        string      `json:"value,omitempty"`
	Type         interface{} `json:"type,omitempty"`
	Category     string      `json:"category,omitempty"`
	Tags         []string    `json:"tags,omitempty"`
	From         string      `json:"from,omitempty"`
	To           string      `json:"to,omitempty"`
	Last         string      `json:"last,omitempty"`
	EventID      string      `json:"eventid,omitempty"`
	Published    bool        `json:"published,omitempty"`
	ToIDS        bool        `json:"to_ids,omitempty"`
	Limit        int         `json:"limit,omitempty"`
	Page         int         `json:"page,omitempty"`
	Timestamp    string      `json:"timestamp,omitempty"`
}

// MISPSearchResponse represents a MISP search response.
type MISPSearchResponse struct {
	Response []struct {
		Event MISPEvent `json:"Event"`
	} `json:"response"`
	Attribute []MISPAttribute `json:"Attribute,omitempty"`
}

// MISPClient implements a MISP API client.
type MISPClient struct {
	client *http.Client
	logger *slog.Logger
}

// NewMISPClient creates a new MISP client.
func NewMISPClient(logger *slog.Logger) *MISPClient {
	return &MISPClient{
		client: &http.Client{Timeout: 5 * time.Minute},
		logger: logger.With("component", "misp-client"),
	}
}

// Fetch fetches IOCs from a MISP instance.
func (c *MISPClient) Fetch(ctx context.Context, feed *Feed, lastSync time.Time) ([]*IOC, error) {
	// Build search request
	searchReq := MISPSearchRequest{
		ReturnFormat: "json",
		Published:    true,
		ToIDS:        true,
		Limit:        10000,
	}

	// Add time filter
	if !lastSync.IsZero() {
		searchReq.Timestamp = fmt.Sprintf("%d", lastSync.Unix())
	}

	// Add type filter
	if len(feed.IOCTypes) > 0 {
		mispTypes := c.mapIOCTypesToMISP(feed.IOCTypes)
		if len(mispTypes) > 0 {
			searchReq.Type = mispTypes
		}
	}

	// Add tag filter
	if len(feed.Tags) > 0 {
		searchReq.Tags = feed.Tags
	}

	// Fetch attributes
	attributes, err := c.searchAttributes(ctx, feed, searchReq)
	if err != nil {
		return nil, err
	}

	// Convert to IOCs
	var iocs []*IOC
	for _, attr := range attributes {
		ioc := c.attributeToIOC(&attr, feed.ID)
		if ioc != nil {
			iocs = append(iocs, ioc)
		}
	}

	c.logger.Info("fetched IOCs from MISP", "count", len(iocs))
	return iocs, nil
}

// Test tests connectivity to a MISP instance.
func (c *MISPClient) Test(ctx context.Context, feed *Feed) error {
	// Try to get server info
	url := strings.TrimSuffix(feed.URL, "/") + "/servers/getVersion.json"

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	c.addAuthHeaders(req, feed)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to connect to MISP: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}

	return nil
}

// SearchAttributes searches for attributes in MISP.
func (c *MISPClient) SearchAttributes(ctx context.Context, feed *Feed, value string, attrType string) ([]MISPAttribute, error) {
	searchReq := MISPSearchRequest{
		ReturnFormat: "json",
		Value:        value,
		Type:         attrType,
		ToIDS:        true,
	}

	return c.searchAttributes(ctx, feed, searchReq)
}

// GetEvent gets a specific MISP event.
func (c *MISPClient) GetEvent(ctx context.Context, feed *Feed, eventID string) (*MISPEvent, error) {
	url := strings.TrimSuffix(feed.URL, "/") + "/events/view/" + eventID

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, feed)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MISP returned status %d", resp.StatusCode)
	}

	var result struct {
		Event MISPEvent `json:"Event"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result.Event, nil
}

// SearchEvents searches for events in MISP.
func (c *MISPClient) SearchEvents(ctx context.Context, feed *Feed, searchReq MISPSearchRequest) ([]MISPEvent, error) {
	url := strings.TrimSuffix(feed.URL, "/") + "/events/restSearch"

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, feed)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MISP returned status %d: %s", resp.StatusCode, string(body))
	}

	var result MISPSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var events []MISPEvent
	for _, r := range result.Response {
		events = append(events, r.Event)
	}

	return events, nil
}

func (c *MISPClient) searchAttributes(ctx context.Context, feed *Feed, searchReq MISPSearchRequest) ([]MISPAttribute, error) {
	url := strings.TrimSuffix(feed.URL, "/") + "/attributes/restSearch"

	body, err := json.Marshal(searchReq)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	c.addAuthHeaders(req, feed)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to search MISP attributes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("MISP returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Response struct {
			Attribute []MISPAttribute `json:"Attribute"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Response.Attribute, nil
}

func (c *MISPClient) addAuthHeaders(req *http.Request, feed *Feed) {
	req.Header.Set("Authorization", feed.APIKey)
	req.Header.Set("Accept", "application/json")

	for k, v := range feed.Headers {
		req.Header.Set(k, v)
	}
}

func (c *MISPClient) attributeToIOC(attr *MISPAttribute, feedID string) *IOC {
	iocType := c.mapMISPTypeToIOC(attr.Type)
	if iocType == "" {
		return nil
	}

	ioc := &IOC{
		ID:          fmt.Sprintf("%s:%s", feedID, attr.UUID),
		Type:        IOCType(iocType),
		Value:       attr.Value,
		Source:      feedID,
		Description: attr.Comment,
		Attributes:  make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Parse timestamps
	if attr.FirstSeen != "" {
		if t, err := time.Parse(time.RFC3339, attr.FirstSeen); err == nil {
			ioc.FirstSeen = t
		}
	}
	if attr.LastSeen != "" {
		if t, err := time.Parse(time.RFC3339, attr.LastSeen); err == nil {
			ioc.LastSeen = t
		}
	}

	// Extract tags and labels
	for _, tag := range attr.Tags {
		ioc.Labels = append(ioc.Labels, tag.Name)

		// Extract TLP
		if strings.HasPrefix(strings.ToLower(tag.Name), "tlp:") {
			ioc.TLP = strings.ToUpper(strings.TrimPrefix(tag.Name, "tlp:"))
		}

		// Extract MITRE ATT&CK
		if strings.Contains(strings.ToLower(tag.Name), "mitre-attack") {
			ioc.MITREAttack = append(ioc.MITREAttack, tag.Name)
		}
	}

	// Extract MITRE from galaxies
	for _, galaxy := range attr.Galaxy {
		if galaxy.Type == "mitre-attack-pattern" || galaxy.Type == "mitre-enterprise-attack-pattern" {
			for _, cluster := range galaxy.GalaxyCluster {
				ioc.MITREAttack = append(ioc.MITREAttack, cluster.Value)
			}
		}
	}

	// Set attributes
	ioc.Attributes["misp_event_id"] = attr.EventID
	ioc.Attributes["misp_uuid"] = attr.UUID
	ioc.Attributes["misp_category"] = attr.Category
	ioc.Attributes["misp_type"] = attr.Type

	// Map threat level
	ioc.Severity = "medium" // Default

	return ioc
}

func (c *MISPClient) mapMISPTypeToIOC(mispType string) string {
	mapping := map[string]IOCType{
		"ip-src":                IOCTypeIP,
		"ip-dst":                IOCTypeIP,
		"ip-src|port":           IOCTypeIP,
		"ip-dst|port":           IOCTypeIP,
		"domain":                IOCTypeDomain,
		"hostname":              IOCTypeDomain,
		"domain|ip":             IOCTypeDomain,
		"url":                   IOCTypeURL,
		"link":                  IOCTypeURL,
		"uri":                   IOCTypeURL,
		"email":                 IOCTypeEmail,
		"email-src":             IOCTypeEmail,
		"email-dst":             IOCTypeEmail,
		"email-subject":         IOCTypeEmail,
		"email-attachment":      IOCTypeEmail,
		"md5":                   IOCTypeMD5,
		"sha1":                  IOCTypeSHA1,
		"sha256":                IOCTypeSHA256,
		"sha512":                IOCTypeHash,
		"ssdeep":                IOCTypeHash,
		"imphash":               IOCTypeHash,
		"filename|md5":          IOCTypeMD5,
		"filename|sha1":         IOCTypeSHA1,
		"filename|sha256":       IOCTypeSHA256,
		"malware-sample":        IOCTypeSHA256,
		"regkey":                IOCTypeRegistry,
		"regkey|value":          IOCTypeRegistry,
		"windows-scheduled-task": IOCTypeOther,
		"windows-service-name":  IOCTypeOther,
		"mutex":                 IOCTypeOther,
		"ja3-fingerprint-md5":   IOCTypeJA3,
	}

	if iocType, ok := mapping[mispType]; ok {
		return string(iocType)
	}
	return ""
}

func (c *MISPClient) mapIOCTypesToMISP(iocTypes []string) []string {
	var mispTypes []string

	typeMapping := map[IOCType][]string{
		IOCTypeIP:       {"ip-src", "ip-dst"},
		IOCTypeDomain:   {"domain", "hostname"},
		IOCTypeURL:      {"url", "link"},
		IOCTypeEmail:    {"email", "email-src", "email-dst"},
		IOCTypeMD5:      {"md5", "filename|md5"},
		IOCTypeSHA1:     {"sha1", "filename|sha1"},
		IOCTypeSHA256:   {"sha256", "filename|sha256", "malware-sample"},
		IOCTypeHash:     {"sha512", "ssdeep", "imphash"},
		IOCTypeRegistry: {"regkey", "regkey|value"},
	}

	for _, iocType := range iocTypes {
		if mapped, ok := typeMapping[IOCType(iocType)]; ok {
			mispTypes = append(mispTypes, mapped...)
		}
	}

	return mispTypes
}
