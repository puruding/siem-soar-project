// Package feed provides STIX 2.1 parsing capabilities.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// STIXBundle represents a STIX 2.1 bundle.
type STIXBundle struct {
	Type    string        `json:"type"`
	ID      string        `json:"id"`
	Objects []STIXObject  `json:"objects"`
}

// STIXObject represents a STIX 2.1 object.
type STIXObject struct {
	Type                 string                 `json:"type"`
	ID                   string                 `json:"id"`
	SpecVersion          string                 `json:"spec_version,omitempty"`
	Created              time.Time              `json:"created"`
	Modified             time.Time              `json:"modified"`
	Name                 string                 `json:"name,omitempty"`
	Description          string                 `json:"description,omitempty"`
	Pattern              string                 `json:"pattern,omitempty"`
	PatternType          string                 `json:"pattern_type,omitempty"`
	ValidFrom            time.Time              `json:"valid_from,omitempty"`
	ValidUntil           time.Time              `json:"valid_until,omitempty"`
	KillChainPhases      []KillChainPhase       `json:"kill_chain_phases,omitempty"`
	Labels               []string               `json:"labels,omitempty"`
	Confidence           int                    `json:"confidence,omitempty"`
	ExternalReferences   []ExternalReference    `json:"external_references,omitempty"`
	ObjectMarkingRefs    []string               `json:"object_marking_refs,omitempty"`
	GranularMarkings     []GranularMarking      `json:"granular_markings,omitempty"`

	// Indicator specific
	IndicatorTypes       []string               `json:"indicator_types,omitempty"`

	// Observable specific
	Value                string                 `json:"value,omitempty"`
	Hashes               map[string]string      `json:"hashes,omitempty"`

	// Relationship specific
	RelationshipType     string                 `json:"relationship_type,omitempty"`
	SourceRef            string                 `json:"source_ref,omitempty"`
	TargetRef            string                 `json:"target_ref,omitempty"`

	// Attack Pattern specific
	Aliases              []string               `json:"aliases,omitempty"`

	// Malware specific
	MalwareTypes         []string               `json:"malware_types,omitempty"`
	IsFamily             bool                   `json:"is_family,omitempty"`

	// Raw data for custom handling
	Raw                  map[string]interface{} `json:"-"`
}

// KillChainPhase represents a MITRE ATT&CK kill chain phase.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// ExternalReference is defined in ioc.go

// GranularMarking represents granular TLP marking.
type GranularMarking struct {
	MarkingRef string   `json:"marking_ref"`
	Selectors  []string `json:"selectors"`
}

// STIXParser parses STIX 2.1 formatted threat intelligence.
type STIXParser struct {
	client *http.Client
	logger *slog.Logger
}

// NewSTIXParser creates a new STIX parser.
func NewSTIXParser(logger *slog.Logger) *STIXParser {
	return &STIXParser{
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger.With("component", "stix-parser"),
	}
}

// Fetch fetches and parses STIX data from a feed.
func (p *STIXParser) Fetch(ctx context.Context, feed *Feed, lastSync time.Time) ([]*IOC, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication
	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}
	for k, v := range feed.Headers {
		req.Header.Set(k, v)
	}

	req.Header.Set("Accept", "application/stix+json;version=2.1")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch STIX data: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return p.Parse(data, feed.ID)
}

// Test tests connectivity to a STIX feed.
func (p *STIXParser) Test(ctx context.Context, feed *Feed) error {
	req, err := http.NewRequestWithContext(ctx, "HEAD", feed.URL, nil)
	if err != nil {
		return err
	}

	if feed.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+feed.APIKey)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusMethodNotAllowed {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil
}

// Parse parses STIX JSON data into IOCs.
func (p *STIXParser) Parse(data []byte, feedID string) ([]*IOC, error) {
	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse STIX bundle: %w", err)
	}

	if bundle.Type != "bundle" {
		return nil, fmt.Errorf("expected STIX bundle, got: %s", bundle.Type)
	}

	var iocs []*IOC

	// Build a map of objects for relationship resolution
	objectMap := make(map[string]*STIXObject)
	for i := range bundle.Objects {
		objectMap[bundle.Objects[i].ID] = &bundle.Objects[i]
	}

	// Process indicators
	for _, obj := range bundle.Objects {
		if obj.Type == "indicator" {
			parsedIOCs := p.parseIndicator(&obj, feedID, objectMap)
			iocs = append(iocs, parsedIOCs...)
		}
	}

	p.logger.Debug("parsed STIX bundle", "iocs_count", len(iocs))
	return iocs, nil
}

func (p *STIXParser) parseIndicator(obj *STIXObject, feedID string, objectMap map[string]*STIXObject) []*IOC {
	var iocs []*IOC

	// Parse STIX pattern
	if obj.Pattern != "" && obj.PatternType == "stix" {
		parsedIOCs := p.parseSTIXPattern(obj.Pattern, feedID)
		for _, ioc := range parsedIOCs {
			p.enrichIOC(ioc, obj, objectMap)
			iocs = append(iocs, ioc)
		}
	}

	return iocs
}

func (p *STIXParser) parseSTIXPattern(pattern, feedID string) []*IOC {
	var iocs []*IOC

	// STIX patterns look like: [ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'evil.com']
	// This is a simplified parser

	// Remove brackets and split by OR
	pattern = strings.TrimSpace(pattern)
	parts := strings.Split(pattern, " OR ")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, "[]")

		// Parse object:property = 'value' or object:property LIKE 'value'
		var objType, property, value string
		var operator string = "="

		if strings.Contains(part, " LIKE ") {
			operator = "LIKE"
			segments := strings.SplitN(part, " LIKE ", 2)
			objType, property = p.parseObjectProperty(segments[0])
			value = p.extractValue(segments[1])
		} else if strings.Contains(part, " = ") {
			segments := strings.SplitN(part, " = ", 2)
			objType, property = p.parseObjectProperty(segments[0])
			value = p.extractValue(segments[1])
		} else {
			continue
		}

		if value == "" {
			continue
		}

		iocType := p.mapSTIXTypeToIOCType(objType, property)
		if iocType == "" {
			continue
		}

		ioc := &IOC{
			ID:        fmt.Sprintf("%s:%s:%s", feedID, iocType, value),
			Type:      IOCType(iocType),
			Value:     value,
			Source:    feedID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		// For LIKE patterns, mark as pattern
		if operator == "LIKE" {
			ioc.Attributes["is_pattern"] = "true"
		}

		iocs = append(iocs, ioc)
	}

	return iocs
}

func (p *STIXParser) parseObjectProperty(s string) (objType, property string) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "", ""
}

func (p *STIXParser) extractValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "'\"")
	return s
}

func (p *STIXParser) mapSTIXTypeToIOCType(stixType, property string) string {
	switch stixType {
	case "ipv4-addr", "ipv6-addr":
		return string(IOCTypeIP)
	case "domain-name":
		return string(IOCTypeDomain)
	case "url":
		return string(IOCTypeURL)
	case "email-addr":
		return string(IOCTypeEmail)
	case "file":
		switch property {
		case "hashes.MD5", "hashes.'MD5'":
			return string(IOCTypeMD5)
		case "hashes.SHA-1", "hashes.'SHA-1'":
			return string(IOCTypeSHA1)
		case "hashes.SHA-256", "hashes.'SHA-256'":
			return string(IOCTypeSHA256)
		default:
			return string(IOCTypeSHA256) // Default to SHA256
		}
	case "windows-registry-key":
		return string(IOCTypeRegistry)
	default:
		return ""
	}
}

func (p *STIXParser) enrichIOC(ioc *IOC, obj *STIXObject, objectMap map[string]*STIXObject) {
	// ioc.Name = obj.Name  // IOC doesn't have Name field
	ioc.Description = obj.Description
	ioc.Confidence = obj.Confidence
	ioc.ValidFrom = obj.ValidFrom
	ioc.ValidUntil = obj.ValidUntil
	ioc.Labels = obj.Labels

	if ioc.Attributes == nil {
		ioc.Attributes = make(map[string]interface{})
	}

	// Extract MITRE ATT&CK references
	for _, phase := range obj.KillChainPhases {
		if phase.KillChainName == "mitre-attack" {
			ioc.MITREAttack = append(ioc.MITREAttack, phase.PhaseName)
		}
	}

	// Extract external references
	for _, ref := range obj.ExternalReferences {
		if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
			ioc.MITREAttack = append(ioc.MITREAttack, ref.ExternalID)
		}
	}

	// Extract indicator types
	for _, indType := range obj.IndicatorTypes {
		switch indType {
		case "malicious-activity":
			ioc.ThreatType = "malware"
		case "anomalous-activity":
			ioc.ThreatType = "suspicious"
		case "compromised":
			ioc.ThreatType = "compromised"
		case "attribution":
			ioc.ThreatType = "apt"
		}
	}

	// Map confidence to severity
	if ioc.Confidence >= 80 {
		ioc.Severity = "critical"
	} else if ioc.Confidence >= 60 {
		ioc.Severity = "high"
	} else if ioc.Confidence >= 40 {
		ioc.Severity = "medium"
	} else {
		ioc.Severity = "low"
	}
}

// ParseSTIXIndicator parses a single STIX indicator.
func ParseSTIXIndicator(data []byte) (*STIXObject, error) {
	var obj STIXObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil, err
	}
	return &obj, nil
}

// ValidateSTIXBundle validates a STIX bundle.
func ValidateSTIXBundle(data []byte) error {
	var bundle STIXBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}

	if bundle.Type != "bundle" {
		return fmt.Errorf("expected type 'bundle', got '%s'", bundle.Type)
	}

	if bundle.ID == "" {
		return fmt.Errorf("bundle ID is required")
	}

	return nil
}
