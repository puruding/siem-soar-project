// Package taxii provides STIX 2.1 object parsing and conversion.
package taxii

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// STIX Object Types
const (
	TypeAttackPattern      = "attack-pattern"
	TypeCampaign           = "campaign"
	TypeCourseOfAction     = "course-of-action"
	TypeGrouping           = "grouping"
	TypeIdentity           = "identity"
	TypeIndicator          = "indicator"
	TypeInfrastructure     = "infrastructure"
	TypeIntrusionSet       = "intrusion-set"
	TypeLocation           = "location"
	TypeMalware            = "malware"
	TypeMalwareAnalysis    = "malware-analysis"
	TypeNote               = "note"
	TypeObservedData       = "observed-data"
	TypeOpinion            = "opinion"
	TypeReport             = "report"
	TypeRelationship       = "relationship"
	TypeSighting           = "sighting"
	TypeThreatActor        = "threat-actor"
	TypeTool               = "tool"
	TypeVulnerability      = "vulnerability"
)

// STIX Cyber Observable Types
const (
	ObservableArtifact           = "artifact"
	ObservableAutonomousSystem   = "autonomous-system"
	ObservableDirectory          = "directory"
	ObservableDomainName         = "domain-name"
	ObservableEmailAddr          = "email-addr"
	ObservableEmailMessage       = "email-message"
	ObservableFile               = "file"
	ObservableIPv4Addr           = "ipv4-addr"
	ObservableIPv6Addr           = "ipv6-addr"
	ObservableMACAddr            = "mac-addr"
	ObservableMutex              = "mutex"
	ObservableNetworkTraffic     = "network-traffic"
	ObservableProcess            = "process"
	ObservableSoftware           = "software"
	ObservableURL                = "url"
	ObservableUserAccount        = "user-account"
	ObservableWindowsRegistryKey = "windows-registry-key"
	ObservableX509Certificate    = "x509-certificate"
)

// STIXObject is the interface for all STIX objects.
type STIXObject interface {
	GetType() string
	GetID() string
	GetCreated() time.Time
	GetModified() time.Time
}

// CommonProperties represents common STIX object properties.
type CommonProperties struct {
	Type               string              `json:"type"`
	SpecVersion        string              `json:"spec_version,omitempty"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	Modified           time.Time           `json:"modified"`
	CreatedByRef       string              `json:"created_by_ref,omitempty"`
	Revoked            bool                `json:"revoked,omitempty"`
	Labels             []string            `json:"labels,omitempty"`
	Confidence         int                 `json:"confidence,omitempty"`
	Lang               string              `json:"lang,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs,omitempty"`
	GranularMarkings   []GranularMarking   `json:"granular_markings,omitempty"`
	Extensions         map[string]interface{} `json:"extensions,omitempty"`
}

// GetType returns the object type.
func (c CommonProperties) GetType() string { return c.Type }

// GetID returns the object ID.
func (c CommonProperties) GetID() string { return c.ID }

// GetCreated returns the creation time.
func (c CommonProperties) GetCreated() time.Time { return c.Created }

// GetModified returns the modification time.
func (c CommonProperties) GetModified() time.Time { return c.Modified }

// ExternalReference represents an external reference.
type ExternalReference struct {
	SourceName  string            `json:"source_name"`
	Description string            `json:"description,omitempty"`
	URL         string            `json:"url,omitempty"`
	Hashes      map[string]string `json:"hashes,omitempty"`
	ExternalID  string            `json:"external_id,omitempty"`
}

// GranularMarking represents a granular marking.
type GranularMarking struct {
	Lang       string   `json:"lang,omitempty"`
	MarkingRef string   `json:"marking_ref,omitempty"`
	Selectors  []string `json:"selectors"`
}

// KillChainPhase represents a kill chain phase.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// Indicator represents a STIX Indicator object.
type Indicator struct {
	CommonProperties
	Name             string           `json:"name,omitempty"`
	Description      string           `json:"description,omitempty"`
	IndicatorTypes   []string         `json:"indicator_types,omitempty"`
	Pattern          string           `json:"pattern"`
	PatternType      string           `json:"pattern_type"`
	PatternVersion   string           `json:"pattern_version,omitempty"`
	ValidFrom        time.Time        `json:"valid_from"`
	ValidUntil       *time.Time       `json:"valid_until,omitempty"`
	KillChainPhases  []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// Malware represents a STIX Malware object.
type Malware struct {
	CommonProperties
	Name                string           `json:"name,omitempty"`
	Description         string           `json:"description,omitempty"`
	MalwareTypes        []string         `json:"malware_types,omitempty"`
	IsFamily            bool             `json:"is_family,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	KillChainPhases     []KillChainPhase `json:"kill_chain_phases,omitempty"`
	FirstSeen           *time.Time       `json:"first_seen,omitempty"`
	LastSeen            *time.Time       `json:"last_seen,omitempty"`
	OperatingSystemRefs []string         `json:"operating_system_refs,omitempty"`
	ArchitectureExecutionEnvs []string   `json:"architecture_execution_envs,omitempty"`
	ImplementationLanguages []string     `json:"implementation_languages,omitempty"`
	Capabilities        []string         `json:"capabilities,omitempty"`
	SampleRefs          []string         `json:"sample_refs,omitempty"`
}

// ThreatActor represents a STIX Threat Actor object.
type ThreatActor struct {
	CommonProperties
	Name            string     `json:"name"`
	Description     string     `json:"description,omitempty"`
	ThreatActorTypes []string  `json:"threat_actor_types,omitempty"`
	Aliases         []string   `json:"aliases,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	Roles           []string   `json:"roles,omitempty"`
	Goals           []string   `json:"goals,omitempty"`
	Sophistication  string     `json:"sophistication,omitempty"`
	ResourceLevel   string     `json:"resource_level,omitempty"`
	PrimaryMotivation string   `json:"primary_motivation,omitempty"`
	SecondaryMotivations []string `json:"secondary_motivations,omitempty"`
	PersonalMotivations []string `json:"personal_motivations,omitempty"`
}

// AttackPattern represents a STIX Attack Pattern object.
type AttackPattern struct {
	CommonProperties
	Name            string           `json:"name"`
	Description     string           `json:"description,omitempty"`
	Aliases         []string         `json:"aliases,omitempty"`
	KillChainPhases []KillChainPhase `json:"kill_chain_phases,omitempty"`
}

// Campaign represents a STIX Campaign object.
type Campaign struct {
	CommonProperties
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Aliases     []string   `json:"aliases,omitempty"`
	FirstSeen   *time.Time `json:"first_seen,omitempty"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
	Objective   string     `json:"objective,omitempty"`
}

// IntrusionSet represents a STIX Intrusion Set object.
type IntrusionSet struct {
	CommonProperties
	Name                 string     `json:"name"`
	Description          string     `json:"description,omitempty"`
	Aliases              []string   `json:"aliases,omitempty"`
	FirstSeen            *time.Time `json:"first_seen,omitempty"`
	LastSeen             *time.Time `json:"last_seen,omitempty"`
	Goals                []string   `json:"goals,omitempty"`
	ResourceLevel        string     `json:"resource_level,omitempty"`
	PrimaryMotivation    string     `json:"primary_motivation,omitempty"`
	SecondaryMotivations []string   `json:"secondary_motivations,omitempty"`
}

// Infrastructure represents a STIX Infrastructure object.
type Infrastructure struct {
	CommonProperties
	Name                string           `json:"name"`
	Description         string           `json:"description,omitempty"`
	InfrastructureTypes []string         `json:"infrastructure_types,omitempty"`
	Aliases             []string         `json:"aliases,omitempty"`
	KillChainPhases     []KillChainPhase `json:"kill_chain_phases,omitempty"`
	FirstSeen           *time.Time       `json:"first_seen,omitempty"`
	LastSeen            *time.Time       `json:"last_seen,omitempty"`
}

// Vulnerability represents a STIX Vulnerability object.
type Vulnerability struct {
	CommonProperties
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// Relationship represents a STIX Relationship object.
type Relationship struct {
	CommonProperties
	RelationshipType string     `json:"relationship_type"`
	Description      string     `json:"description,omitempty"`
	SourceRef        string     `json:"source_ref"`
	TargetRef        string     `json:"target_ref"`
	StartTime        *time.Time `json:"start_time,omitempty"`
	StopTime         *time.Time `json:"stop_time,omitempty"`
}

// Sighting represents a STIX Sighting object.
type Sighting struct {
	CommonProperties
	Description     string     `json:"description,omitempty"`
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	LastSeen        *time.Time `json:"last_seen,omitempty"`
	Count           int        `json:"count,omitempty"`
	SightingOfRef   string     `json:"sighting_of_ref"`
	ObservedDataRefs []string  `json:"observed_data_refs,omitempty"`
	WhereSightedRefs []string  `json:"where_sighted_refs,omitempty"`
	Summary         bool       `json:"summary,omitempty"`
}

// Bundle represents a STIX Bundle.
type Bundle struct {
	Type    string            `json:"type"`
	ID      string            `json:"id"`
	Objects []json.RawMessage `json:"objects"`
}

// ParsedIOC represents a parsed IOC from STIX.
type ParsedIOC struct {
	Type        string
	Value       string
	Name        string
	Description string
	ThreatTypes []string
	Severity    string
	Confidence  int
	ValidFrom   time.Time
	ValidUntil  *time.Time
	Labels      []string
	MITREAttack []string
	Source      string
	Raw         json.RawMessage
}

// ParseBundle parses a STIX bundle and returns parsed IOCs.
func ParseBundle(data []byte) ([]ParsedIOC, error) {
	var bundle Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	if bundle.Type != "bundle" {
		return nil, fmt.Errorf("expected bundle type, got: %s", bundle.Type)
	}

	var iocs []ParsedIOC
	objectMap := make(map[string]json.RawMessage)

	// Build object map
	for _, obj := range bundle.Objects {
		var common CommonProperties
		if err := json.Unmarshal(obj, &common); err != nil {
			continue
		}
		objectMap[common.ID] = obj
	}

	// Parse indicators
	for _, obj := range bundle.Objects {
		var common CommonProperties
		if err := json.Unmarshal(obj, &common); err != nil {
			continue
		}

		if common.Type == TypeIndicator {
			var indicator Indicator
			if err := json.Unmarshal(obj, &indicator); err != nil {
				continue
			}

			parsed := parseIndicator(&indicator, objectMap)
			iocs = append(iocs, parsed...)
		}
	}

	return iocs, nil
}

// parseIndicator parses a STIX indicator into IOCs.
func parseIndicator(indicator *Indicator, objectMap map[string]json.RawMessage) []ParsedIOC {
	var iocs []ParsedIOC

	if indicator.Pattern == "" || indicator.PatternType != "stix" {
		return iocs
	}

	// Parse STIX pattern
	parsed := parseSTIXPattern(indicator.Pattern)

	for _, p := range parsed {
		ioc := ParsedIOC{
			Type:        p.Type,
			Value:       p.Value,
			Name:        indicator.Name,
			Description: indicator.Description,
			ThreatTypes: indicator.IndicatorTypes,
			Confidence:  indicator.Confidence,
			ValidFrom:   indicator.ValidFrom,
			ValidUntil:  indicator.ValidUntil,
			Labels:      indicator.Labels,
		}

		// Extract MITRE ATT&CK references
		for _, phase := range indicator.KillChainPhases {
			if phase.KillChainName == "mitre-attack" {
				ioc.MITREAttack = append(ioc.MITREAttack, phase.PhaseName)
			}
		}

		for _, ref := range indicator.ExternalReferences {
			if ref.SourceName == "mitre-attack" && ref.ExternalID != "" {
				ioc.MITREAttack = append(ioc.MITREAttack, ref.ExternalID)
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

		iocs = append(iocs, ioc)
	}

	return iocs
}

// PatternValue represents a parsed value from STIX pattern.
type PatternValue struct {
	Type  string
	Value string
}

// STIX pattern regex patterns
var (
	ipv4Pattern   = regexp.MustCompile(`\[ipv4-addr:value\s*=\s*'([^']+)'\]`)
	ipv6Pattern   = regexp.MustCompile(`\[ipv6-addr:value\s*=\s*'([^']+)'\]`)
	domainPattern = regexp.MustCompile(`\[domain-name:value\s*=\s*'([^']+)'\]`)
	urlPattern    = regexp.MustCompile(`\[url:value\s*=\s*'([^']+)'\]`)
	emailPattern  = regexp.MustCompile(`\[email-addr:value\s*=\s*'([^']+)'\]`)
	md5Pattern    = regexp.MustCompile(`\[file:hashes\.'?MD5'?\s*=\s*'([^']+)'\]`)
	sha1Pattern   = regexp.MustCompile(`\[file:hashes\.'?SHA-1'?\s*=\s*'([^']+)'\]`)
	sha256Pattern = regexp.MustCompile(`\[file:hashes\.'?SHA-256'?\s*=\s*'([^']+)'\]`)
	sha512Pattern = regexp.MustCompile(`\[file:hashes\.'?SHA-512'?\s*=\s*'([^']+)'\]`)
	registryPattern = regexp.MustCompile(`\[windows-registry-key:key\s*=\s*'([^']+)'\]`)
	macPattern    = regexp.MustCompile(`\[mac-addr:value\s*=\s*'([^']+)'\]`)
	asnPattern    = regexp.MustCompile(`\[autonomous-system:number\s*=\s*'?(\d+)'?\]`)
)

// parseSTIXPattern parses a STIX 2.1 pattern string.
func parseSTIXPattern(pattern string) []PatternValue {
	var results []PatternValue

	// Handle AND/OR combinations
	parts := splitPattern(pattern)

	for _, part := range parts {
		// Try each pattern type
		if matches := ipv4Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "ip", Value: m[1]})
			}
		}
		if matches := ipv6Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "ip", Value: m[1]})
			}
		}
		if matches := domainPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "domain", Value: m[1]})
			}
		}
		if matches := urlPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "url", Value: m[1]})
			}
		}
		if matches := emailPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "email", Value: m[1]})
			}
		}
		if matches := md5Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "md5", Value: m[1]})
			}
		}
		if matches := sha1Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "sha1", Value: m[1]})
			}
		}
		if matches := sha256Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "sha256", Value: m[1]})
			}
		}
		if matches := sha512Pattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "sha512", Value: m[1]})
			}
		}
		if matches := registryPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "registry", Value: m[1]})
			}
		}
		if matches := macPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "mac", Value: m[1]})
			}
		}
		if matches := asnPattern.FindAllStringSubmatch(part, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, PatternValue{Type: "asn", Value: m[1]})
			}
		}
	}

	return results
}

// splitPattern splits a STIX pattern by OR operators.
func splitPattern(pattern string) []string {
	// Simple split by OR - doesn't handle nested patterns
	parts := strings.Split(pattern, " OR ")
	var result []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// ValidateBundle validates a STIX bundle.
func ValidateBundle(data []byte) error {
	var bundle Bundle
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

// CreateIndicator creates a STIX Indicator from IOC data.
func CreateIndicator(iocType, value, name, description string, confidence int, validFrom time.Time) *Indicator {
	pattern := buildSTIXPattern(iocType, value)
	if pattern == "" {
		return nil
	}

	now := time.Now()
	id := fmt.Sprintf("indicator--%s", generateUUID())

	return &Indicator{
		CommonProperties: CommonProperties{
			Type:        TypeIndicator,
			SpecVersion: "2.1",
			ID:          id,
			Created:     now,
			Modified:    now,
			Confidence:  confidence,
		},
		Name:        name,
		Description: description,
		Pattern:     pattern,
		PatternType: "stix",
		ValidFrom:   validFrom,
	}
}

// buildSTIXPattern builds a STIX pattern string from IOC type and value.
func buildSTIXPattern(iocType, value string) string {
	switch iocType {
	case "ip", "ipv4":
		return fmt.Sprintf("[ipv4-addr:value = '%s']", value)
	case "ipv6":
		return fmt.Sprintf("[ipv6-addr:value = '%s']", value)
	case "domain":
		return fmt.Sprintf("[domain-name:value = '%s']", value)
	case "url":
		return fmt.Sprintf("[url:value = '%s']", value)
	case "email":
		return fmt.Sprintf("[email-addr:value = '%s']", value)
	case "md5":
		return fmt.Sprintf("[file:hashes.MD5 = '%s']", value)
	case "sha1":
		return fmt.Sprintf("[file:hashes.'SHA-1' = '%s']", value)
	case "sha256":
		return fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", value)
	case "sha512":
		return fmt.Sprintf("[file:hashes.'SHA-512' = '%s']", value)
	case "registry":
		return fmt.Sprintf("[windows-registry-key:key = '%s']", value)
	case "mac":
		return fmt.Sprintf("[mac-addr:value = '%s']", value)
	default:
		return ""
	}
}

// generateUUID generates a simple UUID-like string.
func generateUUID() string {
	now := time.Now().UnixNano()
	return fmt.Sprintf("%x-%x-%x-%x-%x",
		now&0xffffffff,
		(now>>32)&0xffff,
		(now>>48)&0xfff|0x4000,
		(now>>60)&0x3fff|0x8000,
		now&0xffffffffffff)
}
