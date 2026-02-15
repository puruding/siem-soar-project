// Package feed provides threat intelligence feed management.
package feed

import "time"

// IOCType represents the type of Indicator of Compromise.
type IOCType string

const (
	IOCTypeIP         IOCType = "ip"
	IOCTypeIPv4       IOCType = "ipv4"
	IOCTypeIPv6       IOCType = "ipv6"
	IOCTypeDomain     IOCType = "domain"
	IOCTypeURL        IOCType = "url"
	IOCTypeEmail      IOCType = "email"
	IOCTypeMD5        IOCType = "md5"
	IOCTypeSHA1       IOCType = "sha1"
	IOCTypeSHA256     IOCType = "sha256"
	IOCTypeFileMD5    IOCType = "file_md5"
	IOCTypeFileSHA1   IOCType = "file_sha1"
	IOCTypeFileSHA256 IOCType = "file_sha256"
	IOCTypeHash       IOCType = "hash"
	IOCTypeCVE        IOCType = "cve"
	IOCTypeMutex      IOCType = "mutex"
	IOCTypeRegistry   IOCType = "registry"
	IOCTypeUserAgent  IOCType = "user_agent"
	IOCTypeOther      IOCType = "other"
	IOCTypeJA3        IOCType = "ja3"
)

// IOC represents an Indicator of Compromise from a threat intelligence feed.
type IOC struct {
	// Core identifiers
	ID         string    `json:"id"`
	Type       IOCType   `json:"type"`
	Value      string    `json:"value"`

	// Metadata
	Source     string    `json:"source"`
	FeedID     string    `json:"feed_id"`
	Confidence int       `json:"confidence"` // 0-100
	Severity   string    `json:"severity"`   // low, medium, high, critical

	// Classification
	ThreatType string    `json:"threat_type"` // malware, phishing, c2, etc.
	Category   string    `json:"category"`
	Tags       []string  `json:"tags,omitempty"`

	// Context
	Description string    `json:"description,omitempty"`
	References  []string  `json:"references,omitempty"`
	Mitre       []string  `json:"mitre,omitempty"` // MITRE ATT&CK IDs

	// Temporal data
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	ValidFrom  time.Time `json:"valid_from"`
	ValidUntil time.Time `json:"valid_until,omitempty"`

	// Lifecycle
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Status     string    `json:"status"` // active, inactive, expired

	// Relationship
	RelatedIOCs []string  `json:"related_iocs,omitempty"`
	CampaignID  string    `json:"campaign_id,omitempty"`

	// Additional context (STIX fields)
	KillChain    []string             `json:"kill_chain,omitempty"`
	Labels       []string             `json:"labels,omitempty"`
	ExternalRefs []ExternalReference  `json:"external_refs,omitempty"`

	// MISP-specific fields
	TLP          string               `json:"tlp,omitempty"`
	MITREAttack  []string             `json:"mitre_attack,omitempty"`
	Attributes   map[string]interface{} `json:"attributes,omitempty"`
}

// ExternalReference represents an external reference for an IOC.
type ExternalReference struct {
	SourceName  string `json:"source_name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	ExternalID  string `json:"external_id,omitempty"`
}

// IsExpired checks if the IOC has expired.
func (ioc *IOC) IsExpired() bool {
	if ioc.ValidUntil.IsZero() {
		return false
	}
	return time.Now().After(ioc.ValidUntil)
}

// IsActive checks if the IOC is currently active.
func (ioc *IOC) IsActive() bool {
	if ioc.Status != "active" {
		return false
	}
	if ioc.IsExpired() {
		return false
	}
	if !ioc.ValidFrom.IsZero() && time.Now().Before(ioc.ValidFrom) {
		return false
	}
	return true
}
