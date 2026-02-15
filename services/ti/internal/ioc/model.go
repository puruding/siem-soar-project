// Package ioc provides IOC models and management.
package ioc

import (
	"time"
)

// IOCType represents the type of indicator.
type IOCType string

const (
	TypeIP       IOCType = "ip"
	TypeDomain   IOCType = "domain"
	TypeURL      IOCType = "url"
	TypeEmail    IOCType = "email"
	TypeMD5      IOCType = "md5"
	TypeSHA1     IOCType = "sha1"
	TypeSHA256   IOCType = "sha256"
	TypeHash     IOCType = "hash"
	TypeRegistry IOCType = "registry"
	TypeFilename IOCType = "filename"
	TypeJA3      IOCType = "ja3"
	TypeOther    IOCType = "other"
)

// ThreatType represents the type of threat.
type ThreatType string

const (
	ThreatMalware     ThreatType = "malware"
	ThreatPhishing    ThreatType = "phishing"
	ThreatC2          ThreatType = "c2"
	ThreatBotnet      ThreatType = "botnet"
	ThreatRansomware  ThreatType = "ransomware"
	ThreatAPT         ThreatType = "apt"
	ThreatScanning    ThreatType = "scanning"
	ThreatSpam        ThreatType = "spam"
	ThreatCompromised ThreatType = "compromised"
	ThreatSuspicious  ThreatType = "suspicious"
	ThreatUnknown     ThreatType = "unknown"
)

// Severity represents the severity level.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// TLP represents Traffic Light Protocol classification.
type TLP string

const (
	TLPRed    TLP = "RED"
	TLPAmber  TLP = "AMBER"
	TLPGreen  TLP = "GREEN"
	TLPWhite  TLP = "WHITE"
	TLPClear  TLP = "CLEAR"
)

// IOC represents an Indicator of Compromise.
type IOC struct {
	// Identity
	ID        string  `json:"id" db:"id"`
	TenantID  string  `json:"tenant_id" db:"tenant_id"`
	Type      IOCType `json:"type" db:"type"`
	Value     string  `json:"value" db:"value"`

	// Metadata
	Name        string     `json:"name,omitempty" db:"name"`
	Description string     `json:"description,omitempty" db:"description"`
	Source      string     `json:"source" db:"source"`
	FeedID      string     `json:"feed_id,omitempty" db:"feed_id"`

	// Classification
	ThreatType  ThreatType `json:"threat_type" db:"threat_type"`
	ThreatName  string     `json:"threat_name,omitempty" db:"threat_name"`
	Severity    Severity   `json:"severity" db:"severity"`
	Confidence  int        `json:"confidence" db:"confidence"` // 0-100
	TLP         TLP        `json:"tlp,omitempty" db:"tlp"`

	// Intelligence
	MITREAttack   []string          `json:"mitre_attack,omitempty" db:"mitre_attack"`
	MalwareFamilies []string        `json:"malware_families,omitempty" db:"malware_families"`
	Campaigns     []string          `json:"campaigns,omitempty" db:"campaigns"`
	ThreatActors  []string          `json:"threat_actors,omitempty" db:"threat_actors"`
	Labels        []string          `json:"labels,omitempty" db:"labels"`
	Attributes    map[string]string `json:"attributes,omitempty" db:"attributes"`

	// Related IOCs
	RelatedIOCs []string `json:"related_iocs,omitempty" db:"related_iocs"`

	// Validity
	ValidFrom  time.Time `json:"valid_from" db:"valid_from"`
	ValidUntil time.Time `json:"valid_until,omitempty" db:"valid_until"`
	FirstSeen  time.Time `json:"first_seen" db:"first_seen"`
	LastSeen   time.Time `json:"last_seen" db:"last_seen"`
	ExpiresAt  time.Time `json:"expires_at,omitempty" db:"expires_at"`

	// Status
	IsActive  bool `json:"is_active" db:"is_active"`
	IsWhitelisted bool `json:"is_whitelisted" db:"is_whitelisted"`

	// Timestamps
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`

	// Statistics
	HitCount   int64     `json:"hit_count" db:"hit_count"`
	LastHitAt  time.Time `json:"last_hit_at,omitempty" db:"last_hit_at"`
}

// IOCMatch represents a match between an IOC and an event field.
type IOCMatch struct {
	IOC        *IOC                   `json:"ioc"`
	MatchedOn  string                 `json:"matched_on"`  // Field name that matched
	MatchValue string                 `json:"match_value"` // Value that matched
	EventID    string                 `json:"event_id,omitempty"`
	TenantID   string                 `json:"tenant_id"`
	Timestamp  time.Time              `json:"timestamp"`
	Context    map[string]interface{} `json:"context,omitempty"`
}

// IOCFilter represents filters for IOC queries.
type IOCFilter struct {
	TenantID      string
	Types         []IOCType
	ThreatTypes   []ThreatType
	Severities    []Severity
	Sources       []string
	FeedIDs       []string
	Labels        []string
	MinConfidence int
	IsActive      *bool
	IsWhitelisted *bool
	SearchQuery   string
	ValidAt       time.Time
	ModifiedSince time.Time
}

// IOCStats represents IOC statistics.
type IOCStats struct {
	TotalIOCs       int64            `json:"total_iocs"`
	ActiveIOCs      int64            `json:"active_iocs"`
	IOCsByType      map[string]int64 `json:"iocs_by_type"`
	IOCsByThreat    map[string]int64 `json:"iocs_by_threat"`
	IOCsBySeverity  map[string]int64 `json:"iocs_by_severity"`
	IOCsBySource    map[string]int64 `json:"iocs_by_source"`
	TotalHits       int64            `json:"total_hits"`
	ExpiringToday   int64            `json:"expiring_today"`
	ExpiringSoon    int64            `json:"expiring_soon"` // Next 7 days
}

// NewIOC creates a new IOC with defaults.
func NewIOC(iocType IOCType, value string, source string) *IOC {
	now := time.Now()
	return &IOC{
		Type:       iocType,
		Value:      value,
		Source:     source,
		ThreatType: ThreatUnknown,
		Severity:   SeverityMedium,
		Confidence: 50,
		TLP:        TLPAmber,
		IsActive:   true,
		FirstSeen:  now,
		LastSeen:   now,
		CreatedAt:  now,
		UpdatedAt:  now,
		Attributes: make(map[string]string),
	}
}

// IsExpired checks if the IOC has expired.
func (i *IOC) IsExpired() bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(i.ExpiresAt)
}

// IsValid checks if the IOC is currently valid.
func (i *IOC) IsValid() bool {
	now := time.Now()

	// Check validity window
	if !i.ValidFrom.IsZero() && now.Before(i.ValidFrom) {
		return false
	}
	if !i.ValidUntil.IsZero() && now.After(i.ValidUntil) {
		return false
	}

	// Check expiration
	if i.IsExpired() {
		return false
	}

	return i.IsActive && !i.IsWhitelisted
}

// RecordHit records a hit on this IOC.
func (i *IOC) RecordHit() {
	i.HitCount++
	i.LastHitAt = time.Now()
	i.LastSeen = time.Now()
	i.UpdatedAt = time.Now()
}

// Clone creates a copy of the IOC.
func (i *IOC) Clone() *IOC {
	clone := *i

	// Deep copy slices
	if i.MITREAttack != nil {
		clone.MITREAttack = make([]string, len(i.MITREAttack))
		copy(clone.MITREAttack, i.MITREAttack)
	}
	if i.MalwareFamilies != nil {
		clone.MalwareFamilies = make([]string, len(i.MalwareFamilies))
		copy(clone.MalwareFamilies, i.MalwareFamilies)
	}
	if i.Labels != nil {
		clone.Labels = make([]string, len(i.Labels))
		copy(clone.Labels, i.Labels)
	}
	if i.RelatedIOCs != nil {
		clone.RelatedIOCs = make([]string, len(i.RelatedIOCs))
		copy(clone.RelatedIOCs, i.RelatedIOCs)
	}

	// Deep copy map
	if i.Attributes != nil {
		clone.Attributes = make(map[string]string)
		for k, v := range i.Attributes {
			clone.Attributes[k] = v
		}
	}

	return &clone
}

// Merge merges another IOC into this one (for deduplication).
func (i *IOC) Merge(other *IOC) {
	// Update confidence (average)
	i.Confidence = (i.Confidence + other.Confidence) / 2

	// Update severity (take higher)
	if compareSeverity(other.Severity, i.Severity) > 0 {
		i.Severity = other.Severity
	}

	// Merge arrays
	i.MITREAttack = mergeStrings(i.MITREAttack, other.MITREAttack)
	i.MalwareFamilies = mergeStrings(i.MalwareFamilies, other.MalwareFamilies)
	i.Labels = mergeStrings(i.Labels, other.Labels)
	i.Campaigns = mergeStrings(i.Campaigns, other.Campaigns)
	i.ThreatActors = mergeStrings(i.ThreatActors, other.ThreatActors)

	// Update timestamps
	if other.FirstSeen.Before(i.FirstSeen) {
		i.FirstSeen = other.FirstSeen
	}
	if other.LastSeen.After(i.LastSeen) {
		i.LastSeen = other.LastSeen
	}

	i.HitCount += other.HitCount
	i.UpdatedAt = time.Now()
}

func compareSeverity(a, b Severity) int {
	order := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityInfo:     0,
	}
	return order[a] - order[b]
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool)
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}

	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	return result
}

// DetectIOCType attempts to detect the IOC type from a value.
func DetectIOCType(value string) IOCType {
	// IP address patterns
	if isIPv4(value) || isIPv6(value) {
		return TypeIP
	}

	// Hash patterns
	switch len(value) {
	case 32:
		if isHex(value) {
			return TypeMD5
		}
	case 40:
		if isHex(value) {
			return TypeSHA1
		}
	case 64:
		if isHex(value) {
			return TypeSHA256
		}
	}

	// URL pattern
	if isURL(value) {
		return TypeURL
	}

	// Email pattern
	if isEmail(value) {
		return TypeEmail
	}

	// Domain pattern (simple check)
	if isDomain(value) {
		return TypeDomain
	}

	return TypeOther
}

func isIPv4(s string) bool {
	parts := splitByRune(s, '.')
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if !isNumeric(part) {
			return false
		}
		n := atoi(part)
		if n < 0 || n > 255 {
			return false
		}
	}
	return true
}

func isIPv6(s string) bool {
	return len(s) > 0 && containsRune(s, ':') && !containsRune(s, '.')
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func isURL(s string) bool {
	return len(s) > 7 && (s[:7] == "http://" || s[:8] == "https://")
}

func isEmail(s string) bool {
	at := -1
	for i, c := range s {
		if c == '@' {
			at = i
			break
		}
	}
	return at > 0 && at < len(s)-1
}

func isDomain(s string) bool {
	if len(s) == 0 || containsRune(s, '/') || containsRune(s, '@') {
		return false
	}
	return containsRune(s, '.')
}

func splitByRune(s string, sep rune) []string {
	var result []string
	var current string
	for _, c := range s {
		if c == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	result = append(result, current)
	return result
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func isNumeric(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
