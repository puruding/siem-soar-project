// Package normalizer provides the core normalization engine.
package normalizer

import (
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// EventType represents UDM event types.
type EventType string

const (
	EventTypeGeneric              EventType = "GENERIC_EVENT"
	EventTypeUserLogin            EventType = "USER_LOGIN"
	EventTypeUserLogout           EventType = "USER_LOGOUT"
	EventTypeUserCreation         EventType = "USER_CREATION"
	EventTypeUserDeletion         EventType = "USER_DELETION"
	EventTypeUserPrivilegeChange  EventType = "USER_PRIVILEGE_CHANGE"
	EventTypeUserPasswordChange   EventType = "USER_PASSWORD_CHANGE"
	EventTypeGroupCreation        EventType = "GROUP_CREATION"
	EventTypeGroupDeletion        EventType = "GROUP_DELETION"
	EventTypeGroupModification    EventType = "GROUP_MODIFICATION"
	EventTypeProcessLaunch        EventType = "PROCESS_LAUNCH"
	EventTypeProcessTermination   EventType = "PROCESS_TERMINATION"
	EventTypeProcessInjection     EventType = "PROCESS_INJECTION"
	EventTypeNetworkConnection    EventType = "NETWORK_CONNECTION"
	EventTypeNetworkDNS           EventType = "NETWORK_DNS"
	EventTypeNetworkHTTP          EventType = "NETWORK_HTTP"
	EventTypeFileCreation         EventType = "FILE_CREATION"
	EventTypeFileModification     EventType = "FILE_MODIFICATION"
	EventTypeFileDeletion         EventType = "FILE_DELETION"
	EventTypeFileRead             EventType = "FILE_READ"
	EventTypeRegistryCreation     EventType = "REGISTRY_CREATION"
	EventTypeRegistryModification EventType = "REGISTRY_MODIFICATION"
	EventTypeRegistryDeletion     EventType = "REGISTRY_DELETION"
	EventTypeResourceAccess       EventType = "RESOURCE_ACCESS"
	EventTypeServiceCreation      EventType = "SERVICE_CREATION"
	EventTypeServiceStart         EventType = "SERVICE_START"
	EventTypeServiceStop          EventType = "SERVICE_STOP"
	EventTypeScheduledTask        EventType = "SCHEDULED_TASK"
	EventTypeSystemAudit          EventType = "SYSTEM_AUDIT"
	EventTypeStatusUpdate         EventType = "STATUS_UPDATE"
	EventTypeAlert                EventType = "ALERT"
)

// UDMEvent represents a normalized event in Unified Data Model format.
type UDMEvent struct {
	Metadata       *Metadata              `json:"metadata"`
	Principal      *Entity                `json:"principal,omitempty"`
	Target         *Entity                `json:"target,omitempty"`
	Src            *Entity                `json:"src,omitempty"`
	Observer       *Entity                `json:"observer,omitempty"`
	Network        *Network               `json:"network,omitempty"`
	SecurityResult *SecurityResult        `json:"security_result,omitempty"`
	Extensions     map[string]interface{} `json:"extensions,omitempty"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// Metadata contains event metadata.
type Metadata struct {
	ID                string            `json:"id"`
	EventTimestamp    time.Time         `json:"event_timestamp"`
	CollectedTime     time.Time         `json:"collected_timestamp"`
	IngestionTime     time.Time         `json:"ingestion_timestamp"`
	EventType         EventType         `json:"event_type"`
	VendorName        string            `json:"vendor_name"`
	ProductName       string            `json:"product_name"`
	ProductVersion    string            `json:"product_version,omitempty"`
	ProductEventType  string            `json:"product_event_type,omitempty"`
	Description       string            `json:"description,omitempty"`
	LogType           string            `json:"log_type,omitempty"`
	BaseLabels        map[string]string `json:"base_labels,omitempty"`
	EnrichmentLabels  map[string]string `json:"enrichment_labels,omitempty"`
}

// Entity represents a principal, target, or observer entity.
type Entity struct {
	Hostname             string            `json:"hostname,omitempty"`
	IP                   []string          `json:"ip,omitempty"`
	MAC                  []string          `json:"mac,omitempty"`
	Port                 int               `json:"port,omitempty"`
	AssetID              string            `json:"asset_id,omitempty"`
	URL                  string            `json:"url,omitempty"`
	Application          string            `json:"application,omitempty"`
	AdministrativeDomain string            `json:"administrative_domain,omitempty"`
	Platform             string            `json:"platform,omitempty"`
	PlatformVersion      string            `json:"platform_version,omitempty"`
	User                 *User             `json:"user,omitempty"`
	Process              *Process          `json:"process,omitempty"`
	File                 *File             `json:"file,omitempty"`
	Registry             *Registry         `json:"registry,omitempty"`
	Resource             *Resource         `json:"resource,omitempty"`
	Asset                *Asset            `json:"asset,omitempty"`
	Labels               map[string]string `json:"labels,omitempty"`
}

// User represents user information.
type User struct {
	UserID            string   `json:"userid,omitempty"`
	UserName          string   `json:"user_name,omitempty"`
	DisplayName       string   `json:"user_display_name,omitempty"`
	EmailAddresses    []string `json:"email_addresses,omitempty"`
	GroupIDs          []string `json:"group_ids,omitempty"`
	WindowsSID        string   `json:"windows_sid,omitempty"`
	ProductObjectID   string   `json:"product_object_id,omitempty"`
}

// Process represents process information.
type Process struct {
	PID                      int64    `json:"pid,omitempty"`
	CommandLine              string   `json:"command_line,omitempty"`
	ProductSpecificProcessID string   `json:"product_specific_process_id,omitempty"`
	File                     *File    `json:"file,omitempty"`
	ParentProcess            *Process `json:"parent_process,omitempty"`
}

// File represents file information.
type File struct {
	FullPath      string    `json:"full_path,omitempty"`
	FileName      string    `json:"file_name,omitempty"`
	Size          int64     `json:"size,omitempty"`
	MimeType      string    `json:"mime_type,omitempty"`
	SHA256        string    `json:"sha256,omitempty"`
	SHA1          string    `json:"sha1,omitempty"`
	MD5           string    `json:"md5,omitempty"`
	FirstSeenTime time.Time `json:"first_seen_time,omitempty"`
}

// Registry represents Windows registry information.
type Registry struct {
	RegistryKey       string `json:"registry_key,omitempty"`
	RegistryValueName string `json:"registry_value_name,omitempty"`
	RegistryValueData string `json:"registry_value_data,omitempty"`
}

// Resource represents a generic resource.
type Resource struct {
	Name            string `json:"name,omitempty"`
	Type            string `json:"resource_type,omitempty"`
	SubType         string `json:"resource_subtype,omitempty"`
	ID              string `json:"id,omitempty"`
	ProductObjectID string `json:"product_object_id,omitempty"`
}

// Asset represents asset information.
type Asset struct {
	AssetID         string `json:"asset_id,omitempty"`
	ProductObjectID string `json:"product_object_id,omitempty"`
}

// Network represents network information.
type Network struct {
	ApplicationProtocol string      `json:"application_protocol,omitempty"`
	Direction           string      `json:"direction,omitempty"`
	IPProtocol          string      `json:"ip_protocol,omitempty"`
	ReceivedBytes       int64       `json:"received_bytes,omitempty"`
	SentBytes           int64       `json:"sent_bytes,omitempty"`
	SessionID           string      `json:"session_id,omitempty"`
	SessionDuration     float64     `json:"session_duration,omitempty"`
	DNS                 *DNS        `json:"dns,omitempty"`
	HTTP                *HTTP       `json:"http,omitempty"`
	Email               *Email      `json:"email,omitempty"`
	TLS                 *TLS        `json:"tls,omitempty"`
}

// DNS represents DNS query/response information.
type DNS struct {
	Questions    []DNSQuestion `json:"questions,omitempty"`
	Answers      []DNSAnswer   `json:"answers,omitempty"`
	ResponseCode int           `json:"response_code,omitempty"`
}

// DNSQuestion represents a DNS question.
type DNSQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type,omitempty"`
}

// DNSAnswer represents a DNS answer.
type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type,omitempty"`
	Data string `json:"data,omitempty"`
	TTL  int    `json:"ttl,omitempty"`
}

// HTTP represents HTTP request/response information.
type HTTP struct {
	Method       string `json:"method,omitempty"`
	ReferralURL  string `json:"referral_url,omitempty"`
	ResponseCode int    `json:"response_code,omitempty"`
	UserAgent    string `json:"user_agent,omitempty"`
}

// Email represents email information.
type Email struct {
	From            string   `json:"from,omitempty"`
	To              []string `json:"to,omitempty"`
	CC              []string `json:"cc,omitempty"`
	Subject         string   `json:"subject,omitempty"`
	AttachmentNames []string `json:"attachment_names,omitempty"`
}

// TLS represents TLS information.
type TLS struct {
	Cipher      string       `json:"cipher,omitempty"`
	Version     string       `json:"version,omitempty"`
	JA3         string       `json:"ja3,omitempty"`
	JA3S        string       `json:"ja3s,omitempty"`
	Certificate *Certificate `json:"certificate,omitempty"`
}

// Certificate represents TLS certificate information.
type Certificate struct {
	Serial    string    `json:"serial,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	NotAfter  time.Time `json:"not_after,omitempty"`
}

// SecurityResult represents security detection result.
type SecurityResult struct {
	Action          string              `json:"action,omitempty"`
	Severity        string              `json:"severity,omitempty"`
	SeverityDetails string              `json:"severity_details,omitempty"`
	Confidence      float32             `json:"confidence,omitempty"`
	Category        string              `json:"category,omitempty"`
	CategoryDetails []string            `json:"category_details,omitempty"`
	RuleID          string              `json:"rule_id,omitempty"`
	RuleName        string              `json:"rule_name,omitempty"`
	RuleType        string              `json:"rule_type,omitempty"`
	RuleVersion     string              `json:"rule_version,omitempty"`
	RuleLabels      map[string]string   `json:"rule_labels,omitempty"`
	ThreatID        string              `json:"threat_id,omitempty"`
	ThreatName      string              `json:"threat_name,omitempty"`
	ThreatStatus    string              `json:"threat_status,omitempty"`
	DetectionFields []DetectionField    `json:"detection_fields,omitempty"`
	AlertState      string              `json:"alert_state,omitempty"`
	URLBackToProduct string             `json:"url_back_to_product,omitempty"`
	About           *Entity             `json:"about,omitempty"`
}

// DetectionField represents a detection field key-value pair.
type DetectionField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// InputEvent represents an input event to normalize.
type InputEvent struct {
	EventID    string
	TenantID   string
	SourceType string
	Format     string
	Timestamp  time.Time
	Fields     map[string]interface{}
	RawLog     string
}

// MappingConfig defines mappings for a specific source type.
type MappingConfig struct {
	Name              string
	SourceType        string
	VendorName        string
	ProductName       string
	DefaultEventType  EventType
	EventTypeMappings map[string]EventType
	FieldMappings     []FieldMapping
}

// FieldMapping defines how to map a source field to UDM.
type FieldMapping struct {
	SourceField  string
	TargetField  string
	Transform    string
	Condition    string
	DefaultValue interface{}
	Required     bool
	Multiple     bool
	Parameters   map[string]string
}

// Normalizer is the main normalization engine.
type Normalizer struct {
	mappings            map[string]*MappingConfig
	defaultMapping      *MappingConfig
	preserveUnmapped    bool
	strictValidation    bool
	requiredFields      []string
	logger              *slog.Logger
	mu                  sync.RWMutex

	// Metrics
	eventsNormalized    atomic.Uint64
	normalizationErrors atomic.Uint64
	validationErrors    atomic.Uint64
}

// NewNormalizer creates a new normalizer.
func NewNormalizer(logger *slog.Logger) *Normalizer {
	n := &Normalizer{
		mappings:         make(map[string]*MappingConfig),
		preserveUnmapped: true,
		logger:           logger.With("component", "normalizer"),
	}

	// Load default mappings
	n.loadDefaultMappings()

	return n
}

// SetPreserveUnmapped sets whether to preserve unmapped fields.
func (n *Normalizer) SetPreserveUnmapped(preserve bool) {
	n.preserveUnmapped = preserve
}

// SetStrictValidation sets strict validation mode.
func (n *Normalizer) SetStrictValidation(strict bool) {
	n.strictValidation = strict
}

// SetRequiredFields sets required fields for validation.
func (n *Normalizer) SetRequiredFields(fields []string) {
	n.requiredFields = fields
}

// RegisterMapping registers a mapping configuration.
func (n *Normalizer) RegisterMapping(cfg *MappingConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mappings[cfg.SourceType] = cfg
}

// GetMappings returns all registered mappings.
func (n *Normalizer) GetMappings() map[string]*MappingConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()

	result := make(map[string]*MappingConfig)
	for k, v := range n.mappings {
		result[k] = v
	}
	return result
}

// Normalize normalizes an input event to UDM format.
func (n *Normalizer) Normalize(input *InputEvent) (*UDMEvent, error) {
	n.mu.RLock()
	mapping, ok := n.mappings[input.SourceType]
	n.mu.RUnlock()

	if !ok {
		mapping = n.defaultMapping
	}

	event := &UDMEvent{
		Metadata: &Metadata{
			ID:             uuid.New().String(),
			EventTimestamp: input.Timestamp,
			CollectedTime:  input.Timestamp,
			IngestionTime:  time.Now().UTC(),
			EventType:      EventTypeGeneric,
		},
		Principal: &Entity{},
		Target:    &Entity{},
		Observer:  &Entity{},
	}

	if mapping != nil {
		event.Metadata.VendorName = mapping.VendorName
		event.Metadata.ProductName = mapping.ProductName
		event.Metadata.EventType = mapping.DefaultEventType

		// Apply field mappings
		for _, fm := range mapping.FieldMappings {
			if err := n.applyFieldMapping(event, input.Fields, fm); err != nil {
				n.logger.Debug("field mapping error",
					"field", fm.SourceField,
					"error", err,
				)
			}
		}

		// Determine event type
		if len(mapping.EventTypeMappings) > 0 {
			for condition, eventType := range mapping.EventTypeMappings {
				if n.evaluateCondition(condition, input.Fields) {
					event.Metadata.EventType = eventType
					break
				}
			}
		}
	}

	// Preserve unmapped fields
	if n.preserveUnmapped {
		event.AdditionalData = make(map[string]interface{})
		for k, v := range input.Fields {
			event.AdditionalData[k] = v
		}
	}

	// Set tenant info in base labels
	if event.Metadata.BaseLabels == nil {
		event.Metadata.BaseLabels = make(map[string]string)
	}
	event.Metadata.BaseLabels["tenant_id"] = input.TenantID
	event.Metadata.BaseLabels["original_event_id"] = input.EventID

	n.eventsNormalized.Add(1)
	return event, nil
}

// Validate validates a UDM event.
func (n *Normalizer) Validate(event *UDMEvent) error {
	if event.Metadata == nil {
		return fmt.Errorf("metadata is required")
	}
	if event.Metadata.EventTimestamp.IsZero() {
		return fmt.Errorf("event_timestamp is required")
	}
	if event.Metadata.EventType == "" {
		return fmt.Errorf("event_type is required")
	}
	return nil
}

// Stats returns normalizer statistics.
func (n *Normalizer) Stats() map[string]interface{} {
	n.mu.RLock()
	numMappings := len(n.mappings)
	n.mu.RUnlock()

	return map[string]interface{}{
		"events_normalized":    n.eventsNormalized.Load(),
		"normalization_errors": n.normalizationErrors.Load(),
		"validation_errors":    n.validationErrors.Load(),
		"num_mappings":         numMappings,
	}
}

func (n *Normalizer) applyFieldMapping(event *UDMEvent, fields map[string]interface{}, fm FieldMapping) error {
	// Check condition
	if fm.Condition != "" && !n.evaluateCondition(fm.Condition, fields) {
		return nil
	}

	// Get source value
	value := getNestedValue(fields, fm.SourceField)
	if value == nil {
		if fm.Required {
			return fmt.Errorf("required field %s not found", fm.SourceField)
		}
		if fm.DefaultValue != nil {
			value = fm.DefaultValue
		} else {
			return nil
		}
	}

	// Apply transform
	if fm.Transform != "" {
		transformed, err := n.applyTransform(fm.Transform, value, fm.Parameters)
		if err != nil {
			return err
		}
		value = transformed
	}

	// Set target field
	return setNestedValue(event, fm.TargetField, value)
}

func (n *Normalizer) applyTransform(transform string, value interface{}, params map[string]string) (interface{}, error) {
	switch transform {
	case "to_int":
		return toInt(value), nil
	case "to_timestamp":
		return toTimestamp(value), nil
	case "uppercase":
		return toUppercase(value), nil
	case "lowercase":
		return toLowercase(value), nil
	case "map_value":
		return mapValue(value, params), nil
	default:
		return value, nil
	}
}

func (n *Normalizer) evaluateCondition(condition string, fields map[string]interface{}) bool {
	// Simple condition parser: field==value, field!=value
	if idx := indexOf(condition, "=="); idx > 0 {
		field := condition[:idx]
		expectedValue := condition[idx+2:]
		actualValue := getNestedValue(fields, field)
		return fmt.Sprintf("%v", actualValue) == expectedValue
	}
	if idx := indexOf(condition, "!="); idx > 0 {
		field := condition[:idx]
		expectedValue := condition[idx+2:]
		actualValue := getNestedValue(fields, field)
		return fmt.Sprintf("%v", actualValue) != expectedValue
	}
	// Check field exists
	return getNestedValue(fields, condition) != nil
}

func (n *Normalizer) loadDefaultMappings() {
	n.defaultMapping = &MappingConfig{
		Name:             "default",
		SourceType:       "*",
		VendorName:       "Unknown",
		ProductName:      "Unknown",
		DefaultEventType: EventTypeGeneric,
	}
}

// Helper functions

func getNestedValue(data map[string]interface{}, path string) interface{} {
	parts := splitPath(path)
	current := interface{}(data)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
		if current == nil {
			return nil
		}
	}
	return current
}

func splitPath(path string) []string {
	var parts []string
	var current string
	for _, c := range path {
		if c == '.' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toInt(value interface{}) int64 {
	switch v := value.(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		var i int64
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return 0
}

func toTimestamp(value interface{}) time.Time {
	switch v := value.(type) {
	case time.Time:
		return v
	case string:
		formats := []string{
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05.000Z",
			"2006-01-02 15:04:05",
		}
		for _, f := range formats {
			if t, err := time.Parse(f, v); err == nil {
				return t
			}
		}
	case float64:
		if v > 1e12 {
			return time.UnixMilli(int64(v))
		}
		return time.Unix(int64(v), 0)
	}
	return time.Time{}
}

func toUppercase(value interface{}) string {
	s := fmt.Sprintf("%v", value)
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		result[i] = c
	}
	return string(result)
}

func toLowercase(value interface{}) string {
	s := fmt.Sprintf("%v", value)
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

func mapValue(value interface{}, mapping map[string]string) string {
	key := fmt.Sprintf("%v", value)
	if mapped, ok := mapping[key]; ok {
		return mapped
	}
	if def, ok := mapping["default"]; ok {
		return def
	}
	return key
}

func setNestedValue(event *UDMEvent, path string, value interface{}) error {
	// This is a simplified version - in production, use reflection
	// For now, handle common paths
	parts := splitPath(path)
	if len(parts) < 2 {
		return nil
	}

	// Handle based on first part
	switch parts[0] {
	case "metadata":
		return setMetadataField(event.Metadata, parts[1:], value)
	case "principal":
		if event.Principal == nil {
			event.Principal = &Entity{}
		}
		return setEntityField(event.Principal, parts[1:], value)
	case "target":
		if event.Target == nil {
			event.Target = &Entity{}
		}
		return setEntityField(event.Target, parts[1:], value)
	case "observer":
		if event.Observer == nil {
			event.Observer = &Entity{}
		}
		return setEntityField(event.Observer, parts[1:], value)
	case "network":
		if event.Network == nil {
			event.Network = &Network{}
		}
		return setNetworkField(event.Network, parts[1:], value)
	case "security_result":
		if event.SecurityResult == nil {
			event.SecurityResult = &SecurityResult{}
		}
		return setSecurityResultField(event.SecurityResult, parts[1:], value)
	case "extensions":
		if event.Extensions == nil {
			event.Extensions = make(map[string]interface{})
		}
		setMapValue(event.Extensions, parts[1:], value)
		return nil
	}

	return nil
}

func setMetadataField(m *Metadata, parts []string, value interface{}) error {
	if len(parts) == 0 || m == nil {
		return nil
	}
	switch parts[0] {
	case "event_type":
		if s, ok := value.(string); ok {
			m.EventType = EventType(s)
		}
	case "event_timestamp":
		if t, ok := value.(time.Time); ok {
			m.EventTimestamp = t
		}
	case "vendor_name":
		m.VendorName = fmt.Sprintf("%v", value)
	case "product_name":
		m.ProductName = fmt.Sprintf("%v", value)
	case "product_event_type":
		m.ProductEventType = fmt.Sprintf("%v", value)
	case "description":
		m.Description = fmt.Sprintf("%v", value)
	case "log_type":
		m.LogType = fmt.Sprintf("%v", value)
	case "id":
		m.ID = fmt.Sprintf("%v", value)
	}
	return nil
}

func setEntityField(e *Entity, parts []string, value interface{}) error {
	if len(parts) == 0 || e == nil {
		return nil
	}
	switch parts[0] {
	case "hostname":
		e.Hostname = fmt.Sprintf("%v", value)
	case "ip":
		if s, ok := value.(string); ok {
			e.IP = append(e.IP, s)
		}
	case "mac":
		if s, ok := value.(string); ok {
			e.MAC = append(e.MAC, s)
		}
	case "port":
		e.Port = int(toInt(value))
	case "url":
		e.URL = fmt.Sprintf("%v", value)
	case "application":
		e.Application = fmt.Sprintf("%v", value)
	case "administrative_domain":
		e.AdministrativeDomain = fmt.Sprintf("%v", value)
	case "platform":
		e.Platform = fmt.Sprintf("%v", value)
	case "user":
		if e.User == nil {
			e.User = &User{}
		}
		return setUserField(e.User, parts[1:], value)
	case "process":
		if e.Process == nil {
			e.Process = &Process{}
		}
		return setProcessField(e.Process, parts[1:], value)
	case "file":
		if e.File == nil {
			e.File = &File{}
		}
		return setFileField(e.File, parts[1:], value)
	case "registry":
		if e.Registry == nil {
			e.Registry = &Registry{}
		}
		return setRegistryField(e.Registry, parts[1:], value)
	case "resource":
		if e.Resource == nil {
			e.Resource = &Resource{}
		}
		return setResourceField(e.Resource, parts[1:], value)
	case "labels":
		if e.Labels == nil {
			e.Labels = make(map[string]string)
		}
		e.Labels[parts[len(parts)-1]] = fmt.Sprintf("%v", value)
	}
	return nil
}

func setUserField(u *User, parts []string, value interface{}) error {
	if len(parts) == 0 || u == nil {
		return nil
	}
	switch parts[0] {
	case "userid", "user_id":
		u.UserID = fmt.Sprintf("%v", value)
	case "user_name":
		u.UserName = fmt.Sprintf("%v", value)
	case "user_display_name":
		u.DisplayName = fmt.Sprintf("%v", value)
	case "windows_sid":
		u.WindowsSID = fmt.Sprintf("%v", value)
	case "product_object_id":
		u.ProductObjectID = fmt.Sprintf("%v", value)
	case "group_ids":
		if s, ok := value.(string); ok {
			u.GroupIDs = append(u.GroupIDs, s)
		}
	}
	return nil
}

func setProcessField(p *Process, parts []string, value interface{}) error {
	if len(parts) == 0 || p == nil {
		return nil
	}
	switch parts[0] {
	case "pid":
		p.PID = toInt(value)
	case "command_line":
		p.CommandLine = fmt.Sprintf("%v", value)
	case "product_specific_process_id":
		p.ProductSpecificProcessID = fmt.Sprintf("%v", value)
	case "file":
		if p.File == nil {
			p.File = &File{}
		}
		return setFileField(p.File, parts[1:], value)
	case "parent_process":
		if p.ParentProcess == nil {
			p.ParentProcess = &Process{}
		}
		return setProcessField(p.ParentProcess, parts[1:], value)
	}
	return nil
}

func setFileField(f *File, parts []string, value interface{}) error {
	if len(parts) == 0 || f == nil {
		return nil
	}
	switch parts[0] {
	case "full_path":
		f.FullPath = fmt.Sprintf("%v", value)
	case "file_name":
		f.FileName = fmt.Sprintf("%v", value)
	case "size":
		f.Size = toInt(value)
	case "sha256":
		f.SHA256 = fmt.Sprintf("%v", value)
	case "sha1":
		f.SHA1 = fmt.Sprintf("%v", value)
	case "md5":
		f.MD5 = fmt.Sprintf("%v", value)
	case "mime_type":
		f.MimeType = fmt.Sprintf("%v", value)
	}
	return nil
}

func setRegistryField(r *Registry, parts []string, value interface{}) error {
	if len(parts) == 0 || r == nil {
		return nil
	}
	switch parts[0] {
	case "registry_key":
		r.RegistryKey = fmt.Sprintf("%v", value)
	case "registry_value_name":
		r.RegistryValueName = fmt.Sprintf("%v", value)
	case "registry_value_data":
		r.RegistryValueData = fmt.Sprintf("%v", value)
	}
	return nil
}

func setResourceField(r *Resource, parts []string, value interface{}) error {
	if len(parts) == 0 || r == nil {
		return nil
	}
	switch parts[0] {
	case "name":
		r.Name = fmt.Sprintf("%v", value)
	case "resource_type", "type":
		r.Type = fmt.Sprintf("%v", value)
	case "resource_subtype":
		r.SubType = fmt.Sprintf("%v", value)
	case "id":
		r.ID = fmt.Sprintf("%v", value)
	case "product_object_id":
		r.ProductObjectID = fmt.Sprintf("%v", value)
	}
	return nil
}

func setNetworkField(n *Network, parts []string, value interface{}) error {
	if len(parts) == 0 || n == nil {
		return nil
	}
	switch parts[0] {
	case "application_protocol":
		n.ApplicationProtocol = fmt.Sprintf("%v", value)
	case "direction":
		n.Direction = fmt.Sprintf("%v", value)
	case "ip_protocol":
		n.IPProtocol = fmt.Sprintf("%v", value)
	case "session_id":
		n.SessionID = fmt.Sprintf("%v", value)
	case "received_bytes":
		n.ReceivedBytes = toInt(value)
	case "sent_bytes":
		n.SentBytes = toInt(value)
	case "dns":
		if n.DNS == nil {
			n.DNS = &DNS{}
		}
		// Handle DNS fields
	case "http":
		if n.HTTP == nil {
			n.HTTP = &HTTP{}
		}
		// Handle HTTP fields
	}
	return nil
}

func setSecurityResultField(sr *SecurityResult, parts []string, value interface{}) error {
	if len(parts) == 0 || sr == nil {
		return nil
	}
	switch parts[0] {
	case "action":
		sr.Action = fmt.Sprintf("%v", value)
	case "severity":
		sr.Severity = fmt.Sprintf("%v", value)
	case "severity_details":
		sr.SeverityDetails = fmt.Sprintf("%v", value)
	case "category":
		sr.Category = fmt.Sprintf("%v", value)
	case "rule_id":
		sr.RuleID = fmt.Sprintf("%v", value)
	case "rule_name":
		sr.RuleName = fmt.Sprintf("%v", value)
	case "rule_type":
		sr.RuleType = fmt.Sprintf("%v", value)
	case "threat_id":
		sr.ThreatID = fmt.Sprintf("%v", value)
	case "threat_name":
		sr.ThreatName = fmt.Sprintf("%v", value)
	case "rule_labels":
		if sr.RuleLabels == nil {
			sr.RuleLabels = make(map[string]string)
		}
		sr.RuleLabels[parts[len(parts)-1]] = fmt.Sprintf("%v", value)
	}
	return nil
}

func setMapValue(m map[string]interface{}, parts []string, value interface{}) {
	if len(parts) == 0 {
		return
	}
	if len(parts) == 1 {
		m[parts[0]] = value
		return
	}

	if _, ok := m[parts[0]]; !ok {
		m[parts[0]] = make(map[string]interface{})
	}
	if nested, ok := m[parts[0]].(map[string]interface{}); ok {
		setMapValue(nested, parts[1:], value)
	}
}
