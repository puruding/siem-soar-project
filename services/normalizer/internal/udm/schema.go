// Package udm implements Google Chronicle's Unified Data Model (UDM) schema.
package udm

import (
	"time"
)

// UDMEvent represents a normalized event in UDM format.
// Based on Google Chronicle's UDM schema.
type UDMEvent struct {
	// Core fields
	Metadata   *Metadata   `json:"metadata"`
	Principal  *Entity     `json:"principal,omitempty"`
	Target     *Entity     `json:"target,omitempty"`
	Src        *Entity     `json:"src,omitempty"`
	Observer   *Entity     `json:"observer,omitempty"`
	Intermediary []*Entity `json:"intermediary,omitempty"`

	// Event details
	Network        *Network        `json:"network,omitempty"`
	SecurityResult *SecurityResult `json:"security_result,omitempty"`
	Extensions     *Extensions     `json:"extensions,omitempty"`

	// Additional contexts
	About  []*Entity `json:"about,omitempty"`
	AdditionalEventData map[string]interface{} `json:"additional_event_data,omitempty"`
}

// Metadata contains event metadata.
type Metadata struct {
	EventTimestamp     time.Time `json:"event_timestamp"`
	CollectedTimestamp time.Time `json:"collected_timestamp"`
	IngestedTimestamp  time.Time `json:"ingested_timestamp"`
	EventType          EventType `json:"event_type"`
	VendorName         string    `json:"vendor_name"`
	ProductName        string    `json:"product_name"`
	ProductVersion     string    `json:"product_version,omitempty"`
	ProductEventType   string    `json:"product_event_type,omitempty"`
	Description        string    `json:"description,omitempty"`
	UrlBackToProduct   string    `json:"url_back_to_product,omitempty"`
	ID                 string    `json:"id"`
	LogType            string    `json:"log_type,omitempty"`
}

// EventType represents the type of security event.
type EventType string

const (
	EventTypeUnspecified          EventType = "UNSPECIFIED"
	EventTypeGeneric              EventType = "GENERIC_EVENT"
	EventTypeUserLogin            EventType = "USER_LOGIN"
	EventTypeUserLogout           EventType = "USER_LOGOUT"
	EventTypeUserCreation         EventType = "USER_CREATION"
	EventTypeUserDeletion         EventType = "USER_DELETION"
	EventTypeUserPasswordChange   EventType = "USER_PASSWORD_CHANGE"
	EventTypeUserPrivilegeChange  EventType = "USER_PRIVILEGE_CHANGE"
	EventTypeGroupCreation        EventType = "GROUP_CREATION"
	EventTypeGroupDeletion        EventType = "GROUP_DELETION"
	EventTypeGroupModification    EventType = "GROUP_MODIFICATION"
	EventTypeNetworkConnection    EventType = "NETWORK_CONNECTION"
	EventTypeNetworkFlow          EventType = "NETWORK_FLOW"
	EventTypeNetworkDNS           EventType = "NETWORK_DNS"
	EventTypeNetworkDHCP          EventType = "NETWORK_DHCP"
	EventTypeNetworkHTTP          EventType = "NETWORK_HTTP"
	EventTypeNetworkSMTP          EventType = "NETWORK_SMTP"
	EventTypeNetworkFTP           EventType = "NETWORK_FTP"
	EventTypeFileCreation         EventType = "FILE_CREATION"
	EventTypeFileDeletion         EventType = "FILE_DELETION"
	EventTypeFileModification     EventType = "FILE_MODIFICATION"
	EventTypeFileRead             EventType = "FILE_READ"
	EventTypeFileCopy             EventType = "FILE_COPY"
	EventTypeFileMove             EventType = "FILE_MOVE"
	EventTypeProcessLaunch        EventType = "PROCESS_LAUNCH"
	EventTypeProcessTermination   EventType = "PROCESS_TERMINATION"
	EventTypeProcessInjection     EventType = "PROCESS_INJECTION"
	EventTypeRegistryCreation     EventType = "REGISTRY_CREATION"
	EventTypeRegistryDeletion     EventType = "REGISTRY_DELETION"
	EventTypeRegistryModification EventType = "REGISTRY_MODIFICATION"
	EventTypeServiceCreation      EventType = "SERVICE_CREATION"
	EventTypeServiceDeletion      EventType = "SERVICE_DELETION"
	EventTypeServiceStart         EventType = "SERVICE_START"
	EventTypeServiceStop          EventType = "SERVICE_STOP"
	EventTypeScheduledTask        EventType = "SCHEDULED_TASK"
	EventTypeEmailTransaction     EventType = "EMAIL_TRANSACTION"
	EventTypeScan                 EventType = "SCAN"
	EventTypeResourceAccess       EventType = "RESOURCE_ACCESS"
	EventTypeResourceCreation     EventType = "RESOURCE_CREATION"
	EventTypeResourceDeletion     EventType = "RESOURCE_DELETION"
	EventTypeStatusUpdate         EventType = "STATUS_UPDATE"
	EventTypeSystemAudit          EventType = "SYSTEM_AUDIT_LOG_EVENT"
)

// Entity represents an entity (user, device, resource, etc.).
type Entity struct {
	// Identity
	Hostname         string   `json:"hostname,omitempty"`
	IP               []string `json:"ip,omitempty"`
	MAC              []string `json:"mac,omitempty"`
	Port             int      `json:"port,omitempty"`
	Namespace        string   `json:"namespace,omitempty"`

	// User
	User             *User    `json:"user,omitempty"`

	// Asset
	Asset            *Asset   `json:"asset,omitempty"`

	// Process
	Process          *Process `json:"process,omitempty"`

	// File
	File             *File    `json:"file,omitempty"`

	// Registry
	Registry         *Registry `json:"registry,omitempty"`

	// Resource
	Resource         *Resource `json:"resource,omitempty"`

	// Application
	Application      string   `json:"application,omitempty"`

	// Location
	Location         *Location `json:"location,omitempty"`

	// Cloud
	Cloud            *Cloud   `json:"cloud,omitempty"`

	// Administrative domain
	AdministrativeDomain string `json:"administrative_domain,omitempty"`

	// Labels
	Labels           []Label  `json:"labels,omitempty"`
}

// User represents a user entity.
type User struct {
	UserID            string   `json:"user_id,omitempty"`
	UserName          string   `json:"user_name,omitempty"`
	EmailAddresses    []string `json:"email_addresses,omitempty"`
	GroupIDs          []string `json:"group_ids,omitempty"`
	WindowsSID        string   `json:"windows_sid,omitempty"`
	ProductObjectID   string   `json:"product_object_id,omitempty"`
	Department        string   `json:"department,omitempty"`
	Title             string   `json:"title,omitempty"`
	Company           string   `json:"company,omitempty"`
	EmployeeID        string   `json:"employee_id,omitempty"`
	PhoneNumbers      []string `json:"phone_numbers,omitempty"`
	UserAuthenticationStatus string `json:"user_authentication_status,omitempty"`
}

// Asset represents an asset entity.
type Asset struct {
	AssetID           string   `json:"asset_id,omitempty"`
	ProductObjectID   string   `json:"product_object_id,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	IP                []string `json:"ip,omitempty"`
	MAC               []string `json:"mac,omitempty"`
	HardwareManufacturer string `json:"hardware_manufacturer,omitempty"`
	HardwareModel     string   `json:"hardware_model,omitempty"`
	PlatformSoftware  *PlatformSoftware `json:"platform_software,omitempty"`
	Type              string   `json:"type,omitempty"`
	Category          string   `json:"category,omitempty"`
	FirstSeenTime     time.Time `json:"first_seen_time,omitempty"`
	LastSeenTime      time.Time `json:"last_seen_time,omitempty"`
}

// PlatformSoftware represents OS information.
type PlatformSoftware struct {
	Platform        string `json:"platform,omitempty"`
	PlatformVersion string `json:"platform_version,omitempty"`
}

// Process represents a process entity.
type Process struct {
	PID               int64    `json:"pid,omitempty"`
	PPID              int64    `json:"ppid,omitempty"`
	File              *File    `json:"file,omitempty"`
	CommandLine       string   `json:"command_line,omitempty"`
	ProductSpecificProcessID string `json:"product_specific_process_id,omitempty"`
	ParentProcess     *Process `json:"parent_process,omitempty"`
	User              *User    `json:"user,omitempty"`
}

// File represents a file entity.
type File struct {
	SHA256           string   `json:"sha256,omitempty"`
	SHA1             string   `json:"sha1,omitempty"`
	MD5              string   `json:"md5,omitempty"`
	FullPath         string   `json:"full_path,omitempty"`
	FileName         string   `json:"file_name,omitempty"`
	FileExtension    string   `json:"file_extension,omitempty"`
	Size             int64    `json:"size,omitempty"`
	MimeType         string   `json:"mime_type,omitempty"`
	LastModificationTime time.Time `json:"last_modification_time,omitempty"`
	FirstSeenTime    time.Time `json:"first_seen_time,omitempty"`
}

// Registry represents a Windows registry entity.
type Registry struct {
	RegistryKey      string `json:"registry_key,omitempty"`
	RegistryValueName string `json:"registry_value_name,omitempty"`
	RegistryValueData string `json:"registry_value_data,omitempty"`
}

// Resource represents a cloud or other resource.
type Resource struct {
	Name             string            `json:"name,omitempty"`
	ProductObjectID  string            `json:"product_object_id,omitempty"`
	ResourceType     string            `json:"resource_type,omitempty"`
	ResourceSubType  string            `json:"resource_subtype,omitempty"`
	Attribute        map[string]string `json:"attribute,omitempty"`
}

// Location represents geographical location.
type Location struct {
	City             string  `json:"city,omitempty"`
	State            string  `json:"state,omitempty"`
	CountryOrRegion  string  `json:"country_or_region,omitempty"`
	RegionLatitude   float64 `json:"region_latitude,omitempty"`
	RegionLongitude  float64 `json:"region_longitude,omitempty"`
	Name             string  `json:"name,omitempty"`
	DeskLocation     string  `json:"desk_location,omitempty"`
	FloorName        string  `json:"floor_name,omitempty"`
}

// Cloud represents cloud context.
type Cloud struct {
	Environment      string `json:"environment,omitempty"`
	Project          *CloudProject `json:"project,omitempty"`
	VPC              *VPC   `json:"vpc,omitempty"`
	AvailabilityZone string `json:"availability_zone,omitempty"`
}

// CloudProject represents a cloud project.
type CloudProject struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
	ParentProject    string `json:"parent_project,omitempty"`
	ResourcePath     string `json:"resource_path,omitempty"`
}

// VPC represents a virtual private cloud.
type VPC struct {
	ID               string `json:"id,omitempty"`
	Name             string `json:"name,omitempty"`
}

// Label represents a key-value label.
type Label struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
}

// Network represents network context.
type Network struct {
	ApplicationProtocol string   `json:"application_protocol,omitempty"`
	Direction           string   `json:"direction,omitempty"` // INBOUND, OUTBOUND, UNKNOWN
	IPProtocol          string   `json:"ip_protocol,omitempty"` // TCP, UDP, ICMP, etc.
	SentBytes           int64    `json:"sent_bytes,omitempty"`
	ReceivedBytes       int64    `json:"received_bytes,omitempty"`
	SentPackets         int64    `json:"sent_packets,omitempty"`
	ReceivedPackets     int64    `json:"received_packets,omitempty"`
	SessionDuration     int64    `json:"session_duration,omitempty"`
	SessionID           string   `json:"session_id,omitempty"`
	HTTP                *HTTP    `json:"http,omitempty"`
	DNS                 *DNS     `json:"dns,omitempty"`
	Email               *Email   `json:"email,omitempty"`
	FTP                 *FTP     `json:"ftp,omitempty"`
	DHCP                *DHCP    `json:"dhcp,omitempty"`
	TLS                 *TLS     `json:"tls,omitempty"`
	CommunityID         string   `json:"community_id,omitempty"`
}

// HTTP represents HTTP context.
type HTTP struct {
	Method           string            `json:"method,omitempty"`
	URL              string            `json:"url,omitempty"`
	ReferralURL      string            `json:"referral_url,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	ResponseCode     int               `json:"response_code,omitempty"`
	ParsedUserAgent  *ParsedUserAgent  `json:"parsed_user_agent,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
}

// ParsedUserAgent represents parsed user agent info.
type ParsedUserAgent struct {
	Browser          string `json:"browser,omitempty"`
	BrowserVersion   string `json:"browser_version,omitempty"`
	OS               string `json:"os,omitempty"`
	OSVersion        string `json:"os_version,omitempty"`
	Device           string `json:"device,omitempty"`
}

// DNS represents DNS context.
type DNS struct {
	ID               int      `json:"id,omitempty"`
	OpCode           int      `json:"op_code,omitempty"`
	ResponseCode     int      `json:"response_code,omitempty"`
	Questions        []*DNSQuestion `json:"questions,omitempty"`
	Answers          []*DNSAnswer   `json:"answers,omitempty"`
	Authority        []*DNSAnswer   `json:"authority,omitempty"`
	Additional       []*DNSAnswer   `json:"additional,omitempty"`
	Truncated        bool     `json:"truncated,omitempty"`
	Recursion        bool     `json:"recursion,omitempty"`
}

// DNSQuestion represents a DNS question.
type DNSQuestion struct {
	Name             string `json:"name,omitempty"`
	Type             int    `json:"type,omitempty"`
	Class            int    `json:"class,omitempty"`
}

// DNSAnswer represents a DNS answer.
type DNSAnswer struct {
	Name             string `json:"name,omitempty"`
	Type             int    `json:"type,omitempty"`
	Class            int    `json:"class,omitempty"`
	TTL              int    `json:"ttl,omitempty"`
	Data             string `json:"data,omitempty"`
}

// Email represents email context.
type Email struct {
	From             string   `json:"from,omitempty"`
	To               []string `json:"to,omitempty"`
	CC               []string `json:"cc,omitempty"`
	BCC              []string `json:"bcc,omitempty"`
	Subject          string   `json:"subject,omitempty"`
	MailID           string   `json:"mail_id,omitempty"`
	ReplyTo          string   `json:"reply_to,omitempty"`
}

// FTP represents FTP context.
type FTP struct {
	Command          string `json:"command,omitempty"`
	Arguments        string `json:"arguments,omitempty"`
}

// DHCP represents DHCP context.
type DHCP struct {
	ClientHostname   string `json:"client_hostname,omitempty"`
	ClientIdentifier string `json:"client_identifier,omitempty"`
	RequestedAddress string `json:"requested_address,omitempty"`
	LeaseDuration    int64  `json:"lease_duration,omitempty"`
	MessageType      string `json:"message_type,omitempty"`
}

// TLS represents TLS context.
type TLS struct {
	Version          string   `json:"version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	ServerName       string   `json:"server_name,omitempty"`
	ClientCertificate *Certificate `json:"client_certificate,omitempty"`
	ServerCertificate *Certificate `json:"server_certificate,omitempty"`
}

// Certificate represents a TLS certificate.
type Certificate struct {
	Serial           string    `json:"serial,omitempty"`
	Subject          string    `json:"subject,omitempty"`
	Issuer           string    `json:"issuer,omitempty"`
	NotBefore        time.Time `json:"not_before,omitempty"`
	NotAfter         time.Time `json:"not_after,omitempty"`
	SHA256           string    `json:"sha256,omitempty"`
}

// SecurityResult represents security-related results.
type SecurityResult struct {
	Action           string           `json:"action,omitempty"` // ALLOW, BLOCK, UNKNOWN, etc.
	Category         string           `json:"category,omitempty"`
	CategoryDetails  []string         `json:"category_details,omitempty"`
	Confidence       string           `json:"confidence,omitempty"`
	ConfidenceDetails string          `json:"confidence_details,omitempty"`
	Priority         string           `json:"priority,omitempty"`
	PriorityDetails  string           `json:"priority_details,omitempty"`
	RuleName         string           `json:"rule_name,omitempty"`
	RuleID           string           `json:"rule_id,omitempty"`
	RuleType         string           `json:"rule_type,omitempty"`
	RuleVersion      string           `json:"rule_version,omitempty"`
	RuleLabels       []Label          `json:"rule_labels,omitempty"`
	Severity         string           `json:"severity,omitempty"`
	SeverityDetails  string           `json:"severity_details,omitempty"`
	ThreatID         string           `json:"threat_id,omitempty"`
	ThreatName       string           `json:"threat_name,omitempty"`
	ThreatStatus     string           `json:"threat_status,omitempty"`
	URLBackToProduct string           `json:"url_back_to_product,omitempty"`
	Verdict          string           `json:"verdict,omitempty"`
	VerdictInfo      string           `json:"verdict_info,omitempty"`
	DetectionFields  []DetectionField `json:"detection_fields,omitempty"`
}

// DetectionField represents a detection field.
type DetectionField struct {
	Key              string `json:"key"`
	Value            string `json:"value"`
}

// Extensions contains vendor-specific extensions.
type Extensions struct {
	Auth             *AuthExtension   `json:"auth,omitempty"`
	Vulns            *VulnExtension   `json:"vulns,omitempty"`
	Browser          *BrowserExtension `json:"browser,omitempty"`
}

// AuthExtension contains authentication-specific fields.
type AuthExtension struct {
	Type             string   `json:"type,omitempty"`
	Mechanism        []string `json:"mechanism,omitempty"`
	AuthMetadata     map[string]string `json:"auth_metadata,omitempty"`
}

// VulnExtension contains vulnerability-specific fields.
type VulnExtension struct {
	CVE              []string `json:"cve,omitempty"`
	CVSSBaseScore    float64  `json:"cvss_base_score,omitempty"`
	CVSSVersion      string   `json:"cvss_version,omitempty"`
	Severity         string   `json:"severity,omitempty"`
}

// BrowserExtension contains browser-specific fields.
type BrowserExtension struct {
	Browser          string `json:"browser,omitempty"`
	BrowserVersion   string `json:"browser_version,omitempty"`
}
