// Package udm provides Google Chronicle's Unified Data Model (UDM) schema.
package udm

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

// Severity represents event severity levels.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
	SeverityUnknown       Severity = "UNKNOWN"
)

// NetworkDirection represents network traffic direction.
type NetworkDirection string

const (
	DirectionInbound  NetworkDirection = "INBOUND"
	DirectionOutbound NetworkDirection = "OUTBOUND"
	DirectionUnknown  NetworkDirection = "UNKNOWN"
)

// SecurityAction represents a security action taken.
type SecurityAction string

const (
	ActionAllow       SecurityAction = "ALLOW"
	ActionBlock       SecurityAction = "BLOCK"
	ActionQuarantine  SecurityAction = "QUARANTINE"
	ActionAlert       SecurityAction = "ALERT"
	ActionChallenge   SecurityAction = "CHALLENGE"
	ActionUnknown     SecurityAction = "UNKNOWN"
)

// String returns the string representation of EventType.
func (e EventType) String() string {
	return string(e)
}

// String returns the string representation of Severity.
func (s Severity) String() string {
	return string(s)
}

// String returns the string representation of NetworkDirection.
func (d NetworkDirection) String() string {
	return string(d)
}

// String returns the string representation of SecurityAction.
func (a SecurityAction) String() string {
	return string(a)
}

// ParseEventType parses a string to EventType.
func ParseEventType(s string) EventType {
	switch s {
	case "USER_LOGIN":
		return EventTypeUserLogin
	case "USER_LOGOUT":
		return EventTypeUserLogout
	case "USER_CREATION":
		return EventTypeUserCreation
	case "USER_DELETION":
		return EventTypeUserDeletion
	case "USER_PASSWORD_CHANGE":
		return EventTypeUserPasswordChange
	case "USER_PRIVILEGE_CHANGE":
		return EventTypeUserPrivilegeChange
	case "GROUP_CREATION":
		return EventTypeGroupCreation
	case "GROUP_DELETION":
		return EventTypeGroupDeletion
	case "GROUP_MODIFICATION":
		return EventTypeGroupModification
	case "NETWORK_CONNECTION":
		return EventTypeNetworkConnection
	case "NETWORK_FLOW":
		return EventTypeNetworkFlow
	case "NETWORK_DNS":
		return EventTypeNetworkDNS
	case "NETWORK_DHCP":
		return EventTypeNetworkDHCP
	case "NETWORK_HTTP":
		return EventTypeNetworkHTTP
	case "NETWORK_SMTP":
		return EventTypeNetworkSMTP
	case "NETWORK_FTP":
		return EventTypeNetworkFTP
	case "FILE_CREATION":
		return EventTypeFileCreation
	case "FILE_DELETION":
		return EventTypeFileDeletion
	case "FILE_MODIFICATION":
		return EventTypeFileModification
	case "FILE_READ":
		return EventTypeFileRead
	case "FILE_COPY":
		return EventTypeFileCopy
	case "FILE_MOVE":
		return EventTypeFileMove
	case "PROCESS_LAUNCH":
		return EventTypeProcessLaunch
	case "PROCESS_TERMINATION":
		return EventTypeProcessTermination
	case "PROCESS_INJECTION":
		return EventTypeProcessInjection
	case "REGISTRY_CREATION":
		return EventTypeRegistryCreation
	case "REGISTRY_DELETION":
		return EventTypeRegistryDeletion
	case "REGISTRY_MODIFICATION":
		return EventTypeRegistryModification
	case "SERVICE_CREATION":
		return EventTypeServiceCreation
	case "SERVICE_DELETION":
		return EventTypeServiceDeletion
	case "SERVICE_START":
		return EventTypeServiceStart
	case "SERVICE_STOP":
		return EventTypeServiceStop
	case "SCHEDULED_TASK":
		return EventTypeScheduledTask
	case "EMAIL_TRANSACTION":
		return EventTypeEmailTransaction
	case "SCAN":
		return EventTypeScan
	case "RESOURCE_ACCESS":
		return EventTypeResourceAccess
	case "RESOURCE_CREATION":
		return EventTypeResourceCreation
	case "RESOURCE_DELETION":
		return EventTypeResourceDeletion
	case "STATUS_UPDATE":
		return EventTypeStatusUpdate
	case "SYSTEM_AUDIT_LOG_EVENT":
		return EventTypeSystemAudit
	case "GENERIC_EVENT":
		return EventTypeGeneric
	default:
		return EventTypeUnspecified
	}
}

// ParseSeverity parses a string to Severity.
func ParseSeverity(s string) Severity {
	switch s {
	case "CRITICAL", "critical":
		return SeverityCritical
	case "HIGH", "high":
		return SeverityHigh
	case "MEDIUM", "medium":
		return SeverityMedium
	case "LOW", "low":
		return SeverityLow
	case "INFORMATIONAL", "informational", "INFO", "info":
		return SeverityInformational
	default:
		return SeverityUnknown
	}
}
