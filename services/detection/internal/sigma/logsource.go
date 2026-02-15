// Package sigma provides Sigma rule parsing and log source mapping.
package sigma

import (
	"fmt"
	"strings"
)

// LogSourceMapping maps Sigma log sources to internal data sources.
type LogSourceMapping struct {
	// Event types to filter
	EventTypes []string `json:"event_types"`

	// Index/table patterns
	Indices []string `json:"indices"`

	// Field mappings specific to this log source
	FieldMappings map[string]string `json:"field_mappings"`

	// Default filters to apply
	DefaultFilters map[string]interface{} `json:"default_filters"`
}

// LogSourceMapper maps Sigma log sources to internal representations.
type LogSourceMapper struct {
	mappings map[string]*LogSourceMapping
}

// NewLogSourceMapper creates a new log source mapper with default mappings.
func NewLogSourceMapper() *LogSourceMapper {
	mapper := &LogSourceMapper{
		mappings: make(map[string]*LogSourceMapping),
	}

	// Register default mappings
	mapper.RegisterDefaultMappings()

	return mapper
}

// RegisterDefaultMappings registers the default log source mappings.
func (m *LogSourceMapper) RegisterDefaultMappings() {
	// Windows Event Log - Security
	m.Register("windows:security", &LogSourceMapping{
		EventTypes: []string{"authentication", "authorization", "account_management"},
		Indices:    []string{"winlogbeat-*", "windows-security-*"},
		FieldMappings: map[string]string{
			"EventID":        "event.code",
			"LogonType":      "winlog.event_data.LogonType",
			"TargetUserName": "user.target.name",
			"SubjectUserName": "user.name",
			"IpAddress":      "source.ip",
			"WorkstationName": "source.hostname",
			"Status":         "event.outcome",
			"TargetDomainName": "user.target.domain",
			"SubjectDomainName": "user.domain",
		},
		DefaultFilters: map[string]interface{}{
			"winlog.channel": "Security",
		},
	})

	// Windows Event Log - System
	m.Register("windows:system", &LogSourceMapping{
		EventTypes: []string{"system_audit", "service", "startup"},
		Indices:    []string{"winlogbeat-*", "windows-system-*"},
		FieldMappings: map[string]string{
			"EventID":     "event.code",
			"Provider":    "winlog.provider_name",
			"ServiceName": "service.name",
		},
		DefaultFilters: map[string]interface{}{
			"winlog.channel": "System",
		},
	})

	// Windows Event Log - Sysmon
	m.Register("windows:sysmon", &LogSourceMapping{
		EventTypes: []string{"process_creation", "network_connection", "file_creation", "registry_modification"},
		Indices:    []string{"winlogbeat-*", "sysmon-*"},
		FieldMappings: map[string]string{
			"EventID":           "event.code",
			"Image":             "process.executable",
			"CommandLine":       "process.command_line",
			"ParentImage":       "process.parent.executable",
			"ParentCommandLine": "process.parent.command_line",
			"User":              "user.name",
			"ProcessId":         "process.pid",
			"ProcessGuid":       "process.entity_id",
			"ParentProcessId":   "process.parent.pid",
			"ParentProcessGuid": "process.parent.entity_id",
			"SourceIp":          "source.ip",
			"DestinationIp":     "destination.ip",
			"DestinationPort":   "destination.port",
			"TargetFilename":    "file.path",
			"TargetObject":      "registry.path",
			"QueryName":         "dns.question.name",
		},
		DefaultFilters: map[string]interface{}{
			"winlog.channel": "Microsoft-Windows-Sysmon/Operational",
		},
	})

	// Windows - PowerShell
	m.Register("windows:powershell", &LogSourceMapping{
		EventTypes: []string{"script_execution"},
		Indices:    []string{"winlogbeat-*", "powershell-*"},
		FieldMappings: map[string]string{
			"EventID":       "event.code",
			"ScriptBlockText": "powershell.script_block_text",
			"CommandLine":   "process.command_line",
			"HostApplication": "process.parent.command_line",
		},
		DefaultFilters: map[string]interface{}{
			"winlog.channel": "Microsoft-Windows-PowerShell/Operational",
		},
	})

	// Windows - Process Creation
	m.Register("windows:process_creation", &LogSourceMapping{
		EventTypes: []string{"PROCESS_LAUNCH"},
		Indices:    []string{"winlogbeat-*", "sysmon-*"},
		FieldMappings: map[string]string{
			"Image":             "process.executable",
			"CommandLine":       "process.command_line",
			"ParentImage":       "process.parent.executable",
			"ParentCommandLine": "process.parent.command_line",
			"User":              "user.name",
			"CurrentDirectory":  "process.working_directory",
			"OriginalFileName":  "file.name",
		},
		DefaultFilters: map[string]interface{}{
			"event.type": "process_creation",
		},
	})

	// Linux - Auditd
	m.Register("linux:auditd", &LogSourceMapping{
		EventTypes: []string{"process_creation", "authentication", "file_access"},
		Indices:    []string{"auditbeat-*", "linux-audit-*"},
		FieldMappings: map[string]string{
			"type":     "auditd.data.type",
			"syscall":  "auditd.data.syscall",
			"exe":      "process.executable",
			"comm":     "process.name",
			"a0":       "auditd.data.a0",
			"uid":      "user.id",
			"gid":      "group.id",
			"terminal": "source.hostname",
		},
	})

	// Linux - Syslog
	m.Register("linux:syslog", &LogSourceMapping{
		EventTypes: []string{"authentication", "system_audit"},
		Indices:    []string{"filebeat-*", "syslog-*"},
		FieldMappings: map[string]string{
			"program":  "process.name",
			"hostname": "host.hostname",
			"message":  "message",
		},
	})

	// Firewall
	m.Register("firewall", &LogSourceMapping{
		EventTypes: []string{"NETWORK_CONNECTION"},
		Indices:    []string{"firewall-*", "network-*"},
		FieldMappings: map[string]string{
			"src_ip":    "source.ip",
			"dst_ip":    "destination.ip",
			"src_port":  "source.port",
			"dst_port":  "destination.port",
			"protocol":  "network.protocol",
			"action":    "event.outcome",
		},
	})

	// Web Proxy
	m.Register("proxy", &LogSourceMapping{
		EventTypes: []string{"NETWORK_HTTP"},
		Indices:    []string{"proxy-*", "web-*"},
		FieldMappings: map[string]string{
			"c-uri":           "url.original",
			"cs-host":         "url.domain",
			"cs-method":       "http.request.method",
			"sc-status":       "http.response.status_code",
			"cs-User-Agent":   "user_agent.original",
			"cs-Referer":      "http.request.referrer",
			"c-ip":            "source.ip",
			"s-ip":            "destination.ip",
			"cs-bytes":        "http.request.bytes",
			"sc-bytes":        "http.response.bytes",
		},
	})

	// DNS
	m.Register("dns", &LogSourceMapping{
		EventTypes: []string{"NETWORK_DNS"},
		Indices:    []string{"dns-*", "packetbeat-*"},
		FieldMappings: map[string]string{
			"query":         "dns.question.name",
			"answer":        "dns.answers.name",
			"query_type":    "dns.question.type",
			"response_code": "dns.response_code",
		},
	})

	// Web Server - Apache
	m.Register("apache", &LogSourceMapping{
		EventTypes: []string{"NETWORK_HTTP"},
		Indices:    []string{"apache-*", "webserver-*"},
		FieldMappings: map[string]string{
			"request":   "url.original",
			"method":    "http.request.method",
			"status":    "http.response.status_code",
			"useragent": "user_agent.original",
			"clientip":  "source.ip",
		},
	})

	// Web Server - Nginx
	m.Register("nginx", &LogSourceMapping{
		EventTypes: []string{"NETWORK_HTTP"},
		Indices:    []string{"nginx-*", "webserver-*"},
		FieldMappings: map[string]string{
			"request":     "url.original",
			"method":      "http.request.method",
			"status":      "http.response.status_code",
			"http_user_agent": "user_agent.original",
			"remote_addr": "source.ip",
		},
	})

	// AWS CloudTrail
	m.Register("aws:cloudtrail", &LogSourceMapping{
		EventTypes: []string{"cloud_audit"},
		Indices:    []string{"aws-cloudtrail-*", "cloud-*"},
		FieldMappings: map[string]string{
			"eventSource":       "cloud.service.name",
			"eventName":         "event.action",
			"awsRegion":         "cloud.region",
			"sourceIPAddress":   "source.ip",
			"userIdentity.arn":  "user.id",
			"userAgent":         "user_agent.original",
			"errorCode":         "event.outcome",
		},
	})

	// Azure
	m.Register("azure", &LogSourceMapping{
		EventTypes: []string{"cloud_audit"},
		Indices:    []string{"azure-*", "cloud-*"},
		FieldMappings: map[string]string{
			"operationName": "event.action",
			"resourceType":  "cloud.resource.type",
			"callerIpAddress": "source.ip",
			"properties.statusCode": "http.response.status_code",
		},
	})

	// GCP
	m.Register("gcp", &LogSourceMapping{
		EventTypes: []string{"cloud_audit"},
		Indices:    []string{"gcp-*", "cloud-*"},
		FieldMappings: map[string]string{
			"protoPayload.methodName":  "event.action",
			"protoPayload.serviceName": "cloud.service.name",
			"resource.type":            "cloud.resource.type",
		},
	})
}

// Register registers a log source mapping.
func (m *LogSourceMapper) Register(key string, mapping *LogSourceMapping) {
	m.mappings[key] = mapping
}

// Get returns the mapping for a Sigma log source.
func (m *LogSourceMapper) Get(logsource *LogSource) *LogSourceMapping {
	// Try exact match
	key := m.buildKey(logsource)
	if mapping, ok := m.mappings[key]; ok {
		return mapping
	}

	// Try product:category
	if logsource.Product != "" && logsource.Category != "" {
		key = fmt.Sprintf("%s:%s", logsource.Product, logsource.Category)
		if mapping, ok := m.mappings[key]; ok {
			return mapping
		}
	}

	// Try product only
	if logsource.Product != "" {
		if mapping, ok := m.mappings[logsource.Product]; ok {
			return mapping
		}
	}

	// Try category only
	if logsource.Category != "" {
		if mapping, ok := m.mappings[logsource.Category]; ok {
			return mapping
		}
	}

	return nil
}

// GetFieldMapping returns the field mapping for a Sigma log source.
func (m *LogSourceMapper) GetFieldMapping(logsource *LogSource) map[string]string {
	mapping := m.Get(logsource)
	if mapping == nil {
		return nil
	}
	return mapping.FieldMappings
}

// GetEventTypes returns the event types for a Sigma log source.
func (m *LogSourceMapper) GetEventTypes(logsource *LogSource) []string {
	mapping := m.Get(logsource)
	if mapping == nil {
		return nil
	}
	return mapping.EventTypes
}

// GetIndices returns the index patterns for a Sigma log source.
func (m *LogSourceMapper) GetIndices(logsource *LogSource) []string {
	mapping := m.Get(logsource)
	if mapping == nil {
		return nil
	}
	return mapping.Indices
}

func (m *LogSourceMapper) buildKey(logsource *LogSource) string {
	var parts []string

	if logsource.Product != "" {
		parts = append(parts, logsource.Product)
	}
	if logsource.Category != "" {
		parts = append(parts, logsource.Category)
	}
	if logsource.Service != "" {
		parts = append(parts, logsource.Service)
	}

	return strings.Join(parts, ":")
}

// ListMappings returns all registered log source mappings.
func (m *LogSourceMapper) ListMappings() map[string]*LogSourceMapping {
	result := make(map[string]*LogSourceMapping)
	for k, v := range m.mappings {
		result[k] = v
	}
	return result
}

// MapField maps a Sigma field to internal field for a given log source.
func (m *LogSourceMapper) MapField(logsource *LogSource, sigmaField string) string {
	mapping := m.Get(logsource)
	if mapping != nil {
		if internalField, ok := mapping.FieldMappings[sigmaField]; ok {
			return internalField
		}
	}

	// Fallback to global mapping
	globalMapping := DefaultFieldMapping()
	if internalField, ok := globalMapping[sigmaField]; ok {
		return internalField
	}

	// Return original field as lowercase
	return strings.ToLower(sigmaField)
}
