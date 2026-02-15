// Package mapping provides log source-specific UDM mappings.
package mapping

import (
	"github.com/siem-soar-platform/services/normalizer/internal/udm"
)

// WindowsEventMapping returns UDM mapping for Windows Event Logs.
func WindowsEventMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "windows_event",
		SourceType:   "windows",
		VendorName:   "Microsoft",
		ProductName:  "Windows",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			// Authentication events
			"event_id==4624": udm.EventTypeUserLogin,
			"event_id==4625": udm.EventTypeUserLogin,
			"event_id==4634": udm.EventTypeUserLogout,
			"event_id==4647": udm.EventTypeUserLogout,
			"event_id==4648": udm.EventTypeUserLogin,

			// User management
			"event_id==4720": udm.EventTypeUserCreation,
			"event_id==4722": udm.EventTypeUserCreation,
			"event_id==4726": udm.EventTypeUserDeletion,
			"event_id==4738": udm.EventTypeUserPrivilegeChange,
			"event_id==4740": udm.EventTypeUserPrivilegeChange,
			"event_id==4767": udm.EventTypeUserPrivilegeChange,

			// Group management
			"event_id==4727": udm.EventTypeGroupCreation,
			"event_id==4731": udm.EventTypeGroupCreation,
			"event_id==4730": udm.EventTypeGroupDeletion,
			"event_id==4734": udm.EventTypeGroupDeletion,
			"event_id==4728": udm.EventTypeGroupModification,
			"event_id==4729": udm.EventTypeGroupModification,
			"event_id==4732": udm.EventTypeGroupModification,
			"event_id==4733": udm.EventTypeGroupModification,

			// Process events
			"event_id==4688": udm.EventTypeProcessLaunch,
			"event_id==4689": udm.EventTypeProcessTermination,

			// Service events
			"event_id==4697": udm.EventTypeServiceCreation,
			"event_id==7045": udm.EventTypeServiceCreation,
			"event_id==7036": udm.EventTypeStatusUpdate,

			// File events
			"event_id==4663": udm.EventTypeFileRead,
			"event_id==4656": udm.EventTypeResourceAccess,

			// Network events
			"event_id==5156": udm.EventTypeNetworkConnection,
			"event_id==5157": udm.EventTypeNetworkConnection,

			// Registry events
			"event_id==4657": udm.EventTypeRegistryModification,

			// Scheduled tasks
			"event_id==4698": udm.EventTypeScheduledTask,
			"event_id==4699": udm.EventTypeScheduledTask,
			"event_id==4700": udm.EventTypeScheduledTask,
			"event_id==4701": udm.EventTypeScheduledTask,

			// Audit
			"event_id==4719": udm.EventTypeSystemAudit,
			"event_id==1102": udm.EventTypeSystemAudit,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "event_id", TargetField: "metadata.product_event_type"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "channel", TargetField: "metadata.log_type"},
			{SourceField: "computer", TargetField: "observer.hostname"},
			{SourceField: "provider_name", TargetField: "metadata.product_name"},

			// Principal (Subject/Source)
			{SourceField: "subject_user_name", TargetField: "principal.user.user_name"},
			{SourceField: "subject_user_sid", TargetField: "principal.user.windows_sid"},
			{SourceField: "subject_domain_name", TargetField: "principal.administrative_domain"},
			{SourceField: "subject_logon_id", TargetField: "principal.user.product_object_id"},
			{SourceField: "ip_address", TargetField: "principal.ip"},
			{SourceField: "workstation_name", TargetField: "principal.hostname"},
			{SourceField: "source_network_address", TargetField: "principal.ip"},
			{SourceField: "source_port", TargetField: "principal.port", Transform: "to_int"},

			// Target
			{SourceField: "target_user_name", TargetField: "target.user.user_name"},
			{SourceField: "target_user_sid", TargetField: "target.user.windows_sid"},
			{SourceField: "target_domain_name", TargetField: "target.administrative_domain"},
			{SourceField: "target_server_name", TargetField: "target.hostname"},
			{SourceField: "destination_address", TargetField: "target.ip"},
			{SourceField: "destination_port", TargetField: "target.port", Transform: "to_int"},

			// Process (for 4688)
			{SourceField: "new_process_name", TargetField: "target.process.file.full_path"},
			{SourceField: "new_process_id", TargetField: "target.process.pid", Transform: "to_int"},
			{SourceField: "parent_process_name", TargetField: "principal.process.file.full_path"},
			{SourceField: "creator_process_id", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "command_line", TargetField: "target.process.command_line"},

			// Logon specific
			{
				SourceField: "logon_type",
				TargetField: "extensions.auth.type",
				Transform:   "map_value",
				Parameters: map[string]string{
					"2":  "INTERACTIVE",
					"3":  "NETWORK",
					"4":  "BATCH",
					"5":  "SERVICE",
					"7":  "UNLOCK",
					"8":  "NETWORK_CLEARTEXT",
					"9":  "NEW_CREDENTIALS",
					"10": "REMOTE_INTERACTIVE",
					"11": "CACHED_INTERACTIVE",
				},
			},
			{SourceField: "authentication_package", TargetField: "extensions.auth.mechanism", Multiple: true},
			{SourceField: "logon_process", TargetField: "extensions.auth.mechanism", Multiple: true},

			// Service specific
			{SourceField: "service_name", TargetField: "target.resource.name"},
			{SourceField: "service_file_name", TargetField: "target.file.full_path"},
			{SourceField: "service_type", TargetField: "target.resource.resource_type"},
			{SourceField: "service_start_type", TargetField: "target.resource.resource_subtype"},
			{SourceField: "service_account", TargetField: "target.user.user_name"},

			// Network specific
			{SourceField: "protocol", TargetField: "network.ip_protocol"},
			{SourceField: "direction", TargetField: "network.direction"},

			// Registry specific
			{SourceField: "object_name", TargetField: "target.registry.registry_key"},
			{SourceField: "object_value_name", TargetField: "target.registry.registry_value_name"},

			// File specific
			{SourceField: "object_name", TargetField: "target.file.full_path", Condition: "object_type==File"},

			// Security result
			{
				SourceField: "status",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"0x0":        "ALLOW",
					"0xc0000064": "BLOCK",
					"0xc000006a": "BLOCK",
					"0xc000006d": "BLOCK",
					"0xc000006e": "BLOCK",
					"0xc000006f": "BLOCK",
					"0xc0000070": "BLOCK",
					"0xc0000071": "BLOCK",
					"0xc0000072": "BLOCK",
					"0xc0000133": "BLOCK",
					"default":    "UNKNOWN",
				},
			},
			{SourceField: "failure_reason", TargetField: "security_result.severity_details"},

			// Keywords for severity
			{
				SourceField: "keywords",
				TargetField: "security_result.severity",
				Transform:   "map_value",
				Parameters: map[string]string{
					"Audit Success":    "LOW",
					"Audit Failure":    "MEDIUM",
					"Critical":         "CRITICAL",
					"Error":            "HIGH",
					"Warning":          "MEDIUM",
					"Information":      "INFORMATIONAL",
					"default":          "UNKNOWN",
				},
			},
		},
	}
}

// WindowsSysmonMapping returns UDM mapping for Windows Sysmon logs.
func WindowsSysmonMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "windows_sysmon",
		SourceType:   "sysmon",
		VendorName:   "Microsoft",
		ProductName:  "Sysmon",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"event_id==1":  udm.EventTypeProcessLaunch,
			"event_id==2":  udm.EventTypeFileModification,
			"event_id==3":  udm.EventTypeNetworkConnection,
			"event_id==5":  udm.EventTypeProcessTermination,
			"event_id==6":  udm.EventTypeServiceCreation,
			"event_id==7":  udm.EventTypeProcessInjection,
			"event_id==8":  udm.EventTypeProcessInjection,
			"event_id==9":  udm.EventTypeFileRead,
			"event_id==10": udm.EventTypeProcessInjection,
			"event_id==11": udm.EventTypeFileCreation,
			"event_id==12": udm.EventTypeRegistryCreation,
			"event_id==13": udm.EventTypeRegistryModification,
			"event_id==14": udm.EventTypeRegistryModification,
			"event_id==15": udm.EventTypeFileCreation,
			"event_id==17": udm.EventTypeNetworkConnection,
			"event_id==18": udm.EventTypeNetworkConnection,
			"event_id==19": udm.EventTypeStatusUpdate,
			"event_id==20": udm.EventTypeStatusUpdate,
			"event_id==21": udm.EventTypeStatusUpdate,
			"event_id==22": udm.EventTypeNetworkDNS,
			"event_id==23": udm.EventTypeFileDeletion,
			"event_id==24": udm.EventTypeStatusUpdate,
			"event_id==25": udm.EventTypeProcessInjection,
			"event_id==26": udm.EventTypeFileDeletion,
		},
		FieldMappings: []udm.FieldMapping{
			// Common fields
			{SourceField: "event_id", TargetField: "metadata.product_event_type"},
			{SourceField: "utc_time", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "computer", TargetField: "observer.hostname"},
			{SourceField: "rule_name", TargetField: "security_result.rule_name"},

			// Process fields (Event 1, 5)
			{SourceField: "image", TargetField: "target.process.file.full_path"},
			{SourceField: "command_line", TargetField: "target.process.command_line"},
			{SourceField: "current_directory", TargetField: "target.file.full_path"},
			{SourceField: "process_id", TargetField: "target.process.pid", Transform: "to_int"},
			{SourceField: "process_guid", TargetField: "target.process.product_specific_process_id"},
			{SourceField: "parent_image", TargetField: "principal.process.file.full_path"},
			{SourceField: "parent_command_line", TargetField: "principal.process.command_line"},
			{SourceField: "parent_process_id", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "parent_process_guid", TargetField: "principal.process.product_specific_process_id"},
			{SourceField: "user", TargetField: "principal.user.user_name"},
			{SourceField: "logon_id", TargetField: "principal.user.product_object_id"},
			{SourceField: "integrity_level", TargetField: "security_result.severity_details"},

			// File hashes
			{SourceField: "hashes.sha256", TargetField: "target.process.file.sha256"},
			{SourceField: "hashes.sha1", TargetField: "target.process.file.sha1"},
			{SourceField: "hashes.md5", TargetField: "target.process.file.md5"},

			// Network fields (Event 3)
			{SourceField: "source_ip", TargetField: "principal.ip"},
			{SourceField: "source_port", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "source_hostname", TargetField: "principal.hostname"},
			{SourceField: "destination_ip", TargetField: "target.ip"},
			{SourceField: "destination_port", TargetField: "target.port", Transform: "to_int"},
			{SourceField: "destination_hostname", TargetField: "target.hostname"},
			{SourceField: "protocol", TargetField: "network.ip_protocol"},
			{SourceField: "initiated", TargetField: "network.direction", Transform: "map_value", Parameters: map[string]string{"true": "OUTBOUND", "false": "INBOUND"}},

			// File fields (Events 11, 23)
			{SourceField: "target_filename", TargetField: "target.file.full_path"},
			{SourceField: "creation_utc_time", TargetField: "target.file.first_seen_time", Transform: "to_timestamp"},

			// Registry fields (Events 12, 13, 14)
			{SourceField: "target_object", TargetField: "target.registry.registry_key"},
			{SourceField: "details", TargetField: "target.registry.registry_value_data"},

			// DNS fields (Event 22)
			{SourceField: "query_name", TargetField: "network.dns.questions.0.name"},
			{SourceField: "query_status", TargetField: "network.dns.response_code", Transform: "to_int"},
			{SourceField: "query_results", TargetField: "network.dns.answers.0.data"},
		},
	}
}
