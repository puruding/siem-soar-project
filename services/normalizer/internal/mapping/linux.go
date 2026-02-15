// Package mapping provides log source-specific UDM mappings.
package mapping

import (
	"github.com/siem-soar-platform/services/normalizer/internal/udm"
)

// LinuxAuthMapping returns UDM mapping for Linux authentication logs.
func LinuxAuthMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "linux_auth",
		SourceType:   "linux_auth",
		VendorName:   "Linux",
		ProductName:  "Auth",
		DefaultEventType: udm.EventTypeGeneric,
		EventTypeMappings: map[string]udm.EventType{
			"action==Accepted":    udm.EventTypeUserLogin,
			"action==Failed":      udm.EventTypeUserLogin,
			"action==Invalid":     udm.EventTypeUserLogin,
			"program==sudo":       udm.EventTypeUserPrivilegeChange,
			"program==su":         udm.EventTypeUserLogin,
			"program==passwd":     udm.EventTypeUserPasswordChange,
			"program==useradd":    udm.EventTypeUserCreation,
			"program==userdel":    udm.EventTypeUserDeletion,
			"program==usermod":    udm.EventTypeUserPrivilegeChange,
			"program==groupadd":   udm.EventTypeGroupCreation,
			"program==groupdel":   udm.EventTypeGroupDeletion,
			"program==groupmod":   udm.EventTypeGroupModification,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "program", TargetField: "metadata.product_event_type"},
			{SourceField: "hostname", TargetField: "observer.hostname"},

			// SSH specific
			{SourceField: "username", TargetField: "target.user.user_name"},
			{SourceField: "src_ip", TargetField: "principal.ip"},
			{SourceField: "src_port", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "auth_method", TargetField: "extensions.auth.mechanism", Multiple: true},

			// Sudo specific
			{SourceField: "sudo_user", TargetField: "principal.user.user_name"},
			{SourceField: "target_user", TargetField: "target.user.user_name"},
			{SourceField: "command", TargetField: "target.process.command_line"},
			{SourceField: "pwd", TargetField: "target.file.full_path"},
			{SourceField: "tty", TargetField: "principal.application"},

			// Generic auth
			{SourceField: "pid", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "uid", TargetField: "principal.user.user_id"},
			{SourceField: "gid", TargetField: "principal.user.group_ids", Multiple: true},

			// Security result
			{
				SourceField: "action",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"Accepted": "ALLOW",
					"Failed":   "BLOCK",
					"Invalid":  "BLOCK",
					"default":  "UNKNOWN",
				},
			},
		},
	}
}

// LinuxAuditdMapping returns UDM mapping for Linux auditd logs.
func LinuxAuditdMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "linux_auditd",
		SourceType:   "auditd",
		VendorName:   "Linux",
		ProductName:  "Auditd",
		DefaultEventType: udm.EventTypeSystemAudit,
		EventTypeMappings: map[string]udm.EventType{
			"type==SYSCALL":        udm.EventTypeSystemAudit,
			"type==EXECVE":         udm.EventTypeProcessLaunch,
			"type==PATH":           udm.EventTypeFileRead,
			"type==USER_LOGIN":     udm.EventTypeUserLogin,
			"type==USER_LOGOUT":    udm.EventTypeUserLogout,
			"type==USER_AUTH":      udm.EventTypeUserLogin,
			"type==USER_ACCT":      udm.EventTypeUserCreation,
			"type==ADD_USER":       udm.EventTypeUserCreation,
			"type==DEL_USER":       udm.EventTypeUserDeletion,
			"type==ADD_GROUP":      udm.EventTypeGroupCreation,
			"type==DEL_GROUP":      udm.EventTypeGroupDeletion,
			"type==CRED_ACQ":       udm.EventTypeUserLogin,
			"type==CRED_DISP":      udm.EventTypeUserLogout,
			"type==USER_START":     udm.EventTypeUserLogin,
			"type==USER_END":       udm.EventTypeUserLogout,
			"type==SERVICE_START":  udm.EventTypeServiceStart,
			"type==SERVICE_STOP":   udm.EventTypeServiceStop,
			"type==SOCKADDR":       udm.EventTypeNetworkConnection,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "type", TargetField: "metadata.product_event_type"},
			{SourceField: "msg", TargetField: "metadata.description"},
			{SourceField: "node", TargetField: "observer.hostname"},
			{SourceField: "audit_epoch", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "serial", TargetField: "metadata.id"},

			// Subject/Principal
			{SourceField: "auid", TargetField: "principal.user.user_id"},
			{SourceField: "uid", TargetField: "principal.user.user_id"},
			{SourceField: "euid", TargetField: "target.user.user_id"},
			{SourceField: "suid", TargetField: "principal.user.user_id"},
			{SourceField: "fsuid", TargetField: "principal.user.user_id"},
			{SourceField: "gid", TargetField: "principal.user.group_ids", Multiple: true},
			{SourceField: "egid", TargetField: "target.user.group_ids", Multiple: true},

			// Process
			{SourceField: "pid", TargetField: "target.process.pid", Transform: "to_int"},
			{SourceField: "ppid", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "exe", TargetField: "target.process.file.full_path"},
			{SourceField: "comm", TargetField: "target.process.file.file_name"},
			{SourceField: "cmdline", TargetField: "target.process.command_line"},
			{SourceField: "a0", TargetField: "target.process.command_line"},

			// File
			{SourceField: "name", TargetField: "target.file.full_path"},
			{SourceField: "nametype", TargetField: "target.file.mime_type"},
			{SourceField: "inode", TargetField: "target.file.sha256"}, // Using for unique ID

			// Network
			{SourceField: "saddr", TargetField: "principal.ip"},
			{SourceField: "sport", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "daddr", TargetField: "target.ip"},
			{SourceField: "dport", TargetField: "target.port", Transform: "to_int"},

			// Security result
			{
				SourceField: "success",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"yes": "ALLOW",
					"no":  "BLOCK",
					"default": "UNKNOWN",
				},
			},
			{SourceField: "syscall", TargetField: "security_result.rule_name"},
			{SourceField: "key", TargetField: "security_result.rule_labels"},

			// SELinux
			{SourceField: "subj", TargetField: "principal.labels"},
			{SourceField: "obj", TargetField: "target.labels"},
			{SourceField: "tclass", TargetField: "security_result.category"},
		},
	}
}

// LinuxSyslogMapping returns UDM mapping for generic Linux syslog.
func LinuxSyslogMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "linux_syslog",
		SourceType:   "syslog",
		VendorName:   "Linux",
		ProductName:  "Syslog",
		DefaultEventType: udm.EventTypeStatusUpdate,
		EventTypeMappings: map[string]udm.EventType{
			"facility==4":  udm.EventTypeUserLogin,  // auth
			"facility==10": udm.EventTypeUserLogin,  // authpriv
			"facility==0":  udm.EventTypeSystemAudit, // kern
			"facility==3":  udm.EventTypeServiceStart, // daemon
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "hostname", TargetField: "observer.hostname"},
			{SourceField: "program", TargetField: "metadata.product_event_type"},
			{SourceField: "facility", TargetField: "metadata.log_type"},

			// Process
			{SourceField: "pid", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "program", TargetField: "principal.application"},

			// Severity mapping
			{
				SourceField: "severity",
				TargetField: "security_result.severity",
				Transform:   "map_value",
				Parameters: map[string]string{
					"0": "CRITICAL",   // emerg
					"1": "CRITICAL",   // alert
					"2": "CRITICAL",   // crit
					"3": "HIGH",       // err
					"4": "MEDIUM",     // warning
					"5": "LOW",        // notice
					"6": "INFORMATIONAL", // info
					"7": "INFORMATIONAL", // debug
					"default": "UNKNOWN",
				},
			},
		},
	}
}

// LinuxSystemdMapping returns UDM mapping for systemd journal logs.
func LinuxSystemdMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "linux_systemd",
		SourceType:   "journald",
		VendorName:   "Linux",
		ProductName:  "Systemd",
		DefaultEventType: udm.EventTypeStatusUpdate,
		EventTypeMappings: map[string]udm.EventType{
			"_SYSTEMD_UNIT==sshd.service":    udm.EventTypeUserLogin,
			"_SYSTEMD_UNIT==systemd-logind.service": udm.EventTypeUserLogin,
			"SYSLOG_FACILITY==4":             udm.EventTypeUserLogin,
			"SYSLOG_FACILITY==10":            udm.EventTypeUserLogin,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "__REALTIME_TIMESTAMP", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "MESSAGE", TargetField: "metadata.description"},
			{SourceField: "_HOSTNAME", TargetField: "observer.hostname"},
			{SourceField: "_SYSTEMD_UNIT", TargetField: "metadata.product_event_type"},
			{SourceField: "SYSLOG_IDENTIFIER", TargetField: "metadata.log_type"},

			// Process
			{SourceField: "_PID", TargetField: "principal.process.pid", Transform: "to_int"},
			{SourceField: "_EXE", TargetField: "principal.process.file.full_path"},
			{SourceField: "_CMDLINE", TargetField: "principal.process.command_line"},

			// User
			{SourceField: "_UID", TargetField: "principal.user.user_id"},
			{SourceField: "_GID", TargetField: "principal.user.group_ids", Multiple: true},
			{SourceField: "_AUDIT_LOGINUID", TargetField: "principal.user.user_id"},

			// Boot/Container
			{SourceField: "_BOOT_ID", TargetField: "observer.asset.asset_id"},
			{SourceField: "_MACHINE_ID", TargetField: "observer.asset.product_object_id"},
			{SourceField: "CONTAINER_NAME", TargetField: "target.resource.name"},
			{SourceField: "CONTAINER_ID", TargetField: "target.resource.product_object_id"},

			// Severity
			{
				SourceField: "PRIORITY",
				TargetField: "security_result.severity",
				Transform:   "map_value",
				Parameters: map[string]string{
					"0": "CRITICAL",
					"1": "CRITICAL",
					"2": "CRITICAL",
					"3": "HIGH",
					"4": "MEDIUM",
					"5": "LOW",
					"6": "INFORMATIONAL",
					"7": "INFORMATIONAL",
					"default": "UNKNOWN",
				},
			},
		},
	}
}
