// Package mapping provides log source-specific UDM mappings.
package mapping

import (
	"github.com/siem-soar-platform/services/normalizer/internal/udm"
)

// FirewallMapping returns UDM mapping for generic firewall logs.
func FirewallMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "firewall",
		SourceType:   "firewall",
		VendorName:   "Generic",
		ProductName:  "Firewall",
		DefaultEventType: udm.EventTypeNetworkConnection,
		EventTypeMappings: map[string]udm.EventType{
			"action==allow":  udm.EventTypeNetworkConnection,
			"action==deny":   udm.EventTypeNetworkConnection,
			"action==drop":   udm.EventTypeNetworkConnection,
			"action==block":  udm.EventTypeNetworkConnection,
			"action==reject": udm.EventTypeNetworkConnection,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "device_name", TargetField: "observer.hostname"},
			{SourceField: "rule_name", TargetField: "security_result.rule_name"},
			{SourceField: "rule_id", TargetField: "security_result.rule_id"},

			// Source (Principal)
			{SourceField: "src_ip", TargetField: "principal.ip"},
			{SourceField: "src_port", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "src_mac", TargetField: "principal.mac"},
			{SourceField: "src_zone", TargetField: "principal.location.name"},
			{SourceField: "src_interface", TargetField: "principal.namespace"},
			{SourceField: "src_user", TargetField: "principal.user.user_name"},

			// Destination (Target)
			{SourceField: "dst_ip", TargetField: "target.ip"},
			{SourceField: "dst_port", TargetField: "target.port", Transform: "to_int"},
			{SourceField: "dst_mac", TargetField: "target.mac"},
			{SourceField: "dst_zone", TargetField: "target.location.name"},
			{SourceField: "dst_interface", TargetField: "target.namespace"},

			// Network
			{SourceField: "protocol", TargetField: "network.ip_protocol", Transform: "uppercase"},
			{SourceField: "bytes_sent", TargetField: "network.sent_bytes", Transform: "to_int"},
			{SourceField: "bytes_received", TargetField: "network.received_bytes", Transform: "to_int"},
			{SourceField: "packets_sent", TargetField: "network.sent_packets", Transform: "to_int"},
			{SourceField: "packets_received", TargetField: "network.received_packets", Transform: "to_int"},
			{SourceField: "session_id", TargetField: "network.session_id"},
			{SourceField: "duration", TargetField: "network.session_duration", Transform: "to_int"},
			{SourceField: "application", TargetField: "network.application_protocol"},

			// Security result
			{
				SourceField: "action",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"allow":  "ALLOW",
					"permit": "ALLOW",
					"accept": "ALLOW",
					"deny":   "BLOCK",
					"drop":   "BLOCK",
					"block":  "BLOCK",
					"reject": "BLOCK",
					"default": "UNKNOWN",
				},
			},
			{SourceField: "threat_name", TargetField: "security_result.threat_name"},
			{SourceField: "category", TargetField: "security_result.category"},
			{
				SourceField: "severity",
				TargetField: "security_result.severity",
				Transform:   "map_value",
				Parameters: map[string]string{
					"critical": "CRITICAL",
					"high":     "HIGH",
					"medium":   "MEDIUM",
					"low":      "LOW",
					"info":     "INFORMATIONAL",
					"default":  "UNKNOWN",
				},
			},

			// NAT
			{SourceField: "nat_src_ip", TargetField: "intermediary.0.ip"},
			{SourceField: "nat_src_port", TargetField: "intermediary.0.port", Transform: "to_int"},
			{SourceField: "nat_dst_ip", TargetField: "intermediary.1.ip"},
			{SourceField: "nat_dst_port", TargetField: "intermediary.1.port", Transform: "to_int"},
		},
	}
}

// IPSIDSMapping returns UDM mapping for IPS/IDS logs.
func IPSIDSMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "ips_ids",
		SourceType:   "ips",
		VendorName:   "Generic",
		ProductName:  "IPS/IDS",
		DefaultEventType: udm.EventTypeScan,
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "sensor_name", TargetField: "observer.hostname"},

			// Source/Target
			{SourceField: "src_ip", TargetField: "principal.ip"},
			{SourceField: "src_port", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "dst_ip", TargetField: "target.ip"},
			{SourceField: "dst_port", TargetField: "target.port", Transform: "to_int"},
			{SourceField: "protocol", TargetField: "network.ip_protocol"},

			// Signature/Rule
			{SourceField: "signature_id", TargetField: "security_result.rule_id"},
			{SourceField: "signature_name", TargetField: "security_result.rule_name"},
			{SourceField: "signature_rev", TargetField: "security_result.rule_version"},
			{SourceField: "classification", TargetField: "security_result.category"},
			{SourceField: "priority", TargetField: "security_result.priority"},

			// Action
			{
				SourceField: "action",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"alert":  "ALLOW",
					"drop":   "BLOCK",
					"block":  "BLOCK",
					"pass":   "ALLOW",
					"default": "UNKNOWN",
				},
			},

			// CVE
			{SourceField: "cve", TargetField: "extensions.vulns.cve", Multiple: true},
		},
	}
}

// VPNMapping returns UDM mapping for VPN logs.
func VPNMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "vpn",
		SourceType:   "vpn",
		VendorName:   "Generic",
		ProductName:  "VPN",
		DefaultEventType: udm.EventTypeUserLogin,
		EventTypeMappings: map[string]udm.EventType{
			"event_type==connect":    udm.EventTypeUserLogin,
			"event_type==disconnect": udm.EventTypeUserLogout,
			"event_type==auth":       udm.EventTypeUserLogin,
		},
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "message", TargetField: "metadata.description"},
			{SourceField: "vpn_gateway", TargetField: "observer.hostname"},

			// User
			{SourceField: "user_name", TargetField: "principal.user.user_name"},
			{SourceField: "user_email", TargetField: "principal.user.email_addresses", Multiple: true},
			{SourceField: "user_domain", TargetField: "principal.administrative_domain"},

			// Network
			{SourceField: "client_ip", TargetField: "principal.ip"},
			{SourceField: "assigned_ip", TargetField: "target.ip"},
			{SourceField: "tunnel_type", TargetField: "network.application_protocol"},

			// Authentication
			{SourceField: "auth_method", TargetField: "extensions.auth.mechanism", Multiple: true},
			{SourceField: "mfa_used", TargetField: "extensions.auth.auth_metadata"},

			// Session
			{SourceField: "session_id", TargetField: "network.session_id"},
			{SourceField: "session_duration", TargetField: "network.session_duration", Transform: "to_int"},
			{SourceField: "bytes_sent", TargetField: "network.sent_bytes", Transform: "to_int"},
			{SourceField: "bytes_received", TargetField: "network.received_bytes", Transform: "to_int"},

			// Location
			{SourceField: "country", TargetField: "principal.location.country_or_region"},
			{SourceField: "city", TargetField: "principal.location.city"},

			// Security
			{
				SourceField: "status",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"success":     "ALLOW",
					"connected":   "ALLOW",
					"failure":     "BLOCK",
					"denied":      "BLOCK",
					"disconnected": "ALLOW",
					"default":     "UNKNOWN",
				},
			},
		},
	}
}

// ProxyMapping returns UDM mapping for web proxy logs.
func ProxyMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "proxy",
		SourceType:   "proxy",
		VendorName:   "Generic",
		ProductName:  "Web Proxy",
		DefaultEventType: udm.EventTypeNetworkHTTP,
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "proxy_name", TargetField: "observer.hostname"},

			// Client (Principal)
			{SourceField: "client_ip", TargetField: "principal.ip"},
			{SourceField: "client_port", TargetField: "principal.port", Transform: "to_int"},
			{SourceField: "user_name", TargetField: "principal.user.user_name"},

			// Server (Target)
			{SourceField: "server_ip", TargetField: "target.ip"},
			{SourceField: "server_port", TargetField: "target.port", Transform: "to_int"},
			{SourceField: "server_name", TargetField: "target.hostname"},

			// HTTP
			{SourceField: "method", TargetField: "network.http.method", Transform: "uppercase"},
			{SourceField: "url", TargetField: "network.http.url"},
			{SourceField: "referrer", TargetField: "network.http.referral_url"},
			{SourceField: "user_agent", TargetField: "network.http.user_agent"},
			{SourceField: "status_code", TargetField: "network.http.response_code", Transform: "to_int"},
			{SourceField: "content_type", TargetField: "target.file.mime_type"},

			// Traffic
			{SourceField: "bytes_sent", TargetField: "network.sent_bytes", Transform: "to_int"},
			{SourceField: "bytes_received", TargetField: "network.received_bytes", Transform: "to_int"},
			{SourceField: "duration", TargetField: "network.session_duration", Transform: "to_int"},

			// Category/Security
			{SourceField: "category", TargetField: "security_result.category"},
			{SourceField: "url_category", TargetField: "security_result.category_details", Multiple: true},
			{
				SourceField: "action",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"allowed":   "ALLOW",
					"blocked":   "BLOCK",
					"warned":    "ALLOW",
					"bypassed":  "ALLOW",
					"default":   "UNKNOWN",
				},
			},
			{SourceField: "risk_score", TargetField: "security_result.confidence_details"},
		},
	}
}

// DNSMapping returns UDM mapping for DNS logs.
func DNSMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "dns",
		SourceType:   "dns",
		VendorName:   "Generic",
		ProductName:  "DNS",
		DefaultEventType: udm.EventTypeNetworkDNS,
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "dns_server", TargetField: "observer.hostname"},

			// Client
			{SourceField: "client_ip", TargetField: "principal.ip"},
			{SourceField: "client_port", TargetField: "principal.port", Transform: "to_int"},

			// DNS query
			{SourceField: "query_name", TargetField: "network.dns.questions.0.name"},
			{SourceField: "query_type", TargetField: "network.dns.questions.0.type", Transform: "to_int"},
			{SourceField: "query_class", TargetField: "network.dns.questions.0.class", Transform: "to_int"},

			// DNS response
			{SourceField: "response_code", TargetField: "network.dns.response_code", Transform: "to_int"},
			{SourceField: "answers", TargetField: "network.dns.answers"},
			{SourceField: "answer_ip", TargetField: "network.dns.answers.0.data"},
			{SourceField: "answer_ttl", TargetField: "network.dns.answers.0.ttl", Transform: "to_int"},

			// DNS metadata
			{SourceField: "transaction_id", TargetField: "network.dns.id", Transform: "to_int"},
			{SourceField: "flags", TargetField: "network.dns.op_code", Transform: "to_int"},
			{SourceField: "truncated", TargetField: "network.dns.truncated"},
			{SourceField: "recursion_desired", TargetField: "network.dns.recursion"},

			// Security
			{
				SourceField: "response_code",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"0": "ALLOW",  // NOERROR
					"1": "BLOCK",  // FORMERR
					"2": "BLOCK",  // SERVFAIL
					"3": "BLOCK",  // NXDOMAIN
					"5": "BLOCK",  // REFUSED
					"default": "UNKNOWN",
				},
			},
			{SourceField: "category", TargetField: "security_result.category"},
			{SourceField: "threat_type", TargetField: "security_result.threat_name"},
		},
	}
}

// DHCPMapping returns UDM mapping for DHCP logs.
func DHCPMapping() *udm.MappingConfig {
	return &udm.MappingConfig{
		Name:         "dhcp",
		SourceType:   "dhcp",
		VendorName:   "Generic",
		ProductName:  "DHCP",
		DefaultEventType: udm.EventTypeNetworkDHCP,
		FieldMappings: []udm.FieldMapping{
			// Metadata
			{SourceField: "timestamp", TargetField: "metadata.event_timestamp", Transform: "to_timestamp"},
			{SourceField: "dhcp_server", TargetField: "observer.hostname"},
			{SourceField: "message_type", TargetField: "metadata.product_event_type"},

			// Client
			{SourceField: "client_mac", TargetField: "principal.mac"},
			{SourceField: "client_hostname", TargetField: "network.dhcp.client_hostname"},
			{SourceField: "client_id", TargetField: "network.dhcp.client_identifier"},

			// Address assignment
			{SourceField: "assigned_ip", TargetField: "principal.ip"},
			{SourceField: "requested_ip", TargetField: "network.dhcp.requested_address"},
			{SourceField: "lease_time", TargetField: "network.dhcp.lease_duration", Transform: "to_int"},

			// DHCP specific
			{
				SourceField: "message_type",
				TargetField: "network.dhcp.message_type",
				Transform:   "map_value",
				Parameters: map[string]string{
					"1": "DISCOVER",
					"2": "OFFER",
					"3": "REQUEST",
					"4": "DECLINE",
					"5": "ACK",
					"6": "NAK",
					"7": "RELEASE",
					"8": "INFORM",
				},
			},

			// Security
			{
				SourceField: "result",
				TargetField: "security_result.action",
				Transform:   "map_value",
				Parameters: map[string]string{
					"success": "ALLOW",
					"ack":     "ALLOW",
					"nak":     "BLOCK",
					"declined": "BLOCK",
					"default": "UNKNOWN",
				},
			},
		},
	}
}
