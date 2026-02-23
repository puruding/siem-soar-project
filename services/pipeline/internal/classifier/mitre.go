// Package classifier provides event classification capabilities.
package classifier

import (
	"errors"
	"regexp"
	"strings"
)

// MITREFramework contains MITRE ATT&CK mappings.
type MITREFramework struct {
	Tactics    map[string]TacticInfo
	Techniques map[string]TechniqueInfo
}

// TacticInfo represents a MITRE tactic.
type TacticInfo struct {
	ID          string
	Name        string
	Description string
}

// TechniqueInfo represents a MITRE technique.
type TechniqueInfo struct {
	ID          string
	Name        string
	TacticIDs   []string
	Description string
}

// MITREMapping represents MITRE ATT&CK mapping for a rule.
type MITREMapping struct {
	TacticID      string
	TacticName    string
	TechniqueID   string
	TechniqueName string
}

// NewMITREFramework creates a new MITRE framework with default mappings.
func NewMITREFramework() *MITREFramework {
	return &MITREFramework{
		Tactics:    defaultTactics(),
		Techniques: defaultTechniques(),
	}
}

// GetTacticName returns the tactic name for an ID.
func (m *MITREFramework) GetTacticName(tacticID string) string {
	tacticID = strings.ToUpper(tacticID)
	if tactic, ok := m.Tactics[tacticID]; ok {
		return tactic.Name
	}
	return ""
}

// GetTechniqueName returns the technique name for an ID.
func (m *MITREFramework) GetTechniqueName(techniqueID string) string {
	techniqueID = strings.ToUpper(techniqueID)
	if tech, ok := m.Techniques[techniqueID]; ok {
		return tech.Name
	}
	return ""
}

// GetTacticByName returns the tactic info by its name.
func (m *MITREFramework) GetTacticByName(name string) *TacticInfo {
	name = strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	for _, tactic := range m.Tactics {
		tacticName := strings.ToLower(strings.ReplaceAll(tactic.Name, " ", "-"))
		if tacticName == name {
			return &tactic
		}
	}
	return nil
}

// GetTechniquesByTactic returns all techniques for a given tactic ID.
func (m *MITREFramework) GetTechniquesByTactic(tacticID string) []TechniqueInfo {
	tacticID = strings.ToUpper(tacticID)
	var techniques []TechniqueInfo
	for _, tech := range m.Techniques {
		for _, tid := range tech.TacticIDs {
			if strings.ToUpper(tid) == tacticID {
				techniques = append(techniques, tech)
				break
			}
		}
	}
	return techniques
}

// GetMapping returns a MITREMapping for a technique ID.
func (m *MITREFramework) GetMapping(techniqueID string) *MITREMapping {
	techniqueID = strings.ToUpper(techniqueID)
	tech, ok := m.Techniques[techniqueID]
	if !ok {
		return nil
	}

	mapping := &MITREMapping{
		TechniqueID:   tech.ID,
		TechniqueName: tech.Name,
	}

	// Get first tactic as primary
	if len(tech.TacticIDs) > 0 {
		tacticID := tech.TacticIDs[0]
		if tactic, ok := m.Tactics[tacticID]; ok {
			mapping.TacticID = tactic.ID
			mapping.TacticName = tactic.Name
		}
	}

	return mapping
}

// ParseMITRETag parses a Sigma tag like "attack.t1110" and returns tactic/technique info.
func ParseMITRETag(tag string) (tacticID, techniqueID string, err error) {
	if !strings.HasPrefix(tag, "attack.") {
		return "", "", errors.New("invalid MITRE tag: must start with 'attack.'")
	}

	value := strings.TrimPrefix(tag, "attack.")
	if value == "" {
		return "", "", errors.New("invalid MITRE tag: empty value after 'attack.'")
	}

	// Check if it's a technique ID (starts with t/T followed by digits)
	techniquePattern := regexp.MustCompile(`^[tT](\d{4})(?:\.(\d{3}))?$`)
	if matches := techniquePattern.FindStringSubmatch(value); len(matches) > 0 {
		techniqueID = "T" + matches[1]
		if matches[2] != "" {
			techniqueID += "." + matches[2]
		}
		return "", techniqueID, nil
	}

	// Otherwise it's a tactic name (e.g., "credential_access", "defense_evasion")
	tacticID = value
	return tacticID, "", nil
}

// tacticNameToID converts a tactic name to its ID.
func tacticNameToID(name string) string {
	nameToID := map[string]string{
		"initial-access":      "TA0001",
		"initial_access":      "TA0001",
		"execution":           "TA0002",
		"persistence":         "TA0003",
		"privilege-escalation": "TA0004",
		"privilege_escalation": "TA0004",
		"defense-evasion":     "TA0005",
		"defense_evasion":     "TA0005",
		"credential-access":   "TA0006",
		"credential_access":   "TA0006",
		"discovery":           "TA0007",
		"lateral-movement":    "TA0008",
		"lateral_movement":    "TA0008",
		"collection":          "TA0009",
		"exfiltration":        "TA0010",
		"command-and-control": "TA0011",
		"command_and_control": "TA0011",
		"impact":              "TA0040",
		"reconnaissance":      "TA0043",
		"resource-development": "TA0042",
		"resource_development": "TA0042",
	}
	if id, ok := nameToID[strings.ToLower(name)]; ok {
		return id
	}
	return ""
}

// defaultTactics returns the default MITRE ATT&CK tactics.
func defaultTactics() map[string]TacticInfo {
	return map[string]TacticInfo{
		"TA0001": {
			ID:          "TA0001",
			Name:        "Initial Access",
			Description: "The adversary is trying to get into your network.",
		},
		"TA0002": {
			ID:          "TA0002",
			Name:        "Execution",
			Description: "The adversary is trying to run malicious code.",
		},
		"TA0003": {
			ID:          "TA0003",
			Name:        "Persistence",
			Description: "The adversary is trying to maintain their foothold.",
		},
		"TA0004": {
			ID:          "TA0004",
			Name:        "Privilege Escalation",
			Description: "The adversary is trying to gain higher-level permissions.",
		},
		"TA0005": {
			ID:          "TA0005",
			Name:        "Defense Evasion",
			Description: "The adversary is trying to avoid being detected.",
		},
		"TA0006": {
			ID:          "TA0006",
			Name:        "Credential Access",
			Description: "The adversary is trying to steal account names and passwords.",
		},
		"TA0007": {
			ID:          "TA0007",
			Name:        "Discovery",
			Description: "The adversary is trying to figure out your environment.",
		},
		"TA0008": {
			ID:          "TA0008",
			Name:        "Lateral Movement",
			Description: "The adversary is trying to move through your environment.",
		},
		"TA0009": {
			ID:          "TA0009",
			Name:        "Collection",
			Description: "The adversary is trying to gather data of interest to their goal.",
		},
		"TA0010": {
			ID:          "TA0010",
			Name:        "Exfiltration",
			Description: "The adversary is trying to steal data.",
		},
		"TA0011": {
			ID:          "TA0011",
			Name:        "Command and Control",
			Description: "The adversary is trying to communicate with compromised systems.",
		},
		"TA0040": {
			ID:          "TA0040",
			Name:        "Impact",
			Description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.",
		},
		"TA0042": {
			ID:          "TA0042",
			Name:        "Resource Development",
			Description: "The adversary is trying to establish resources they can use to support operations.",
		},
		"TA0043": {
			ID:          "TA0043",
			Name:        "Reconnaissance",
			Description: "The adversary is trying to gather information they can use to plan future operations.",
		},
	}
}

// defaultTechniques returns common MITRE ATT&CK techniques.
func defaultTechniques() map[string]TechniqueInfo {
	return map[string]TechniqueInfo{
		// Initial Access
		"T1190": {
			ID:          "T1190",
			Name:        "Exploit Public-Facing Application",
			TacticIDs:   []string{"TA0001"},
			Description: "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer.",
		},
		"T1133": {
			ID:          "T1133",
			Name:        "External Remote Services",
			TacticIDs:   []string{"TA0001", "TA0003"},
			Description: "Adversaries may leverage external-facing remote services to initially access or persist.",
		},
		"T1566": {
			ID:          "T1566",
			Name:        "Phishing",
			TacticIDs:   []string{"TA0001"},
			Description: "Adversaries may send phishing messages to gain access to victim systems.",
		},
		"T1566.001": {
			ID:          "T1566.001",
			Name:        "Phishing: Spearphishing Attachment",
			TacticIDs:   []string{"TA0001"},
			Description: "Adversaries may send spearphishing emails with a malicious attachment.",
		},
		"T1566.002": {
			ID:          "T1566.002",
			Name:        "Phishing: Spearphishing Link",
			TacticIDs:   []string{"TA0001"},
			Description: "Adversaries may send spearphishing emails with a malicious link.",
		},

		// Execution
		"T1059": {
			ID:          "T1059",
			Name:        "Command and Scripting Interpreter",
			TacticIDs:   []string{"TA0002"},
			Description: "Adversaries may abuse command and script interpreters to execute commands.",
		},
		"T1059.001": {
			ID:          "T1059.001",
			Name:        "PowerShell",
			TacticIDs:   []string{"TA0002"},
			Description: "Adversaries may abuse PowerShell commands and scripts for execution.",
		},
		"T1059.003": {
			ID:          "T1059.003",
			Name:        "Windows Command Shell",
			TacticIDs:   []string{"TA0002"},
			Description: "Adversaries may abuse the Windows command shell for execution.",
		},
		"T1204": {
			ID:          "T1204",
			Name:        "User Execution",
			TacticIDs:   []string{"TA0002"},
			Description: "An adversary may rely upon specific actions by a user to gain execution.",
		},
		"T1047": {
			ID:          "T1047",
			Name:        "Windows Management Instrumentation",
			TacticIDs:   []string{"TA0002"},
			Description: "Adversaries may abuse WMI to execute malicious commands.",
		},

		// Persistence
		"T1547": {
			ID:          "T1547",
			Name:        "Boot or Logon Autostart Execution",
			TacticIDs:   []string{"TA0003", "TA0004"},
			Description: "Adversaries may configure system settings to automatically execute.",
		},
		"T1547.001": {
			ID:          "T1547.001",
			Name:        "Registry Run Keys / Startup Folder",
			TacticIDs:   []string{"TA0003", "TA0004"},
			Description: "Adversaries may achieve persistence by adding a program to a startup folder or Registry run key.",
		},
		"T1053": {
			ID:          "T1053",
			Name:        "Scheduled Task/Job",
			TacticIDs:   []string{"TA0002", "TA0003", "TA0004"},
			Description: "Adversaries may abuse task scheduling functionality to facilitate execution.",
		},
		"T1136": {
			ID:          "T1136",
			Name:        "Create Account",
			TacticIDs:   []string{"TA0003"},
			Description: "Adversaries may create an account to maintain access.",
		},
		"T1543": {
			ID:          "T1543",
			Name:        "Create or Modify System Process",
			TacticIDs:   []string{"TA0003", "TA0004"},
			Description: "Adversaries may create or modify system-level processes for persistence.",
		},

		// Privilege Escalation
		"T1068": {
			ID:          "T1068",
			Name:        "Exploitation for Privilege Escalation",
			TacticIDs:   []string{"TA0004"},
			Description: "Adversaries may exploit software vulnerabilities to elevate privileges.",
		},
		"T1078": {
			ID:          "T1078",
			Name:        "Valid Accounts",
			TacticIDs:   []string{"TA0001", "TA0003", "TA0004", "TA0005"},
			Description: "Adversaries may obtain and abuse credentials of existing accounts.",
		},
		"T1548": {
			ID:          "T1548",
			Name:        "Abuse Elevation Control Mechanism",
			TacticIDs:   []string{"TA0004", "TA0005"},
			Description: "Adversaries may circumvent mechanisms designed to control elevated privileges.",
		},

		// Defense Evasion
		"T1070": {
			ID:          "T1070",
			Name:        "Indicator Removal",
			TacticIDs:   []string{"TA0005"},
			Description: "Adversaries may delete or modify artifacts generated within systems.",
		},
		"T1070.001": {
			ID:          "T1070.001",
			Name:        "Clear Windows Event Logs",
			TacticIDs:   []string{"TA0005"},
			Description: "Adversaries may clear Windows Event Logs to hide the activity of an intrusion.",
		},
		"T1027": {
			ID:          "T1027",
			Name:        "Obfuscated Files or Information",
			TacticIDs:   []string{"TA0005"},
			Description: "Adversaries may attempt to make files or information difficult to discover.",
		},
		"T1562": {
			ID:          "T1562",
			Name:        "Impair Defenses",
			TacticIDs:   []string{"TA0005"},
			Description: "Adversaries may maliciously modify components of a victim environment.",
		},
		"T1036": {
			ID:          "T1036",
			Name:        "Masquerading",
			TacticIDs:   []string{"TA0005"},
			Description: "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate.",
		},

		// Credential Access
		"T1110": {
			ID:          "T1110",
			Name:        "Brute Force",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may use brute force techniques to gain access to accounts.",
		},
		"T1110.001": {
			ID:          "T1110.001",
			Name:        "Password Guessing",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may guess passwords to attempt access to accounts.",
		},
		"T1110.003": {
			ID:          "T1110.003",
			Name:        "Password Spraying",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may use a single or small list of commonly used passwords against many accounts.",
		},
		"T1003": {
			ID:          "T1003",
			Name:        "OS Credential Dumping",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may attempt to dump credentials from the operating system.",
		},
		"T1003.001": {
			ID:          "T1003.001",
			Name:        "LSASS Memory",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may attempt to access credential material stored in LSASS memory.",
		},
		"T1555": {
			ID:          "T1555",
			Name:        "Credentials from Password Stores",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may search for common password storage locations.",
		},
		"T1552": {
			ID:          "T1552",
			Name:        "Unsecured Credentials",
			TacticIDs:   []string{"TA0006"},
			Description: "Adversaries may search compromised systems to find and obtain credentials.",
		},

		// Discovery
		"T1087": {
			ID:          "T1087",
			Name:        "Account Discovery",
			TacticIDs:   []string{"TA0007"},
			Description: "Adversaries may attempt to get a listing of accounts on a system or within an environment.",
		},
		"T1083": {
			ID:          "T1083",
			Name:        "File and Directory Discovery",
			TacticIDs:   []string{"TA0007"},
			Description: "Adversaries may enumerate files and directories.",
		},
		"T1057": {
			ID:          "T1057",
			Name:        "Process Discovery",
			TacticIDs:   []string{"TA0007"},
			Description: "Adversaries may attempt to get information about running processes.",
		},
		"T1018": {
			ID:          "T1018",
			Name:        "Remote System Discovery",
			TacticIDs:   []string{"TA0007"},
			Description: "Adversaries may attempt to get a listing of other systems by network.",
		},
		"T1082": {
			ID:          "T1082",
			Name:        "System Information Discovery",
			TacticIDs:   []string{"TA0007"},
			Description: "An adversary may attempt to get detailed information about the operating system.",
		},

		// Lateral Movement
		"T1021": {
			ID:          "T1021",
			Name:        "Remote Services",
			TacticIDs:   []string{"TA0008"},
			Description: "Adversaries may use valid accounts to log into a service for remote access.",
		},
		"T1021.001": {
			ID:          "T1021.001",
			Name:        "Remote Desktop Protocol",
			TacticIDs:   []string{"TA0008"},
			Description: "Adversaries may use RDP to move laterally between systems.",
		},
		"T1021.002": {
			ID:          "T1021.002",
			Name:        "SMB/Windows Admin Shares",
			TacticIDs:   []string{"TA0008"},
			Description: "Adversaries may use SMB to move laterally between systems.",
		},
		"T1570": {
			ID:          "T1570",
			Name:        "Lateral Tool Transfer",
			TacticIDs:   []string{"TA0008"},
			Description: "Adversaries may transfer tools or other files between systems.",
		},

		// Collection
		"T1005": {
			ID:          "T1005",
			Name:        "Data from Local System",
			TacticIDs:   []string{"TA0009"},
			Description: "Adversaries may search local system sources for data of interest.",
		},
		"T1039": {
			ID:          "T1039",
			Name:        "Data from Network Shared Drive",
			TacticIDs:   []string{"TA0009"},
			Description: "Adversaries may search network shares for data of interest.",
		},
		"T1114": {
			ID:          "T1114",
			Name:        "Email Collection",
			TacticIDs:   []string{"TA0009"},
			Description: "Adversaries may target user email to collect sensitive information.",
		},
		"T1056": {
			ID:          "T1056",
			Name:        "Input Capture",
			TacticIDs:   []string{"TA0006", "TA0009"},
			Description: "Adversaries may use methods of capturing user input to obtain credentials.",
		},

		// Exfiltration
		"T1041": {
			ID:          "T1041",
			Name:        "Exfiltration Over C2 Channel",
			TacticIDs:   []string{"TA0010"},
			Description: "Adversaries may steal data by exfiltrating it over an existing C2 channel.",
		},
		"T1567": {
			ID:          "T1567",
			Name:        "Exfiltration Over Web Service",
			TacticIDs:   []string{"TA0010"},
			Description: "Adversaries may use an existing, legitimate external Web service to exfiltrate data.",
		},
		"T1048": {
			ID:          "T1048",
			Name:        "Exfiltration Over Alternative Protocol",
			TacticIDs:   []string{"TA0010"},
			Description: "Adversaries may steal data by exfiltrating it over a different protocol.",
		},

		// Command and Control
		"T1071": {
			ID:          "T1071",
			Name:        "Application Layer Protocol",
			TacticIDs:   []string{"TA0011"},
			Description: "Adversaries may communicate using application layer protocols.",
		},
		"T1071.001": {
			ID:          "T1071.001",
			Name:        "Web Protocols",
			TacticIDs:   []string{"TA0011"},
			Description: "Adversaries may communicate using HTTP/HTTPS.",
		},
		"T1105": {
			ID:          "T1105",
			Name:        "Ingress Tool Transfer",
			TacticIDs:   []string{"TA0011"},
			Description: "Adversaries may transfer tools from an external system into a compromised environment.",
		},
		"T1571": {
			ID:          "T1571",
			Name:        "Non-Standard Port",
			TacticIDs:   []string{"TA0011"},
			Description: "Adversaries may communicate over a non-standard port.",
		},
		"T1572": {
			ID:          "T1572",
			Name:        "Protocol Tunneling",
			TacticIDs:   []string{"TA0011"},
			Description: "Adversaries may tunnel network communications to avoid detection.",
		},

		// Impact
		"T1486": {
			ID:          "T1486",
			Name:        "Data Encrypted for Impact",
			TacticIDs:   []string{"TA0040"},
			Description: "Adversaries may encrypt data on target systems to interrupt availability.",
		},
		"T1490": {
			ID:          "T1490",
			Name:        "Inhibit System Recovery",
			TacticIDs:   []string{"TA0040"},
			Description: "Adversaries may delete or remove built-in operating system data.",
		},
		"T1489": {
			ID:          "T1489",
			Name:        "Service Stop",
			TacticIDs:   []string{"TA0040"},
			Description: "Adversaries may stop or disable services on a system.",
		},
		"T1485": {
			ID:          "T1485",
			Name:        "Data Destruction",
			TacticIDs:   []string{"TA0040"},
			Description: "Adversaries may destroy data and files on specific systems.",
		},
		"T1498": {
			ID:          "T1498",
			Name:        "Network Denial of Service",
			TacticIDs:   []string{"TA0040"},
			Description: "Adversaries may perform Network Denial of Service attacks.",
		},
	}
}
