// Package mitre provides MITRE ATT&CK mapping capabilities.
package mitre

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Technique represents a MITRE ATT&CK technique.
type Technique struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	Tactics         []string `json:"tactics"`
	SubTechniques   []string `json:"sub_techniques,omitempty"`
	IsSubTechnique  bool     `json:"is_sub_technique"`
	ParentID        string   `json:"parent_id,omitempty"`
	Platforms       []string `json:"platforms,omitempty"`
	DataSources     []string `json:"data_sources,omitempty"`
	DetectionTips   string   `json:"detection_tips,omitempty"`
	MitigationTips  string   `json:"mitigation_tips,omitempty"`
	URL             string   `json:"url,omitempty"`
}

// Tactic represents a MITRE ATT&CK tactic.
type Tactic struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	ShortName   string `json:"short_name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
}

// ATTACKMapping represents the full ATT&CK mapping for a detection.
type ATTACKMapping struct {
	Techniques    []*Technique `json:"techniques"`
	Tactics       []*Tactic    `json:"tactics"`
	KillChainPhases []string   `json:"kill_chain_phases,omitempty"`
	Severity      string       `json:"severity,omitempty"`
}

// Mapper provides MITRE ATT&CK mapping functionality.
type Mapper struct {
	techniques     map[string]*Technique
	tactics        map[string]*Tactic
	tacticToTechs  map[string][]string // tactic short_name -> technique IDs
	techToTactics  map[string][]string // technique ID -> tactic short_names
	mu             sync.RWMutex
}

// NewMapper creates a new MITRE ATT&CK mapper with embedded data.
func NewMapper() *Mapper {
	m := &Mapper{
		techniques:    make(map[string]*Technique),
		tactics:       make(map[string]*Tactic),
		tacticToTechs: make(map[string][]string),
		techToTactics: make(map[string][]string),
	}

	// Initialize with embedded ATT&CK data
	m.initializeTactics()
	m.initializeTechniques()

	return m
}

// NewMapperFromFile creates a mapper loading data from a JSON file.
func NewMapperFromFile(path string) (*Mapper, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read ATT&CK data: %w", err)
	}

	m := &Mapper{
		techniques:    make(map[string]*Technique),
		tactics:       make(map[string]*Tactic),
		tacticToTechs: make(map[string][]string),
		techToTactics: make(map[string][]string),
	}

	var attackData struct {
		Techniques []*Technique `json:"techniques"`
		Tactics    []*Tactic    `json:"tactics"`
	}

	if err := json.Unmarshal(data, &attackData); err != nil {
		return nil, fmt.Errorf("failed to parse ATT&CK data: %w", err)
	}

	for _, t := range attackData.Tactics {
		m.tactics[t.ShortName] = t
	}

	for _, t := range attackData.Techniques {
		m.techniques[t.ID] = t
		for _, tactic := range t.Tactics {
			m.tacticToTechs[tactic] = append(m.tacticToTechs[tactic], t.ID)
			m.techToTactics[t.ID] = append(m.techToTactics[t.ID], tactic)
		}
	}

	return m, nil
}

// GetTechnique returns a technique by ID.
func (m *Mapper) GetTechnique(id string) (*Technique, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	id = strings.ToUpper(id)
	tech, ok := m.techniques[id]
	return tech, ok
}

// GetTactic returns a tactic by short name.
func (m *Mapper) GetTactic(shortName string) (*Tactic, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shortName = strings.ToLower(shortName)
	tactic, ok := m.tactics[shortName]
	return tactic, ok
}

// MapTechniques maps technique IDs to full Technique objects.
func (m *Mapper) MapTechniques(techniqueIDs []string) []*Technique {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var techniques []*Technique
	for _, id := range techniqueIDs {
		id = strings.ToUpper(id)
		if tech, ok := m.techniques[id]; ok {
			techniques = append(techniques, tech)
		}
	}
	return techniques
}

// MapTactics maps tactic names to full Tactic objects.
func (m *Mapper) MapTactics(tacticNames []string) []*Tactic {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tactics []*Tactic
	seen := make(map[string]bool)

	for _, name := range tacticNames {
		name = strings.ToLower(name)
		// Remove common prefixes
		name = strings.TrimPrefix(name, "attack.")

		if seen[name] {
			continue
		}

		if tactic, ok := m.tactics[name]; ok {
			tactics = append(tactics, tactic)
			seen[name] = true
		}
	}
	return tactics
}

// MapToATTACK creates a full ATT&CK mapping from technique and tactic names.
func (m *Mapper) MapToATTACK(techniqueIDs, tacticNames []string) *ATTACKMapping {
	techniques := m.MapTechniques(techniqueIDs)
	tactics := m.MapTactics(tacticNames)

	// If we have techniques but no tactics, infer tactics from techniques
	if len(tactics) == 0 && len(techniques) > 0 {
		tacticSet := make(map[string]bool)
		for _, tech := range techniques {
			for _, tactic := range tech.Tactics {
				tacticSet[tactic] = true
			}
		}

		for tacticName := range tacticSet {
			if tactic, ok := m.tactics[tacticName]; ok {
				tactics = append(tactics, tactic)
			}
		}
	}

	// Determine kill chain phases
	var phases []string
	phaseSet := make(map[string]bool)
	for _, tactic := range tactics {
		if !phaseSet[tactic.ShortName] {
			phases = append(phases, tactic.ShortName)
			phaseSet[tactic.ShortName] = true
		}
	}

	return &ATTACKMapping{
		Techniques:      techniques,
		Tactics:         tactics,
		KillChainPhases: phases,
		Severity:        m.estimateSeverity(techniques, tactics),
	}
}

// GetTechniquesForTactic returns all techniques for a given tactic.
func (m *Mapper) GetTechniquesForTactic(tacticName string) []*Technique {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tacticName = strings.ToLower(tacticName)
	techIDs := m.tacticToTechs[tacticName]

	var techniques []*Technique
	for _, id := range techIDs {
		if tech, ok := m.techniques[id]; ok {
			techniques = append(techniques, tech)
		}
	}
	return techniques
}

// GetSubTechniques returns sub-techniques for a given technique.
func (m *Mapper) GetSubTechniques(techniqueID string) []*Technique {
	m.mu.RLock()
	defer m.mu.RUnlock()

	techniqueID = strings.ToUpper(techniqueID)
	var subTechniques []*Technique

	for id, tech := range m.techniques {
		if tech.IsSubTechnique && tech.ParentID == techniqueID {
			subTechniques = append(subTechniques, m.techniques[id])
		}
	}
	return subTechniques
}

// GetAttackChain returns the ordered sequence of tactics for a set of techniques.
func (m *Mapper) GetAttackChain(techniqueIDs []string) []*Tactic {
	tacticOrder := []string{
		"reconnaissance", "resource-development", "initial-access",
		"execution", "persistence", "privilege-escalation",
		"defense-evasion", "credential-access", "discovery",
		"lateral-movement", "collection", "command-and-control",
		"exfiltration", "impact",
	}

	tacticSet := make(map[string]bool)
	for _, techID := range techniqueIDs {
		if tech, ok := m.GetTechnique(techID); ok {
			for _, tactic := range tech.Tactics {
				tacticSet[tactic] = true
			}
		}
	}

	var chain []*Tactic
	for _, tacticName := range tacticOrder {
		if tacticSet[tacticName] {
			if tactic, ok := m.tactics[tacticName]; ok {
				chain = append(chain, tactic)
			}
		}
	}

	return chain
}

// estimateSeverity estimates severity based on tactics involved.
func (m *Mapper) estimateSeverity(techniques []*Technique, tactics []*Tactic) string {
	// High severity tactics
	highSeverity := map[string]bool{
		"impact": true, "exfiltration": true, "command-and-control": true,
	}

	// Critical tactics
	criticalTactics := map[string]bool{
		"credential-access": true, "privilege-escalation": true,
	}

	for _, tactic := range tactics {
		if criticalTactics[tactic.ShortName] {
			return "critical"
		}
	}

	for _, tactic := range tactics {
		if highSeverity[tactic.ShortName] {
			return "high"
		}
	}

	if len(tactics) > 3 || len(techniques) > 2 {
		return "high"
	}

	if len(tactics) > 1 || len(techniques) > 1 {
		return "medium"
	}

	return "low"
}

// initializeTactics initializes the default ATT&CK tactics.
func (m *Mapper) initializeTactics() {
	tactics := []*Tactic{
		{ID: "TA0043", Name: "Reconnaissance", ShortName: "reconnaissance"},
		{ID: "TA0042", Name: "Resource Development", ShortName: "resource-development"},
		{ID: "TA0001", Name: "Initial Access", ShortName: "initial-access"},
		{ID: "TA0002", Name: "Execution", ShortName: "execution"},
		{ID: "TA0003", Name: "Persistence", ShortName: "persistence"},
		{ID: "TA0004", Name: "Privilege Escalation", ShortName: "privilege-escalation"},
		{ID: "TA0005", Name: "Defense Evasion", ShortName: "defense-evasion"},
		{ID: "TA0006", Name: "Credential Access", ShortName: "credential-access"},
		{ID: "TA0007", Name: "Discovery", ShortName: "discovery"},
		{ID: "TA0008", Name: "Lateral Movement", ShortName: "lateral-movement"},
		{ID: "TA0009", Name: "Collection", ShortName: "collection"},
		{ID: "TA0011", Name: "Command and Control", ShortName: "command-and-control"},
		{ID: "TA0010", Name: "Exfiltration", ShortName: "exfiltration"},
		{ID: "TA0040", Name: "Impact", ShortName: "impact"},
	}

	for _, t := range tactics {
		t.URL = fmt.Sprintf("https://attack.mitre.org/tactics/%s/", t.ID)
		m.tactics[t.ShortName] = t
	}
}

// initializeTechniques initializes common ATT&CK techniques.
func (m *Mapper) initializeTechniques() {
	// Common Enterprise techniques
	techniques := []*Technique{
		// Initial Access
		{ID: "T1566", Name: "Phishing", Tactics: []string{"initial-access"}},
		{ID: "T1566.001", Name: "Spearphishing Attachment", Tactics: []string{"initial-access"}, IsSubTechnique: true, ParentID: "T1566"},
		{ID: "T1566.002", Name: "Spearphishing Link", Tactics: []string{"initial-access"}, IsSubTechnique: true, ParentID: "T1566"},
		{ID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"}},
		{ID: "T1078", Name: "Valid Accounts", Tactics: []string{"initial-access", "persistence", "privilege-escalation", "defense-evasion"}},
		{ID: "T1133", Name: "External Remote Services", Tactics: []string{"initial-access", "persistence"}},

		// Execution
		{ID: "T1059", Name: "Command and Scripting Interpreter", Tactics: []string{"execution"}},
		{ID: "T1059.001", Name: "PowerShell", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1059.003", Name: "Windows Command Shell", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1059.004", Name: "Unix Shell", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1059.005", Name: "Visual Basic", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1059.006", Name: "Python", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1059.007", Name: "JavaScript", Tactics: []string{"execution"}, IsSubTechnique: true, ParentID: "T1059"},
		{ID: "T1204", Name: "User Execution", Tactics: []string{"execution"}},
		{ID: "T1047", Name: "Windows Management Instrumentation", Tactics: []string{"execution"}},
		{ID: "T1053", Name: "Scheduled Task/Job", Tactics: []string{"execution", "persistence", "privilege-escalation"}},

		// Persistence
		{ID: "T1547", Name: "Boot or Logon Autostart Execution", Tactics: []string{"persistence", "privilege-escalation"}},
		{ID: "T1547.001", Name: "Registry Run Keys / Startup Folder", Tactics: []string{"persistence", "privilege-escalation"}, IsSubTechnique: true, ParentID: "T1547"},
		{ID: "T1136", Name: "Create Account", Tactics: []string{"persistence"}},
		{ID: "T1543", Name: "Create or Modify System Process", Tactics: []string{"persistence", "privilege-escalation"}},
		{ID: "T1543.003", Name: "Windows Service", Tactics: []string{"persistence", "privilege-escalation"}, IsSubTechnique: true, ParentID: "T1543"},

		// Privilege Escalation
		{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactics: []string{"privilege-escalation", "defense-evasion"}},
		{ID: "T1548.002", Name: "Bypass User Account Control", Tactics: []string{"privilege-escalation", "defense-evasion"}, IsSubTechnique: true, ParentID: "T1548"},
		{ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactics: []string{"privilege-escalation"}},

		// Defense Evasion
		{ID: "T1070", Name: "Indicator Removal", Tactics: []string{"defense-evasion"}},
		{ID: "T1070.001", Name: "Clear Windows Event Logs", Tactics: []string{"defense-evasion"}, IsSubTechnique: true, ParentID: "T1070"},
		{ID: "T1070.004", Name: "File Deletion", Tactics: []string{"defense-evasion"}, IsSubTechnique: true, ParentID: "T1070"},
		{ID: "T1027", Name: "Obfuscated Files or Information", Tactics: []string{"defense-evasion"}},
		{ID: "T1055", Name: "Process Injection", Tactics: []string{"defense-evasion", "privilege-escalation"}},
		{ID: "T1112", Name: "Modify Registry", Tactics: []string{"defense-evasion"}},
		{ID: "T1562", Name: "Impair Defenses", Tactics: []string{"defense-evasion"}},
		{ID: "T1562.001", Name: "Disable or Modify Tools", Tactics: []string{"defense-evasion"}, IsSubTechnique: true, ParentID: "T1562"},

		// Credential Access
		{ID: "T1003", Name: "OS Credential Dumping", Tactics: []string{"credential-access"}},
		{ID: "T1003.001", Name: "LSASS Memory", Tactics: []string{"credential-access"}, IsSubTechnique: true, ParentID: "T1003"},
		{ID: "T1003.002", Name: "Security Account Manager", Tactics: []string{"credential-access"}, IsSubTechnique: true, ParentID: "T1003"},
		{ID: "T1110", Name: "Brute Force", Tactics: []string{"credential-access"}},
		{ID: "T1558", Name: "Steal or Forge Kerberos Tickets", Tactics: []string{"credential-access"}},
		{ID: "T1552", Name: "Unsecured Credentials", Tactics: []string{"credential-access"}},

		// Discovery
		{ID: "T1087", Name: "Account Discovery", Tactics: []string{"discovery"}},
		{ID: "T1083", Name: "File and Directory Discovery", Tactics: []string{"discovery"}},
		{ID: "T1057", Name: "Process Discovery", Tactics: []string{"discovery"}},
		{ID: "T1012", Name: "Query Registry", Tactics: []string{"discovery"}},
		{ID: "T1082", Name: "System Information Discovery", Tactics: []string{"discovery"}},
		{ID: "T1016", Name: "System Network Configuration Discovery", Tactics: []string{"discovery"}},
		{ID: "T1049", Name: "System Network Connections Discovery", Tactics: []string{"discovery"}},
		{ID: "T1018", Name: "Remote System Discovery", Tactics: []string{"discovery"}},

		// Lateral Movement
		{ID: "T1021", Name: "Remote Services", Tactics: []string{"lateral-movement"}},
		{ID: "T1021.001", Name: "Remote Desktop Protocol", Tactics: []string{"lateral-movement"}, IsSubTechnique: true, ParentID: "T1021"},
		{ID: "T1021.002", Name: "SMB/Windows Admin Shares", Tactics: []string{"lateral-movement"}, IsSubTechnique: true, ParentID: "T1021"},
		{ID: "T1021.004", Name: "SSH", Tactics: []string{"lateral-movement"}, IsSubTechnique: true, ParentID: "T1021"},
		{ID: "T1021.006", Name: "Windows Remote Management", Tactics: []string{"lateral-movement"}, IsSubTechnique: true, ParentID: "T1021"},
		{ID: "T1570", Name: "Lateral Tool Transfer", Tactics: []string{"lateral-movement"}},

		// Collection
		{ID: "T1560", Name: "Archive Collected Data", Tactics: []string{"collection"}},
		{ID: "T1005", Name: "Data from Local System", Tactics: []string{"collection"}},
		{ID: "T1039", Name: "Data from Network Shared Drive", Tactics: []string{"collection"}},
		{ID: "T1114", Name: "Email Collection", Tactics: []string{"collection"}},

		// Command and Control
		{ID: "T1071", Name: "Application Layer Protocol", Tactics: []string{"command-and-control"}},
		{ID: "T1071.001", Name: "Web Protocols", Tactics: []string{"command-and-control"}, IsSubTechnique: true, ParentID: "T1071"},
		{ID: "T1071.004", Name: "DNS", Tactics: []string{"command-and-control"}, IsSubTechnique: true, ParentID: "T1071"},
		{ID: "T1105", Name: "Ingress Tool Transfer", Tactics: []string{"command-and-control"}},
		{ID: "T1572", Name: "Protocol Tunneling", Tactics: []string{"command-and-control"}},
		{ID: "T1090", Name: "Proxy", Tactics: []string{"command-and-control"}},
		{ID: "T1219", Name: "Remote Access Software", Tactics: []string{"command-and-control"}},

		// Exfiltration
		{ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactics: []string{"exfiltration"}},
		{ID: "T1567", Name: "Exfiltration Over Web Service", Tactics: []string{"exfiltration"}},
		{ID: "T1048", Name: "Exfiltration Over Alternative Protocol", Tactics: []string{"exfiltration"}},

		// Impact
		{ID: "T1486", Name: "Data Encrypted for Impact", Tactics: []string{"impact"}},
		{ID: "T1489", Name: "Service Stop", Tactics: []string{"impact"}},
		{ID: "T1490", Name: "Inhibit System Recovery", Tactics: []string{"impact"}},
		{ID: "T1485", Name: "Data Destruction", Tactics: []string{"impact"}},
		{ID: "T1531", Name: "Account Access Removal", Tactics: []string{"impact"}},
	}

	for _, t := range techniques {
		t.URL = fmt.Sprintf("https://attack.mitre.org/techniques/%s/", strings.ReplaceAll(t.ID, ".", "/"))
		m.techniques[t.ID] = t

		for _, tactic := range t.Tactics {
			m.tacticToTechs[tactic] = append(m.tacticToTechs[tactic], t.ID)
			m.techToTactics[t.ID] = append(m.techToTactics[t.ID], tactic)
		}
	}
}

// ListAllTactics returns all tactics.
func (m *Mapper) ListAllTactics() []*Tactic {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tactics := make([]*Tactic, 0, len(m.tactics))
	for _, t := range m.tactics {
		tactics = append(tactics, t)
	}
	return tactics
}

// ListAllTechniques returns all techniques.
func (m *Mapper) ListAllTechniques() []*Technique {
	m.mu.RLock()
	defer m.mu.RUnlock()

	techniques := make([]*Technique, 0, len(m.techniques))
	for _, t := range m.techniques {
		techniques = append(techniques, t)
	}
	return techniques
}

// SearchTechniques searches techniques by name or ID.
func (m *Mapper) SearchTechniques(query string) []*Technique {
	m.mu.RLock()
	defer m.mu.RUnlock()

	query = strings.ToLower(query)
	var results []*Technique

	for _, tech := range m.techniques {
		if strings.Contains(strings.ToLower(tech.ID), query) ||
			strings.Contains(strings.ToLower(tech.Name), query) {
			results = append(results, tech)
		}
	}

	return results
}
