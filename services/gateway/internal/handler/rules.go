package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule represents a Sigma detection rule
type Rule struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"` // low, medium, high, critical
	Status          string     `json:"status"`   // enabled, disabled
	Content         string     `json:"content"`  // Sigma YAML content
	Author          string     `json:"author"`
	Tags            []string   `json:"tags"`
	MITRETactics    []string   `json:"mitre_tactics"`
	MITRETechniques []string   `json:"mitre_techniques"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	HitCount        int        `json:"hit_count"`
	LastHitAt       *time.Time `json:"last_hit_at"`
}

// In-memory rule store
var (
	ruleStore   = make([]Rule, 0)
	ruleStoreMu sync.RWMutex
	ruleCounter = 100
)

// Sample Sigma YAML content for rules
var sampleRuleContents = map[string]string{
	"rule-001": `title: Brute Force Detection
id: rule-001
status: enabled
description: Detects multiple failed login attempts from single source indicating potential brute force attack
author: SOC Team
date: 2024/01/15
modified: 2024/02/01
references:
    - https://attack.mitre.org/techniques/T1110/
logsource:
    category: authentication
    product: any
detection:
    selection:
        EventType: 'authentication'
        Status: 'failed'
    condition: selection | count() by SourceIP > 5
    timeframe: 5m
falsepositives:
    - Legitimate users with multiple failed password attempts
    - Service accounts with expired credentials
level: critical
tags:
    - attack.credential_access
    - attack.t1110
    - attack.t1110.001`,

	"rule-002": `title: PowerShell Encoded Command Execution
id: rule-002
status: enabled
description: Detects execution of PowerShell with Base64 encoded command line which is often used for obfuscation
author: SOC Team
date: 2024/01/20
modified: 2024/02/10
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1027/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - '-enc '
            - '-EncodedCommand '
            - '-ec '
            - 'FromBase64String'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
    - Software deployment tools
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027`,

	"rule-003": `title: Suspicious Process Execution from Temp Directory
id: rule-003
status: enabled
description: Detects execution of processes from temporary directories which may indicate malware activity
author: SOC Team
date: 2024/01/25
modified: 2024/02/05
references:
    - https://attack.mitre.org/techniques/T1204/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains:
            - '\Temp\'
            - '\tmp\'
            - '\AppData\Local\Temp\'
    filter:
        Image|endswith:
            - '\setup.exe'
            - '\installer.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate software installers
    - Browser downloads being executed
level: medium
tags:
    - attack.execution
    - attack.t1204
    - attack.t1204.002`,

	"rule-004": `title: Data Exfiltration Detection - Large Outbound Transfer
id: rule-004
status: enabled
description: Detects unusually large data transfers to external IP addresses indicating potential data exfiltration
author: SOC Team
date: 2024/02/01
modified: 2024/02/15
references:
    - https://attack.mitre.org/techniques/T1041/
    - https://attack.mitre.org/techniques/T1048/
logsource:
    category: network_connection
    product: any
detection:
    selection:
        DestinationIsExternal: true
        BytesSent|gte: 104857600
    timeframe: 1h
    condition: selection
falsepositives:
    - Cloud backup services
    - Large file uploads to legitimate services
    - Video conferencing
level: high
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.t1048`,

	"rule-005": `title: Privilege Escalation via UAC Bypass
id: rule-005
status: enabled
description: Detects potential UAC bypass techniques used for privilege escalation on Windows systems
author: SOC Team
date: 2024/02/05
modified: 2024/02/12
references:
    - https://attack.mitre.org/techniques/T1548/002/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith:
            - '\fodhelper.exe'
            - '\eventvwr.exe'
            - '\computerdefaults.exe'
        IntegrityLevel: 'High'
    condition: selection
falsepositives:
    - Legitimate use of these utilities
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548
    - attack.t1548.002`,

	"rule-006": `title: Suspicious DNS Query to Known C2 Domain
id: rule-006
status: enabled
description: Detects DNS queries to known command and control infrastructure domains
author: Threat Intel Team
date: 2024/02/08
modified: 2024/02/18
references:
    - https://attack.mitre.org/techniques/T1071/004/
logsource:
    category: dns
    product: any
detection:
    selection:
        QueryName|endswith:
            - '.evil.com'
            - '.malware.net'
            - '.c2server.org'
        QueryType:
            - 'A'
            - 'AAAA'
            - 'TXT'
    condition: selection
falsepositives:
    - Security research activities
    - Threat intelligence gathering
level: critical
tags:
    - attack.command_and_control
    - attack.t1071
    - attack.t1071.004`,

	"rule-007": `title: Mimikatz Credential Dumping
id: rule-007
status: enabled
description: Detects potential Mimikatz execution or similar credential dumping tools
author: SOC Team
date: 2024/02/10
modified: 2024/02/20
references:
    - https://attack.mitre.org/techniques/T1003/001/
    - https://attack.mitre.org/techniques/T1003/002/
logsource:
    category: process_creation
    product: windows
detection:
    selection_name:
        Image|endswith:
            - '\mimikatz.exe'
            - '\mimi.exe'
            - '\mimikatz64.exe'
    selection_args:
        CommandLine|contains:
            - 'sekurlsa::logonpasswords'
            - 'lsadump::sam'
            - 'lsadump::dcsync'
            - 'privilege::debug'
    condition: selection_name or selection_args
falsepositives:
    - Legitimate penetration testing
level: critical
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1003.001
    - attack.t1003.002`,

	"rule-008": `title: Lateral Movement via PsExec
id: rule-008
status: enabled
description: Detects execution of PsExec or similar tools used for lateral movement
author: SOC Team
date: 2024/02/12
modified: 2024/02/19
references:
    - https://attack.mitre.org/techniques/T1021/002/
    - https://attack.mitre.org/software/S0029/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\psexec.exe'
    selection_service:
        Image|endswith: '\PSEXESVC.exe'
    condition: selection or selection_service
falsepositives:
    - Legitimate administrative activities
    - IT automation tools
level: high
tags:
    - attack.lateral_movement
    - attack.t1021
    - attack.t1021.002
    - attack.execution
    - attack.t1569.002`,

	"rule-009": `title: Ransomware File Extension Modification
id: rule-009
status: enabled
description: Detects mass file extension changes indicating potential ransomware activity
author: Incident Response Team
date: 2024/02/14
modified: 2024/02/21
references:
    - https://attack.mitre.org/techniques/T1486/
logsource:
    category: file_rename
    product: windows
detection:
    selection:
        TargetFilename|endswith:
            - '.encrypted'
            - '.locked'
            - '.crypted'
            - '.enc'
            - '.ransom'
    condition: selection | count() > 10
    timeframe: 1m
falsepositives:
    - Legitimate encryption software
    - Backup applications
level: critical
tags:
    - attack.impact
    - attack.t1486`,

	"rule-010": `title: Suspicious Scheduled Task Creation
id: rule-010
status: enabled
description: Detects creation of scheduled tasks that may be used for persistence
author: SOC Team
date: 2024/02/16
modified: 2024/02/20
references:
    - https://attack.mitre.org/techniques/T1053/005/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    filter:
        User|contains:
            - 'SYSTEM'
            - 'NT AUTHORITY'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative scripts
    - Software installation
level: medium
tags:
    - attack.persistence
    - attack.t1053
    - attack.t1053.005`,
}

func init() {
	now := time.Now()
	lastWeek := now.Add(-7 * 24 * time.Hour)
	lastHit1 := now.Add(-2 * time.Hour)
	lastHit2 := now.Add(-30 * time.Minute)
	lastHit3 := now.Add(-1 * time.Hour)

	sampleRules := []Rule{
		{
			ID:              "rule-001",
			Name:            "Brute Force Detection",
			Description:     "Detects multiple failed login attempts from single source indicating potential brute force attack",
			Severity:        "critical",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-001"],
			Author:          "SOC Team",
			Tags:            []string{"authentication", "brute-force", "credential-access"},
			MITRETactics:    []string{"TA0006"},
			MITRETechniques: []string{"T1110", "T1110.001"},
			CreatedAt:       lastWeek,
			UpdatedAt:       now.Add(-24 * time.Hour),
			HitCount:        127,
			LastHitAt:       &lastHit1,
		},
		{
			ID:              "rule-002",
			Name:            "PowerShell Encoded Command Execution",
			Description:     "Detects execution of PowerShell with Base64 encoded command line which is often used for obfuscation",
			Severity:        "high",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-002"],
			Author:          "SOC Team",
			Tags:            []string{"powershell", "obfuscation", "execution"},
			MITRETactics:    []string{"TA0002", "TA0005"},
			MITRETechniques: []string{"T1059.001", "T1027"},
			CreatedAt:       lastWeek.Add(24 * time.Hour),
			UpdatedAt:       now.Add(-12 * time.Hour),
			HitCount:        89,
			LastHitAt:       &lastHit2,
		},
		{
			ID:              "rule-003",
			Name:            "Suspicious Process Execution from Temp Directory",
			Description:     "Detects execution of processes from temporary directories which may indicate malware activity",
			Severity:        "medium",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-003"],
			Author:          "SOC Team",
			Tags:            []string{"process", "malware", "temp-directory"},
			MITRETactics:    []string{"TA0002"},
			MITRETechniques: []string{"T1204", "T1204.002"},
			CreatedAt:       lastWeek.Add(48 * time.Hour),
			UpdatedAt:       now.Add(-6 * time.Hour),
			HitCount:        234,
			LastHitAt:       &lastHit3,
		},
		{
			ID:              "rule-004",
			Name:            "Data Exfiltration Detection - Large Outbound Transfer",
			Description:     "Detects unusually large data transfers to external IP addresses indicating potential data exfiltration",
			Severity:        "high",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-004"],
			Author:          "SOC Team",
			Tags:            []string{"exfiltration", "network", "data-theft"},
			MITRETactics:    []string{"TA0010"},
			MITRETechniques: []string{"T1041", "T1048"},
			CreatedAt:       lastWeek.Add(72 * time.Hour),
			UpdatedAt:       now.Add(-48 * time.Hour),
			HitCount:        45,
			LastHitAt:       nil,
		},
		{
			ID:              "rule-005",
			Name:            "Privilege Escalation via UAC Bypass",
			Description:     "Detects potential UAC bypass techniques used for privilege escalation on Windows systems",
			Severity:        "high",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-005"],
			Author:          "SOC Team",
			Tags:            []string{"privilege-escalation", "uac-bypass", "windows"},
			MITRETactics:    []string{"TA0004"},
			MITRETechniques: []string{"T1548", "T1548.002"},
			CreatedAt:       lastWeek.Add(96 * time.Hour),
			UpdatedAt:       now.Add(-72 * time.Hour),
			HitCount:        12,
			LastHitAt:       nil,
		},
		{
			ID:              "rule-006",
			Name:            "Suspicious DNS Query to Known C2 Domain",
			Description:     "Detects DNS queries to known command and control infrastructure domains",
			Severity:        "critical",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-006"],
			Author:          "Threat Intel Team",
			Tags:            []string{"c2", "dns", "command-and-control"},
			MITRETactics:    []string{"TA0011"},
			MITRETechniques: []string{"T1071", "T1071.004"},
			CreatedAt:       lastWeek.Add(120 * time.Hour),
			UpdatedAt:       now.Add(-24 * time.Hour),
			HitCount:        8,
			LastHitAt:       nil,
		},
		{
			ID:              "rule-007",
			Name:            "Mimikatz Credential Dumping",
			Description:     "Detects potential Mimikatz execution or similar credential dumping tools",
			Severity:        "critical",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-007"],
			Author:          "SOC Team",
			Tags:            []string{"mimikatz", "credential-dumping", "lsass"},
			MITRETactics:    []string{"TA0006"},
			MITRETechniques: []string{"T1003", "T1003.001", "T1003.002"},
			CreatedAt:       lastWeek.Add(144 * time.Hour),
			UpdatedAt:       now.Add(-12 * time.Hour),
			HitCount:        3,
			LastHitAt:       nil,
		},
		{
			ID:              "rule-008",
			Name:            "Lateral Movement via PsExec",
			Description:     "Detects execution of PsExec or similar tools used for lateral movement",
			Severity:        "high",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-008"],
			Author:          "SOC Team",
			Tags:            []string{"psexec", "lateral-movement", "remote-execution"},
			MITRETactics:    []string{"TA0008", "TA0002"},
			MITRETechniques: []string{"T1021", "T1021.002", "T1569.002"},
			CreatedAt:       now.Add(-5 * 24 * time.Hour),
			UpdatedAt:       now.Add(-6 * time.Hour),
			HitCount:        67,
			LastHitAt:       &lastHit1,
		},
		{
			ID:              "rule-009",
			Name:            "Ransomware File Extension Modification",
			Description:     "Detects mass file extension changes indicating potential ransomware activity",
			Severity:        "critical",
			Status:          "enabled",
			Content:         sampleRuleContents["rule-009"],
			Author:          "Incident Response Team",
			Tags:            []string{"ransomware", "encryption", "impact"},
			MITRETactics:    []string{"TA0040"},
			MITRETechniques: []string{"T1486"},
			CreatedAt:       now.Add(-4 * 24 * time.Hour),
			UpdatedAt:       now.Add(-24 * time.Hour),
			HitCount:        1,
			LastHitAt:       nil,
		},
		{
			ID:              "rule-010",
			Name:            "Suspicious Scheduled Task Creation",
			Description:     "Detects creation of scheduled tasks that may be used for persistence",
			Severity:        "medium",
			Status:          "disabled",
			Content:         sampleRuleContents["rule-010"],
			Author:          "SOC Team",
			Tags:            []string{"persistence", "scheduled-task", "windows"},
			MITRETactics:    []string{"TA0003"},
			MITRETechniques: []string{"T1053", "T1053.005"},
			CreatedAt:       now.Add(-3 * 24 * time.Hour),
			UpdatedAt:       now.Add(-2 * 24 * time.Hour),
			HitCount:        156,
			LastHitAt:       nil,
		},
	}

	ruleStoreMu.Lock()
	ruleStore = sampleRules
	ruleStoreMu.Unlock()
}

// ListRulesHandler returns list of rules with filtering and pagination
func ListRulesHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	ruleStoreMu.RLock()
	defer ruleStoreMu.RUnlock()

	query := r.URL.Query()
	status := query.Get("status")
	severity := query.Get("severity")
	search := strings.ToLower(query.Get("search"))

	// Pagination
	page := 1
	pageSize := 50
	if p := query.Get("page"); p != "" {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	if ps := query.Get("pageSize"); ps != "" {
		if n, err := strconv.Atoi(ps); err == nil && n > 0 && n <= 100 {
			pageSize = n
		}
	}

	// Filter rules
	var filtered []Rule
	for _, rule := range ruleStore {
		// Status filter
		if status != "" && status != "all" && rule.Status != status {
			continue
		}

		// Severity filter
		if severity != "" && severity != "all" && rule.Severity != severity {
			continue
		}

		// Search filter
		if search != "" {
			if !strings.Contains(strings.ToLower(rule.Name), search) &&
				!strings.Contains(strings.ToLower(rule.Description), search) &&
				!strings.Contains(strings.ToLower(rule.Author), search) &&
				!containsTag(rule.Tags, search) {
				continue
			}
		}

		filtered = append(filtered, rule)
	}

	total := len(filtered)

	// Apply pagination
	offset := (page - 1) * pageSize
	if offset >= len(filtered) {
		filtered = []Rule{}
	} else {
		end := offset + pageSize
		if end > len(filtered) {
			end = len(filtered)
		}
		filtered = filtered[offset:end]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules":    filtered,
		"total":    total,
		"page":     page,
		"pageSize": pageSize,
	})
}

// GetRuleHandler returns a single rule by ID
func GetRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	ruleStoreMu.RLock()
	defer ruleStoreMu.RUnlock()

	for _, rule := range ruleStore {
		if rule.ID == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(rule)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error": "Rule not found",
	})
}

// CreateRuleRequest represents the request body for creating a rule
type CreateRuleRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	Content         string   `json:"content"`
	Author          string   `json:"author"`
	Tags            []string `json:"tags"`
	MITRETactics    []string `json:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques"`
}

// CreateRuleHandler creates a new rule
func CreateRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req CreateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	// Validate required fields
	if req.Name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Name is required",
		})
		return
	}

	if req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Content (Sigma YAML) is required",
		})
		return
	}

	// Validate severity
	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if req.Severity != "" && !validSeverities[strings.ToLower(req.Severity)] {
		req.Severity = "medium"
	} else if req.Severity == "" {
		req.Severity = "medium"
	}

	now := time.Now()

	ruleStoreMu.Lock()
	ruleCounter++
	newRule := Rule{
		ID:              fmt.Sprintf("rule-%03d", ruleCounter),
		Name:            req.Name,
		Description:     req.Description,
		Severity:        strings.ToLower(req.Severity),
		Status:          "enabled",
		Content:         req.Content,
		Author:          req.Author,
		Tags:            req.Tags,
		MITRETactics:    req.MITRETactics,
		MITRETechniques: req.MITRETechniques,
		CreatedAt:       now,
		UpdatedAt:       now,
		HitCount:        0,
		LastHitAt:       nil,
	}

	if newRule.Author == "" {
		newRule.Author = "Unknown"
	}
	if newRule.Tags == nil {
		newRule.Tags = []string{}
	}
	if newRule.MITRETactics == nil {
		newRule.MITRETactics = []string{}
	}
	if newRule.MITRETechniques == nil {
		newRule.MITRETechniques = []string{}
	}

	ruleStore = append([]Rule{newRule}, ruleStore...)
	ruleStoreMu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(newRule)
}

// UpdateRuleRequest represents the request body for updating a rule
type UpdateRuleRequest struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	Status          string   `json:"status"`
	Content         string   `json:"content"`
	Author          string   `json:"author"`
	Tags            []string `json:"tags"`
	MITRETactics    []string `json:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques"`
}

// UpdateRuleHandler updates an existing rule
func UpdateRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	var req UpdateRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	ruleStoreMu.Lock()
	defer ruleStoreMu.Unlock()

	for i := range ruleStore {
		if ruleStore[i].ID == id {
			// Update fields if provided
			if req.Name != "" {
				ruleStore[i].Name = req.Name
			}
			if req.Description != "" {
				ruleStore[i].Description = req.Description
			}
			if req.Severity != "" {
				validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
				if validSeverities[strings.ToLower(req.Severity)] {
					ruleStore[i].Severity = strings.ToLower(req.Severity)
				}
			}
			if req.Status != "" {
				validStatuses := map[string]bool{"enabled": true, "disabled": true}
				if validStatuses[strings.ToLower(req.Status)] {
					ruleStore[i].Status = strings.ToLower(req.Status)
				}
			}
			if req.Content != "" {
				ruleStore[i].Content = req.Content
			}
			if req.Author != "" {
				ruleStore[i].Author = req.Author
			}
			if req.Tags != nil {
				ruleStore[i].Tags = req.Tags
			}
			if req.MITRETactics != nil {
				ruleStore[i].MITRETactics = req.MITRETactics
			}
			if req.MITRETechniques != nil {
				ruleStore[i].MITRETechniques = req.MITRETechniques
			}

			ruleStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ruleStore[i])
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Rule not found",
	})
}

// DeleteRuleHandler deletes a rule
func DeleteRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	ruleStoreMu.Lock()
	defer ruleStoreMu.Unlock()

	for i := range ruleStore {
		if ruleStore[i].ID == id {
			// Remove rule from slice
			ruleStore = append(ruleStore[:i], ruleStore[i+1:]...)

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "Rule deleted successfully",
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Rule not found",
	})
}

// EnableRuleHandler enables a rule
func EnableRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	ruleStoreMu.Lock()
	defer ruleStoreMu.Unlock()

	for i := range ruleStore {
		if ruleStore[i].ID == id {
			ruleStore[i].Status = "enabled"
			ruleStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ruleStore[i])
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Rule not found",
	})
}

// DisableRuleHandler disables a rule
func DisableRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	id := r.PathValue("id")

	ruleStoreMu.Lock()
	defer ruleStoreMu.Unlock()

	for i := range ruleStore {
		if ruleStore[i].ID == id {
			ruleStore[i].Status = "disabled"
			ruleStore[i].UpdatedAt = time.Now()

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(ruleStore[i])
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   "Rule not found",
	})
}

// TestRuleRequest represents the request body for testing a rule
type TestRuleRequest struct {
	Content     string                   `json:"content"` // Sigma YAML content
	SampleEvent map[string]interface{}   `json:"sample_event"`
	Events      []map[string]interface{} `json:"events"` // Multiple events for testing
}

// TestRuleHandler tests a rule against sample events
func TestRuleHandler(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w)
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req TestRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid request body",
		})
		return
	}

	if req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Rule content is required",
		})
		return
	}

	// Validate YAML syntax (basic check)
	if !strings.Contains(req.Content, "title:") || !strings.Contains(req.Content, "detection:") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Invalid Sigma rule: missing required fields (title, detection)",
			"valid":   false,
		})
		return
	}

	// Prepare test events
	var testEvents []map[string]interface{}
	if req.SampleEvent != nil {
		testEvents = append(testEvents, req.SampleEvent)
	}
	if len(req.Events) > 0 {
		testEvents = append(testEvents, req.Events...)
	}

	// If no events provided, use sample events
	if len(testEvents) == 0 {
		testEvents = []map[string]interface{}{
			{
				"EventType":   "authentication",
				"Status":      "failed",
				"SourceIP":    "192.168.1.100",
				"User":        "admin",
				"DestIP":      "10.0.0.1",
				"Timestamp":   time.Now().Format(time.RFC3339),
				"ProcessName": "sshd",
			},
			{
				"EventType":   "process_creation",
				"Image":       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
				"CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ=",
				"User":        "john.doe",
				"Hostname":    "ws-prod-01",
				"Timestamp":   time.Now().Format(time.RFC3339),
			},
		}
	}

	// Simulate rule matching (in production, use actual Sigma engine)
	matches := []map[string]interface{}{}
	for i, event := range testEvents {
		// Simple simulation: check if any detection keywords match event fields
		matched := simulateRuleMatch(req.Content, event)
		if matched {
			matches = append(matches, map[string]interface{}{
				"event_index": i,
				"event":       event,
				"matched":     true,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"valid":        true,
		"matches":      matches,
		"match_count":  len(matches),
		"events_tested": len(testEvents),
		"message":      fmt.Sprintf("Rule validated successfully. %d/%d events matched.", len(matches), len(testEvents)),
	})
}

// simulateRuleMatch simulates matching a Sigma rule against an event
func simulateRuleMatch(ruleContent string, event map[string]interface{}) bool {
	ruleContentLower := strings.ToLower(ruleContent)

	// Check for common detection patterns
	for key, value := range event {
		keyLower := strings.ToLower(key)
		valueLower := strings.ToLower(fmt.Sprintf("%v", value))

		// Check if the rule mentions this field
		if strings.Contains(ruleContentLower, keyLower) {
			// Check for value matches
			if strings.Contains(ruleContentLower, valueLower) {
				return true
			}

			// Check for pattern matches (e.g., endswith, contains)
			if strings.Contains(ruleContentLower, "contains") && len(valueLower) > 3 {
				// Extract potential patterns from rule and check
				patterns := []string{"-enc", "encoded", "powershell", "failed", "blocked"}
				for _, pattern := range patterns {
					if strings.Contains(valueLower, pattern) && strings.Contains(ruleContentLower, pattern) {
						return true
					}
				}
			}
		}
	}

	return false
}

// containsTag checks if any tag contains the search string
func containsTag(tags []string, search string) bool {
	for _, tag := range tags {
		if strings.Contains(strings.ToLower(tag), search) {
			return true
		}
	}
	return false
}
