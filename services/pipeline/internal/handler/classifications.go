// Package handler provides HTTP handlers for the pipeline service.
package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
	"github.com/siem-soar-platform/services/pipeline/internal/service"
)

// ClassificationHandler handles HTTP requests for classification operations.
type ClassificationHandler struct {
	service *service.PipelineService
	logger  *slog.Logger
}

// NewClassificationHandler creates a new classification handler.
func NewClassificationHandler(svc *service.PipelineService, logger *slog.Logger) *ClassificationHandler {
	return &ClassificationHandler{
		service: svc,
		logger:  logger,
	}
}

// RegisterRoutes registers all classification routes on the given mux.
func (h *ClassificationHandler) RegisterRoutes(mux *http.ServeMux) {
	// Classification routes
	mux.HandleFunc("GET /api/v1/pipeline/classifications", h.corsMiddleware(h.ListClassifications))
	mux.HandleFunc("GET /api/v1/pipeline/classifications/{id}", h.corsMiddleware(h.GetClassification))
	mux.HandleFunc("GET /api/v1/pipeline/classifications/{id}/mitre", h.corsMiddleware(h.GetMITREMapping))
	mux.HandleFunc("OPTIONS /api/v1/pipeline/classifications", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/classifications/{id}", h.corsPreflightHandler)
	mux.HandleFunc("OPTIONS /api/v1/pipeline/classifications/{id}/mitre", h.corsPreflightHandler)
}

// ClassificationPagination represents pagination information for classification responses.
type ClassificationPagination struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

// ClassificationListResponse represents the response for classification list.
type ClassificationListResponse struct {
	Classifications []ClassificationSummary  `json:"classifications"`
	Pagination      ClassificationPagination `json:"pagination"`
}

// ClassificationSummary represents a summary of a classification result.
type ClassificationSummary struct {
	ID              string    `json:"id"`
	EventID         string    `json:"event_id"`
	Label           string    `json:"label"`
	Confidence      float32   `json:"confidence"`
	Method          string    `json:"method"`
	MITRETactics    []string  `json:"mitre_tactics"`
	PlaybookMatched bool      `json:"playbook_matched"`
	CreatedAt       time.Time `json:"created_at"`
}

// ClassificationDetailResponse represents the detailed response for a classification.
type ClassificationDetailResponse struct {
	ID               string               `json:"id"`
	EventID          string               `json:"event_id"`
	EventSummary     model.EventSummary   `json:"event_summary"`
	Label            string               `json:"label"`
	Confidence       float32              `json:"confidence"`
	Method           string               `json:"method"`
	MatchedRules     []RuleMatch          `json:"matched_rules"`
	MatchedIOCs      []IOCMatch           `json:"matched_iocs"`
	Evidence         []EvidenceItem       `json:"evidence"`
	MITREMapping     *MITREMappingDetail  `json:"mitre_mapping"`
	PlaybookMatch    *model.PlaybookMatch `json:"playbook_match,omitempty"`
	ProcessingTimeMs int                  `json:"processing_time_ms"`
	CreatedAt        time.Time            `json:"created_at"`
}

// RuleMatch represents a matched detection rule.
type RuleMatch struct {
	RuleID      string  `json:"rule_id"`
	RuleName    string  `json:"rule_name"`
	Level       string  `json:"level"`
	Score       float32 `json:"score"`
	Description string  `json:"description"`
}

// IOCMatch represents a matched indicator of compromise.
type IOCMatch struct {
	Type       string  `json:"type"`
	Value      string  `json:"value"`
	Source     string  `json:"source"`
	ThreatType string  `json:"threat_type"`
	Confidence float32 `json:"confidence"`
}

// EvidenceItem represents a piece of evidence for the classification.
type EvidenceItem struct {
	Type        string `json:"type"`       // rule_match, ioc_match, pattern, anomaly
	Description string `json:"description"`
	Importance  string `json:"importance"` // high, medium, low
	Details     string `json:"details"`
}

// MITREMappingDetail represents detailed MITRE ATT&CK mapping.
type MITREMappingDetail struct {
	Tactics     []TacticMapping    `json:"tactics"`
	Techniques  []TechniqueMapping `json:"techniques"`
	AttackChain []AttackChainStep  `json:"attack_chain"`
}

// TacticMapping represents a MITRE tactic mapping.
type TacticMapping struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	IsActive    bool   `json:"is_active"`
}

// TechniqueMapping represents a MITRE technique mapping.
type TechniqueMapping struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TacticIDs   []string `json:"tactic_ids"`
	Description string   `json:"description"`
	IsMatched   bool     `json:"is_matched"`
}

// AttackChainStep represents a step in the attack chain.
type AttackChainStep struct {
	Order       int    `json:"order"`
	TacticID    string `json:"tactic_id"`
	TacticName  string `json:"tactic_name"`
	TechniqueID string `json:"technique_id,omitempty"`
	Status      string `json:"status"` // done, active, predicted
}

// corsMiddleware wraps a handler with CORS headers.
func (h *ClassificationHandler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// corsPreflightHandler handles CORS preflight requests.
func (h *ClassificationHandler) corsPreflightHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// ListClassifications handles GET /api/v1/pipeline/classifications
func (h *ClassificationHandler) ListClassifications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Parse query parameters
	page := 1
	pageSize := 20
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}
	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if ps, err := strconv.Atoi(pageSizeStr); err == nil && ps > 0 && ps <= 100 {
			pageSize = ps
		}
	}

	filter := model.PipelineEventFilter{
		Limit:  pageSize,
		Offset: (page - 1) * pageSize,
	}

	// Apply filters
	if tenantID := r.URL.Query().Get("tenant_id"); tenantID != "" {
		filter.TenantID = tenantID
	}
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" && filter.TenantID == "" {
		filter.TenantID = tenantID
	}
	if source := r.URL.Query().Get("source"); source != "" {
		filter.Source = source
	}
	if severity := r.URL.Query().Get("severity"); severity != "" {
		filter.Severity = severity
	}
	if label := r.URL.Query().Get("label"); label != "" {
		// Label filter will be applied post-query
		_ = label
	}

	events, total, err := h.service.ListEvents(r.Context(), filter)
	if err != nil {
		h.logger.Error("failed to list events", "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to list classifications")
		return
	}

	// Build classification summaries from events with classifications
	summaries := make([]ClassificationSummary, 0)
	for _, event := range events {
		if event.Classification == nil {
			continue
		}

		// Apply label filter if provided
		labelFilter := r.URL.Query().Get("label")
		if labelFilter != "" && event.Classification.Label != labelFilter {
			continue
		}

		summary := ClassificationSummary{
			ID:              event.ID + "-cls",
			EventID:         event.ID,
			Label:           event.Classification.Label,
			Confidence:      event.Classification.Confidence,
			Method:          event.Classification.Method,
			MITRETactics:    event.Classification.MITRETactics,
			PlaybookMatched: event.PlaybookMatch != nil,
			CreatedAt:       event.CreatedAt,
		}
		summaries = append(summaries, summary)
	}

	totalPages := (total + pageSize - 1) / pageSize

	response := ClassificationListResponse{
		Classifications: summaries,
		Pagination: ClassificationPagination{
			Page:       page,
			PageSize:   pageSize,
			Total:      total,
			TotalPages: totalPages,
		},
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetClassification handles GET /api/v1/pipeline/classifications/:id
func (h *ClassificationHandler) GetClassification(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "classification ID required")
		return
	}

	// Extract event ID from classification ID (format: eventID-cls)
	eventID := id
	if len(id) > 4 && id[len(id)-4:] == "-cls" {
		eventID = id[:len(id)-4]
	}

	event, err := h.service.GetEvent(r.Context(), eventID)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "classification not found: "+id)
		return
	}

	if event.Classification == nil {
		h.writeError(w, http.StatusNotFound, "no classification for event: "+eventID)
		return
	}

	// Build rule matches from classification
	matchedRules := buildRuleMatches(event.Classification.MatchedRules)

	// Build IOC matches from classification
	matchedIOCs := buildIOCMatches(event.Classification.MatchedIOCs)

	// Build evidence items
	evidence := buildEvidenceItems(event.Classification, matchedRules, matchedIOCs)

	// Build MITRE mapping
	mitreMapping := buildMITREMapping(event.Classification.MITRETactics, event.Classification.MITRETechniques)

	response := ClassificationDetailResponse{
		ID:      id,
		EventID: eventID,
		EventSummary: model.EventSummary{
			ID:        event.ID,
			Source:    event.Source,
			Severity:  event.Severity,
			Label:     event.Classification.Label,
			Timestamp: event.CreatedAt,
		},
		Label:            event.Classification.Label,
		Confidence:       event.Classification.Confidence,
		Method:           event.Classification.Method,
		MatchedRules:     matchedRules,
		MatchedIOCs:      matchedIOCs,
		Evidence:         evidence,
		MITREMapping:     mitreMapping,
		PlaybookMatch:    event.PlaybookMatch,
		ProcessingTimeMs: event.Classification.ProcessingTimeMs,
		CreatedAt:        event.CreatedAt,
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GetMITREMapping handles GET /api/v1/pipeline/classifications/:id/mitre
func (h *ClassificationHandler) GetMITREMapping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := r.PathValue("id")
	if id == "" {
		h.writeError(w, http.StatusBadRequest, "classification ID required")
		return
	}

	// Extract event ID from classification ID
	eventID := id
	if len(id) > 4 && id[len(id)-4:] == "-cls" {
		eventID = id[:len(id)-4]
	}

	event, err := h.service.GetEvent(r.Context(), eventID)
	if err != nil {
		h.writeError(w, http.StatusNotFound, "classification not found: "+id)
		return
	}

	if event.Classification == nil {
		h.writeError(w, http.StatusNotFound, "no classification for event: "+eventID)
		return
	}

	mitreMapping := buildMITREMapping(event.Classification.MITRETactics, event.Classification.MITRETechniques)
	if mitreMapping == nil {
		mitreMapping = &MITREMappingDetail{
			Tactics:     []TacticMapping{},
			Techniques:  []TechniqueMapping{},
			AttackChain: []AttackChainStep{},
		}
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(mitreMapping)
}

// writeError writes an error response.
func (h *ClassificationHandler) writeError(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// buildRuleMatches builds RuleMatch objects from rule IDs.
func buildRuleMatches(ruleIDs []string) []RuleMatch {
	matches := make([]RuleMatch, 0, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		match := RuleMatch{
			RuleID:      ruleID,
			RuleName:    getRuleName(ruleID),
			Level:       getRuleLevel(ruleID),
			Score:       0.8, // Default score
			Description: getRuleDescription(ruleID),
		}
		matches = append(matches, match)
	}
	return matches
}

// buildIOCMatches builds IOCMatch objects from IOC values.
func buildIOCMatches(iocValues []string) []IOCMatch {
	matches := make([]IOCMatch, 0, len(iocValues))
	for _, value := range iocValues {
		match := IOCMatch{
			Type:       detectIOCType(value),
			Value:      value,
			Source:     "threat_intel",
			ThreatType: "unknown",
			Confidence: 0.75,
		}
		matches = append(matches, match)
	}
	return matches
}

// buildEvidenceItems builds evidence items from classification data.
func buildEvidenceItems(classification *model.Classification, rules []RuleMatch, iocs []IOCMatch) []EvidenceItem {
	evidence := make([]EvidenceItem, 0)

	// Add rule-based evidence
	for _, rule := range rules {
		importance := "medium"
		if rule.Level == "critical" || rule.Level == "high" {
			importance = "high"
		}
		evidence = append(evidence, EvidenceItem{
			Type:        "rule_match",
			Description: "Detection rule triggered: " + rule.RuleName,
			Importance:  importance,
			Details:     rule.Description,
		})
	}

	// Add IOC-based evidence
	for _, ioc := range iocs {
		evidence = append(evidence, EvidenceItem{
			Type:        "ioc_match",
			Description: "Threat indicator matched: " + ioc.Type,
			Importance:  "high",
			Details:     "Value: " + ioc.Value + ", Source: " + ioc.Source,
		})
	}

	// Add classification confidence evidence
	if classification.Confidence >= 0.8 {
		evidence = append(evidence, EvidenceItem{
			Type:        "pattern",
			Description: "High confidence classification",
			Importance:  "medium",
			Details:     "Classification confidence: " + strconv.FormatFloat(float64(classification.Confidence), 'f', 2, 32),
		})
	}

	return evidence
}

// buildMITREMapping builds MITRE ATT&CK mapping from tactics and techniques.
func buildMITREMapping(tactics, techniques []string) *MITREMappingDetail {
	if len(tactics) == 0 && len(techniques) == 0 {
		return nil
	}

	mapping := &MITREMappingDetail{
		Tactics:     make([]TacticMapping, 0, len(tactics)),
		Techniques:  make([]TechniqueMapping, 0, len(techniques)),
		AttackChain: make([]AttackChainStep, 0),
	}

	// Build tactic mappings
	for _, tacticID := range tactics {
		mapping.Tactics = append(mapping.Tactics, TacticMapping{
			ID:          tacticID,
			Name:        getTacticName(tacticID),
			Description: getTacticDescription(tacticID),
			IsActive:    true,
		})
	}

	// Build technique mappings
	for _, techniqueID := range techniques {
		mapping.Techniques = append(mapping.Techniques, TechniqueMapping{
			ID:          techniqueID,
			Name:        getTechniqueName(techniqueID),
			TacticIDs:   getTechniqueTactics(techniqueID),
			Description: getTechniqueDescription(techniqueID),
			IsMatched:   true,
		})
	}

	// Build attack chain from tactics
	for i, tacticID := range tactics {
		step := AttackChainStep{
			Order:      i + 1,
			TacticID:   tacticID,
			TacticName: getTacticName(tacticID),
			Status:     "done",
		}
		// Associate first matching technique
		for _, techniqueID := range techniques {
			tacticList := getTechniqueTactics(techniqueID)
			for _, tid := range tacticList {
				if tid == tacticID {
					step.TechniqueID = techniqueID
					break
				}
			}
			if step.TechniqueID != "" {
				break
			}
		}
		mapping.AttackChain = append(mapping.AttackChain, step)
	}

	return mapping
}

// Helper functions for MITRE ATT&CK data (simplified - would be loaded from database)

func getRuleName(ruleID string) string {
	// In production, this would look up the rule name from a database
	return "Rule " + ruleID
}

func getRuleLevel(ruleID string) string {
	return "medium"
}

func getRuleDescription(ruleID string) string {
	return "Detection rule " + ruleID
}

func detectIOCType(value string) string {
	// Simple IOC type detection
	if len(value) == 32 || len(value) == 40 || len(value) == 64 {
		return "hash"
	}
	// Check if it looks like an IP
	if len(value) >= 7 && len(value) <= 15 {
		return "ip"
	}
	// Check if it looks like a domain
	if len(value) > 4 && (value[len(value)-4:] == ".com" || value[len(value)-3:] == ".io" || value[len(value)-4:] == ".net") {
		return "domain"
	}
	return "unknown"
}

func getTacticName(tacticID string) string {
	tacticNames := map[string]string{
		"TA0001": "Initial Access",
		"TA0002": "Execution",
		"TA0003": "Persistence",
		"TA0004": "Privilege Escalation",
		"TA0005": "Defense Evasion",
		"TA0006": "Credential Access",
		"TA0007": "Discovery",
		"TA0008": "Lateral Movement",
		"TA0009": "Collection",
		"TA0010": "Exfiltration",
		"TA0011": "Command and Control",
		"TA0040": "Impact",
	}
	if name, ok := tacticNames[tacticID]; ok {
		return name
	}
	return tacticID
}

func getTacticDescription(tacticID string) string {
	tacticDescriptions := map[string]string{
		"TA0001": "The adversary is trying to get into your network.",
		"TA0002": "The adversary is trying to run malicious code.",
		"TA0003": "The adversary is trying to maintain their foothold.",
		"TA0004": "The adversary is trying to gain higher-level permissions.",
		"TA0005": "The adversary is trying to avoid being detected.",
		"TA0006": "The adversary is trying to steal account names and passwords.",
		"TA0007": "The adversary is trying to figure out your environment.",
		"TA0008": "The adversary is trying to move through your environment.",
		"TA0009": "The adversary is trying to gather data of interest to their goal.",
		"TA0010": "The adversary is trying to steal data.",
		"TA0011": "The adversary is trying to communicate with compromised systems.",
		"TA0040": "The adversary is trying to manipulate, interrupt, or destroy systems and data.",
	}
	if desc, ok := tacticDescriptions[tacticID]; ok {
		return desc
	}
	return "MITRE ATT&CK Tactic"
}

func getTechniqueName(techniqueID string) string {
	techniqueNames := map[string]string{
		"T1059": "Command and Scripting Interpreter",
		"T1078": "Valid Accounts",
		"T1190": "Exploit Public-Facing Application",
		"T1566": "Phishing",
		"T1203": "Exploitation for Client Execution",
		"T1053": "Scheduled Task/Job",
		"T1547": "Boot or Logon Autostart Execution",
		"T1068": "Exploitation for Privilege Escalation",
		"T1027": "Obfuscated Files or Information",
		"T1110": "Brute Force",
		"T1087": "Account Discovery",
		"T1021": "Remote Services",
		"T1005": "Data from Local System",
		"T1041": "Exfiltration Over C2 Channel",
		"T1071": "Application Layer Protocol",
		"T1486": "Data Encrypted for Impact",
	}
	if name, ok := techniqueNames[techniqueID]; ok {
		return name
	}
	return techniqueID
}

func getTechniqueDescription(techniqueID string) string {
	return "MITRE ATT&CK Technique " + techniqueID
}

func getTechniqueTactics(techniqueID string) []string {
	techniqueTactics := map[string][]string{
		"T1059": {"TA0002"},
		"T1078": {"TA0001", "TA0003", "TA0004", "TA0005"},
		"T1190": {"TA0001"},
		"T1566": {"TA0001"},
		"T1203": {"TA0002"},
		"T1053": {"TA0002", "TA0003", "TA0004"},
		"T1547": {"TA0003", "TA0004"},
		"T1068": {"TA0004"},
		"T1027": {"TA0005"},
		"T1110": {"TA0006"},
		"T1087": {"TA0007"},
		"T1021": {"TA0008"},
		"T1005": {"TA0009"},
		"T1041": {"TA0010"},
		"T1071": {"TA0011"},
		"T1486": {"TA0040"},
	}
	if tactics, ok := techniqueTactics[techniqueID]; ok {
		return tactics
	}
	return []string{}
}
