// Package classifier provides event classification capabilities.
package classifier

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/siem-soar-platform/services/pipeline/internal/model"
)

// RuleEngine handles event classification using Sigma rules.
type RuleEngine struct {
	rules       []SigmaRule
	rulesByID   map[string]*SigmaRule
	mitreMaps   map[string]MITREMapping
	framework   *MITREFramework
	mu          sync.RWMutex
	levelScores map[string]float32
}

// SigmaRule represents a loaded Sigma rule.
type SigmaRule struct {
	ID             string                 `yaml:"id" json:"id"`
	Title          string                 `yaml:"title" json:"title"`
	Description    string                 `yaml:"description" json:"description"`
	Level          string                 `yaml:"level" json:"level"`
	Status         string                 `yaml:"status" json:"status"`
	Tags           []string               `yaml:"tags" json:"tags"`
	Author         string                 `yaml:"author" json:"author"`
	Date           string                 `yaml:"date" json:"date"`
	Modified       string                 `yaml:"modified" json:"modified"`
	References     []string               `yaml:"references" json:"references"`
	FalsePositives []string               `yaml:"falsepositives" json:"false_positives"`
	LogSource      LogSource              `yaml:"logsource" json:"log_source"`
	Detection      map[string]interface{} `yaml:"detection" json:"detection"`
	Fields         []string               `yaml:"fields" json:"fields"`
}

// LogSource represents Sigma log source specification.
type LogSource struct {
	Product    string `yaml:"product" json:"product"`
	Service    string `yaml:"service" json:"service"`
	Category   string `yaml:"category" json:"category"`
	Definition string `yaml:"definition" json:"definition"`
}

// MatchResult represents a single rule match result.
type MatchResult struct {
	RuleID        string            `json:"rule_id"`
	RuleTitle     string            `json:"rule_title"`
	Level         string            `json:"level"`
	Score         float32           `json:"score"`
	MatchedFields map[string]string `json:"matched_fields"`
	Tags          []string          `json:"tags"`
}

// NewRuleEngine creates a new rule engine and loads rules.
func NewRuleEngine(rulesDir string) (*RuleEngine, error) {
	engine := &RuleEngine{
		rules:     make([]SigmaRule, 0),
		rulesByID: make(map[string]*SigmaRule),
		mitreMaps: make(map[string]MITREMapping),
		framework: NewMITREFramework(),
		levelScores: map[string]float32{
			"critical":      0.95,
			"high":          0.85,
			"medium":        0.70,
			"low":           0.50,
			"informational": 0.30,
		},
	}

	if rulesDir != "" {
		if err := engine.LoadRules(rulesDir); err != nil {
			return nil, fmt.Errorf("failed to load rules: %w", err)
		}
	}

	return engine, nil
}

// LoadRules loads Sigma rules from a directory (YAML files).
func (r *RuleEngine) LoadRules(dir string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("failed to access rules directory: %w", err)
	}

	if !info.IsDir() {
		// Single file
		return r.loadRuleFile(dir)
	}

	// Walk directory
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yml" && ext != ".yaml" {
			return nil
		}

		if loadErr := r.loadRuleFile(path); loadErr != nil {
			// Log warning but continue loading other rules
			fmt.Printf("warning: failed to load rule %s: %v\n", path, loadErr)
		}

		return nil
	})
}

func (r *RuleEngine) loadRuleFile(path string) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	var rule SigmaRule
	if err := yaml.Unmarshal(content, &rule); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Validate required fields
	if rule.Title == "" && rule.ID == "" {
		return fmt.Errorf("rule must have title or id")
	}

	// Generate ID if not present
	if rule.ID == "" {
		rule.ID = strings.ReplaceAll(strings.ToLower(rule.Title), " ", "-")
	}

	// Validate and normalize level
	rule.Level = r.normalizeLevel(rule.Level)

	// Validate status
	if rule.Status == "" {
		rule.Status = "experimental"
	}

	r.rules = append(r.rules, rule)
	r.rulesByID[rule.ID] = &r.rules[len(r.rules)-1]

	// Build MITRE mappings for this rule
	r.buildMITREMapping(&rule)

	return nil
}

func (r *RuleEngine) normalizeLevel(level string) string {
	level = strings.ToLower(level)
	validLevels := []string{"critical", "high", "medium", "low", "informational"}
	for _, v := range validLevels {
		if level == v {
			return level
		}
	}
	return "medium" // default
}

func (r *RuleEngine) buildMITREMapping(rule *SigmaRule) {
	for _, tag := range rule.Tags {
		tacticName, techniqueID, err := ParseMITRETag(tag)
		if err != nil {
			continue
		}

		if techniqueID != "" {
			if mapping := r.framework.GetMapping(techniqueID); mapping != nil {
				r.mitreMaps[rule.ID+"_"+techniqueID] = *mapping
			}
		} else if tacticName != "" {
			// Resolve tactic name to ID
			tacticID := tacticNameToID(tacticName)
			if tacticID != "" {
				if tactic, ok := r.framework.Tactics[tacticID]; ok {
					r.mitreMaps[rule.ID+"_"+tacticID] = MITREMapping{
						TacticID:   tacticID,
						TacticName: tactic.Name,
					}
				}
			}
		}
	}
}

// LoadRuleYAML loads a single rule from YAML content.
func (r *RuleEngine) LoadRuleYAML(content string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var rule SigmaRule
	if err := yaml.Unmarshal([]byte(content), &rule); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	if rule.ID == "" {
		rule.ID = strings.ReplaceAll(strings.ToLower(rule.Title), " ", "-")
	}

	rule.Level = r.normalizeLevel(rule.Level)

	r.rules = append(r.rules, rule)
	r.rulesByID[rule.ID] = &r.rules[len(r.rules)-1]
	r.buildMITREMapping(&rule)

	return nil
}

// Classify classifies an event against all loaded rules.
// Returns matching rules and MITRE mappings.
func (r *RuleEngine) Classify(ctx context.Context, event *model.PipelineEvent) (*model.Classification, error) {
	start := time.Now()

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Convert event to map for matching
	eventMap, err := r.eventToMap(event)
	if err != nil {
		return nil, fmt.Errorf("failed to convert event: %w", err)
	}

	var matchedRules []string
	var highestScore float32
	var allTactics []string
	var allTechniques []string
	var bestLevel string

	for _, rule := range r.rules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Skip non-active rules
		if rule.Status == "deprecated" || rule.Status == "unsupported" {
			continue
		}

		matched, score := r.MatchRule(&rule, eventMap)
		if matched {
			matchedRules = append(matchedRules, rule.ID)

			if score > highestScore {
				highestScore = score
				bestLevel = rule.Level
			}

			// Extract MITRE tags
			tactics, techniques := r.GetMITRETags(rule.Tags)
			allTactics = append(allTactics, tactics...)
			allTechniques = append(allTechniques, techniques...)
		}
	}

	if len(matchedRules) == 0 {
		return &model.Classification{
			Label:            "benign",
			Confidence:       0.0,
			Method:           model.MethodSIGMA,
			MatchedRules:     []string{},
			MITRETactics:     []string{},
			MITRETechniques:  []string{},
			ProcessingTimeMs: int(time.Since(start).Milliseconds()),
		}, nil
	}

	// Deduplicate tactics and techniques
	allTactics = uniqueStrings(allTactics)
	allTechniques = uniqueStrings(allTechniques)

	return &model.Classification{
		Label:            r.levelToLabel(bestLevel),
		Confidence:       highestScore,
		Method:           model.MethodSIGMA,
		MatchedRules:     matchedRules,
		MITRETactics:     allTactics,
		MITRETechniques:  allTechniques,
		ProcessingTimeMs: int(time.Since(start).Milliseconds()),
	}, nil
}

func (r *RuleEngine) levelToLabel(level string) string {
	switch level {
	case "critical", "high":
		return "malicious"
	case "medium":
		return "suspicious"
	case "low", "informational":
		return "anomaly"
	default:
		return "suspicious"
	}
}

// MatchRule checks if a single rule matches the event.
func (r *RuleEngine) MatchRule(rule *SigmaRule, event map[string]interface{}) (bool, float32) {
	detection, ok := rule.Detection["condition"]
	if !ok {
		return false, 0
	}

	condition, ok := detection.(string)
	if !ok {
		return false, 0
	}

	// Simple condition evaluation
	matched := r.evaluateCondition(condition, rule.Detection, event)
	if !matched {
		return false, 0
	}

	// Calculate score based on level
	score := r.levelScores[rule.Level]
	if score == 0 {
		score = r.levelScores["medium"]
	}

	return true, score
}

func (r *RuleEngine) evaluateCondition(condition string, detection map[string]interface{}, event map[string]interface{}) bool {
	// Handle simple conditions: "selection", "selection and not filter", etc.
	condition = strings.TrimSpace(strings.ToLower(condition))

	// Check for "all of" pattern
	if strings.HasPrefix(condition, "all of") {
		return r.evaluateAllOf(condition, detection, event)
	}

	// Check for "1 of" pattern
	if strings.HasPrefix(condition, "1 of") {
		return r.evaluateOneOf(condition, detection, event)
	}

	// Parse boolean conditions
	// Handle "selection and not filter"
	if strings.Contains(condition, " and not ") {
		parts := strings.SplitN(condition, " and not ", 2)
		return r.matchSelection(parts[0], detection, event) && !r.matchSelection(parts[1], detection, event)
	}

	// Handle "selection or ..."
	if strings.Contains(condition, " or ") {
		parts := strings.Split(condition, " or ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if r.matchSelection(part, detection, event) {
				return true
			}
		}
		return false
	}

	// Handle "selection and ..."
	if strings.Contains(condition, " and ") {
		parts := strings.Split(condition, " and ")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "not ") {
				if r.matchSelection(strings.TrimPrefix(part, "not "), detection, event) {
					return false
				}
			} else {
				if !r.matchSelection(part, detection, event) {
					return false
				}
			}
		}
		return true
	}

	// Simple condition - just selection name
	return r.matchSelection(condition, detection, event)
}

func (r *RuleEngine) evaluateAllOf(condition string, detection map[string]interface{}, event map[string]interface{}) bool {
	// Extract pattern after "all of"
	pattern := strings.TrimSpace(strings.TrimPrefix(condition, "all of"))
	pattern = strings.Trim(pattern, "()")

	if pattern == "them" || pattern == "*" {
		// Match all selection_ prefixed keys
		for key := range detection {
			if key == "condition" || key == "timeframe" {
				continue
			}
			if !r.matchSelection(key, detection, event) {
				return false
			}
		}
		return true
	}

	// Match pattern like "selection*"
	pattern = strings.TrimSuffix(pattern, "*")
	for key := range detection {
		if strings.HasPrefix(key, pattern) {
			if !r.matchSelection(key, detection, event) {
				return false
			}
		}
	}
	return true
}

func (r *RuleEngine) evaluateOneOf(condition string, detection map[string]interface{}, event map[string]interface{}) bool {
	// Extract pattern after "1 of"
	pattern := strings.TrimSpace(strings.TrimPrefix(condition, "1 of"))
	pattern = strings.Trim(pattern, "()")

	if pattern == "them" || pattern == "*" {
		for key := range detection {
			if key == "condition" || key == "timeframe" {
				continue
			}
			if r.matchSelection(key, detection, event) {
				return true
			}
		}
		return false
	}

	// Match pattern like "selection*"
	pattern = strings.TrimSuffix(pattern, "*")
	for key := range detection {
		if strings.HasPrefix(key, pattern) {
			if r.matchSelection(key, detection, event) {
				return true
			}
		}
	}
	return false
}

func (r *RuleEngine) matchSelection(name string, detection map[string]interface{}, event map[string]interface{}) bool {
	selection, ok := detection[name]
	if !ok {
		return false
	}

	selMap, ok := selection.(map[string]interface{})
	if !ok {
		return false
	}

	// All fields in selection must match
	for field, expected := range selMap {
		if !r.matchField(field, expected, event) {
			return false
		}
	}

	return true
}

func (r *RuleEngine) matchField(field string, expected interface{}, event map[string]interface{}) bool {
	// Parse field modifiers (e.g., "CommandLine|contains")
	parts := strings.Split(field, "|")
	fieldName := parts[0]
	var modifiers []string
	if len(parts) > 1 {
		modifiers = parts[1:]
	}

	// Get value from event (support nested fields)
	eventValue := r.getFieldValue(fieldName, event)
	if eventValue == nil {
		return false
	}

	// Handle expected as list
	switch exp := expected.(type) {
	case []interface{}:
		for _, e := range exp {
			if r.matchValue(eventValue, e, modifiers) {
				return true
			}
		}
		return false
	default:
		return r.matchValue(eventValue, expected, modifiers)
	}
}

func (r *RuleEngine) getFieldValue(field string, event map[string]interface{}) interface{} {
	// Support dot notation for nested fields
	parts := strings.Split(field, ".")
	var current interface{} = event

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				// Try case-insensitive match
				for k, val := range v {
					if strings.EqualFold(k, part) {
						current = val
						ok = true
						break
					}
				}
				if !ok {
					return nil
				}
			}
		default:
			return nil
		}
	}

	return current
}

func (r *RuleEngine) matchValue(actual, expected interface{}, modifiers []string) bool {
	actualStr := fmt.Sprintf("%v", actual)
	expectedStr := fmt.Sprintf("%v", expected)

	// Apply modifiers
	for _, mod := range modifiers {
		switch mod {
		case "contains":
			return strings.Contains(strings.ToLower(actualStr), strings.ToLower(expectedStr))
		case "startswith":
			return strings.HasPrefix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
		case "endswith":
			return strings.HasSuffix(strings.ToLower(actualStr), strings.ToLower(expectedStr))
		case "all":
			// All values must be present (handled at list level)
			continue
		}
	}

	// Default: case-insensitive equality
	return strings.EqualFold(actualStr, expectedStr)
}

// GetMITRETags extracts MITRE tactic/technique tags from rule tags.
func (r *RuleEngine) GetMITRETags(tags []string) (tactics []string, techniques []string) {
	for _, tag := range tags {
		tacticName, techniqueID, err := ParseMITRETag(tag)
		if err != nil {
			continue
		}

		if techniqueID != "" {
			techniques = append(techniques, techniqueID)
		} else if tacticName != "" {
			// Convert tactic name to ID
			tacticID := tacticNameToID(tacticName)
			if tacticID != "" {
				tactics = append(tactics, tacticID)
			} else {
				// Use the name as-is if no ID mapping
				tactics = append(tactics, tacticName)
			}
		}
	}

	return tactics, techniques
}

// GetRule returns a rule by ID.
func (r *RuleEngine) GetRule(id string) (*SigmaRule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rule, ok := r.rulesByID[id]
	return rule, ok
}

// GetRules returns all loaded rules.
func (r *RuleEngine) GetRules() []SigmaRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rules := make([]SigmaRule, len(r.rules))
	copy(rules, r.rules)
	return rules
}

// RuleCount returns the number of loaded rules.
func (r *RuleEngine) RuleCount() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.rules)
}

// GetMITREMappings returns all MITRE mappings.
func (r *RuleEngine) GetMITREMappings() map[string]MITREMapping {
	r.mu.RLock()
	defer r.mu.RUnlock()

	mappings := make(map[string]MITREMapping, len(r.mitreMaps))
	for k, v := range r.mitreMaps {
		mappings[k] = v
	}
	return mappings
}

// GetRulesByTechnique returns rules matching a MITRE technique.
func (r *RuleEngine) GetRulesByTechnique(techniqueID string) []SigmaRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	techniqueID = strings.ToUpper(techniqueID)
	var rules []SigmaRule

	for _, rule := range r.rules {
		for _, tag := range rule.Tags {
			_, techID, err := ParseMITRETag(tag)
			if err == nil && strings.ToUpper(techID) == techniqueID {
				rules = append(rules, rule)
				break
			}
		}
	}

	return rules
}

// GetRulesByTactic returns rules matching a MITRE tactic.
func (r *RuleEngine) GetRulesByTactic(tacticName string) []SigmaRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tacticName = strings.ToLower(tacticName)
	var rules []SigmaRule

	for _, rule := range r.rules {
		for _, tag := range rule.Tags {
			tactic, _, err := ParseMITRETag(tag)
			if err == nil && strings.ToLower(tactic) == tacticName {
				rules = append(rules, rule)
				break
			}
		}
	}

	return rules
}

// GetRulesByLevel returns rules with a specific severity level.
func (r *RuleEngine) GetRulesByLevel(level string) []SigmaRule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	level = strings.ToLower(level)
	var rules []SigmaRule

	for _, rule := range r.rules {
		if rule.Level == level {
			rules = append(rules, rule)
		}
	}

	return rules
}

// eventToMap converts a PipelineEvent to a map for rule matching.
func (r *RuleEngine) eventToMap(event *model.PipelineEvent) (map[string]interface{}, error) {
	// First try to parse RawLog as JSON
	var eventMap map[string]interface{}
	if err := json.Unmarshal([]byte(event.RawLog), &eventMap); err != nil {
		// If not JSON, create a simple map with the raw log
		eventMap = map[string]interface{}{
			"raw":      event.RawLog,
			"source":   event.Source,
			"severity": event.Severity,
		}
	}

	// Add pipeline event metadata
	eventMap["_id"] = event.ID
	eventMap["_tenant_id"] = event.TenantID
	eventMap["_source"] = event.Source
	eventMap["_severity"] = event.Severity
	eventMap["_timestamp"] = event.CreatedAt

	return eventMap, nil
}

// uniqueStrings returns unique strings from a slice.
func uniqueStrings(slice []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
