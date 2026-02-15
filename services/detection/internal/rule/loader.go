// Package rule provides detection rule models and validation.
package rule

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// LoaderConfig holds loader configuration.
type LoaderConfig struct {
	// File-based loading
	RulesDirectory string
	WatchDirectory bool
	FileExtensions []string

	// Database-based loading
	UseDatabase    bool
	TenantID       string
}

// RuleRepository defines the interface for rule storage.
type RuleRepository interface {
	GetByID(ctx context.Context, tenantID, ruleID string) (*Rule, error)
	ListEnabled(ctx context.Context, tenantID string) ([]*Rule, error)
	Save(ctx context.Context, rule *Rule) error
	Delete(ctx context.Context, tenantID, ruleID string) error
}

// Loader loads detection rules from various sources.
type Loader struct {
	config      LoaderConfig
	repository  RuleRepository
	validator   *Validator
	converter   *SigmaConverter
	logger      *slog.Logger

	// Cache
	rules       map[string]*Rule
	rulesMu     sync.RWMutex
}

// SigmaConverter converts Sigma rules to internal format.
type SigmaConverter struct {
	logger *slog.Logger
}

// NewLoader creates a new rule loader.
func NewLoader(cfg LoaderConfig, repo RuleRepository, logger *slog.Logger) *Loader {
	return &Loader{
		config:     cfg,
		repository: repo,
		validator:  NewValidator(),
		converter:  &SigmaConverter{logger: logger},
		logger:     logger.With("component", "rule-loader"),
		rules:      make(map[string]*Rule),
	}
}

// LoadAll loads all enabled rules.
func (l *Loader) LoadAll(ctx context.Context) ([]*Rule, error) {
	var rules []*Rule

	// Load from database
	if l.config.UseDatabase && l.repository != nil {
		dbRules, err := l.repository.ListEnabled(ctx, l.config.TenantID)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from database: %w", err)
		}
		rules = append(rules, dbRules...)
	}

	// Load from directory
	if l.config.RulesDirectory != "" {
		fileRules, err := l.loadFromDirectory(ctx, l.config.RulesDirectory)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules from directory: %w", err)
		}
		rules = append(rules, fileRules...)
	}

	// Parse and validate all rules
	validRules := make([]*Rule, 0, len(rules))
	for _, r := range rules {
		if err := l.parseRule(r); err != nil {
			l.logger.Warn("failed to parse rule", "rule_id", r.ID, "error", err)
			continue
		}

		if err := l.validator.Validate(r); err != nil {
			l.logger.Warn("rule validation failed", "rule_id", r.ID, "error", err)
			continue
		}

		validRules = append(validRules, r)
	}

	// Update cache
	l.rulesMu.Lock()
	l.rules = make(map[string]*Rule)
	for _, r := range validRules {
		l.rules[r.ID] = r
	}
	l.rulesMu.Unlock()

	l.logger.Info("rules loaded", "total", len(rules), "valid", len(validRules))

	return validRules, nil
}

// LoadByID loads a single rule by ID.
func (l *Loader) LoadByID(ctx context.Context, ruleID string) (*Rule, error) {
	// Check cache first
	l.rulesMu.RLock()
	if r, ok := l.rules[ruleID]; ok {
		l.rulesMu.RUnlock()
		return r, nil
	}
	l.rulesMu.RUnlock()

	// Load from database
	if l.repository != nil {
		rule, err := l.repository.GetByID(ctx, l.config.TenantID, ruleID)
		if err != nil {
			return nil, err
		}
		if rule != nil {
			if err := l.parseRule(rule); err != nil {
				return nil, err
			}
			return rule, nil
		}
	}

	return nil, fmt.Errorf("rule not found: %s", ruleID)
}

// LoadFromFile loads a rule from a single file.
func (l *Loader) LoadFromFile(ctx context.Context, filePath string) (*Rule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	return l.loadFromReader(file, filePath)
}

// LoadFromYAML loads a rule from YAML content.
func (l *Loader) LoadFromYAML(content string) (*Rule, error) {
	return l.loadFromReader(strings.NewReader(content), "inline")
}

// LoadFromJSON loads a rule from JSON content.
func (l *Loader) LoadFromJSON(content string) (*Rule, error) {
	var rule Rule
	if err := json.Unmarshal([]byte(content), &rule); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	if err := l.parseRule(&rule); err != nil {
		return nil, err
	}

	return &rule, nil
}

func (l *Loader) loadFromDirectory(ctx context.Context, dir string) ([]*Rule, error) {
	var rules []*Rule

	extensions := l.config.FileExtensions
	if len(extensions) == 0 {
		extensions = []string{".yml", ".yaml", ".json"}
	}

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		validExt := false
		for _, e := range extensions {
			if ext == e {
				validExt = true
				break
			}
		}

		if !validExt {
			return nil
		}

		rule, err := l.LoadFromFile(ctx, path)
		if err != nil {
			l.logger.Warn("failed to load rule file", "path", path, "error", err)
			return nil
		}

		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, err
	}

	return rules, nil
}

func (l *Loader) loadFromReader(reader io.Reader, source string) (*Rule, error) {
	content, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %w", err)
	}

	var rule Rule

	// Try YAML first
	if err := yaml.Unmarshal(content, &rule); err != nil {
		// Try JSON
		if err := json.Unmarshal(content, &rule); err != nil {
			return nil, fmt.Errorf("failed to parse rule (tried YAML and JSON): %w", err)
		}
	}

	rule.RawContent = string(content)

	if err := l.parseRule(&rule); err != nil {
		return nil, fmt.Errorf("failed to parse rule: %w", err)
	}

	return &rule, nil
}

func (l *Loader) parseRule(r *Rule) error {
	switch r.Type {
	case TypeSigma:
		return l.converter.Convert(r)
	case TypeSimple, TypeCorrelation, TypeThreshold:
		return l.parseSimpleRule(r)
	default:
		return nil
	}
}

func (l *Loader) parseSimpleRule(r *Rule) error {
	if r.Detection == nil {
		return nil
	}

	conditions := &ParsedConditions{
		Conditions: make([]*Condition, 0),
		Logic:      LogicAnd,
	}

	// Parse selection
	for field, value := range r.Detection.Selection {
		cond, err := parseConditionValue(field, value)
		if err != nil {
			return err
		}
		cond.Required = true
		conditions.Conditions = append(conditions.Conditions, cond)
	}

	r.ParsedConditions = conditions
	return nil
}

func parseConditionValue(field string, value interface{}) (*Condition, error) {
	cond := &Condition{
		Field:    field,
		Operator: OpEquals,
	}

	switch v := value.(type) {
	case string:
		// Check for operators in field name
		if strings.HasSuffix(field, "|contains") {
			cond.Field = strings.TrimSuffix(field, "|contains")
			cond.Operator = OpContains
		} else if strings.HasSuffix(field, "|startswith") {
			cond.Field = strings.TrimSuffix(field, "|startswith")
			cond.Operator = OpStartsWith
		} else if strings.HasSuffix(field, "|endswith") {
			cond.Field = strings.TrimSuffix(field, "|endswith")
			cond.Operator = OpEndsWith
		} else if strings.HasSuffix(field, "|re") {
			cond.Field = strings.TrimSuffix(field, "|re")
			cond.Operator = OpRegex
		}
		cond.Value = v

	case []interface{}:
		cond.Operator = OpIn
		cond.Values = v

	case map[string]interface{}:
		// Handle nested conditions
		for op, val := range v {
			switch op {
			case "contains":
				cond.Operator = OpContains
			case "startswith":
				cond.Operator = OpStartsWith
			case "endswith":
				cond.Operator = OpEndsWith
			case "regex", "re":
				cond.Operator = OpRegex
			case "gt":
				cond.Operator = OpGreaterThan
			case "lt":
				cond.Operator = OpLessThan
			case "gte":
				cond.Operator = OpGreaterOrEqual
			case "lte":
				cond.Operator = OpLessOrEqual
			}
			cond.Value = val
		}

	default:
		cond.Value = value
	}

	return cond, nil
}

// Convert converts a Sigma rule to internal format.
func (c *SigmaConverter) Convert(r *Rule) error {
	if r.Detection == nil {
		return fmt.Errorf("sigma rule has no detection section")
	}

	conditions := &ParsedConditions{
		Conditions: make([]*Condition, 0),
		Logic:      LogicAnd,
	}

	// Parse selection
	for field, value := range r.Detection.Selection {
		cond, err := c.parseSelection(field, value)
		if err != nil {
			return err
		}
		conditions.Conditions = append(conditions.Conditions, cond...)
	}

	// Apply filter (NOT conditions)
	if r.Detection.Filter != nil {
		for field, value := range r.Detection.Filter {
			cond, err := c.parseFilter(field, value)
			if err != nil {
				return err
			}
			conditions.Conditions = append(conditions.Conditions, cond...)
		}
	}

	r.ParsedConditions = conditions
	return nil
}

func (c *SigmaConverter) parseSelection(field string, value interface{}) ([]*Condition, error) {
	var conditions []*Condition

	// Handle modifiers in field name
	parts := strings.Split(field, "|")
	baseField := parts[0]
	modifiers := parts[1:]

	cond := &Condition{
		Field:    baseField,
		Operator: OpEquals,
		Required: true,
	}

	// Apply modifiers
	for _, mod := range modifiers {
		switch mod {
		case "contains":
			cond.Operator = OpContains
		case "startswith":
			cond.Operator = OpStartsWith
		case "endswith":
			cond.Operator = OpEndsWith
		case "re", "regex":
			cond.Operator = OpRegex
		case "all":
			// All values must match - handle lists
		case "base64":
			// Base64 decode before matching
		case "wide":
			// Wide string matching
		case "cidr":
			cond.Operator = OpCIDR
		}
	}

	switch v := value.(type) {
	case string:
		cond.Value = v
	case []interface{}:
		if cond.Operator == OpEquals {
			cond.Operator = OpIn
		}
		cond.Values = v
	default:
		cond.Value = value
	}

	conditions = append(conditions, cond)
	return conditions, nil
}

func (c *SigmaConverter) parseFilter(field string, value interface{}) ([]*Condition, error) {
	conds, err := c.parseSelection(field, value)
	if err != nil {
		return nil, err
	}

	// Negate filter conditions
	for _, cond := range conds {
		switch cond.Operator {
		case OpEquals:
			cond.Operator = OpNotEquals
		case OpContains:
			cond.Operator = OpNotContains
		case OpIn:
			cond.Operator = OpNotIn
		}
		cond.Required = false
	}

	return conds, nil
}
