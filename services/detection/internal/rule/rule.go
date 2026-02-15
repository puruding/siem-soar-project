// Package rule provides detection rule models and validation.
package rule

import (
	"fmt"
	"time"
)

// RuleType represents the type of detection rule.
type RuleType string

const (
	TypeSimple      RuleType = "simple"
	TypeSigma       RuleType = "sigma"
	TypeCorrelation RuleType = "correlation"
	TypeThreshold   RuleType = "threshold"
	TypeSequence    RuleType = "sequence"
	TypeML          RuleType = "ml"
)

// RuleStatus represents the status of a rule.
type RuleStatus string

const (
	StatusDraft      RuleStatus = "draft"
	StatusActive     RuleStatus = "active"
	StatusInactive   RuleStatus = "inactive"
	StatusDeprecated RuleStatus = "deprecated"
	StatusTesting    RuleStatus = "testing"
)

// Severity represents the severity level of a rule.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Operator represents condition operators.
type Operator string

const (
	OpEquals        Operator = "eq"
	OpNotEquals     Operator = "ne"
	OpContains      Operator = "contains"
	OpNotContains   Operator = "not_contains"
	OpStartsWith    Operator = "starts_with"
	OpEndsWith      Operator = "ends_with"
	OpRegex         Operator = "regex"
	OpIn            Operator = "in"
	OpNotIn         Operator = "not_in"
	OpGreaterThan   Operator = "gt"
	OpLessThan      Operator = "lt"
	OpGreaterOrEqual Operator = "gte"
	OpLessOrEqual   Operator = "lte"
	OpExists        Operator = "exists"
	OpNotExists     Operator = "not_exists"
	OpCIDR          Operator = "cidr"
)

// Rule represents a detection rule.
type Rule struct {
	// Identity
	ID        string `json:"id" yaml:"id"`
	TenantID  string `json:"tenant_id" yaml:"tenant_id"`
	Name      string `json:"name" yaml:"name"`
	Title     string `json:"title" yaml:"title"`

	// Description
	Description string   `json:"description" yaml:"description"`
	References  []string `json:"references,omitempty" yaml:"references"`
	Author      string   `json:"author,omitempty" yaml:"author"`

	// Classification
	Type        RuleType   `json:"type" yaml:"type"`
	Status      RuleStatus `json:"status" yaml:"status"`
	Severity    string     `json:"severity" yaml:"severity"`
	FalsePositives []string `json:"false_positives,omitempty" yaml:"falsepositives"`

	// MITRE ATT&CK
	MITRETactics    []string `json:"mitre_tactics,omitempty" yaml:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques,omitempty" yaml:"mitre_techniques"`

	// Tags and metadata
	Tags     []string          `json:"tags,omitempty" yaml:"tags"`
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata"`

	// Rule content (for Sigma rules)
	RawContent string `json:"raw_content,omitempty" yaml:"-"`

	// Conditions
	LogSource         *LogSource          `json:"logsource,omitempty" yaml:"logsource"`
	Detection         *Detection          `json:"detection,omitempty" yaml:"detection"`
	ParsedConditions  *ParsedConditions   `json:"-" yaml:"-"`

	// Scheduling
	Schedule string        `json:"schedule,omitempty" yaml:"schedule"`
	Lookback time.Duration `json:"lookback,omitempty" yaml:"lookback"`

	// Threshold/Aggregation
	Threshold    *ThresholdConfig    `json:"threshold,omitempty" yaml:"threshold"`
	Aggregation  *AggregationConfig  `json:"aggregation,omitempty" yaml:"aggregation"`

	// Correlation
	Correlation *CorrelationConfig `json:"correlation,omitempty" yaml:"correlation"`

	// State
	IsEnabled bool      `json:"is_enabled" yaml:"is_enabled"`
	Version   int       `json:"version" yaml:"version"`
	CreatedAt time.Time `json:"created_at" yaml:"-"`
	UpdatedAt time.Time `json:"updated_at" yaml:"-"`

	// Runtime stats
	ExecutionCount int64 `json:"execution_count,omitempty" yaml:"-"`
	MatchCount     int64 `json:"match_count,omitempty" yaml:"-"`
}

// LogSource defines the log source for Sigma rules.
type LogSource struct {
	Category   string `json:"category,omitempty" yaml:"category"`
	Product    string `json:"product,omitempty" yaml:"product"`
	Service    string `json:"service,omitempty" yaml:"service"`
	Definition string `json:"definition,omitempty" yaml:"definition"`
}

// Detection defines the detection logic for Sigma rules.
type Detection struct {
	Selection   map[string]interface{} `json:"selection,omitempty" yaml:"selection"`
	Filter      map[string]interface{} `json:"filter,omitempty" yaml:"filter"`
	Condition   string                 `json:"condition" yaml:"condition"`
	Timeframe   string                 `json:"timeframe,omitempty" yaml:"timeframe"`
}

// ParsedConditions represents parsed rule conditions.
type ParsedConditions struct {
	Conditions []*Condition `json:"conditions"`
	Logic      LogicType    `json:"logic"` // AND, OR
	Groups     []*ConditionGroup `json:"groups,omitempty"`
}

// LogicType represents the logical operator between conditions.
type LogicType string

const (
	LogicAnd LogicType = "and"
	LogicOr  LogicType = "or"
)

// ConditionGroup represents a group of conditions.
type ConditionGroup struct {
	Conditions []*Condition `json:"conditions"`
	Logic      LogicType    `json:"logic"`
	Negate     bool         `json:"negate,omitempty"`
}

// Condition represents a single detection condition.
type Condition struct {
	Field     string        `json:"field"`
	Operator  Operator      `json:"operator"`
	Value     interface{}   `json:"value,omitempty"`
	Values    []interface{} `json:"values,omitempty"`
	Required  bool          `json:"required"`
	CaseSensitive bool      `json:"case_sensitive,omitempty"`
}

// ThresholdConfig defines threshold-based detection.
type ThresholdConfig struct {
	Field     string        `json:"field"`
	GroupBy   []string      `json:"group_by,omitempty"`
	Threshold int           `json:"threshold"`
	TimeWindow time.Duration `json:"time_window"`
}

// AggregationConfig defines aggregation-based detection.
type AggregationConfig struct {
	Function   string        `json:"function"` // count, sum, avg, min, max, cardinality
	Field      string        `json:"field,omitempty"`
	GroupBy    []string      `json:"group_by,omitempty"`
	Condition  string        `json:"condition"` // >, <, >=, <=, ==, !=
	Value      float64       `json:"value"`
	TimeWindow time.Duration `json:"time_window"`
}

// CorrelationConfig defines correlation-based detection.
type CorrelationConfig struct {
	Type          string        `json:"type"` // event_count, unique_count, sequence
	GroupBy       []string      `json:"group_by,omitempty"`
	TimeWindow    time.Duration `json:"time_window"`
	OrderedBy     string        `json:"ordered_by,omitempty"`
	OrderDirection string       `json:"order_direction,omitempty"`

	// For event_count
	MinCount int `json:"min_count,omitempty"`
	MaxCount int `json:"max_count,omitempty"`

	// For unique_count
	DistinctField string `json:"distinct_field,omitempty"`
	MinDistinct   int    `json:"min_distinct,omitempty"`

	// For sequence detection
	Sequence []SequenceStep `json:"sequence,omitempty"`
}

// SequenceStep defines a step in sequence detection.
type SequenceStep struct {
	Name       string     `json:"name"`
	Conditions []*Condition `json:"conditions"`
	MaxSpan    time.Duration `json:"max_span,omitempty"` // Max time from previous step
}

// Validate validates the rule.
func (r *Rule) Validate() error {
	if r.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if r.Name == "" {
		return fmt.Errorf("rule name is required")
	}
	if r.Type == "" {
		return fmt.Errorf("rule type is required")
	}

	switch r.Type {
	case TypeSimple:
		if r.ParsedConditions == nil || len(r.ParsedConditions.Conditions) == 0 {
			return fmt.Errorf("simple rule must have conditions")
		}
	case TypeSigma:
		if r.Detection == nil {
			return fmt.Errorf("sigma rule must have detection section")
		}
	case TypeCorrelation:
		if r.Correlation == nil {
			return fmt.Errorf("correlation rule must have correlation config")
		}
	case TypeThreshold:
		if r.Threshold == nil {
			return fmt.Errorf("threshold rule must have threshold config")
		}
	}

	return nil
}

// NewRule creates a new rule with defaults.
func NewRule(id, name string, ruleType RuleType) *Rule {
	return &Rule{
		ID:        id,
		Name:      name,
		Type:      ruleType,
		Status:    StatusDraft,
		Severity:  string(SeverityMedium),
		IsEnabled: false,
		Version:   1,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// Clone creates a deep copy of the rule.
func (r *Rule) Clone() *Rule {
	clone := *r

	// Deep copy slices
	if r.MITRETactics != nil {
		clone.MITRETactics = make([]string, len(r.MITRETactics))
		copy(clone.MITRETactics, r.MITRETactics)
	}
	if r.MITRETechniques != nil {
		clone.MITRETechniques = make([]string, len(r.MITRETechniques))
		copy(clone.MITRETechniques, r.MITRETechniques)
	}
	if r.Tags != nil {
		clone.Tags = make([]string, len(r.Tags))
		copy(clone.Tags, r.Tags)
	}

	// Deep copy maps
	if r.Metadata != nil {
		clone.Metadata = make(map[string]string)
		for k, v := range r.Metadata {
			clone.Metadata[k] = v
		}
	}

	return &clone
}
