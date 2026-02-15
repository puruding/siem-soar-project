// Package rule provides detection rule models and validation.
package rule

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationError represents a rule validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult holds validation results.
type ValidationResult struct {
	Valid    bool               `json:"valid"`
	Errors   []ValidationError  `json:"errors,omitempty"`
	Warnings []ValidationError  `json:"warnings,omitempty"`
}

// ValidatorConfig holds validator configuration.
type ValidatorConfig struct {
	AllowUnknownFields      bool
	RequireMITREMapping     bool
	RequireDescription      bool
	MaxConditions           int
	AllowedSeverities       []string
	AllowedRuleTypes        []RuleType
	RegexTimeout            int // milliseconds
}

// DefaultValidatorConfig returns default validator configuration.
func DefaultValidatorConfig() ValidatorConfig {
	return ValidatorConfig{
		AllowUnknownFields:  false,
		RequireMITREMapping: false,
		RequireDescription:  true,
		MaxConditions:       100,
		AllowedSeverities: []string{
			string(SeverityCritical),
			string(SeverityHigh),
			string(SeverityMedium),
			string(SeverityLow),
			string(SeverityInfo),
		},
		AllowedRuleTypes: []RuleType{
			TypeSimple,
			TypeSigma,
			TypeCorrelation,
			TypeThreshold,
			TypeSequence,
		},
		RegexTimeout: 100,
	}
}

// Validator validates detection rules.
type Validator struct {
	config ValidatorConfig
}

// NewValidator creates a new validator with default config.
func NewValidator() *Validator {
	return &Validator{
		config: DefaultValidatorConfig(),
	}
}

// NewValidatorWithConfig creates a new validator with custom config.
func NewValidatorWithConfig(cfg ValidatorConfig) *Validator {
	return &Validator{
		config: cfg,
	}
}

// Validate validates a rule.
func (v *Validator) Validate(r *Rule) error {
	result := v.ValidateWithResult(r)
	if !result.Valid {
		messages := make([]string, len(result.Errors))
		for i, e := range result.Errors {
			messages[i] = e.Error()
		}
		return fmt.Errorf("validation failed: %s", strings.Join(messages, "; "))
	}
	return nil
}

// ValidateWithResult validates a rule and returns detailed results.
func (v *Validator) ValidateWithResult(r *Rule) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationError{},
	}

	// Required fields
	v.validateRequired(r, result)

	// Rule type specific validation
	v.validateByType(r, result)

	// Conditions validation
	v.validateConditions(r, result)

	// Severity validation
	v.validateSeverity(r, result)

	// MITRE mapping
	v.validateMITRE(r, result)

	// Description
	v.validateDescription(r, result)

	// Regex patterns
	v.validateRegexPatterns(r, result)

	result.Valid = len(result.Errors) == 0
	return result
}

func (v *Validator) validateRequired(r *Rule, result *ValidationResult) {
	if r.ID == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "id",
			Message: "rule ID is required",
		})
	}

	if r.Name == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "name",
			Message: "rule name is required",
		})
	}

	if r.Type == "" {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "type",
			Message: "rule type is required",
		})
	} else {
		// Check if type is allowed
		allowed := false
		for _, t := range v.config.AllowedRuleTypes {
			if r.Type == t {
				allowed = true
				break
			}
		}
		if !allowed {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "type",
				Message: fmt.Sprintf("rule type '%s' is not allowed", r.Type),
			})
		}
	}
}

func (v *Validator) validateByType(r *Rule, result *ValidationResult) {
	switch r.Type {
	case TypeSimple:
		if r.ParsedConditions == nil || len(r.ParsedConditions.Conditions) == 0 {
			if r.Detection == nil || len(r.Detection.Selection) == 0 {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "conditions",
					Message: "simple rule must have at least one condition",
				})
			}
		}

	case TypeSigma:
		if r.Detection == nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "detection",
				Message: "sigma rule must have a detection section",
			})
		} else {
			if r.Detection.Condition == "" {
				result.Warnings = append(result.Warnings, ValidationError{
					Field:   "detection.condition",
					Message: "detection condition is empty, using default 'selection'",
				})
			}
		}

		if r.LogSource == nil {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   "logsource",
				Message: "sigma rule should have a logsource section",
			})
		}

	case TypeCorrelation:
		if r.Correlation == nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "correlation",
				Message: "correlation rule must have correlation configuration",
			})
		} else {
			if r.Correlation.TimeWindow <= 0 {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "correlation.time_window",
					Message: "correlation rule must have a positive time window",
				})
			}
		}

	case TypeThreshold:
		if r.Threshold == nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "threshold",
				Message: "threshold rule must have threshold configuration",
			})
		} else {
			if r.Threshold.Threshold <= 0 {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "threshold.threshold",
					Message: "threshold must be a positive number",
				})
			}
			if r.Threshold.TimeWindow <= 0 {
				result.Errors = append(result.Errors, ValidationError{
					Field:   "threshold.time_window",
					Message: "time window must be positive",
				})
			}
		}

	case TypeSequence:
		if r.Correlation == nil || len(r.Correlation.Sequence) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   "correlation.sequence",
				Message: "sequence rule must have at least one sequence step",
			})
		}
	}
}

func (v *Validator) validateConditions(r *Rule, result *ValidationResult) {
	if r.ParsedConditions == nil {
		return
	}

	if len(r.ParsedConditions.Conditions) > v.config.MaxConditions {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "conditions",
			Message: fmt.Sprintf("rule has too many conditions (%d > %d)", len(r.ParsedConditions.Conditions), v.config.MaxConditions),
		})
	}

	for i, cond := range r.ParsedConditions.Conditions {
		if cond.Field == "" {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].field", i),
				Message: "condition field is required",
			})
		}

		// Validate operator
		if !isValidOperator(cond.Operator) {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].operator", i),
				Message: fmt.Sprintf("invalid operator: %s", cond.Operator),
			})
		}

		// Validate value presence for operators that require it
		if requiresValue(cond.Operator) && cond.Value == nil && len(cond.Values) == 0 {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].value", i),
				Message: "condition value is required for this operator",
			})
		}
	}
}

func (v *Validator) validateSeverity(r *Rule, result *ValidationResult) {
	if r.Severity == "" {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "severity",
			Message: "severity is not set, defaulting to medium",
		})
		return
	}

	valid := false
	for _, s := range v.config.AllowedSeverities {
		if strings.EqualFold(r.Severity, s) {
			valid = true
			break
		}
	}

	if !valid {
		result.Errors = append(result.Errors, ValidationError{
			Field:   "severity",
			Message: fmt.Sprintf("invalid severity '%s', allowed: %v", r.Severity, v.config.AllowedSeverities),
		})
	}
}

func (v *Validator) validateMITRE(r *Rule, result *ValidationResult) {
	if !v.config.RequireMITREMapping {
		return
	}

	if len(r.MITRETactics) == 0 && len(r.MITRETechniques) == 0 {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "mitre",
			Message: "rule should have MITRE ATT&CK mapping",
		})
	}

	// Validate technique format (e.g., T1055, T1055.001)
	techniquePattern := regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
	for _, tech := range r.MITRETechniques {
		if !techniquePattern.MatchString(tech) {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   "mitre_techniques",
				Message: fmt.Sprintf("invalid MITRE technique format: %s", tech),
			})
		}
	}
}

func (v *Validator) validateDescription(r *Rule, result *ValidationResult) {
	if !v.config.RequireDescription {
		return
	}

	if r.Description == "" {
		result.Warnings = append(result.Warnings, ValidationError{
			Field:   "description",
			Message: "rule should have a description",
		})
	}
}

func (v *Validator) validateRegexPatterns(r *Rule, result *ValidationResult) {
	if r.ParsedConditions == nil {
		return
	}

	for i, cond := range r.ParsedConditions.Conditions {
		if cond.Operator != OpRegex {
			continue
		}

		pattern, ok := cond.Value.(string)
		if !ok {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].value", i),
				Message: "regex pattern must be a string",
			})
			continue
		}

		// Validate regex syntax
		_, err := regexp.Compile(pattern)
		if err != nil {
			result.Errors = append(result.Errors, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].value", i),
				Message: fmt.Sprintf("invalid regex pattern: %s", err.Error()),
			})
		}

		// Check for potentially dangerous patterns
		if isExpensiveRegex(pattern) {
			result.Warnings = append(result.Warnings, ValidationError{
				Field:   fmt.Sprintf("conditions[%d].value", i),
				Message: "regex pattern may be expensive to execute",
			})
		}
	}
}

func isValidOperator(op Operator) bool {
	switch op {
	case OpEquals, OpNotEquals, OpContains, OpNotContains,
		OpStartsWith, OpEndsWith, OpRegex, OpIn, OpNotIn,
		OpGreaterThan, OpLessThan, OpGreaterOrEqual, OpLessOrEqual,
		OpExists, OpNotExists, OpCIDR:
		return true
	default:
		return false
	}
}

func requiresValue(op Operator) bool {
	switch op {
	case OpExists, OpNotExists:
		return false
	default:
		return true
	}
}

func isExpensiveRegex(pattern string) bool {
	// Check for patterns that could be expensive
	// - Catastrophic backtracking patterns
	// - Excessive wildcards
	if strings.Contains(pattern, ".*.*") {
		return true
	}
	if strings.Count(pattern, ".*") > 3 {
		return true
	}
	if strings.Contains(pattern, "(.+)+") || strings.Contains(pattern, "(.*)*") {
		return true
	}
	return false
}
