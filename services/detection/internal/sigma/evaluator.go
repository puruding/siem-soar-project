// Package sigma provides Sigma rule parsing and evaluation.
package sigma

import (
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Evaluator evaluates Sigma conditions against events.
type Evaluator struct {
	fieldMapping  map[string]string
	patternCache  map[string]*regexp.Regexp
}

// EvaluationResult represents the result of an evaluation.
type EvaluationResult struct {
	Matched       bool                   `json:"matched"`
	MatchedFields map[string]interface{} `json:"matched_fields,omitempty"`
	Score         float64                `json:"score,omitempty"`
	Details       string                 `json:"details,omitempty"`
}

// NewEvaluator creates a new Sigma evaluator.
func NewEvaluator() *Evaluator {
	return &Evaluator{
		fieldMapping: DefaultFieldMapping(),
		patternCache: make(map[string]*regexp.Regexp),
	}
}

// NewEvaluatorWithMapping creates an evaluator with custom field mapping.
func NewEvaluatorWithMapping(mapping map[string]string) *Evaluator {
	return &Evaluator{
		fieldMapping: mapping,
		patternCache: make(map[string]*regexp.Regexp),
	}
}

// Evaluate evaluates a converted rule against an event.
func (e *Evaluator) Evaluate(rule *InternalRule, event map[string]interface{}) *EvaluationResult {
	result := &EvaluationResult{
		Matched:       false,
		MatchedFields: make(map[string]interface{}),
	}

	if len(rule.Conditions) == 0 {
		return result
	}

	var matches []bool
	for _, cond := range rule.Conditions {
		matched := e.evaluateCondition(&cond, event)
		matches = append(matches, matched)

		if matched {
			value, _ := e.getFieldValue(cond.Field, event)
			result.MatchedFields[cond.Field] = value
		}
	}

	// Determine overall match based on logic
	switch rule.Logic {
	case "and":
		result.Matched = allTrue(matches)
	case "or":
		result.Matched = anyTrue(matches)
	default:
		result.Matched = allTrue(matches)
	}

	if result.Matched {
		result.Score = float64(countTrue(matches)) / float64(len(matches))
	}

	return result
}

// EvaluateSigmaYAML evaluates raw Sigma YAML against an event.
func (e *Evaluator) EvaluateSigmaYAML(content string, event map[string]interface{}) (*EvaluationResult, error) {
	converter := NewConverterWithMapping(e.fieldMapping)
	rule, err := converter.ConvertYAML(content)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sigma rule: %w", err)
	}
	return e.Evaluate(rule, event), nil
}

func (e *Evaluator) evaluateCondition(cond *InternalCondition, event map[string]interface{}) bool {
	value, found := e.getFieldValue(cond.Field, event)
	if !found {
		// Field not found - condition doesn't match (unless it's a negated condition)
		return cond.Negate
	}

	var matched bool

	switch cond.Operator {
	case "eq":
		matched = e.equals(value, cond.Value, cond.Modifier)
	case "contains":
		matched = e.contains(value, cond.Value, cond.Modifier)
	case "startswith":
		matched = e.startsWith(value, cond.Value, cond.Modifier)
	case "endswith":
		matched = e.endsWith(value, cond.Value, cond.Modifier)
	case "regex":
		matched = e.matchesRegex(value, cond.Value)
	case "in":
		matched = e.inValues(value, cond.Values, cond.Modifier)
	case "cidr":
		matched = e.inCIDR(value, cond.Value)
	case "gt":
		matched = e.greaterThan(value, cond.Value)
	case "lt":
		matched = e.lessThan(value, cond.Value)
	case "gte":
		matched = e.greaterOrEqual(value, cond.Value)
	case "lte":
		matched = e.lessOrEqual(value, cond.Value)
	default:
		matched = e.equals(value, cond.Value, cond.Modifier)
	}

	if cond.Negate {
		return !matched
	}
	return matched
}

func (e *Evaluator) getFieldValue(field string, event map[string]interface{}) (interface{}, bool) {
	// Support nested fields with dot notation
	parts := strings.Split(field, ".")

	var current interface{} = event
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil, false
			}
		default:
			return nil, false
		}
	}

	return current, true
}

func (e *Evaluator) equals(value, expected interface{}, modifier string) bool {
	// Apply modifier transformations
	value = e.applyModifier(value, modifier)
	expected = e.applyModifier(expected, modifier)

	// String comparison (case-insensitive)
	if vs, ok := value.(string); ok {
		if es, ok := expected.(string); ok {
			return strings.EqualFold(vs, es)
		}
	}

	return value == expected
}

func (e *Evaluator) contains(value, substr interface{}, modifier string) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := substr.(string)
	if !ok {
		return false
	}

	vs = e.applyModifier(vs, modifier).(string)
	ss = e.applyModifier(ss, modifier).(string)

	return strings.Contains(strings.ToLower(vs), strings.ToLower(ss))
}

func (e *Evaluator) startsWith(value, prefix interface{}, modifier string) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ps, ok := prefix.(string)
	if !ok {
		return false
	}

	vs = e.applyModifier(vs, modifier).(string)
	ps = e.applyModifier(ps, modifier).(string)

	return strings.HasPrefix(strings.ToLower(vs), strings.ToLower(ps))
}

func (e *Evaluator) endsWith(value, suffix interface{}, modifier string) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ss, ok := suffix.(string)
	if !ok {
		return false
	}

	vs = e.applyModifier(vs, modifier).(string)
	ss = e.applyModifier(ss, modifier).(string)

	return strings.HasSuffix(strings.ToLower(vs), strings.ToLower(ss))
}

func (e *Evaluator) matchesRegex(value, pattern interface{}) bool {
	vs, ok := value.(string)
	if !ok {
		return false
	}
	ps, ok := pattern.(string)
	if !ok {
		return false
	}

	// Check cache
	re, ok := e.patternCache[ps]
	if !ok {
		var err error
		re, err = regexp.Compile("(?i)" + ps)
		if err != nil {
			return false
		}
		e.patternCache[ps] = re
	}

	return re.MatchString(vs)
}

func (e *Evaluator) inValues(value interface{}, values []interface{}, modifier string) bool {
	for _, v := range values {
		if e.equals(value, v, modifier) {
			return true
		}
	}
	return false
}

func (e *Evaluator) inCIDR(value, cidr interface{}) bool {
	ip, ok := value.(string)
	if !ok {
		return false
	}

	cidrStr, ok := cidr.(string)
	if !ok {
		return false
	}

	_, network, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return network.Contains(parsedIP)
}

func (e *Evaluator) greaterThan(value, threshold interface{}) bool {
	v, t := e.toFloat64(value), e.toFloat64(threshold)
	if v == nil || t == nil {
		return false
	}
	return *v > *t
}

func (e *Evaluator) lessThan(value, threshold interface{}) bool {
	v, t := e.toFloat64(value), e.toFloat64(threshold)
	if v == nil || t == nil {
		return false
	}
	return *v < *t
}

func (e *Evaluator) greaterOrEqual(value, threshold interface{}) bool {
	v, t := e.toFloat64(value), e.toFloat64(threshold)
	if v == nil || t == nil {
		return false
	}
	return *v >= *t
}

func (e *Evaluator) lessOrEqual(value, threshold interface{}) bool {
	v, t := e.toFloat64(value), e.toFloat64(threshold)
	if v == nil || t == nil {
		return false
	}
	return *v <= *t
}

func (e *Evaluator) applyModifier(value interface{}, modifier string) interface{} {
	if modifier == "" {
		return value
	}

	s, ok := value.(string)
	if !ok {
		return value
	}

	switch modifier {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err == nil {
			return string(decoded)
		}
	case "base64offset":
		// Try different offsets for base64 matching
		for offset := 0; offset <= 2; offset++ {
			if offset > 0 {
				s = s[offset:]
			}
			decoded, err := base64.StdEncoding.DecodeString(s)
			if err == nil {
				return string(decoded)
			}
		}
	case "wide":
		// Convert to wide string format (UTF-16LE like encoding)
		return toWideString(s)
	}

	return value
}

func (e *Evaluator) toFloat64(value interface{}) *float64 {
	var result float64

	switch v := value.(type) {
	case float64:
		result = v
	case float32:
		result = float64(v)
	case int:
		result = float64(v)
	case int64:
		result = float64(v)
	case int32:
		result = float64(v)
	case string:
		var err error
		result, err = strconv.ParseFloat(v, 64)
		if err != nil {
			return nil
		}
	default:
		return nil
	}

	return &result
}

func allTrue(matches []bool) bool {
	for _, m := range matches {
		if !m {
			return false
		}
	}
	return true
}

func anyTrue(matches []bool) bool {
	for _, m := range matches {
		if m {
			return true
		}
	}
	return false
}

func countTrue(matches []bool) int {
	count := 0
	for _, m := range matches {
		if m {
			count++
		}
	}
	return count
}

func toWideString(s string) string {
	var result strings.Builder
	for _, c := range s {
		result.WriteByte(byte(c))
		result.WriteByte(0)
	}
	return result.String()
}
