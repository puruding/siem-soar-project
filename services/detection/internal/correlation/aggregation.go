// Package correlation provides aggregation functions for correlation.
package correlation

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// AggregateFunction represents an aggregation function type.
type AggregateFunction string

const (
	FuncCount       AggregateFunction = "count"
	FuncSum         AggregateFunction = "sum"
	FuncAvg         AggregateFunction = "avg"
	FuncMin         AggregateFunction = "min"
	FuncMax         AggregateFunction = "max"
	FuncCardinality AggregateFunction = "cardinality" // Count distinct
	FuncStdDev      AggregateFunction = "stddev"
	FuncVariance    AggregateFunction = "variance"
	FuncPercentile  AggregateFunction = "percentile"
	FuncMedian      AggregateFunction = "median"
	FuncFirst       AggregateFunction = "first"
	FuncLast        AggregateFunction = "last"
)

// AggregateSpec defines an aggregation specification.
type AggregateSpec struct {
	Function   AggregateFunction `json:"function"`
	Field      string            `json:"field,omitempty"`
	Alias      string            `json:"alias,omitempty"`
	Percentile float64           `json:"percentile,omitempty"` // For percentile function
}

// Aggregator performs aggregations on event data.
type Aggregator struct {
	specs []AggregateSpec
}

// NewAggregator creates a new aggregator with the given specs.
func NewAggregator(specs []AggregateSpec) *Aggregator {
	return &Aggregator{
		specs: specs,
	}
}

// Aggregate computes aggregates for a slice of events.
func (a *Aggregator) Aggregate(events []map[string]interface{}) map[string]interface{} {
	results := make(map[string]interface{})

	for _, spec := range a.specs {
		name := spec.Alias
		if name == "" {
			name = fmt.Sprintf("%s_%s", spec.Function, spec.Field)
		}

		value := a.computeAggregate(spec, events)
		results[name] = value
	}

	return results
}

// AggregateGrouped computes aggregates for grouped events.
func (a *Aggregator) AggregateGrouped(groups map[string][]map[string]interface{}) map[string]map[string]interface{} {
	results := make(map[string]map[string]interface{})

	for groupKey, events := range groups {
		results[groupKey] = a.Aggregate(events)
	}

	return results
}

func (a *Aggregator) computeAggregate(spec AggregateSpec, events []map[string]interface{}) interface{} {
	switch spec.Function {
	case FuncCount:
		return len(events)

	case FuncCardinality:
		return a.cardinality(spec.Field, events)

	case FuncSum:
		return a.sum(spec.Field, events)

	case FuncAvg:
		return a.avg(spec.Field, events)

	case FuncMin:
		return a.min(spec.Field, events)

	case FuncMax:
		return a.max(spec.Field, events)

	case FuncStdDev:
		return a.stdDev(spec.Field, events)

	case FuncVariance:
		return a.variance(spec.Field, events)

	case FuncPercentile:
		return a.percentile(spec.Field, events, spec.Percentile)

	case FuncMedian:
		return a.percentile(spec.Field, events, 50.0)

	case FuncFirst:
		if len(events) > 0 {
			return getFieldValue(events[0], spec.Field)
		}
		return nil

	case FuncLast:
		if len(events) > 0 {
			return getFieldValue(events[len(events)-1], spec.Field)
		}
		return nil

	default:
		return nil
	}
}

func (a *Aggregator) cardinality(field string, events []map[string]interface{}) int {
	unique := make(map[string]bool)
	for _, event := range events {
		value := getFieldValue(event, field)
		if value != nil {
			unique[fmt.Sprintf("%v", value)] = true
		}
	}
	return len(unique)
}

func (a *Aggregator) sum(field string, events []map[string]interface{}) float64 {
	var sum float64
	for _, event := range events {
		value := getFieldValue(event, field)
		if num := toNumber(value); num != nil {
			sum += *num
		}
	}
	return sum
}

func (a *Aggregator) avg(field string, events []map[string]interface{}) float64 {
	var sum float64
	var count int
	for _, event := range events {
		value := getFieldValue(event, field)
		if num := toNumber(value); num != nil {
			sum += *num
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return sum / float64(count)
}

func (a *Aggregator) min(field string, events []map[string]interface{}) interface{} {
	var minVal *float64
	for _, event := range events {
		value := getFieldValue(event, field)
		if num := toNumber(value); num != nil {
			if minVal == nil || *num < *minVal {
				minVal = num
			}
		}
	}
	if minVal != nil {
		return *minVal
	}
	return nil
}

func (a *Aggregator) max(field string, events []map[string]interface{}) interface{} {
	var maxVal *float64
	for _, event := range events {
		value := getFieldValue(event, field)
		if num := toNumber(value); num != nil {
			if maxVal == nil || *num > *maxVal {
				maxVal = num
			}
		}
	}
	if maxVal != nil {
		return *maxVal
	}
	return nil
}

func (a *Aggregator) variance(field string, events []map[string]interface{}) float64 {
	values := a.extractNumbers(field, events)
	if len(values) == 0 {
		return 0
	}

	mean := a.avg(field, events)
	var sumSquares float64
	for _, v := range values {
		diff := v - mean
		sumSquares += diff * diff
	}
	return sumSquares / float64(len(values))
}

func (a *Aggregator) stdDev(field string, events []map[string]interface{}) float64 {
	return math.Sqrt(a.variance(field, events))
}

func (a *Aggregator) percentile(field string, events []map[string]interface{}, p float64) float64 {
	values := a.extractNumbers(field, events)
	if len(values) == 0 {
		return 0
	}

	sort.Float64s(values)
	n := len(values)

	// Linear interpolation
	k := (p / 100) * float64(n-1)
	f := math.Floor(k)
	c := math.Ceil(k)

	if f == c {
		return values[int(k)]
	}

	d0 := values[int(f)] * (c - k)
	d1 := values[int(c)] * (k - f)
	return d0 + d1
}

func (a *Aggregator) extractNumbers(field string, events []map[string]interface{}) []float64 {
	var values []float64
	for _, event := range events {
		value := getFieldValue(event, field)
		if num := toNumber(value); num != nil {
			values = append(values, *num)
		}
	}
	return values
}

func getFieldValue(event map[string]interface{}, field string) interface{} {
	parts := strings.Split(field, ".")
	var current interface{} = event

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = v[part]
			if !ok {
				return nil
			}
		default:
			return nil
		}
	}

	return current
}

func toNumber(value interface{}) *float64 {
	if value == nil {
		return nil
	}

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

// GroupBy groups events by specified fields.
func GroupBy(events []map[string]interface{}, fields []string) map[string][]map[string]interface{} {
	groups := make(map[string][]map[string]interface{})

	for _, event := range events {
		key := buildGroupKey(event, fields)
		groups[key] = append(groups[key], event)
	}

	return groups
}

func buildGroupKey(event map[string]interface{}, fields []string) string {
	var parts []string
	for _, field := range fields {
		value := getFieldValue(event, field)
		parts = append(parts, fmt.Sprintf("%v", value))
	}
	return strings.Join(parts, "|")
}

// ConditionEvaluator evaluates aggregate conditions.
type ConditionEvaluator struct{}

// NewConditionEvaluator creates a new condition evaluator.
func NewConditionEvaluator() *ConditionEvaluator {
	return &ConditionEvaluator{}
}

// Evaluate evaluates an aggregate condition.
func (e *ConditionEvaluator) Evaluate(operator string, value, threshold interface{}) bool {
	v := toNumber(value)
	t := toNumber(threshold)

	if v == nil || t == nil {
		return false
	}

	switch operator {
	case ">", "gt":
		return *v > *t
	case "<", "lt":
		return *v < *t
	case ">=", "gte":
		return *v >= *t
	case "<=", "lte":
		return *v <= *t
	case "==", "eq":
		return *v == *t
	case "!=", "ne":
		return *v != *t
	default:
		return false
	}
}
