// Package udm implements Google Chronicle's Unified Data Model (UDM) schema.
package udm

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// FieldMapping defines how to map a source field to a UDM field.
type FieldMapping struct {
	SourceField  string            `json:"source_field" yaml:"source_field"`
	TargetField  string            `json:"target_field" yaml:"target_field"`
	Transform    string            `json:"transform,omitempty" yaml:"transform,omitempty"`
	Condition    string            `json:"condition,omitempty" yaml:"condition,omitempty"`
	DefaultValue interface{}       `json:"default_value,omitempty" yaml:"default_value,omitempty"`
	Required     bool              `json:"required,omitempty" yaml:"required,omitempty"`
	Multiple     bool              `json:"multiple,omitempty" yaml:"multiple,omitempty"`
	Parameters   map[string]string `json:"parameters,omitempty" yaml:"parameters,omitempty"`
}

// MappingConfig defines mappings for a specific source type.
type MappingConfig struct {
	Name           string         `json:"name" yaml:"name"`
	SourceType     string         `json:"source_type" yaml:"source_type"`
	VendorName     string         `json:"vendor_name" yaml:"vendor_name"`
	ProductName    string         `json:"product_name" yaml:"product_name"`
	EventTypeMappings map[string]EventType `json:"event_type_mappings" yaml:"event_type_mappings"`
	FieldMappings  []FieldMapping `json:"field_mappings" yaml:"field_mappings"`
	DefaultEventType EventType    `json:"default_event_type" yaml:"default_event_type"`
}

// Mapper handles field mapping from parsed events to UDM.
type Mapper struct {
	configs    map[string]*MappingConfig
	transforms map[string]TransformFunc
}

// TransformFunc is a function that transforms a value.
type TransformFunc func(value interface{}, params map[string]string) (interface{}, error)

// NewMapper creates a new mapper.
func NewMapper() *Mapper {
	m := &Mapper{
		configs:    make(map[string]*MappingConfig),
		transforms: make(map[string]TransformFunc),
	}

	// Register built-in transforms
	m.registerBuiltinTransforms()

	return m
}

// RegisterConfig registers a mapping configuration.
func (m *Mapper) RegisterConfig(cfg *MappingConfig) {
	m.configs[cfg.SourceType] = cfg
}

// RegisterTransform registers a custom transform function.
func (m *Mapper) RegisterTransform(name string, fn TransformFunc) {
	m.transforms[name] = fn
}

// Map maps parsed fields to UDM format.
func (m *Mapper) Map(sourceType string, fields map[string]interface{}) (*UDMEvent, error) {
	cfg, ok := m.configs[sourceType]
	if !ok {
		// Use default mapping
		return m.defaultMap(sourceType, fields)
	}

	event := &UDMEvent{
		Metadata: &Metadata{
			VendorName:   cfg.VendorName,
			ProductName:  cfg.ProductName,
			EventType:    cfg.DefaultEventType,
		},
	}

	// Apply field mappings
	for _, mapping := range cfg.FieldMappings {
		// Check condition
		if mapping.Condition != "" && !m.evaluateCondition(mapping.Condition, fields) {
			continue
		}

		// Get source value
		value := m.getFieldValue(mapping.SourceField, fields)
		if value == nil {
			if mapping.Required {
				return nil, fmt.Errorf("required field %s not found", mapping.SourceField)
			}
			if mapping.DefaultValue != nil {
				value = mapping.DefaultValue
			} else {
				continue
			}
		}

		// Apply transform
		if mapping.Transform != "" {
			transformed, err := m.applyTransform(mapping.Transform, value, mapping.Parameters)
			if err != nil {
				continue // Skip on transform error
			}
			value = transformed
		}

		// Set target field
		if err := m.setFieldValue(event, mapping.TargetField, value, mapping.Multiple); err != nil {
			continue
		}
	}

	// Determine event type from mappings
	if len(cfg.EventTypeMappings) > 0 {
		eventType := m.determineEventType(cfg.EventTypeMappings, fields)
		if eventType != "" {
			event.Metadata.EventType = eventType
		}
	}

	return event, nil
}

// defaultMap applies default mapping logic.
func (m *Mapper) defaultMap(sourceType string, fields map[string]interface{}) (*UDMEvent, error) {
	event := &UDMEvent{
		Metadata: &Metadata{
			VendorName:  "Unknown",
			ProductName: sourceType,
			EventType:   EventTypeGeneric,
		},
		Principal: &Entity{},
		Target:    &Entity{},
	}

	// Common field mappings
	commonMappings := map[string]string{
		// Source/Principal
		"src_ip":         "principal.ip",
		"source_ip":      "principal.ip",
		"source.ip":      "principal.ip",
		"src":            "principal.ip",
		"client_ip":      "principal.ip",
		"src_port":       "principal.port",
		"source_port":    "principal.port",
		"source.port":    "principal.port",
		"src_host":       "principal.hostname",
		"source_host":    "principal.hostname",
		"hostname":       "principal.hostname",
		"src_user":       "principal.user.user_name",
		"source_user":    "principal.user.user_name",
		"user":           "principal.user.user_name",
		"username":       "principal.user.user_name",
		"user_name":      "principal.user.user_name",

		// Target
		"dst_ip":         "target.ip",
		"dest_ip":        "target.ip",
		"destination_ip": "target.ip",
		"destination.ip": "target.ip",
		"dst":            "target.ip",
		"dst_port":       "target.port",
		"dest_port":      "target.port",
		"destination_port": "target.port",
		"dst_host":       "target.hostname",
		"dest_host":      "target.hostname",
		"dst_user":       "target.user.user_name",
		"dest_user":      "target.user.user_name",

		// Network
		"protocol":       "network.ip_protocol",
		"proto":          "network.ip_protocol",

		// Security
		"action":         "security_result.action",
		"severity":       "security_result.severity",
		"rule_name":      "security_result.rule_name",

		// Metadata
		"message":        "metadata.description",
		"msg":            "metadata.description",
	}

	for srcField, dstField := range commonMappings {
		if value := m.getFieldValue(srcField, fields); value != nil {
			m.setFieldValue(event, dstField, value, false)
		}
	}

	// Store remaining fields in additional_event_data
	event.AdditionalEventData = make(map[string]interface{})
	for k, v := range fields {
		event.AdditionalEventData[k] = v
	}

	return event, nil
}

// getFieldValue retrieves a field value using dot notation.
func (m *Mapper) getFieldValue(path string, fields map[string]interface{}) interface{} {
	parts := strings.Split(path, ".")
	current := interface{}(fields)

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		default:
			return nil
		}
		if current == nil {
			return nil
		}
	}

	return current
}

// setFieldValue sets a field value on the UDM event using dot notation.
func (m *Mapper) setFieldValue(event *UDMEvent, path string, value interface{}, multiple bool) error {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return fmt.Errorf("empty path")
	}

	// Navigate to parent and set final field
	current := reflect.ValueOf(event).Elem()

	for i, part := range parts[:len(parts)-1] {
		field := current.FieldByName(toCamelCase(part))
		if !field.IsValid() {
			return fmt.Errorf("field %s not found at %s", part, strings.Join(parts[:i+1], "."))
		}

		// Handle pointer fields
		if field.Kind() == reflect.Ptr {
			if field.IsNil() {
				// Create new instance
				field.Set(reflect.New(field.Type().Elem()))
			}
			current = field.Elem()
		} else {
			current = field
		}
	}

	// Set final field
	finalPart := parts[len(parts)-1]
	field := current.FieldByName(toCamelCase(finalPart))
	if !field.IsValid() {
		return fmt.Errorf("field %s not found", finalPart)
	}

	return setReflectValue(field, value, multiple)
}

// setReflectValue sets a reflect value handling type conversion.
func setReflectValue(field reflect.Value, value interface{}, multiple bool) error {
	if !field.CanSet() {
		return fmt.Errorf("cannot set field")
	}

	// Handle slices
	if field.Kind() == reflect.Slice {
		elemType := field.Type().Elem()
		var vals []interface{}

		if multiple {
			// Value should be slice or we convert single to slice
			switch v := value.(type) {
			case []interface{}:
				vals = v
			case []string:
				for _, s := range v {
					vals = append(vals, s)
				}
			default:
				vals = []interface{}{value}
			}
		} else {
			vals = []interface{}{value}
		}

		newSlice := reflect.MakeSlice(field.Type(), 0, len(vals))
		for _, v := range vals {
			elem := reflect.New(elemType).Elem()
			if err := setReflectValue(elem, v, false); err != nil {
				continue
			}
			newSlice = reflect.Append(newSlice, elem)
		}
		field.Set(newSlice)
		return nil
	}

	// Direct type handling
	switch field.Kind() {
	case reflect.String:
		field.SetString(fmt.Sprintf("%v", value))
	case reflect.Int, reflect.Int64:
		switch v := value.(type) {
		case int:
			field.SetInt(int64(v))
		case int64:
			field.SetInt(v)
		case float64:
			field.SetInt(int64(v))
		case string:
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				field.SetInt(n)
			}
		}
	case reflect.Float64:
		switch v := value.(type) {
		case float64:
			field.SetFloat(v)
		case int:
			field.SetFloat(float64(v))
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				field.SetFloat(f)
			}
		}
	case reflect.Bool:
		switch v := value.(type) {
		case bool:
			field.SetBool(v)
		case string:
			b, _ := strconv.ParseBool(v)
			field.SetBool(b)
		}
	case reflect.Struct:
		if field.Type() == reflect.TypeOf(time.Time{}) {
			if ts, ok := value.(time.Time); ok {
				field.Set(reflect.ValueOf(ts))
			} else if s, ok := value.(string); ok {
				if ts, err := time.Parse(time.RFC3339, s); err == nil {
					field.Set(reflect.ValueOf(ts))
				}
			}
		}
	case reflect.Ptr:
		if field.IsNil() {
			field.Set(reflect.New(field.Type().Elem()))
		}
		return setReflectValue(field.Elem(), value, multiple)
	}

	return nil
}

// applyTransform applies a transform to a value.
func (m *Mapper) applyTransform(name string, value interface{}, params map[string]string) (interface{}, error) {
	if fn, ok := m.transforms[name]; ok {
		return fn(value, params)
	}
	return nil, fmt.Errorf("unknown transform: %s", name)
}

// evaluateCondition evaluates a simple condition.
func (m *Mapper) evaluateCondition(condition string, fields map[string]interface{}) bool {
	// Simple conditions: field==value, field!=value, field exists
	if strings.Contains(condition, "==") {
		parts := strings.SplitN(condition, "==", 2)
		if len(parts) == 2 {
			value := m.getFieldValue(strings.TrimSpace(parts[0]), fields)
			expected := strings.TrimSpace(parts[1])
			return fmt.Sprintf("%v", value) == expected
		}
	}
	if strings.Contains(condition, "!=") {
		parts := strings.SplitN(condition, "!=", 2)
		if len(parts) == 2 {
			value := m.getFieldValue(strings.TrimSpace(parts[0]), fields)
			expected := strings.TrimSpace(parts[1])
			return fmt.Sprintf("%v", value) != expected
		}
	}
	// Check field exists
	return m.getFieldValue(condition, fields) != nil
}

// determineEventType determines event type from field values.
func (m *Mapper) determineEventType(mappings map[string]EventType, fields map[string]interface{}) EventType {
	for condition, eventType := range mappings {
		if m.evaluateCondition(condition, fields) {
			return eventType
		}
	}
	return ""
}

// registerBuiltinTransforms registers built-in transform functions.
func (m *Mapper) registerBuiltinTransforms() {
	// String transforms
	m.transforms["uppercase"] = func(value interface{}, _ map[string]string) (interface{}, error) {
		return strings.ToUpper(fmt.Sprintf("%v", value)), nil
	}
	m.transforms["lowercase"] = func(value interface{}, _ map[string]string) (interface{}, error) {
		return strings.ToLower(fmt.Sprintf("%v", value)), nil
	}
	m.transforms["trim"] = func(value interface{}, _ map[string]string) (interface{}, error) {
		return strings.TrimSpace(fmt.Sprintf("%v", value)), nil
	}

	// Type transforms
	m.transforms["to_int"] = func(value interface{}, _ map[string]string) (interface{}, error) {
		switch v := value.(type) {
		case int:
			return v, nil
		case int64:
			return int(v), nil
		case float64:
			return int(v), nil
		case string:
			return strconv.Atoi(v)
		}
		return 0, fmt.Errorf("cannot convert to int")
	}

	m.transforms["to_timestamp"] = func(value interface{}, params map[string]string) (interface{}, error) {
		format := params["format"]
		if format == "" {
			format = time.RFC3339
		}
		switch v := value.(type) {
		case time.Time:
			return v, nil
		case string:
			return time.Parse(format, v)
		case float64:
			if v > 1e12 {
				return time.UnixMilli(int64(v)), nil
			}
			return time.Unix(int64(v), 0), nil
		}
		return time.Time{}, fmt.Errorf("cannot convert to timestamp")
	}

	// Split transform
	m.transforms["split"] = func(value interface{}, params map[string]string) (interface{}, error) {
		sep := params["separator"]
		if sep == "" {
			sep = ","
		}
		return strings.Split(fmt.Sprintf("%v", value), sep), nil
	}

	// Regex extract
	m.transforms["regex_extract"] = func(value interface{}, params map[string]string) (interface{}, error) {
		pattern := params["pattern"]
		if pattern == "" {
			return value, nil
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, err
		}
		matches := re.FindStringSubmatch(fmt.Sprintf("%v", value))
		if len(matches) > 1 {
			return matches[1], nil
		}
		return value, nil
	}

	// Map values
	m.transforms["map_value"] = func(value interface{}, params map[string]string) (interface{}, error) {
		key := fmt.Sprintf("%v", value)
		if mapped, ok := params[key]; ok {
			return mapped, nil
		}
		if def, ok := params["default"]; ok {
			return def, nil
		}
		return value, nil
	}
}

// toCamelCase converts snake_case or kebab-case to CamelCase.
func toCamelCase(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for i, part := range parts {
		if len(part) > 0 {
			parts[i] = strings.ToUpper(part[:1]) + part[1:]
		}
	}
	return strings.Join(parts, "")
}
