// Package udm provides Google Chronicle's Unified Data Model (UDM) schema.
package udm

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// fieldPathRegex matches field paths with optional array indices.
// Examples: "principal.ip[0]", "network.dns.questions[0].name"
var fieldPathRegex = regexp.MustCompile(`^([a-z_][a-z0-9_]*)(?:\[(\d+)\])?$`)

// GetField retrieves a value from a UDMEvent using a dot-notation path.
// Supports array indexing with bracket notation.
//
// Examples:
//   - GetField(event, "principal.user.user_name") -> "john"
//   - GetField(event, "principal.ip[0]") -> "192.168.1.1"
//   - GetField(event, "network.dns.questions[0].name") -> "example.com"
//   - GetField(event, "metadata.event_type") -> "USER_LOGIN"
func GetField(event *UDMEvent, path string) (interface{}, error) {
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}
	if path == "" {
		return nil, fmt.Errorf("path is empty")
	}

	parts := splitPath(path)
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid path: %s", path)
	}

	return getFieldRecursive(reflect.ValueOf(event), parts, path)
}

// GetFieldOrDefault retrieves a value or returns the default if not found.
func GetFieldOrDefault(event *UDMEvent, path string, defaultValue interface{}) interface{} {
	value, err := GetField(event, path)
	if err != nil || value == nil {
		return defaultValue
	}
	return value
}

// GetFieldAsString retrieves a value as a string.
func GetFieldAsString(event *UDMEvent, path string) (string, error) {
	value, err := GetField(event, path)
	if err != nil {
		return "", err
	}
	if value == nil {
		return "", nil
	}
	return fmt.Sprintf("%v", value), nil
}

// GetFieldAsStringSlice retrieves a value as a string slice.
func GetFieldAsStringSlice(event *UDMEvent, path string) ([]string, error) {
	value, err := GetField(event, path)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return nil, nil
	}

	// Handle reflect.Value
	rv := reflect.ValueOf(value)
	if rv.Kind() == reflect.Slice {
		result := make([]string, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			result[i] = fmt.Sprintf("%v", rv.Index(i).Interface())
		}
		return result, nil
	}

	// Single value -> slice of one
	return []string{fmt.Sprintf("%v", value)}, nil
}

// GetFieldAsInt retrieves a value as an int64.
func GetFieldAsInt(event *UDMEvent, path string) (int64, error) {
	value, err := GetField(event, path)
	if err != nil {
		return 0, err
	}
	if value == nil {
		return 0, nil
	}

	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		return strconv.ParseInt(v, 10, 64)
	default:
		return 0, fmt.Errorf("cannot convert %T to int64", value)
	}
}

// HasField checks if a field exists and is non-nil.
func HasField(event *UDMEvent, path string) bool {
	value, err := GetField(event, path)
	return err == nil && value != nil && !isZeroValue(value)
}

// GetFields retrieves multiple fields at once.
// Returns a map of path -> value. Missing fields are omitted.
func GetFields(event *UDMEvent, paths ...string) map[string]interface{} {
	result := make(map[string]interface{})
	for _, path := range paths {
		value, err := GetField(event, path)
		if err == nil && value != nil {
			result[path] = value
		}
	}
	return result
}

// GetFieldPaths returns all non-nil field paths in the event.
// Useful for debugging and introspection.
func GetFieldPaths(event *UDMEvent) []string {
	if event == nil {
		return nil
	}

	var paths []string
	collectPaths(reflect.ValueOf(event), "", &paths)
	return paths
}

// splitPath splits a dot-notation path into parts.
func splitPath(path string) []pathPart {
	segments := strings.Split(path, ".")
	parts := make([]pathPart, 0, len(segments))

	for _, segment := range segments {
		match := fieldPathRegex.FindStringSubmatch(segment)
		if match == nil {
			// Invalid segment format, treat as plain field name
			parts = append(parts, pathPart{name: segment, index: -1})
			continue
		}

		name := match[1]
		index := -1
		if match[2] != "" {
			idx, err := strconv.Atoi(match[2])
			if err == nil {
				index = idx
			}
		}
		parts = append(parts, pathPart{name: name, index: index})
	}

	return parts
}

// pathPart represents a single part of a field path.
type pathPart struct {
	name  string
	index int // -1 if no index specified
}

// getFieldRecursive recursively navigates the struct to get the value.
func getFieldRecursive(v reflect.Value, parts []pathPart, fullPath string) (interface{}, error) {
	if len(parts) == 0 {
		return extractValue(v), nil
	}

	// Dereference pointers
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, nil
		}
		v = v.Elem()
	}

	part := parts[0]
	remaining := parts[1:]

	switch v.Kind() {
	case reflect.Struct:
		field := findField(v, part.name)
		if !field.IsValid() {
			return nil, fmt.Errorf("field %q not found in path %q", part.name, fullPath)
		}

		if part.index >= 0 {
			// Array access on this field
			return getArrayElement(field, part.index, remaining, fullPath)
		}

		return getFieldRecursive(field, remaining, fullPath)

	case reflect.Slice, reflect.Array:
		if part.index >= 0 {
			return getArrayElement(v, part.index, remaining, fullPath)
		}
		// If no index but we have a slice, try to access by field name
		// This shouldn't happen in normal usage
		return nil, fmt.Errorf("expected index for slice at %q", part.name)

	case reflect.Map:
		key := reflect.ValueOf(part.name)
		mapVal := v.MapIndex(key)
		if !mapVal.IsValid() {
			return nil, nil
		}
		return getFieldRecursive(mapVal, remaining, fullPath)

	default:
		return nil, fmt.Errorf("unexpected type %s at %q", v.Kind(), part.name)
	}
}

// getArrayElement gets an element from a slice/array and continues navigation.
func getArrayElement(v reflect.Value, index int, remaining []pathPart, fullPath string) (interface{}, error) {
	// Dereference pointers
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil, nil
		}
		v = v.Elem()
	}

	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return nil, fmt.Errorf("expected slice/array but got %s in path %q", v.Kind(), fullPath)
	}

	if index < 0 || index >= v.Len() {
		return nil, nil // Out of bounds returns nil
	}

	elem := v.Index(index)
	return getFieldRecursive(elem, remaining, fullPath)
}

// findField finds a struct field by name (case-insensitive, handles snake_case).
func findField(v reflect.Value, name string) reflect.Value {
	t := v.Type()

	// Try exact match first (case-insensitive)
	normalizedName := strings.ToLower(name)

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Check JSON tag
		jsonTag := field.Tag.Get("json")
		if jsonTag != "" {
			tagName := strings.Split(jsonTag, ",")[0]
			if strings.ToLower(tagName) == normalizedName {
				return v.Field(i)
			}
		}

		// Check field name (convert to snake_case for comparison)
		if toSnakeCase(field.Name) == normalizedName {
			return v.Field(i)
		}

		// Direct name match
		if strings.ToLower(field.Name) == normalizedName {
			return v.Field(i)
		}
	}

	return reflect.Value{}
}

// toSnakeCase converts CamelCase to snake_case.
func toSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteByte('_')
		}
		result.WriteRune(r)
	}
	return strings.ToLower(result.String())
}

// extractValue extracts the underlying value from a reflect.Value.
func extractValue(v reflect.Value) interface{} {
	// Dereference pointers
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}

	if !v.IsValid() {
		return nil
	}

	// Return the interface value
	return v.Interface()
}

// isZeroValue checks if a value is the zero value for its type.
func isZeroValue(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.IsZero()
}

// collectPaths recursively collects all non-nil field paths.
func collectPaths(v reflect.Value, prefix string, paths *[]string) {
	// Dereference pointers
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			fieldValue := v.Field(i)

			// Get JSON tag name or use snake_case field name
			name := toSnakeCase(field.Name)
			if jsonTag := field.Tag.Get("json"); jsonTag != "" {
				name = strings.Split(jsonTag, ",")[0]
			}

			path := name
			if prefix != "" {
				path = prefix + "." + name
			}

			collectPaths(fieldValue, path, paths)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			path := fmt.Sprintf("%s[%d]", prefix, i)
			collectPaths(v.Index(i), path, paths)
		}

	case reflect.Map:
		for _, key := range v.MapKeys() {
			path := key.String()
			if prefix != "" {
				path = prefix + "." + path
			}
			collectPaths(v.MapIndex(key), path, paths)
		}

	default:
		// Terminal value
		if prefix != "" && !v.IsZero() {
			*paths = append(*paths, prefix)
		}
	}
}

// ToMap converts a UDMEvent to a map[string]interface{} for compatibility
// with legacy code that uses map-based access.
func ToMap(event *UDMEvent) (map[string]interface{}, error) {
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}

	result := make(map[string]interface{})
	paths := GetFieldPaths(event)

	for _, path := range paths {
		value, err := GetField(event, path)
		if err == nil && value != nil {
			setNestedMapValue(result, path, value)
		}
	}

	return result, nil
}

// setNestedMapValue sets a value in a nested map structure.
func setNestedMapValue(m map[string]interface{}, path string, value interface{}) {
	parts := strings.Split(path, ".")
	current := m

	for i, part := range parts[:len(parts)-1] {
		// Handle array notation
		if idx := strings.Index(part, "["); idx > 0 {
			// Skip array elements for now - complex nested structure
			part = part[:idx]
		}

		if _, ok := current[part]; !ok {
			current[part] = make(map[string]interface{})
		}

		next, ok := current[part].(map[string]interface{})
		if !ok {
			// Can't navigate further
			return
		}
		current = next
		_ = i // Silence unused variable warning
	}

	lastPart := parts[len(parts)-1]
	if idx := strings.Index(lastPart, "["); idx > 0 {
		lastPart = lastPart[:idx]
	}
	current[lastPart] = value
}
