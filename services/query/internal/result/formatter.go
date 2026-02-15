// Package result provides query result formatting and pagination.
package result

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// Format represents an output format.
type Format string

const (
	FormatJSON    Format = "json"
	FormatCSV     Format = "csv"
	FormatTable   Format = "table"
	FormatNDJSON  Format = "ndjson" // Newline-delimited JSON
	FormatArrow   Format = "arrow"
	FormatParquet Format = "parquet"
)

// FormatterConfig holds formatter configuration.
type FormatterConfig struct {
	Format           Format            `json:"format"`
	IncludeMetadata  bool              `json:"include_metadata"`
	IncludeColumns   bool              `json:"include_columns"`
	DateFormat       string            `json:"date_format"`
	NullValue        string            `json:"null_value"`
	BoolFormat       string            `json:"bool_format"` // "true/false", "1/0", "yes/no"
	FloatPrecision   int               `json:"float_precision"`
	FieldMapping     map[string]string `json:"field_mapping,omitempty"`
	ExcludeFields    []string          `json:"exclude_fields,omitempty"`
	IncludeFields    []string          `json:"include_fields,omitempty"`
	MaxFieldLength   int               `json:"max_field_length"`
	EscapeHTML       bool              `json:"escape_html"`
	PrettyPrint      bool              `json:"pretty_print"`
}

// DefaultFormatterConfig returns default formatter configuration.
func DefaultFormatterConfig() FormatterConfig {
	return FormatterConfig{
		Format:          FormatJSON,
		IncludeMetadata: true,
		IncludeColumns:  true,
		DateFormat:      time.RFC3339,
		NullValue:       "null",
		BoolFormat:      "true/false",
		FloatPrecision:  6,
		MaxFieldLength:  10000,
		EscapeHTML:      true,
		PrettyPrint:     false,
	}
}

// QueryResult represents a query result to be formatted.
type QueryResult struct {
	Rows         []map[string]interface{} `json:"rows"`
	Columns      []ColumnInfo             `json:"columns"`
	RowCount     int64                    `json:"row_count"`
	TotalCount   int64                    `json:"total_count"`
	ExecutionMS  int64                    `json:"execution_ms"`
	Metadata     map[string]interface{}   `json:"metadata,omitempty"`
}

// ColumnInfo represents column metadata.
type ColumnInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
}

// FormattedResult represents a formatted result.
type FormattedResult struct {
	Format      Format      `json:"format"`
	ContentType string      `json:"content_type"`
	Data        interface{} `json:"data"`
	Size        int64       `json:"size"`
}

// Formatter formats query results.
type Formatter struct {
	config FormatterConfig
}

// NewFormatter creates a new result formatter.
func NewFormatter(config FormatterConfig) *Formatter {
	return &Formatter{config: config}
}

// Format formats a query result.
func (f *Formatter) Format(result *QueryResult) (*FormattedResult, error) {
	switch f.config.Format {
	case FormatJSON:
		return f.formatJSON(result)
	case FormatCSV:
		return f.formatCSV(result)
	case FormatTable:
		return f.formatTable(result)
	case FormatNDJSON:
		return f.formatNDJSON(result)
	default:
		return f.formatJSON(result)
	}
}

// FormatTo formats and writes to a writer.
func (f *Formatter) FormatTo(result *QueryResult, w io.Writer) error {
	switch f.config.Format {
	case FormatJSON:
		return f.writeJSON(result, w)
	case FormatCSV:
		return f.writeCSV(result, w)
	case FormatNDJSON:
		return f.writeNDJSON(result, w)
	default:
		return f.writeJSON(result, w)
	}
}

// formatJSON formats result as JSON.
func (f *Formatter) formatJSON(result *QueryResult) (*FormattedResult, error) {
	// Apply transformations
	transformed := f.transformRows(result.Rows)

	output := make(map[string]interface{})

	if f.config.IncludeMetadata {
		output["metadata"] = map[string]interface{}{
			"row_count":    result.RowCount,
			"total_count":  result.TotalCount,
			"execution_ms": result.ExecutionMS,
		}
		if result.Metadata != nil {
			for k, v := range result.Metadata {
				output["metadata"].(map[string]interface{})[k] = v
			}
		}
	}

	if f.config.IncludeColumns {
		output["columns"] = result.Columns
	}

	output["data"] = transformed

	var data []byte
	var err error
	if f.config.PrettyPrint {
		data, err = json.MarshalIndent(output, "", "  ")
	} else {
		data, err = json.Marshal(output)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return &FormattedResult{
		Format:      FormatJSON,
		ContentType: "application/json",
		Data:        string(data),
		Size:        int64(len(data)),
	}, nil
}

// formatCSV formats result as CSV.
func (f *Formatter) formatCSV(result *QueryResult) (*FormattedResult, error) {
	var sb strings.Builder
	if err := f.writeCSV(result, &sb); err != nil {
		return nil, err
	}

	data := sb.String()
	return &FormattedResult{
		Format:      FormatCSV,
		ContentType: "text/csv",
		Data:        data,
		Size:        int64(len(data)),
	}, nil
}

// formatTable formats result as ASCII table.
func (f *Formatter) formatTable(result *QueryResult) (*FormattedResult, error) {
	if len(result.Rows) == 0 {
		return &FormattedResult{
			Format:      FormatTable,
			ContentType: "text/plain",
			Data:        "(empty result)",
			Size:        14,
		}, nil
	}

	// Get column names
	var columns []string
	if len(result.Columns) > 0 {
		for _, col := range result.Columns {
			columns = append(columns, col.Name)
		}
	} else if len(result.Rows) > 0 {
		for key := range result.Rows[0] {
			columns = append(columns, key)
		}
	}

	// Calculate column widths
	widths := make(map[string]int)
	for _, col := range columns {
		widths[col] = len(col)
	}
	for _, row := range result.Rows {
		for _, col := range columns {
			val := f.formatValue(row[col])
			if len(val) > widths[col] {
				widths[col] = len(val)
			}
		}
	}

	// Cap widths
	maxWidth := 50
	for col := range widths {
		if widths[col] > maxWidth {
			widths[col] = maxWidth
		}
	}

	var sb strings.Builder

	// Header separator
	sb.WriteString("+")
	for _, col := range columns {
		sb.WriteString(strings.Repeat("-", widths[col]+2))
		sb.WriteString("+")
	}
	sb.WriteString("\n")

	// Header
	sb.WriteString("|")
	for _, col := range columns {
		sb.WriteString(" ")
		sb.WriteString(f.padRight(col, widths[col]))
		sb.WriteString(" |")
	}
	sb.WriteString("\n")

	// Header separator
	sb.WriteString("+")
	for _, col := range columns {
		sb.WriteString(strings.Repeat("-", widths[col]+2))
		sb.WriteString("+")
	}
	sb.WriteString("\n")

	// Rows
	for _, row := range result.Rows {
		sb.WriteString("|")
		for _, col := range columns {
			val := f.formatValue(row[col])
			if len(val) > widths[col] {
				val = val[:widths[col]-3] + "..."
			}
			sb.WriteString(" ")
			sb.WriteString(f.padRight(val, widths[col]))
			sb.WriteString(" |")
		}
		sb.WriteString("\n")
	}

	// Footer separator
	sb.WriteString("+")
	for _, col := range columns {
		sb.WriteString(strings.Repeat("-", widths[col]+2))
		sb.WriteString("+")
	}
	sb.WriteString("\n")

	// Row count
	sb.WriteString(fmt.Sprintf("(%d rows)\n", len(result.Rows)))

	data := sb.String()
	return &FormattedResult{
		Format:      FormatTable,
		ContentType: "text/plain",
		Data:        data,
		Size:        int64(len(data)),
	}, nil
}

// formatNDJSON formats result as newline-delimited JSON.
func (f *Formatter) formatNDJSON(result *QueryResult) (*FormattedResult, error) {
	var sb strings.Builder
	if err := f.writeNDJSON(result, &sb); err != nil {
		return nil, err
	}

	data := sb.String()
	return &FormattedResult{
		Format:      FormatNDJSON,
		ContentType: "application/x-ndjson",
		Data:        data,
		Size:        int64(len(data)),
	}, nil
}

// writeJSON writes JSON to a writer.
func (f *Formatter) writeJSON(result *QueryResult, w io.Writer) error {
	formatted, err := f.formatJSON(result)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, formatted.Data.(string))
	return err
}

// writeCSV writes CSV to a writer.
func (f *Formatter) writeCSV(result *QueryResult, w io.Writer) error {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Get column names
	var columns []string
	if len(result.Columns) > 0 {
		for _, col := range result.Columns {
			columns = append(columns, col.Name)
		}
	} else if len(result.Rows) > 0 {
		for key := range result.Rows[0] {
			columns = append(columns, key)
		}
	}

	// Apply field filtering
	columns = f.filterColumns(columns)

	// Write header
	if f.config.IncludeColumns {
		mappedColumns := make([]string, len(columns))
		for i, col := range columns {
			if mapped, ok := f.config.FieldMapping[col]; ok {
				mappedColumns[i] = mapped
			} else {
				mappedColumns[i] = col
			}
		}
		if err := writer.Write(mappedColumns); err != nil {
			return fmt.Errorf("failed to write CSV header: %w", err)
		}
	}

	// Write rows
	for _, row := range result.Rows {
		record := make([]string, len(columns))
		for i, col := range columns {
			record[i] = f.formatValue(row[col])
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

// writeNDJSON writes newline-delimited JSON to a writer.
func (f *Formatter) writeNDJSON(result *QueryResult, w io.Writer) error {
	encoder := json.NewEncoder(w)

	for _, row := range result.Rows {
		transformed := f.transformRow(row)
		if err := encoder.Encode(transformed); err != nil {
			return fmt.Errorf("failed to encode row: %w", err)
		}
	}

	return nil
}

// transformRows transforms multiple rows.
func (f *Formatter) transformRows(rows []map[string]interface{}) []map[string]interface{} {
	transformed := make([]map[string]interface{}, len(rows))
	for i, row := range rows {
		transformed[i] = f.transformRow(row)
	}
	return transformed
}

// transformRow transforms a single row.
func (f *Formatter) transformRow(row map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	for key, value := range row {
		// Check exclusion list
		if f.isExcluded(key) {
			continue
		}

		// Check inclusion list (if specified)
		if len(f.config.IncludeFields) > 0 && !f.isIncluded(key) {
			continue
		}

		// Apply field mapping
		outputKey := key
		if mapped, ok := f.config.FieldMapping[key]; ok {
			outputKey = mapped
		}

		// Transform value
		result[outputKey] = f.transformValue(value)
	}

	return result
}

// transformValue transforms a single value.
func (f *Formatter) transformValue(value interface{}) interface{} {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case time.Time:
		return v.Format(f.config.DateFormat)
	case float64:
		return fmt.Sprintf("%.*f", f.config.FloatPrecision, v)
	case float32:
		return fmt.Sprintf("%.*f", f.config.FloatPrecision, v)
	case bool:
		switch f.config.BoolFormat {
		case "1/0":
			if v {
				return 1
			}
			return 0
		case "yes/no":
			if v {
				return "yes"
			}
			return "no"
		default:
			return v
		}
	case string:
		if f.config.MaxFieldLength > 0 && len(v) > f.config.MaxFieldLength {
			return v[:f.config.MaxFieldLength] + "..."
		}
		return v
	default:
		return value
	}
}

// formatValue formats a value as string.
func (f *Formatter) formatValue(value interface{}) string {
	if value == nil {
		return f.config.NullValue
	}

	switch v := value.(type) {
	case time.Time:
		return v.Format(f.config.DateFormat)
	case float64:
		return fmt.Sprintf("%.*f", f.config.FloatPrecision, v)
	case float32:
		return fmt.Sprintf("%.*f", f.config.FloatPrecision, v)
	case bool:
		switch f.config.BoolFormat {
		case "1/0":
			if v {
				return "1"
			}
			return "0"
		case "yes/no":
			if v {
				return "yes"
			}
			return "no"
		default:
			return fmt.Sprintf("%v", v)
		}
	case string:
		if f.config.MaxFieldLength > 0 && len(v) > f.config.MaxFieldLength {
			return v[:f.config.MaxFieldLength] + "..."
		}
		return v
	default:
		return fmt.Sprintf("%v", value)
	}
}

// filterColumns filters columns based on config.
func (f *Formatter) filterColumns(columns []string) []string {
	var filtered []string

	for _, col := range columns {
		if f.isExcluded(col) {
			continue
		}
		if len(f.config.IncludeFields) > 0 && !f.isIncluded(col) {
			continue
		}
		filtered = append(filtered, col)
	}

	return filtered
}

// isExcluded checks if a field is excluded.
func (f *Formatter) isExcluded(field string) bool {
	for _, excluded := range f.config.ExcludeFields {
		if excluded == field {
			return true
		}
	}
	return false
}

// isIncluded checks if a field is included.
func (f *Formatter) isIncluded(field string) bool {
	for _, included := range f.config.IncludeFields {
		if included == field {
			return true
		}
	}
	return false
}

// padRight pads a string on the right.
func (f *Formatter) padRight(s string, length int) string {
	if len(s) >= length {
		return s
	}
	return s + strings.Repeat(" ", length-len(s))
}

// StreamFormatter streams formatted results.
type StreamFormatter struct {
	config    FormatterConfig
	writer    io.Writer
	csvWriter *csv.Writer
	encoder   *json.Encoder
	rowCount  int64
	started   bool
}

// NewStreamFormatter creates a new stream formatter.
func NewStreamFormatter(config FormatterConfig, w io.Writer) *StreamFormatter {
	sf := &StreamFormatter{
		config: config,
		writer: w,
	}

	switch config.Format {
	case FormatCSV:
		sf.csvWriter = csv.NewWriter(w)
	case FormatNDJSON:
		sf.encoder = json.NewEncoder(w)
	}

	return sf
}

// WriteHeader writes the header (for CSV).
func (sf *StreamFormatter) WriteHeader(columns []string) error {
	if sf.config.Format == FormatCSV && sf.config.IncludeColumns {
		return sf.csvWriter.Write(columns)
	}
	return nil
}

// WriteRow writes a single row.
func (sf *StreamFormatter) WriteRow(row map[string]interface{}) error {
	sf.rowCount++

	switch sf.config.Format {
	case FormatCSV:
		// Need column order for CSV
		return fmt.Errorf("use WriteRowValues for CSV streaming")
	case FormatNDJSON:
		return sf.encoder.Encode(row)
	default:
		return fmt.Errorf("streaming not supported for format: %s", sf.config.Format)
	}
}

// WriteRowValues writes a row as values (for CSV).
func (sf *StreamFormatter) WriteRowValues(values []string) error {
	if sf.config.Format != FormatCSV {
		return fmt.Errorf("WriteRowValues only supported for CSV format")
	}
	sf.rowCount++
	return sf.csvWriter.Write(values)
}

// Flush flushes any buffered data.
func (sf *StreamFormatter) Flush() error {
	if sf.csvWriter != nil {
		sf.csvWriter.Flush()
		return sf.csvWriter.Error()
	}
	return nil
}

// RowCount returns the number of rows written.
func (sf *StreamFormatter) RowCount() int64 {
	return sf.rowCount
}
