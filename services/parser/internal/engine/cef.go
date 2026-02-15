// Package engine provides the core parsing engine for log events.
package engine

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// CEFParser parses Common Event Format (CEF) logs.
// CEF Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|[Extension]
type CEFParser struct {
	headerPattern *regexp.Regexp
	extPattern    *regexp.Regexp
}

// NewCEFParser creates a new CEF parser.
func NewCEFParser() *CEFParser {
	return &CEFParser{
		// CEF header pattern
		headerPattern: regexp.MustCompile(`^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$`),
		// Extension key=value pattern (handles escaped characters)
		extPattern: regexp.MustCompile(`(\w+)=`),
	}
}

// Name returns the parser name.
func (p *CEFParser) Name() string {
	return "cef"
}

// Parse parses a CEF log message.
func (p *CEFParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	data := string(raw.Data)

	// Find CEF prefix (might have syslog header before it)
	cefStart := strings.Index(data, "CEF:")
	if cefStart == -1 {
		return nil, fmt.Errorf("not a CEF message")
	}

	// Extract syslog header if present
	var syslogHeader string
	if cefStart > 0 {
		syslogHeader = data[:cefStart]
	}
	cefData := data[cefStart:]

	// Parse CEF header
	matches := p.headerPattern.FindStringSubmatch(cefData)
	if matches == nil {
		return nil, fmt.Errorf("invalid CEF format")
	}

	fields := make(map[string]interface{})

	// CEF header fields
	fields["cef.version"] = matches[1]
	fields["cef.device_vendor"] = p.unescapeValue(matches[2])
	fields["cef.device_product"] = p.unescapeValue(matches[3])
	fields["cef.device_version"] = p.unescapeValue(matches[4])
	fields["cef.signature_id"] = p.unescapeValue(matches[5])
	fields["cef.name"] = p.unescapeValue(matches[6])
	fields["cef.severity"] = p.parseSeverity(matches[7])

	// Parse extensions
	if matches[8] != "" {
		extensions := p.parseExtensions(matches[8])
		for k, v := range extensions {
			fields["cef."+k] = v
		}
	}

	// Parse syslog header if present
	if syslogHeader != "" {
		fields["syslog.header"] = strings.TrimSpace(syslogHeader)
	}

	// Extract timestamp
	timestamp := p.extractTimestamp(fields)
	if timestamp.IsZero() {
		timestamp = raw.Timestamp
	}

	// Map CEF fields to normalized names
	p.normalizeFields(fields)

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "cef",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// CanParse returns true if the data looks like CEF.
func (p *CEFParser) CanParse(data []byte) bool {
	return strings.Contains(string(data), "CEF:")
}

// parseExtensions parses CEF extension key=value pairs.
func (p *CEFParser) parseExtensions(ext string) map[string]interface{} {
	result := make(map[string]interface{})

	// Find all key positions
	keyMatches := p.extPattern.FindAllStringIndex(ext, -1)
	if len(keyMatches) == 0 {
		return result
	}

	for i, match := range keyMatches {
		keyStart := match[0]
		keyEnd := match[1] - 1 // Exclude '='

		key := ext[keyStart:keyEnd]

		// Value starts after '='
		valueStart := match[1]

		// Value ends at next key or end of string
		var valueEnd int
		if i+1 < len(keyMatches) {
			// Find last space before next key
			valueEnd = keyMatches[i+1][0] - 1
			// Trim trailing spaces
			for valueEnd > valueStart && ext[valueEnd-1] == ' ' {
				valueEnd--
			}
		} else {
			valueEnd = len(ext)
		}

		if valueStart < valueEnd {
			value := p.unescapeValue(ext[valueStart:valueEnd])
			result[key] = value
		}
	}

	return result
}

// unescapeValue unescapes CEF special characters.
func (p *CEFParser) unescapeValue(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, `\\`, "\x00")
	s = strings.ReplaceAll(s, `\|`, "|")
	s = strings.ReplaceAll(s, `\=`, "=")
	s = strings.ReplaceAll(s, `\n`, "\n")
	s = strings.ReplaceAll(s, `\r`, "\r")
	s = strings.ReplaceAll(s, "\x00", `\`)
	return s
}

// parseSeverity parses CEF severity (0-10 or Unknown/Low/Medium/High/Very-High).
func (p *CEFParser) parseSeverity(s string) interface{} {
	s = strings.TrimSpace(s)
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	// Return as string for named severities
	return s
}

// extractTimestamp extracts timestamp from CEF fields.
func (p *CEFParser) extractTimestamp(fields map[string]interface{}) time.Time {
	// CEF timestamp fields
	tsFields := []string{"cef.rt", "cef.start", "cef.end", "cef.deviceReceiptTime"}

	for _, field := range tsFields {
		if val, ok := fields[field]; ok {
			switch v := val.(type) {
			case string:
				if ts := p.parseTimestampString(v); !ts.IsZero() {
					return ts
				}
			case float64:
				return time.UnixMilli(int64(v))
			}
		}
	}

	return time.Time{}
}

// parseTimestampString parses various CEF timestamp formats.
func (p *CEFParser) parseTimestampString(s string) time.Time {
	// CEF timestamp formats
	formats := []string{
		"Jan 02 2006 15:04:05",
		"Jan 02 2006 15:04:05 MST",
		"Jan 02 15:04:05 MST 2006",
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	}

	// Try epoch milliseconds
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n > 1e12 {
			return time.UnixMilli(n)
		}
		return time.Unix(n, 0)
	}

	for _, format := range formats {
		if ts, err := time.Parse(format, s); err == nil {
			return ts
		}
	}

	return time.Time{}
}

// normalizeFields maps CEF field names to normalized names.
func (p *CEFParser) normalizeFields(fields map[string]interface{}) {
	// Common CEF to normalized field mappings
	mappings := map[string]string{
		"cef.src":        "source.ip",
		"cef.dst":        "destination.ip",
		"cef.spt":        "source.port",
		"cef.dpt":        "destination.port",
		"cef.suser":      "source.user",
		"cef.duser":      "destination.user",
		"cef.shost":      "source.hostname",
		"cef.dhost":      "destination.hostname",
		"cef.smac":       "source.mac",
		"cef.dmac":       "destination.mac",
		"cef.proto":      "network.protocol",
		"cef.act":        "event.action",
		"cef.msg":        "message",
		"cef.cat":        "event.category",
		"cef.outcome":    "event.outcome",
		"cef.reason":     "event.reason",
		"cef.app":        "application.name",
		"cef.request":    "http.request",
		"cef.requestMethod": "http.method",
		"cef.requestUrl": "url.original",
		"cef.fname":      "file.name",
		"cef.fsize":      "file.size",
		"cef.filePath":   "file.path",
		"cef.fileHash":   "file.hash",
		"cef.oldFileName": "file.old_name",
		"cef.cs1":        "custom.string1",
		"cef.cs2":        "custom.string2",
		"cef.cs3":        "custom.string3",
		"cef.cs4":        "custom.string4",
		"cef.cs5":        "custom.string5",
		"cef.cs6":        "custom.string6",
		"cef.cn1":        "custom.number1",
		"cef.cn2":        "custom.number2",
		"cef.cn3":        "custom.number3",
		"cef.in":         "network.bytes_in",
		"cef.out":        "network.bytes_out",
		"cef.cnt":        "event.count",
	}

	for cefField, normField := range mappings {
		if val, ok := fields[cefField]; ok {
			fields[normField] = val
		}
	}
}

// CEFBuilder helps build CEF messages.
type CEFBuilder struct {
	version       int
	deviceVendor  string
	deviceProduct string
	deviceVersion string
	signatureID   string
	name          string
	severity      int
	extensions    map[string]string
}

// NewCEFBuilder creates a new CEF builder.
func NewCEFBuilder() *CEFBuilder {
	return &CEFBuilder{
		version:    0,
		extensions: make(map[string]string),
	}
}

// SetHeader sets CEF header fields.
func (b *CEFBuilder) SetHeader(vendor, product, version, sigID, name string, severity int) *CEFBuilder {
	b.deviceVendor = vendor
	b.deviceProduct = product
	b.deviceVersion = version
	b.signatureID = sigID
	b.name = name
	b.severity = severity
	return b
}

// AddExtension adds an extension field.
func (b *CEFBuilder) AddExtension(key, value string) *CEFBuilder {
	b.extensions[key] = value
	return b
}

// Build builds the CEF message.
func (b *CEFBuilder) Build() string {
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `|`, `\|`)
		return s
	}

	escapeExt := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `=`, `\=`)
		s = strings.ReplaceAll(s, "\n", `\n`)
		s = strings.ReplaceAll(s, "\r", `\r`)
		return s
	}

	header := fmt.Sprintf("CEF:%d|%s|%s|%s|%s|%s|%d",
		b.version,
		escape(b.deviceVendor),
		escape(b.deviceProduct),
		escape(b.deviceVersion),
		escape(b.signatureID),
		escape(b.name),
		b.severity,
	)

	if len(b.extensions) == 0 {
		return header + "|"
	}

	var extParts []string
	for k, v := range b.extensions {
		extParts = append(extParts, fmt.Sprintf("%s=%s", k, escapeExt(v)))
	}

	return header + "|" + strings.Join(extParts, " ")
}
