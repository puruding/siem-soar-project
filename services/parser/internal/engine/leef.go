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

// LEEFParser parses Log Event Extended Format (LEEF) logs.
// LEEF Format: LEEF:Version|Vendor|Product|Version|EventID|[delimiter]key1=value1[delimiter]key2=value2...
// LEEF 1.0: delimiter is \t (tab)
// LEEF 2.0: delimiter can be specified in header
type LEEFParser struct {
	headerPattern *regexp.Regexp
}

// NewLEEFParser creates a new LEEF parser.
func NewLEEFParser() *LEEFParser {
	return &LEEFParser{
		// LEEF header pattern - handles both LEEF 1.0 and 2.0
		headerPattern: regexp.MustCompile(`^LEEF:(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$`),
	}
}

// Name returns the parser name.
func (p *LEEFParser) Name() string {
	return "leef"
}

// Parse parses a LEEF log message.
func (p *LEEFParser) Parse(ctx context.Context, raw *RawEvent) (*ParsedEvent, error) {
	data := string(raw.Data)

	// Find LEEF prefix (might have syslog header before it)
	leefStart := strings.Index(data, "LEEF:")
	if leefStart == -1 {
		return nil, fmt.Errorf("not a LEEF message")
	}

	// Extract syslog header if present
	var syslogHeader string
	if leefStart > 0 {
		syslogHeader = data[:leefStart]
	}
	leefData := data[leefStart:]

	// Parse LEEF header
	matches := p.headerPattern.FindStringSubmatch(leefData)
	if matches == nil {
		return nil, fmt.Errorf("invalid LEEF format")
	}

	fields := make(map[string]interface{})

	// LEEF header fields
	version := matches[1]
	fields["leef.version"] = version
	fields["leef.vendor"] = matches[2]
	fields["leef.product"] = matches[3]
	fields["leef.product_version"] = matches[4]
	fields["leef.event_id"] = matches[5]

	// Determine delimiter based on version
	delimiter := "\t" // Default for LEEF 1.0
	attrData := matches[6]

	// LEEF 2.0 can have custom delimiter specified
	if strings.HasPrefix(version, "2") {
		// Check if delimiter is specified (first character followed by another delimiter)
		if len(attrData) > 0 {
			// LEEF 2.0 format: delimiter char followed by attributes
			// Check for common delimiters
			possibleDelims := []string{"\t", "^", "|", "~", ";"}
			for _, d := range possibleDelims {
				if strings.Contains(attrData, d) {
					delimiter = d
					break
				}
			}

			// Check for hex-encoded delimiter (e.g., 0x09 for tab)
			if strings.HasPrefix(attrData, "0x") || strings.HasPrefix(attrData, "x") {
				endIdx := 4
				if strings.HasPrefix(attrData, "x") {
					endIdx = 3
				}
				if len(attrData) >= endIdx {
					hexStr := attrData[:endIdx]
					if strings.HasPrefix(hexStr, "0x") {
						hexStr = hexStr[2:]
					} else {
						hexStr = hexStr[1:]
					}
					if val, err := strconv.ParseInt(hexStr, 16, 8); err == nil {
						delimiter = string(rune(val))
						attrData = attrData[endIdx:]
					}
				}
			}
		}
	}

	// Parse attributes
	attrs := p.parseAttributes(attrData, delimiter)
	for k, v := range attrs {
		fields["leef."+k] = v
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

	// Normalize fields
	p.normalizeFields(fields)

	return &ParsedEvent{
		EventID:      raw.EventID,
		TenantID:     raw.TenantID,
		Timestamp:    timestamp,
		ReceivedAt:   time.Now(),
		SourceType:   raw.SourceType,
		Format:       "leef",
		Fields:       fields,
		RawLog:       string(raw.Data),
		ParseSuccess: true,
	}, nil
}

// CanParse returns true if the data looks like LEEF.
func (p *LEEFParser) CanParse(data []byte) bool {
	return strings.Contains(string(data), "LEEF:")
}

// parseAttributes parses LEEF attribute key=value pairs.
func (p *LEEFParser) parseAttributes(data, delimiter string) map[string]interface{} {
	result := make(map[string]interface{})

	// Split by delimiter
	pairs := strings.Split(data, delimiter)

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		// Split by first '='
		idx := strings.Index(pair, "=")
		if idx == -1 {
			continue
		}

		key := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])

		if key != "" {
			result[key] = value
		}
	}

	return result
}

// extractTimestamp extracts timestamp from LEEF fields.
func (p *LEEFParser) extractTimestamp(fields map[string]interface{}) time.Time {
	// LEEF timestamp fields
	tsFields := []string{"leef.devTime", "leef.devTimeFormat", "leef.eventTime"}

	for _, field := range tsFields {
		if val, ok := fields[field]; ok {
			if s, ok := val.(string); ok {
				if ts := p.parseTimestampString(s); !ts.IsZero() {
					return ts
				}
			}
		}
	}

	return time.Time{}
}

// parseTimestampString parses various LEEF timestamp formats.
func (p *LEEFParser) parseTimestampString(s string) time.Time {
	// LEEF timestamp formats
	formats := []string{
		time.RFC3339,
		time.RFC3339Nano,
		"Jan 02 2006 15:04:05",
		"Jan 02 2006 15:04:05 MST",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05",
		"MMM dd yyyy HH:mm:ss", // LEEF common format
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

// normalizeFields maps LEEF field names to normalized names.
func (p *LEEFParser) normalizeFields(fields map[string]interface{}) {
	// Common LEEF to normalized field mappings
	mappings := map[string]string{
		"leef.src":         "source.ip",
		"leef.dst":         "destination.ip",
		"leef.srcPort":     "source.port",
		"leef.dstPort":     "destination.port",
		"leef.usrName":     "user.name",
		"leef.srcUserName": "source.user",
		"leef.dstUserName": "destination.user",
		"leef.srcHostName": "source.hostname",
		"leef.dstHostName": "destination.hostname",
		"leef.srcMAC":      "source.mac",
		"leef.dstMAC":      "destination.mac",
		"leef.proto":       "network.protocol",
		"leef.action":      "event.action",
		"leef.msg":         "message",
		"leef.cat":         "event.category",
		"leef.sev":         "event.severity",
		"leef.severity":    "event.severity",
		"leef.resource":    "resource.name",
		"leef.url":         "url.original",
		"leef.fileName":    "file.name",
		"leef.fileSize":    "file.size",
		"leef.filePath":    "file.path",
		"leef.fileHash":    "file.hash",
		"leef.bytesIn":     "network.bytes_in",
		"leef.bytesOut":    "network.bytes_out",
		"leef.identSrc":    "source.identity",
		"leef.identHostName": "identity.hostname",
		"leef.vSrc":        "source.virtual_ip",
		"leef.vDst":        "destination.virtual_ip",
		"leef.srcZone":     "source.zone",
		"leef.dstZone":     "destination.zone",
		"leef.domain":      "domain.name",
		"leef.policy":      "policy.name",
		"leef.reason":      "event.reason",
		"leef.isLoginEvent": "event.is_login",
		"leef.isLogoutEvent": "event.is_logout",
	}

	for leefField, normField := range mappings {
		if val, ok := fields[leefField]; ok {
			fields[normField] = val
		}
	}
}

// LEEFBuilder helps build LEEF messages.
type LEEFBuilder struct {
	version        string
	vendor         string
	product        string
	productVersion string
	eventID        string
	delimiter      string
	attributes     map[string]string
}

// NewLEEFBuilder creates a new LEEF builder.
func NewLEEFBuilder() *LEEFBuilder {
	return &LEEFBuilder{
		version:    "1.0",
		delimiter:  "\t",
		attributes: make(map[string]string),
	}
}

// SetVersion sets the LEEF version.
func (b *LEEFBuilder) SetVersion(version string) *LEEFBuilder {
	b.version = version
	return b
}

// SetDelimiter sets the attribute delimiter (LEEF 2.0).
func (b *LEEFBuilder) SetDelimiter(delimiter string) *LEEFBuilder {
	b.delimiter = delimiter
	return b
}

// SetHeader sets LEEF header fields.
func (b *LEEFBuilder) SetHeader(vendor, product, productVersion, eventID string) *LEEFBuilder {
	b.vendor = vendor
	b.product = product
	b.productVersion = productVersion
	b.eventID = eventID
	return b
}

// AddAttribute adds an attribute field.
func (b *LEEFBuilder) AddAttribute(key, value string) *LEEFBuilder {
	b.attributes[key] = value
	return b
}

// Build builds the LEEF message.
func (b *LEEFBuilder) Build() string {
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `|`, `\|`)
		return s
	}

	header := fmt.Sprintf("LEEF:%s|%s|%s|%s|%s",
		b.version,
		escape(b.vendor),
		escape(b.product),
		escape(b.productVersion),
		escape(b.eventID),
	)

	if len(b.attributes) == 0 {
		return header + "|"
	}

	var attrParts []string
	for k, v := range b.attributes {
		attrParts = append(attrParts, fmt.Sprintf("%s=%s", k, v))
	}

	return header + "|" + strings.Join(attrParts, b.delimiter)
}
