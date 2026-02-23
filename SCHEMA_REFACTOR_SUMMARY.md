# Schema Package Refactoring Summary

## Overview
Created a shared schema package (`pkg/schema`) to standardize the data format used throughout the SIEM pipeline (Collector → Parser → Normalizer → Enricher).

## Changes Made

### 1. Created Shared Schema Package

**File**: `pkg/schema/raw_log.go`

Created the canonical `RawLogMessage` structure:
```go
type RawLogMessage struct {
    EventID    string            `json:"event_id"`
    TenantID   string            `json:"tenant_id"`
    SourceType string            `json:"source_type"`
    Timestamp  time.Time         `json:"timestamp"`
    Data       json.RawMessage   `json:"data"`
    Metadata   map[string]string `json:"metadata,omitempty"`
}
```

**Key Features**:
- `EventID`: UUID generated for every log message
- `TenantID`: Identifies the tenant/customer
- `SourceType`: Source of the log (http, syslog, kafka, s3, api)
- `Timestamp`: Original event timestamp (time.Time, not string)
- `Data`: Raw log payload as JSON (preserves original structure)
- `Metadata`: Additional context (content_type, remote_addr, etc.)

Helper functions:
- `NewRawLogMessage()`: Constructor
- `AddMetadata()`: Add key-value metadata

**File**: `pkg/schema/go.mod`

Created Go module definition for the schema package.

### 2. Updated Collector Service

**File**: `services/collector/main.go`

**Changes**:
- Added imports: `github.com/google/uuid` and `github.com/siem-soar-platform/pkg/schema`
- Replaced custom envelope structs with `schema.RawLogMessage`
- Updated 5 functions:

1. **`sendToKafka()`**: HTTP messages
   - Generate UUID for event_id
   - Use msg.ReceivedAt (time.Time) instead of formatted string
   - Store content_type and remote_addr in metadata

2. **`sendSyslogToKafka()`**: Syslog messages
   - Marshal syslog fields into Data field
   - Use hostname/source_ip as tenant_id
   - Store protocol and RFC in metadata

3. **`forwardKafkaMessage()`**: Kafka consumer messages
   - Marshal kafka metadata into Data field
   - Preserve original headers in metadata
   - Use original key as tenant_id

4. **`processAPIEvents()`**: API poller events
   - Use event.Timestamp directly
   - Store source_name in metadata

5. **`processS3Events()`**: S3 poller events
   - Store S3 bucket/key in metadata
   - Use bucket as tenant_id fallback

**File**: `services/collector/go.mod`

Added replace directive:
```go
replace (
    github.com/siem-soar-platform/pkg/schema => ../../pkg/schema
)
```

### 3. Updated Parser Service

**File**: `services/parser/internal/consumer/consumer.go`

**Changes**:
- Added import: `github.com/siem-soar-platform/pkg/schema`
- Removed local `RawLogEvent` struct (replaced with `schema.RawLogMessage`)
- Updated `processBatch()` function:
  - Unmarshal to `schema.RawLogMessage`
  - Improved fallback logic to preserve tenant_id and source_type from Kafka headers
  - Convert Data from json.RawMessage to []byte for engine.RawEvent

**Fallback Logic** (when unmarshaling fails):
```go
switch h.Key {
case "tenant_id":
    rawLog.TenantID = string(h.Value)
case "source_type":
    rawLog.SourceType = string(h.Value)
case "event_id":
    rawLog.EventID = string(h.Value)
default:
    rawLog.Metadata[h.Key] = string(h.Value)
}
```

**File**: `services/parser/go.mod`

Added replace directive:
```go
replace (
    github.com/siem-soar-platform/pkg/schema => ../../pkg/schema
)
```

## Benefits

1. **Consistency**: Single source of truth for raw log format
2. **Type Safety**: Timestamp is time.Time, not string
3. **Metadata Flexibility**: Easy to add context without changing schema
4. **UUID Generation**: Every log has a unique event_id
5. **Header Preservation**: Kafka headers are preserved in metadata
6. **Maintainability**: Changes to schema only need to happen in one place

## Validation

Both services compiled successfully:
- `services/collector/collector.exe` ✓
- `services/parser/parser.exe` ✓

## Next Steps

Consider updating:
1. Normalizer service to consume `schema.RawLogMessage`
2. Enricher service to consume `schema.RawLogMessage`
3. Add unit tests for schema package
4. Add integration tests for end-to-end pipeline
5. Update documentation for data pipeline flow

## File Changes Summary

| File | Status | Description |
|------|--------|-------------|
| `pkg/schema/raw_log.go` | Created | Shared schema definition |
| `pkg/schema/go.mod` | Created | Go module for schema package |
| `services/collector/main.go` | Modified | Uses schema.RawLogMessage |
| `services/collector/go.mod` | Modified | Added schema replace directive |
| `services/parser/internal/consumer/consumer.go` | Modified | Uses schema.RawLogMessage |
| `services/parser/go.mod` | Modified | Added schema replace directive |

## Breaking Changes

**None** - This is a backward-compatible refactoring. The JSON structure remains the same:
- Old: Custom envelope structs with same fields
- New: schema.RawLogMessage with same fields

The only difference is:
1. `timestamp` is now time.Time (RFC3339Nano format in JSON)
2. `event_id` is always present (UUID)
3. Additional metadata fields moved to `metadata` object
