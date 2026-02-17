# Alerts API and Dashboard Integration - Implementation Summary

## Overview
Implemented a complete alerts API in the gateway service and updated the dashboard to fetch and display real alerts from the detection pipeline.

## Changes Made

### 1. Gateway Service - Alerts API

**File: `services/gateway/internal/handler/alerts.go`** (NEW)
- Created Alert struct matching detection service output
- Implemented in-memory alert store (1000 alert capacity)
- Added `ListAlertsHandler` - GET /api/v1/alerts
  - Returns alerts in format: `{"alerts": [...], "total": N}`
  - Includes CORS headers for frontend access
- Added `CreateAlertHandler` - POST /api/v1/alerts
  - Receives alerts from detection service
  - Auto-fills defaults (status="new", source="Detection")
  - Stores in reverse chronological order (newest first)

**File: `services/gateway/main.go`** (UPDATED)
- Imported handler package
- Added routes:
  - `GET /api/v1/alerts` → ListAlertsHandler
  - `POST /api/v1/alerts` → CreateAlertHandler
  - `OPTIONS /api/v1/alerts` → CORS preflight

### 2. Dashboard - AlertList Component

**File: `web/dashboard/src/features/alerts/components/AlertList.tsx`** (UPDATED)

Added API Integration:
- Removed mock data array (mockAlerts)
- Added state management:
  - `alerts` - fetched from API
  - `loading` - loading state
  - `error` - error state
- Added `fetchAlerts()` function
  - Fetches from `http://localhost:8080/api/v1/alerts`
  - Maps API response to Alert interface
  - Extracts target from fields (user, source_ip, or source_type)
  - Builds description from matched_fields
  - Maps MITRE tactic IDs to names
- Added `useEffect` hooks:
  - Initial fetch on mount
  - Auto-refresh every 10 seconds
- Updated UI:
  - Loading state with spinner
  - Error state with retry button
  - Empty state with helpful message
  - Refresh button with loading indicator

MITRE Tactic Mapping:
```typescript
TA0001 → Initial Access
TA0002 → Execution
TA0006 → Credential Access
TA0007 → Discovery
TA0011 → Command and Control
TA0040 → Impact
```

### 3. Detection Service - Gateway Forwarding

**File: `services/detection/internal/consumer/consumer.go`** (UPDATED)

Added HTTP forwarding:
- Added imports: `bytes`, `net/http`
- Added `httpClient` field to Consumer struct
- Created HTTP client in `NewConsumer()` with:
  - 5-second timeout
  - Connection pooling (100 max idle, 10 per host)
- Updated `produceAlerts()`:
  - Fires goroutine to forward each alert
  - Maintains existing Kafka production
- Added `forwardAlertToGateway()` function:
  - POST to `http://gateway:8080/api/v1/alerts`
  - Falls back to localhost in dev mode
  - Fire-and-forget (logs warnings on failure)
  - Content-Type: application/json

## Data Flow

```
Log Message
    ↓
Parser → Normalizer → Enricher (Kafka topics)
    ↓
Detection Consumer
    ↓ (evaluates rules)
Alert Generated
    ├→ Kafka (alerts topic)
    └→ HTTP POST → Gateway API
                        ↓
                   In-Memory Store
                        ↓
                   Dashboard (GET /api/v1/alerts, auto-refresh 10s)
```

## API Response Format

### GET /api/v1/alerts
```json
{
  "alerts": [
    {
      "id": "uuid",
      "alert_id": "uuid",
      "event_id": "uuid",
      "tenant_id": "tenant-001",
      "rule_id": "rule-001",
      "rule_name": "Failed Login Detection",
      "title": "Failed Login Detection",
      "description": "",
      "severity": "medium",
      "status": "new",
      "source": "Detection",
      "source_type": "auth",
      "target": "",
      "timestamp": "2026-02-15T13:12:10Z",
      "fields": {
        "user": "admin",
        "event_type": "login_failure"
      },
      "matched_fields": {
        "event_type": "login_failure"
      },
      "raw_log": "...",
      "mitre_tactics": ["TA0001"],
      "mitre_techniques": ["T1078"]
    }
  ],
  "total": 1
}
```

## Testing Instructions

### 1. Start Services

```bash
# Terminal 1 - Gateway
cd services/gateway
go run main.go

# Terminal 2 - Detection
cd services/detection
go run main.go

# Terminal 3 - Dashboard
cd web/dashboard
pnpm dev
```

### 2. Send Test Log

Use the existing test script to send a login failure log:
```bash
curl -X POST http://localhost:8081/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-001",
    "source_type": "auth",
    "raw_log": "Failed password for admin from 10.0.0.1"
  }'
```

### 3. Verify Alert Flow

1. Check detection service logs for alert generation
2. Check gateway logs for POST /api/v1/alerts
3. Open dashboard at http://localhost:5173/alerts
4. Alert should appear automatically within 10 seconds
5. Click on alert to see details panel

### 4. Test Auto-Refresh

1. Send multiple test logs
2. Watch dashboard auto-refresh every 10 seconds
3. Click "Refresh" button for immediate update
4. Verify loading spinner appears during refresh

## Build Verification

Both services compile successfully:
```bash
✓ services/gateway builds without errors
✓ services/detection builds without errors
```

## Features Implemented

- [x] Gateway alerts API (GET, POST)
- [x] CORS support for frontend
- [x] In-memory alert storage (1000 capacity)
- [x] Dashboard API integration
- [x] Real-time alert fetching
- [x] Auto-refresh (10s interval)
- [x] Loading states
- [x] Error handling with retry
- [x] Empty state messaging
- [x] Detection → Gateway HTTP forwarding
- [x] Fire-and-forget async forwarding
- [x] MITRE tactic name mapping
- [x] Field-based target extraction

## Notes

- In-memory storage is for demo purposes only
- Production should use ClickHouse or PostgreSQL
- HTTP forwarding is fire-and-forget (no retry logic)
- Gateway runs on port 8080
- Dashboard expects gateway at localhost:8080
- Auto-refresh interval: 10 seconds
- Alert store capacity: 1000 (FIFO)

## Next Steps

For production deployment:
1. Replace in-memory store with persistent database
2. Add authentication/authorization to API
3. Implement alert status update endpoint
4. Add pagination for large alert sets
5. Add WebSocket support for real-time updates
6. Implement retry logic for HTTP forwarding
7. Add metrics for alert API usage
