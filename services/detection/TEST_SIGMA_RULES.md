# Sigma Rules Testing Guide

## Overview

The detection service now supports Sigma rules loaded from YAML files in the `rules/` directory.

## Loaded Sigma Rules

| Rule ID | Title | Severity | Description |
|---------|-------|----------|-------------|
| sigma-001 | Suspicious Encoded PowerShell Command | high | Detects encoded PowerShell command execution |
| sigma-002 | Port Scan Detection | medium | Detects port scanning activity |
| sigma-003 | Privilege Escalation Attempt | critical | Detects privilege escalation attempts |
| sigma-004 | Suspicious DNS Query | high | Detects DNS queries to suspicious domains |
| sigma-005 | Suspicious File Creation in Temp Directory | high | Detects suspicious file creation in temp directories |

## Test Events

### Test 1: PowerShell Encoded Command (sigma-001)

**Event:**
```json
{
  "event_id": "evt-001",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "windows",
  "parse_success": true,
  "fields": {
    "process": "powershell.exe",
    "command_line": "powershell.exe -enc SGVsbG9Xb3JsZA=="
  }
}
```

**Expected Alert:**
- Rule ID: sigma-001
- Severity: high
- MITRE Tactics: TA0002 (Execution)
- MITRE Techniques: T1059.001 (PowerShell)

### Test 2: Port Scan Detection (sigma-002)

**Event:**
```json
{
  "event_id": "evt-002",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "firewall",
  "parse_success": true,
  "fields": {
    "event_type": "port_scan",
    "source_ip": "10.0.0.100",
    "destination_ip": "192.168.1.1"
  }
}
```

**Expected Alert:**
- Rule ID: sigma-002
- Severity: medium
- MITRE Tactics: TA0007 (Discovery)
- MITRE Techniques: T1046 (Network Service Scanning)

### Test 3: Privilege Escalation (sigma-003)

**Event:**
```json
{
  "event_id": "evt-003",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "windows",
  "parse_success": true,
  "fields": {
    "event_type": "privilege_escalation",
    "user": "standard_user",
    "target_user": "SYSTEM"
  }
}
```

**Expected Alert:**
- Rule ID: sigma-003
- Severity: critical
- MITRE Tactics: TA0004 (Privilege Escalation)
- MITRE Techniques: T1068 (Exploitation for Privilege Escalation)

### Test 4: Suspicious DNS Query (sigma-004)

**Event:**
```json
{
  "event_id": "evt-004",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "dns",
  "parse_success": true,
  "fields": {
    "event_type": "dns_query",
    "query": "malicious.xyz",
    "destination": "malicious.xyz"
  }
}
```

**Expected Alert:**
- Rule ID: sigma-004
- Severity: high
- MITRE Tactics: TA0011 (Command and Control)
- MITRE Techniques: T1071.004 (Application Layer Protocol: DNS)

### Test 5: Malware File Creation (sigma-005)

**Event:**
```json
{
  "event_id": "evt-005",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "windows",
  "parse_success": true,
  "fields": {
    "event_type": "file_create",
    "file_path": "C:\\Temp\\malware.exe",
    "user": "attacker"
  }
}
```

**Expected Alert:**
- Rule ID: sigma-005
- Severity: high
- MITRE Tactics: TA0005 (Defense Evasion)
- MITRE Techniques: T1036 (Masquerading)

## How to Send Test Events

### Using Kafka

```bash
# Produce test event to logs.parsed topic
echo '{
  "event_id": "evt-001",
  "tenant_id": "tenant-1",
  "timestamp": "2024-02-15T22:30:00Z",
  "source_type": "windows",
  "parse_success": true,
  "fields": {
    "process": "powershell.exe",
    "command_line": "powershell.exe -enc SGVsbG9Xb3JsZA=="
  }
}' | kafka-console-producer --broker-list localhost:9092 --topic logs.parsed
```

### Check Alerts

```bash
# Consume alerts from alerts.raw topic
kafka-console-consumer --bootstrap-server localhost:9092 --topic alerts.raw --from-beginning
```

### Check Gateway API

```bash
# Query alerts via Gateway API
curl http://localhost:8080/api/v1/alerts
```

## Sigma Rule Format

Each Sigma rule in `rules/*.yml` follows this structure:

```yaml
title: Rule Title
id: sigma-XXX
status: experimental
description: Rule description
author: SIEM-SOAR
logsource:
  category: log_category
  product: product_name
detection:
  selection:
    field_name: value
    field_name|contains:
      - value1
      - value2
  condition: selection
level: high
tags:
  - attack.tactic_name
  - attack.t1234
```

### Supported Modifiers

- `field|contains`: Field contains substring (case-insensitive)
- `field|startswith`: Field starts with substring
- `field|endswith`: Field ends with substring
- No modifier: Exact match (case-insensitive)

### MITRE ATT&CK Tag Format

- Tactics: `attack.execution`, `attack.privilege_escalation`, etc.
- Techniques: `attack.t1059.001`, `attack.t1068`, etc.

## Adding New Sigma Rules

1. Create a new `.yml` file in `services/detection/rules/`
2. Follow the Sigma rule format above
3. Restart the detection service
4. Rules are loaded automatically at startup

## Verification

Check detection service logs at startup:

```
INFO loaded Sigma rules count=5 path=/app/rules
DEBUG loaded Sigma rule id=sigma-001 title="Suspicious Encoded PowerShell Command"
DEBUG loaded Sigma rule id=sigma-002 title="Port Scan Detection"
DEBUG loaded Sigma rule id=sigma-003 title="Privilege Escalation Attempt"
DEBUG loaded Sigma rule id=sigma-004 title="Suspicious DNS Query"
DEBUG loaded Sigma rule id=sigma-005 title="Suspicious File Creation in Temp Directory"
```

## Implementation Details

### Key Components

1. **SigmaRule struct** (`types.go`): Parses YAML rule files
2. **loadSigmaRules()** (`consumer.go`): Loads rules from filesystem
3. **evaluateSigmaRule()** (`consumer.go`): Evaluates rules against events
4. **extractMITREFromTags()** (`consumer.go`): Extracts MITRE ATT&CK metadata
5. **normalizeSeverity()** (`consumer.go`): Converts Sigma severity to standard levels

### Rule Evaluation Logic

1. Check if detection condition is "selection" (only supported condition)
2. For each field in selection criteria:
   - Extract field value from event
   - Apply field modifier (contains, startswith, endswith)
   - Match against criteria value(s)
3. All criteria must match (AND logic)
4. Multiple values in a list use OR logic

### MITRE ATT&CK Extraction

Tags are parsed to extract:
- **Tactics**: Mapped from names (e.g., "execution" → "TA0002")
- **Techniques**: Extracted from IDs (e.g., "t1059.001" → "T1059.001")

### Alert Generation

When a Sigma rule matches:
- Alert ID: Generated UUID
- Rule ID: From Sigma rule `id` field
- Rule Name: From Sigma rule `title` field
- Severity: Normalized from `level` field
- MITRE Metadata: Extracted from `tags` field
- Matched Fields: Fields that triggered the rule

## Future Enhancements

1. Support for complex detection conditions (AND, OR, NOT)
2. Support for aggregation rules (count, timeframe)
3. Support for field transformations
4. Integration with Sigma rule repositories
5. Dynamic rule reloading without restart
6. Rule performance metrics
