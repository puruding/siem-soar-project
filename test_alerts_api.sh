#!/bin/bash
# Test script for Alerts API

echo "=== Testing Alerts API ==="
echo

# Test 1: Create an alert
echo "1. Creating test alert..."
curl -X POST http://localhost:8080/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-alert-001",
    "event_id": "event-001",
    "tenant_id": "tenant-001",
    "rule_id": "rule-001",
    "rule_name": "Failed Login Detection",
    "severity": "medium",
    "status": "new",
    "source_type": "auth",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "fields": {
      "user": "admin",
      "event_type": "login_failure",
      "source_ip": "192.168.1.100"
    },
    "matched_fields": {
      "event_type": "login_failure"
    },
    "raw_log": "Failed password for admin from 192.168.1.100",
    "mitre_tactics": ["TA0001"],
    "mitre_techniques": ["T1078"]
  }'
echo -e "\n"

# Test 2: List alerts
echo "2. Listing all alerts..."
curl -s http://localhost:8080/api/v1/alerts | jq
echo

# Test 3: Create another alert
echo "3. Creating second test alert..."
curl -X POST http://localhost:8080/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id": "test-alert-002",
    "event_id": "event-002",
    "tenant_id": "tenant-001",
    "rule_id": "rule-003",
    "rule_name": "Suspicious PowerShell",
    "severity": "high",
    "status": "new",
    "source_type": "windows",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "fields": {
      "process": {
        "command_line": "powershell.exe -encodedcommand ABC123"
      },
      "user": "user01"
    },
    "matched_fields": {
      "process.command_line": "-encodedcommand"
    },
    "raw_log": "PowerShell execution detected",
    "mitre_tactics": ["TA0002"],
    "mitre_techniques": ["T1059.001"]
  }'
echo -e "\n"

# Test 4: List alerts again
echo "4. Listing all alerts (should show 2)..."
curl -s http://localhost:8080/api/v1/alerts | jq '.total'
echo

echo "=== Tests Complete ==="
echo "Open http://localhost:5173/alerts to view in dashboard"
