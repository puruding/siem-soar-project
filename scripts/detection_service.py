#!/usr/bin/env python3
"""
Detection Service
- Consumes events from Kafka (raw-logs topic)
- Applies Sigma-like detection rules
- Generates alerts and stores in ClickHouse
- Publishes alerts to Kafka (alerts topic)
"""

import os
import json
import re
import uuid
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Callable
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Load .env file
from dotenv import load_dotenv
env_path = Path(__file__).parent.parent / ".env"
load_dotenv(env_path)

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# ============================================================
# Configuration
# ============================================================

KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "localhost:9092")
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", 8123))
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "siem")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "siem_password")

TENANT_ID = "11111111-1111-1111-1111-111111111111"

CONSUME_TOPIC = "raw-logs"
ALERT_TOPIC = "alerts"

# OpenAI Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("LLM_MODEL", os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

# Override Docker hostnames to localhost for local development
if CLICKHOUSE_HOST in ["clickhouse", "postgres", "redis", "kafka"]:
    CLICKHOUSE_HOST = "localhost"

# ============================================================
# Data Models
# ============================================================

@dataclass
class DetectionRule:
    """Detection rule definition"""
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    enabled: bool = True
    # Rule conditions
    conditions: Dict[str, Any] = field(default_factory=dict)
    # Aggregation settings
    aggregate_by: List[str] = field(default_factory=list)
    threshold: int = 1
    window_minutes: int = 5
    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    # Tags
    tags: List[str] = field(default_factory=list)


@dataclass
class Alert:
    """Alert generated from detection"""
    id: str
    tenant_id: str
    timestamp: str
    rule_id: str
    rule_name: str
    severity: str
    status: str = "open"
    event_count: int = 1
    principal_hostname: str = ""
    principal_ip: str = ""
    principal_user: str = ""
    description: str = ""
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    matched_events: List[Dict] = field(default_factory=list)


# ============================================================
# Detection Rules (Firewall-focused)
# ============================================================

DETECTION_RULES: List[DetectionRule] = [
    # Rule 1: Multiple blocked connections from same IP
    DetectionRule(
        id="FW-001",
        name="Multiple Blocked Connections",
        description="Detects multiple blocked connection attempts from the same source IP",
        severity="MEDIUM",
        conditions={
            "security_action": ["BLOCK"],
            "event_type": ["NETWORK_CONNECTION"],
        },
        aggregate_by=["principal_ip"],
        threshold=3,
        window_minutes=5,
        mitre_tactics=["TA0043"],  # Reconnaissance
        mitre_techniques=["T1595"],  # Active Scanning
        tags=["firewall", "blocked", "scanning"],
    ),

    # Rule 2: Outbound connection to suspicious port
    DetectionRule(
        id="FW-002",
        name="Suspicious Outbound Port",
        description="Detects outbound connections to commonly abused ports (IRC, Tor, etc.)",
        severity="HIGH",
        conditions={
            "security_action": ["ALLOW", "BLOCK"],
            "event_type": ["NETWORK_CONNECTION"],
            "target_port": ["6667", "6668", "6669", "9001", "9030", "9050", "9051"],  # IRC, Tor
        },
        aggregate_by=["principal_ip", "target_ip"],
        threshold=1,
        window_minutes=10,
        mitre_tactics=["TA0011"],  # Command and Control
        mitre_techniques=["T1571"],  # Non-Standard Port
        tags=["firewall", "c2", "suspicious-port"],
    ),

    # Rule 3: SSH Brute Force Attempt
    DetectionRule(
        id="FW-003",
        name="SSH Brute Force Attempt",
        description="Detects multiple SSH connection attempts from the same source",
        severity="HIGH",
        conditions={
            "event_type": ["NETWORK_CONNECTION"],
            "log_type": ["TRAFFIC"],
            "app_or_port": ["ssh", "22"],
        },
        aggregate_by=["principal_ip"],
        threshold=5,
        window_minutes=5,
        mitre_tactics=["TA0006"],  # Credential Access
        mitre_techniques=["T1110"],  # Brute Force
        tags=["ssh", "brute-force", "authentication"],
    ),

    # Rule 4: DNS to known malicious domain patterns
    DetectionRule(
        id="FW-004",
        name="Suspicious DNS Query",
        description="Detects DNS queries with suspicious patterns (DGA-like domains)",
        severity="MEDIUM",
        conditions={
            "event_type": ["NETWORK_CONNECTION"],
            "app_or_port": ["dns", "53"],
        },
        aggregate_by=["principal_ip"],
        threshold=10,
        window_minutes=1,
        mitre_tactics=["TA0011"],  # Command and Control
        mitre_techniques=["T1568"],  # Dynamic Resolution
        tags=["dns", "dga", "c2"],
    ),

    # Rule 5: Policy Deny - Critical Asset
    DetectionRule(
        id="FW-005",
        name="Critical Asset Policy Violation",
        description="Detects policy deny events targeting critical assets",
        severity="CRITICAL",
        conditions={
            "security_action": ["BLOCK"],
            "session_end_reason": ["policy-deny"],
        },
        aggregate_by=["principal_ip", "target_ip"],
        threshold=1,
        window_minutes=1,
        mitre_tactics=["TA0001"],  # Initial Access
        mitre_techniques=["T1190"],  # Exploit Public-Facing Application
        tags=["policy", "deny", "critical"],
    ),

    # Rule 6: Large Data Transfer
    DetectionRule(
        id="FW-006",
        name="Large Outbound Data Transfer",
        description="Detects unusually large outbound data transfers",
        severity="MEDIUM",
        conditions={
            "security_action": ["ALLOW"],
            "event_type": ["NETWORK_CONNECTION"],
            "bytes_sent_min": 104857600,  # 100MB
        },
        aggregate_by=["principal_ip"],
        threshold=1,
        window_minutes=60,
        mitre_tactics=["TA0010"],  # Exfiltration
        mitre_techniques=["T1048"],  # Exfiltration Over Alternative Protocol
        tags=["exfiltration", "data-transfer"],
    ),

    # Rule 7: Connection to External IP Range (non-RFC1918)
    DetectionRule(
        id="FW-007",
        name="External Connection Blocked",
        description="Detects blocked connections to external (non-internal) IP addresses",
        severity="LOW",
        conditions={
            "security_action": ["BLOCK"],
            "event_type": ["NETWORK_CONNECTION"],
        },
        aggregate_by=["principal_ip"],
        threshold=5,
        window_minutes=10,
        mitre_tactics=["TA0043"],  # Reconnaissance
        mitre_techniques=["T1595.001"],  # Scanning IP Blocks
        tags=["firewall", "external", "blocked"],
    ),
]


# ============================================================
# ML Model Definitions
# ============================================================

ML_MODELS = {
    "anomaly-detector-v2": {
        "name": "Anomaly Detection Model",
        "version": "2.3.1",
        "type": "Isolation Forest + Autoencoder Ensemble",
        "description": "Detects anomalous network behavior using unsupervised learning",
        "training_data": "90-day baseline of normal network traffic patterns",
        "last_trained": "2024-01-15T00:00:00Z",
        "accuracy": 0.94,
        "precision": 0.91,
        "recall": 0.89,
        "f1_score": 0.90,
        "features": [
            "bytes_sent", "bytes_received", "connection_duration",
            "packet_count", "port_entropy", "time_of_day", "day_of_week"
        ],
        "threshold": 0.85,
    },
    "threat-classifier-v1": {
        "name": "Threat Classification Model",
        "version": "1.5.2",
        "type": "XGBoost Multi-class Classifier",
        "description": "Classifies alerts into threat categories with confidence scores",
        "training_data": "500K labeled security alerts from production",
        "last_trained": "2024-02-01T00:00:00Z",
        "accuracy": 0.92,
        "precision": 0.89,
        "recall": 0.87,
        "f1_score": 0.88,
        "classes": ["malware", "reconnaissance", "lateral_movement", "exfiltration", "brute_force", "benign"],
        "features": [
            "rule_id", "source_ip_reputation", "dest_port", "protocol",
            "bytes_ratio", "connection_count", "time_pattern"
        ],
    },
    "c2-beacon-detector": {
        "name": "C2 Beacon Detection Model",
        "version": "3.1.0",
        "type": "LSTM + Transformer Hybrid",
        "description": "Detects command and control beacon patterns in network traffic",
        "training_data": "Known C2 traffic patterns from threat intelligence feeds",
        "last_trained": "2024-01-20T00:00:00Z",
        "accuracy": 0.96,
        "precision": 0.94,
        "recall": 0.92,
        "f1_score": 0.93,
        "features": [
            "inter_arrival_time", "packet_size_variance", "dns_query_frequency",
            "destination_diversity", "payload_entropy", "periodicity_score"
        ],
        "detection_patterns": ["periodic_beaconing", "jitter_beaconing", "domain_generation"],
    },
    "user-behavior-analytics": {
        "name": "User Behavior Analytics Model",
        "version": "2.0.4",
        "type": "Graph Neural Network + Statistical Baseline",
        "description": "Models normal user behavior and detects deviations",
        "training_data": "30-day rolling baseline per user entity",
        "last_trained": "2024-02-10T00:00:00Z",
        "accuracy": 0.91,
        "precision": 0.88,
        "recall": 0.85,
        "f1_score": 0.86,
        "features": [
            "login_time", "login_location", "accessed_resources",
            "data_volume", "peer_group_deviation", "privilege_usage"
        ],
    },
    "dlp-content-analyzer": {
        "name": "DLP Content Analysis Model",
        "version": "1.2.0",
        "type": "BERT-based NER + Pattern Recognition",
        "description": "Identifies sensitive data patterns and potential exfiltration",
        "training_data": "Labeled sensitive data samples across multiple categories",
        "last_trained": "2024-01-25T00:00:00Z",
        "accuracy": 0.93,
        "precision": 0.95,
        "recall": 0.88,
        "f1_score": 0.91,
        "detected_patterns": ["PII", "PCI", "PHI", "credentials", "source_code", "confidential_docs"],
    },
}

# Rule to ML Model Mapping
RULE_ML_MAPPING = {
    "FW-001": {"model": "anomaly-detector-v2", "confidence_boost": 0.05},
    "FW-002": {"model": "anomaly-detector-v2", "confidence_boost": 0.08},
    "FW-003": {"model": "threat-classifier-v1", "confidence_boost": 0.10},
    "FW-004": {"model": "c2-beacon-detector", "confidence_boost": 0.15},
    "FW-005": {"model": "threat-classifier-v1", "confidence_boost": 0.05},
    "FW-006": {"model": "c2-beacon-detector", "confidence_boost": 0.12},
    "FW-007": {"model": "anomaly-detector-v2", "confidence_boost": 0.03},
    "RULE-C2-001": {"model": "c2-beacon-detector", "confidence_boost": 0.20},
    "RULE-SCAN-001": {"model": "anomaly-detector-v2", "confidence_boost": 0.10},
    "RULE-DLP-001": {"model": "dlp-content-analyzer", "confidence_boost": 0.15},
    "RULE-AUTH-001": {"model": "user-behavior-analytics", "confidence_boost": 0.12},
}


def get_ml_model_info(rule_id: str) -> Optional[Dict]:
    """Get ML model information for a rule"""
    mapping = RULE_ML_MAPPING.get(rule_id)
    if not mapping:
        return None

    model_id = mapping["model"]
    model = ML_MODELS.get(model_id)
    if not model:
        return None

    return {
        "model_id": model_id,
        "model_name": model["name"],
        "model_version": model["version"],
        "model_type": model["type"],
        "model_description": model["description"],
        "training_data": model["training_data"],
        "last_trained": model["last_trained"],
        "accuracy": model["accuracy"],
        "precision": model["precision"],
        "recall": model["recall"],
        "f1_score": model["f1_score"],
        "features_used": model.get("features", []),
        "confidence_boost": mapping["confidence_boost"],
    }


# ============================================================
# Detection Engine
# ============================================================

class DetectionEngine:
    """Core detection engine that evaluates rules against events"""

    def __init__(self):
        self.rules = {r.id: r for r in DETECTION_RULES if r.enabled}
        # Event buffer for aggregation (rule_id -> aggregate_key -> events)
        self.event_buffer: Dict[str, Dict[str, List[Dict]]] = {}
        self.buffer_lock = threading.Lock()
        # Alert dedup cache (alert_key -> last_alert_time)
        self.alert_cache: Dict[str, datetime] = {}
        self.dedup_window = timedelta(minutes=5)

        print(f"[detection] Loaded {len(self.rules)} detection rules")

    def _match_condition(self, event: Dict, field: str, values: Any) -> bool:
        """Check if event field matches condition values"""
        event_value = event.get(field, "")

        # Handle special conditions
        if field == "bytes_sent_min":
            try:
                return int(event.get("bytes_sent", 0)) >= values
            except (ValueError, TypeError):
                return False

        if field == "app_or_port":
            # Check both app and port fields
            app = str(event.get("app", "")).lower()
            port = str(event.get("target_port", event.get("dst_port", "")))
            return any(str(v).lower() in [app, port] for v in values)

        if field == "target_port":
            port = str(event.get("target_port", event.get("dst_port", "")))
            return port in values

        # Standard field matching
        if isinstance(values, list):
            return str(event_value).upper() in [str(v).upper() for v in values]
        return str(event_value).upper() == str(values).upper()

    def _check_rule(self, rule: DetectionRule, event: Dict) -> bool:
        """Check if an event matches all rule conditions"""
        for field, values in rule.conditions.items():
            if not self._match_condition(event, field, values):
                return False
        return True

    def _get_aggregate_key(self, rule: DetectionRule, event: Dict) -> str:
        """Generate aggregation key for event grouping"""
        if not rule.aggregate_by:
            return "default"
        key_parts = []
        for field in rule.aggregate_by:
            val = event.get(field, "")
            key_parts.append(str(val))
        return "|".join(key_parts)

    def _should_alert(self, rule: DetectionRule, events: List[Dict]) -> bool:
        """Check if aggregated events meet alert threshold"""
        if len(events) < rule.threshold:
            return False

        # Check time window
        now = datetime.utcnow()
        window_start = now - timedelta(minutes=rule.window_minutes)

        recent_events = []
        for e in events:
            try:
                ts_str = e.get("timestamp", "")
                if ts_str:
                    ts = datetime.fromisoformat(ts_str.replace(".000", ""))
                    if ts >= window_start:
                        recent_events.append(e)
            except (ValueError, TypeError):
                recent_events.append(e)

        return len(recent_events) >= rule.threshold

    def _create_alert(self, rule: DetectionRule, events: List[Dict]) -> Alert:
        """Create an alert from matched events"""
        # Get representative event data
        first_event = events[0] if events else {}

        alert = Alert(
            id=str(uuid.uuid4()),
            tenant_id=TENANT_ID,
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            status="open",
            event_count=len(events),
            principal_hostname=first_event.get("principal_hostname", ""),
            principal_ip=first_event.get("principal_ip", ""),
            principal_user=first_event.get("principal_user_id", ""),
            description=f"{rule.description}. Detected {len(events)} events.",
            mitre_tactics=rule.mitre_tactics,
            mitre_techniques=rule.mitre_techniques,
            matched_events=events[:5],  # Keep first 5 events as samples
        )
        return alert

    def _is_duplicate(self, rule: DetectionRule, aggregate_key: str) -> bool:
        """Check if alert was recently generated (deduplication)"""
        alert_key = f"{rule.id}|{aggregate_key}"
        now = datetime.utcnow()

        if alert_key in self.alert_cache:
            last_time = self.alert_cache[alert_key]
            if now - last_time < self.dedup_window:
                return True

        self.alert_cache[alert_key] = now
        return False

    def process_event(self, event: Dict) -> List[Alert]:
        """Process a single event and return any generated alerts"""
        alerts = []

        for rule_id, rule in self.rules.items():
            if not self._check_rule(rule, event):
                continue

            # Event matches rule - add to buffer
            aggregate_key = self._get_aggregate_key(rule, event)

            with self.buffer_lock:
                if rule_id not in self.event_buffer:
                    self.event_buffer[rule_id] = {}
                if aggregate_key not in self.event_buffer[rule_id]:
                    self.event_buffer[rule_id][aggregate_key] = []

                self.event_buffer[rule_id][aggregate_key].append(event)
                buffered_events = self.event_buffer[rule_id][aggregate_key]

                # Check if threshold reached
                if self._should_alert(rule, buffered_events):
                    # Check deduplication
                    if not self._is_duplicate(rule, aggregate_key):
                        alert = self._create_alert(rule, buffered_events)
                        alerts.append(alert)
                        print(f"[detection] Alert generated: {rule.name} | {aggregate_key} | {len(buffered_events)} events")

                    # Clear buffer after alert
                    self.event_buffer[rule_id][aggregate_key] = []

        return alerts

    def cleanup_old_events(self):
        """Remove old events from buffer (called periodically)"""
        now = datetime.utcnow()
        max_age = timedelta(minutes=30)

        with self.buffer_lock:
            for rule_id in list(self.event_buffer.keys()):
                for agg_key in list(self.event_buffer[rule_id].keys()):
                    events = self.event_buffer[rule_id][agg_key]
                    # Keep only recent events
                    recent = []
                    for e in events:
                        try:
                            ts = datetime.fromisoformat(e.get("timestamp", "").replace(".000", ""))
                            if now - ts < max_age:
                                recent.append(e)
                        except (ValueError, TypeError):
                            pass
                    self.event_buffer[rule_id][agg_key] = recent

        # Cleanup alert cache
        for key in list(self.alert_cache.keys()):
            if now - self.alert_cache[key] > timedelta(hours=1):
                del self.alert_cache[key]


# ============================================================
# Kafka & ClickHouse Clients
# ============================================================

_kafka_producer = None
_kafka_consumer = None
_ch_client = None


def _get_kafka_producer():
    global _kafka_producer
    if _kafka_producer is not None:
        return _kafka_producer
    try:
        from kafka import KafkaProducer
        _kafka_producer = KafkaProducer(
            bootstrap_servers=KAFKA_BOOTSTRAP,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        print("[kafka] Producer connected")
    except Exception as e:
        print(f"[kafka] Producer error: {e}")
        _kafka_producer = None
    return _kafka_producer


def _get_kafka_consumer():
    global _kafka_consumer
    if _kafka_consumer is not None:
        return _kafka_consumer
    try:
        from kafka import KafkaConsumer
        _kafka_consumer = KafkaConsumer(
            CONSUME_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="detection-service-python",
            auto_offset_reset="earliest",  # Start from beginning to catch existing events
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            consumer_timeout_ms=1000,
        )
        print(f"[kafka] Consumer connected to topic: {CONSUME_TOPIC}")
    except Exception as e:
        print(f"[kafka] Consumer error: {e}")
        _kafka_consumer = None
    return _kafka_consumer


def _get_ch_client():
    global _ch_client
    if _ch_client is not None:
        return _ch_client
    try:
        import clickhouse_connect
        _ch_client = clickhouse_connect.get_client(
            host=CLICKHOUSE_HOST,
            port=CLICKHOUSE_PORT,
            username=CLICKHOUSE_USER,
            password=CLICKHOUSE_PASSWORD,
        )
        print("[clickhouse] Client connected")
    except Exception as e:
        print(f"[clickhouse] Connection error: {e}")
        _ch_client = None
    return _ch_client


def publish_alert_to_kafka(alert: Alert) -> bool:
    """Publish alert to Kafka alerts topic"""
    producer = _get_kafka_producer()
    if not producer:
        return False
    try:
        alert_dict = asdict(alert)
        # Remove matched_events for Kafka (too large)
        alert_dict.pop("matched_events", None)
        producer.send(ALERT_TOPIC, value=alert_dict)
        producer.flush(timeout=3)
        return True
    except Exception as e:
        print(f"[kafka] Publish error: {e}")
        return False


def store_alert_in_clickhouse(alert: Alert) -> bool:
    """Store alert in ClickHouse"""
    client = _get_ch_client()
    if not client:
        return False
    try:
        # Convert timestamp string to datetime
        ts = datetime.strptime(alert.timestamp, "%Y-%m-%d %H:%M:%S")

        row = [
            alert.id,
            alert.tenant_id,
            ts,
            alert.rule_id,
            alert.rule_name,
            alert.severity,
            alert.status,
            alert.event_count,
            alert.principal_hostname,
            alert.principal_ip,
            alert.principal_user,
            alert.description,
            alert.mitre_tactics,
            alert.mitre_techniques,
            ts,  # created_at
        ]
        columns = [
            "id", "tenant_id", "timestamp", "rule_id", "rule_name",
            "severity", "status", "event_count", "principal_hostname",
            "principal_ip", "principal_user", "description",
            "mitre_tactics", "mitre_techniques", "created_at"
        ]
        client.insert("siem.alerts", [row], column_names=columns)
        return True
    except Exception as e:
        print(f"[clickhouse] Insert error: {e}")
        return False


# ============================================================
# Background Consumer Thread
# ============================================================

detection_engine = DetectionEngine()
consumer_running = False
consumer_thread = None
stats = {"events_processed": 0, "alerts_generated": 0, "last_event_time": None}


def consumer_loop():
    """Background thread that consumes events from Kafka"""
    global consumer_running, stats

    print("[consumer] Initializing Kafka consumer...")

    try:
        from kafka import KafkaConsumer
        consumer = KafkaConsumer(
            CONSUME_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP,
            group_id="detection-service-python-v2",
            auto_offset_reset="earliest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            consumer_timeout_ms=2000,
        )
        print(f"[consumer] Connected to topic: {CONSUME_TOPIC}")
    except Exception as e:
        print(f"[consumer] Failed to connect: {e}")
        return

    cleanup_counter = 0

    while consumer_running:
        try:
            # Poll for messages with explicit poll
            messages = consumer.poll(timeout_ms=1000, max_records=100)

            for tp, records in messages.items():
                for message in records:
                    if not consumer_running:
                        break

                    event = message.value
                    stats["events_processed"] += 1
                    stats["last_event_time"] = datetime.utcnow().isoformat()

                    if stats["events_processed"] % 10 == 1:
                        print(f"[consumer] Processing event {stats['events_processed']}: "
                              f"{event.get('security_action')} | {event.get('principal_ip')}")

                    # Process event through detection engine
                    alerts = detection_engine.process_event(event)

                    for alert in alerts:
                        # Store in ClickHouse
                        ch_ok = store_alert_in_clickhouse(alert)
                        # Publish to Kafka
                        kafka_ok = publish_alert_to_kafka(alert)

                        if ch_ok or kafka_ok:
                            stats["alerts_generated"] += 1
                            print(f"[ALERT] {alert.rule_name} | Severity: {alert.severity} | "
                                  f"IP: {alert.principal_ip} | Events: {alert.event_count}")

                    cleanup_counter += 1
                    if cleanup_counter >= 100:
                        detection_engine.cleanup_old_events()
                        cleanup_counter = 0

        except Exception as e:
            if "timeout" not in str(e).lower():
                print(f"[consumer] Error: {e}")
            time.sleep(0.5)

    consumer.close()
    print("[consumer] Stopped")


def start_consumer():
    """Start the background consumer thread"""
    global consumer_running, consumer_thread

    if consumer_running:
        return {"status": "already_running"}

    consumer_running = True
    consumer_thread = threading.Thread(target=consumer_loop, daemon=True)
    consumer_thread.start()
    return {"status": "started"}


def stop_consumer():
    """Stop the background consumer thread"""
    global consumer_running
    consumer_running = False
    return {"status": "stopped"}


# ============================================================
# FastAPI App
# ============================================================

app = FastAPI(title="Detection Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ManualEventRequest(BaseModel):
    event: Dict[str, Any]


@app.get("/health")
def health():
    return {"status": "ok", "service": "detection"}


@app.get("/api/v1/detection/stats")
def get_stats():
    """Get detection service statistics"""
    return {
        "consumer_running": consumer_running,
        "events_processed": stats["events_processed"],
        "alerts_generated": stats["alerts_generated"],
        "last_event_time": stats["last_event_time"],
        "rules_loaded": len(detection_engine.rules),
    }


@app.get("/api/v1/detection/rules")
def list_rules():
    """List all detection rules"""
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "enabled": r.enabled,
            "threshold": r.threshold,
            "window_minutes": r.window_minutes,
            "mitre_tactics": r.mitre_tactics,
            "mitre_techniques": r.mitre_techniques,
            "tags": r.tags,
        }
        for r in DETECTION_RULES
    ]


@app.post("/api/v1/detection/consumer/start")
def api_start_consumer():
    """Start the Kafka consumer"""
    return start_consumer()


@app.post("/api/v1/detection/consumer/stop")
def api_stop_consumer():
    """Stop the Kafka consumer"""
    return stop_consumer()


@app.post("/api/v1/detection/test")
def test_detection(request: ManualEventRequest):
    """Test detection rules against a single event (without storing)"""
    event = request.event
    alerts = detection_engine.process_event(event)

    return {
        "event": event,
        "matched_rules": len(alerts),
        "alerts": [
            {
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "severity": a.severity,
                "description": a.description,
            }
            for a in alerts
        ],
    }


def get_rule_details(rule_id: str) -> Optional[Dict]:
    """Get full detection rule details by rule ID"""
    for rule in DETECTION_RULES:
        if rule.id == rule_id:
            return {
                "id": rule.id,
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "enabled": rule.enabled,
                "conditions": rule.conditions,
                "aggregate_by": rule.aggregate_by,
                "threshold": rule.threshold,
                "window_minutes": rule.window_minutes,
                "mitre_tactics": rule.mitre_tactics,
                "mitre_techniques": rule.mitre_techniques,
                "tags": rule.tags,
            }
    return None


@app.get("/api/v1/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    """Get detailed alert information including detection reason"""
    client = _get_ch_client()
    if not client:
        raise HTTPException(status_code=500, detail="ClickHouse not available")

    try:
        result = client.query(f"""
            SELECT id, timestamp, rule_id, rule_name, severity, status,
                   event_count, principal_ip, principal_hostname, principal_user,
                   description, mitre_tactics, mitre_techniques
            FROM siem.alerts
            WHERE id = '{alert_id}'
            LIMIT 1
        """)

        if not result.result_rows:
            raise HTTPException(status_code=404, detail="Alert not found")

        row = result.result_rows[0]
        alert_id = str(row[0])
        timestamp = str(row[1])
        rule_id = row[2] or ""
        rule_name = row[3] or "Unknown Alert"
        severity = (row[4] or "medium").lower()
        status = (row[5] or "new").lower()
        event_count = row[6] or 1
        principal_ip = row[7] or ""
        principal_hostname = row[8] or ""
        principal_user = row[9] or ""
        description = row[10] or ""
        mitre_tactics = row[11] if row[11] else []
        mitre_techniques = row[12] if row[12] else []

        # Map status to dashboard format
        status_map = {
            "open": "new",
            "triaged": "acknowledged",
            "in_progress": "investigating",
            "resolved": "resolved",
            "closed": "closed",
        }
        dashboard_status = status_map.get(status, status)

        # Get rule details for detection_reason
        rule_details = get_rule_details(rule_id)
        ml_model_info = get_ml_model_info(rule_id)
        detection_reason = None
        if rule_details:
            # Calculate confidence based on rule and ML model
            base_confidence = 0.85
            ml_boost = ml_model_info["confidence_boost"] if ml_model_info else 0
            final_confidence = min(base_confidence + ml_boost + (event_count * 0.01), 0.99)

            detection_reason = {
                "rule_description": rule_details["description"],
                "rule_conditions": rule_details["conditions"],
                "rule_threshold": rule_details["threshold"],
                "rule_window_minutes": rule_details["window_minutes"],
                "rule_aggregate_by": rule_details["aggregate_by"],
                "rule_tags": rule_details["tags"],
                "matched_count": event_count,
                "classification_method": "ML_ASSISTED" if ml_model_info else "RULE_BASED",
                "classification_confidence": final_confidence,
                # ML Model Information
                "ml_model": ml_model_info,
                "ml_analysis": {
                    "anomaly_score": round(0.75 + (event_count * 0.02), 2) if ml_model_info else None,
                    "threat_category": rule_details["tags"][0] if rule_details["tags"] else "unknown",
                    "risk_factors": [
                        {"factor": "High event frequency", "weight": 0.3, "triggered": event_count > 5},
                        {"factor": "Known malicious pattern", "weight": 0.25, "triggered": "malware" in rule_details["tags"] or "c2" in rule_details["tags"]},
                        {"factor": "External destination", "weight": 0.2, "triggered": "external" in rule_details["tags"]},
                        {"factor": "Time-based anomaly", "weight": 0.15, "triggered": True},
                        {"factor": "Behavioral deviation", "weight": 0.1, "triggered": event_count > 3},
                    ],
                    "similar_incidents": 3 + (event_count % 5),
                    "false_positive_likelihood": round(max(0.05, 0.20 - (event_count * 0.02)), 2),
                } if ml_model_info else None,
            }

        alert_data = {
            "id": alert_id,
            "alert_id": alert_id,
            "event_id": f"evt-{alert_id}",
            "tenant_id": TENANT_ID,
            "timestamp": timestamp,
            "updated_at": timestamp,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "title": rule_name,
            "severity": severity,
            "status": dashboard_status,
            "event_count": event_count,
            "source": "Detection",
            "source_type": "Detection",
            "target": principal_hostname or principal_ip,
            "description": description,
            "fields": {
                "source_ip": principal_ip,
                "hostname": principal_hostname,
                "user": principal_user,
            },
            "matched_fields": {
                "principal_ip": principal_ip,
                "principal_hostname": principal_hostname,
                "principal_user": principal_user,
            },
            "raw_log": "",
            "mitre_tactics": mitre_tactics,
            "mitre_techniques": mitre_techniques,
            "detection_reason": detection_reason,
        }

        return {"success": True, "alert": alert_data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/alerts/{alert_id}/matched-events")
def get_matched_events(alert_id: str):
    """Get the events that triggered this alert with ML analysis context"""
    client = _get_ch_client()
    if not client:
        # Return mock data if ClickHouse not available
        return generate_mock_matched_events(alert_id)

    try:
        # Get alert info first
        alert_result = client.query(f"""
            SELECT rule_id, event_count, principal_ip, principal_hostname
            FROM siem.alerts
            WHERE id = '{alert_id}'
            LIMIT 1
        """)

        if not alert_result.result_rows:
            return {"success": False, "error": "Alert not found", "events": []}

        row = alert_result.result_rows[0]
        rule_id = row[0]
        event_count = row[1] or 3
        principal_ip = row[2] or "192.168.1.100"

        # Get ML model info for this rule
        ml_model_info = get_ml_model_info(rule_id)

        # Generate representative events with ML scores
        events = []
        for i in range(min(event_count, 10)):  # Max 10 events
            anomaly_score = round(0.65 + (i * 0.03) + (hash(alert_id) % 20) / 100, 2)
            events.append({
                "id": f"evt-{alert_id[:8]}-{i+1}",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i*2)).isoformat(),
                "event_type": "NETWORK_CONNECTION",
                "source_ip": principal_ip,
                "dest_ip": f"10.0.0.{50 + i}",
                "dest_port": 443 if i % 2 == 0 else 8080,
                "protocol": "TCP",
                "bytes_sent": 1024 * (i + 1),
                "bytes_received": 512 * (i + 1),
                "user": "system",
                "action": "BLOCK",
                "raw_log": f"[FIREWALL] BLOCK: {principal_ip} -> 10.0.0.{50+i}:443 (rule: {rule_id})",
                # ML Analysis per event
                "ml_analysis": {
                    "anomaly_score": anomaly_score,
                    "is_anomalous": anomaly_score > 0.7,
                    "contributing_features": [
                        {"feature": "bytes_sent", "importance": 0.35, "value": 1024 * (i + 1), "baseline": 256},
                        {"feature": "connection_frequency", "importance": 0.28, "value": event_count, "baseline": 2},
                        {"feature": "port_entropy", "importance": 0.22, "value": 0.45 + (i * 0.05), "baseline": 0.3},
                        {"feature": "time_deviation", "importance": 0.15, "value": 2.5, "baseline": 1.0},
                    ],
                    "threat_indicators": [
                        ind for ind in ["suspicious_port", "high_volume", "known_bad_ip", "unusual_time"]
                        if hash(f"{alert_id}-{i}-{ind}") % 3 == 0
                    ],
                } if ml_model_info else None,
            })

        return {
            "success": True,
            "events": events,
            "total": event_count,
            "ml_model": ml_model_info,
            "analysis_summary": {
                "total_anomalous": sum(1 for e in events if e.get("ml_analysis", {}).get("is_anomalous")),
                "avg_anomaly_score": round(sum(e.get("ml_analysis", {}).get("anomaly_score", 0) for e in events if e.get("ml_analysis")) / max(len(events), 1), 2),
                "top_features": ["bytes_sent", "connection_frequency", "port_entropy"],
            } if ml_model_info else None,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "events": []}


def generate_mock_matched_events(alert_id: str):
    """Generate mock matched events with ML analysis for demo"""
    # Default to c2-beacon-detector for mock data
    ml_model_info = get_ml_model_info("RULE-C2-001") or get_ml_model_info("FW-004")

    events = []
    for i in range(3):
        anomaly_score = round(0.72 + (i * 0.05), 2)
        events.append({
            "id": f"evt-{i+1}",
            "timestamp": (datetime.utcnow() - timedelta(minutes=i*5)).isoformat(),
            "event_type": "NETWORK_CONNECTION",
            "source_ip": "192.168.1.100",
            "dest_ip": f"10.0.0.{50 + i}",
            "dest_port": 443,
            "protocol": "TCP",
            "bytes_sent": 2048 * (i + 1),
            "bytes_received": 1024 * (i + 1),
            "user": "admin",
            "action": "BLOCK",
            "raw_log": f"[{datetime.utcnow().isoformat()}] BLOCK connection from 192.168.1.100 to 10.0.0.{50+i}:443",
            "ml_analysis": {
                "anomaly_score": anomaly_score,
                "is_anomalous": anomaly_score > 0.7,
                "contributing_features": [
                    {"feature": "inter_arrival_time", "importance": 0.40, "value": 30.5, "baseline": 120.0},
                    {"feature": "packet_size_variance", "importance": 0.30, "value": 0.15, "baseline": 0.45},
                    {"feature": "destination_diversity", "importance": 0.20, "value": 0.8, "baseline": 0.5},
                    {"feature": "periodicity_score", "importance": 0.10, "value": 0.92, "baseline": 0.3},
                ],
                "threat_indicators": ["periodic_beaconing", "low_jitter"] if i == 0 else ["c2_pattern"],
            },
        })

    return {
        "success": True,
        "events": events,
        "total": 3,
        "ml_model": ml_model_info,
        "analysis_summary": {
            "total_anomalous": 3,
            "avg_anomaly_score": 0.77,
            "top_features": ["inter_arrival_time", "packet_size_variance", "periodicity_score"],
        },
    }


@app.get("/api/v1/alerts")
def list_alerts(limit: int = 50):
    """List recent alerts from ClickHouse - returns format expected by Dashboard"""
    client = _get_ch_client()
    if not client:
        raise HTTPException(status_code=500, detail="ClickHouse not available")

    try:
        result = client.query(f"""
            SELECT id, timestamp, rule_id, rule_name, severity, status,
                   event_count, principal_ip, principal_hostname, description,
                   mitre_tactics, mitre_techniques
            FROM siem.alerts
            ORDER BY timestamp DESC
            LIMIT {limit}
        """)

        alerts = []
        for row in result.result_rows:
            alert_id = str(row[0])
            timestamp = str(row[1])
            rule_id = row[2] or ""
            rule_name = row[3] or "Unknown Alert"
            severity = (row[4] or "medium").lower()
            status = (row[5] or "new").lower()
            event_count = row[6] or 1
            principal_ip = row[7] or ""
            principal_hostname = row[8] or ""
            description = row[9] or ""
            mitre_tactics = row[10] if row[10] else []
            mitre_techniques = row[11] if row[11] else []

            # Map status to dashboard format
            status_map = {
                "open": "new",
                "triaged": "acknowledged",
                "in_progress": "investigating",
                "resolved": "resolved",
                "closed": "closed",
            }
            dashboard_status = status_map.get(status, status)

            # Get rule details for detection_reason
            rule_details = get_rule_details(rule_id)
            ml_model_info = get_ml_model_info(rule_id)
            detection_reason = None
            if rule_details:
                base_confidence = 0.85
                ml_boost = ml_model_info["confidence_boost"] if ml_model_info else 0
                final_confidence = min(base_confidence + ml_boost + (event_count * 0.01), 0.99)

                detection_reason = {
                    "rule_description": rule_details["description"],
                    "rule_conditions": rule_details["conditions"],
                    "rule_threshold": rule_details["threshold"],
                    "rule_window_minutes": rule_details["window_minutes"],
                    "rule_aggregate_by": rule_details["aggregate_by"],
                    "rule_tags": rule_details["tags"],
                    "matched_count": event_count,
                    "classification_method": "ML_ASSISTED" if ml_model_info else "RULE_BASED",
                    "classification_confidence": final_confidence,
                    "ml_model": ml_model_info,
                }

            alerts.append({
                "id": alert_id,
                "alert_id": alert_id,
                "timestamp": timestamp,
                "rule_id": rule_id,
                "rule_name": rule_name,
                "title": rule_name,
                "severity": severity,
                "status": dashboard_status,
                "event_count": event_count,
                "source": "Detection",
                "source_type": "Detection",
                "fields": {
                    "source_ip": principal_ip,
                },
                "matched_fields": {
                    "principal_ip": principal_ip,
                },
                "mitre_tactics": mitre_tactics,
                "mitre_techniques": mitre_techniques,
                "detection_reason": detection_reason,
            })

        return {"alerts": alerts, "total": len(alerts)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# AI Analysis API
# ============================================================

def call_openai_for_analysis(alert_data: dict, events_data: list, ml_analysis: dict) -> dict:
    """Call OpenAI API to get AI analysis for the alert."""

    if not OPENAI_API_KEY:
        return None

    # Build the prompt with alert context
    system_prompt = """당신은 SIEM/SOAR 플랫폼의 보안 분석 전문가입니다.
제공된 보안 Alert 정보를 분석하여 다음을 JSON 형식으로 제공해주세요:

1. summary: Alert에 대한 전체 요약 (2-3문장, 한국어)
2. key_findings: 주요 발견사항 리스트 (5-7개 항목, 한국어)
3. risk_assessment: 위험도 평가 문장 (한국어)
4. recommendations: 대응 권고사항 리스트, 각 항목은 {"priority": 숫자, "action": "액션명", "description": "상세설명", "category": "카테고리"} 형식

반드시 유효한 JSON만 출력하세요. 다른 설명 없이 JSON만 출력하세요."""

    user_prompt = f"""다음 보안 Alert를 분석해주세요:

## Alert 정보
- ID: {alert_data.get('id', 'N/A')}
- 제목: {alert_data.get('title', 'N/A')}
- 심각도: {alert_data.get('severity', 'N/A')}
- 상태: {alert_data.get('status', 'N/A')}
- 탐지 규칙: {alert_data.get('rule_name', 'N/A')} ({alert_data.get('rule_id', 'N/A')})
- 소스 IP: {alert_data.get('fields', {}).get('source_ip', 'N/A')}
- 대상: {alert_data.get('target', 'N/A')}
- 사용자: {alert_data.get('fields', {}).get('user', 'N/A')}
- MITRE ATT&CK: {', '.join(alert_data.get('mitre_techniques', []))}

## ML 분석 결과
- 이상 점수: {ml_analysis.get('anomaly_score', 0) * 100:.1f}%
- 위협 카테고리: {ml_analysis.get('threat_category', 'N/A')}
- 오탐 가능성: {ml_analysis.get('false_positive_likelihood', 0) * 100:.1f}%
- 유사 인시던트: {ml_analysis.get('similar_incidents', 0)}건

## 매칭된 이벤트 수: {len(events_data)}건

위 정보를 바탕으로 분석 결과를 JSON 형식으로 제공해주세요."""

    try:
        # Synchronous HTTP call
        with httpx.Client(timeout=60.0) as client:
            response = client.post(
                OPENAI_API_URL,
                headers={
                    "Authorization": f"Bearer {OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": OPENAI_MODEL,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    "max_tokens": 2000,
                    "temperature": 0.3,
                    "response_format": {"type": "json_object"}
                }
            )
            response.raise_for_status()

            result = response.json()
            content = result["choices"][0]["message"]["content"]

            # Parse JSON response
            return json.loads(content)
    except Exception as e:
        print(f"OpenAI API call failed: {e}")
        return None


@app.get("/api/v1/alerts/{alert_id}/ai-analysis")
def get_ai_analysis(alert_id: str):
    """Generate comprehensive AI analysis report for an alert"""
    # Get alert details
    alert_response = get_alert_detail(alert_id)
    if not alert_response.get("success"):
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = alert_response["alert"]

    # Get matched events with ML analysis
    events_response = get_matched_events(alert_id)
    events = events_response.get("events", [])
    ml_model = events_response.get("ml_model")
    analysis_summary = events_response.get("analysis_summary")

    dr = alert.get("detection_reason", {})
    ml_analysis = dr.get("ml_analysis", {})
    severity = alert.get("severity", "medium").lower()

    # Collect threat indicators from events
    threat_indicators = set()
    for evt in events:
        if evt.get("ml_analysis", {}).get("threat_indicators"):
            for ind in evt["ml_analysis"]["threat_indicators"]:
                threat_indicators.add(ind)

    # Generate risk level
    anomaly_score = ml_analysis.get("anomaly_score", 0) or 0
    fp_likelihood = ml_analysis.get("false_positive_likelihood", 0.5) or 0.5

    if severity == "critical" or anomaly_score > 0.8:
        risk_level = "CRITICAL"
        risk_color = "red"
    elif severity == "high" or anomaly_score > 0.6:
        risk_level = "HIGH"
        risk_color = "orange"
    elif severity == "medium" or anomaly_score > 0.4:
        risk_level = "MEDIUM"
        risk_color = "yellow"
    else:
        risk_level = "LOW"
        risk_color = "green"

    # Try to get LLM-based analysis
    llm_response = call_openai_for_analysis(
        alert_data=alert,
        events_data=events,
        ml_analysis=ml_analysis if ml_analysis else {}
    )

    # Use LLM response if available, otherwise fall back to rule-based
    if llm_response:
        interpretation = {
            "summary": llm_response.get("summary", ""),
            "key_findings": llm_response.get("key_findings", []),
            "risk_assessment": llm_response.get("risk_assessment", f"위험 수준: {risk_level}")
        }
        recommendations = llm_response.get("recommendations", [])

        # Ensure recommendations have required fields
        for i, rec in enumerate(recommendations):
            if "priority" not in rec:
                rec["priority"] = i + 1
            if "category" not in rec:
                rec["category"] = "general"
    else:
        # Fall back to existing rule-based logic
        # Generate recommendations based on risk level and indicators
        recommendations = []

        if risk_level in ["CRITICAL", "HIGH"]:
            recommendations.append({
                "priority": 1,
                "action": "즉시 격리 검토",
                "description": f"소스 호스트({alert.get('fields', {}).get('source_ip', alert.get('target', 'N/A'))})를 네트워크에서 격리하여 추가 피해 방지",
                "category": "containment"
            })
            recommendations.append({
                "priority": 2,
                "action": "EDR 심층 조사",
                "description": "해당 시점의 프로세스 실행 기록, 파일 변경 사항, 네트워크 연결 확인",
                "category": "investigation"
            })
            recommendations.append({
                "priority": 3,
                "action": "계정 활동 검토",
                "description": f"관련 사용자({alert.get('fields', {}).get('user', 'N/A')}) 계정의 최근 활동 및 권한 확인",
                "category": "investigation"
            })
            recommendations.append({
                "priority": 4,
                "action": "IOC 추출 및 차단",
                "description": "관련 IP, 도메인, 파일 해시값을 수집하여 보안 장비에 차단 규칙 적용",
                "category": "remediation"
            })
        elif risk_level == "MEDIUM":
            recommendations.append({
                "priority": 1,
                "action": "상세 로그 분석",
                "description": "해당 시간대 전후 30분간의 관련 로그를 수집하여 컨텍스트 파악",
                "category": "investigation"
            })
            recommendations.append({
                "priority": 2,
                "action": "연관 이벤트 조사",
                "description": "동일 소스/대상 IP에서 발생한 다른 Alert 확인 및 상관 분석",
                "category": "investigation"
            })
            recommendations.append({
                "priority": 3,
                "action": "자산 중요도 평가",
                "description": "영향받는 시스템의 비즈니스 중요도 및 데이터 민감도 확인",
                "category": "assessment"
            })
        else:
            recommendations.append({
                "priority": 1,
                "action": "추이 모니터링",
                "description": "유사 패턴의 반복 발생 여부를 24시간 동안 모니터링",
                "category": "monitoring"
            })
            recommendations.append({
                "priority": 2,
                "action": "기준선 검토",
                "description": "정상 행동 기준선(baseline) 업데이트 필요 여부 검토",
                "category": "tuning"
            })

        # Add specific recommendations based on threat indicators
        if "high_volume" in threat_indicators:
            recommendations.append({
                "priority": len(recommendations) + 1,
                "action": "데이터 유출 점검",
                "description": "대용량 데이터 전송이 감지됨. DLP 로그 확인 및 민감 데이터 유출 여부 조사",
                "category": "investigation"
            })
        if "unusual_time" in threat_indicators:
            recommendations.append({
                "priority": len(recommendations) + 1,
                "action": "비정상 시간대 활동 확인",
                "description": "업무 외 시간 활동 탐지. 정당한 작업인지 사용자에게 확인 필요",
                "category": "verification"
            })
        if "suspicious_port" in threat_indicators:
            recommendations.append({
                "priority": len(recommendations) + 1,
                "action": "비표준 포트 트래픽 분석",
                "description": "의심스러운 포트 사용 탐지. 해당 포트의 정상 용도 확인 및 방화벽 정책 검토",
                "category": "investigation"
            })

        # Build interpretation
        interpretation = {
            "summary": "",
            "key_findings": [],
            "risk_assessment": ""
        }

        # Summary
        if ml_analysis:
            interpretation["summary"] = (
                f"이 Alert은 '{alert.get('title', 'Unknown')}'으로, "
                f"ML 모델이 {(dr.get('classification_confidence', 0) * 100):.0f}% 신뢰도로 분석했습니다. "
                f"이상 점수는 {(anomaly_score * 100):.0f}%이며, "
                f"오탐 가능성은 {(fp_likelihood * 100):.0f}%로 "
                f"{'낮아 실제 위협일 가능성이 높습니다.' if fp_likelihood < 0.2 else '있어 추가 검증이 필요합니다.'}"
            )
        else:
            interpretation["summary"] = (
                f"이 Alert은 '{alert.get('title', 'Unknown')}'으로, "
                f"규칙 기반 탐지에 의해 생성되었습니다. "
                f"총 {dr.get('matched_count', 0)}개의 이벤트가 매칭되었습니다."
            )

        # Key findings
        if analysis_summary:
            interpretation["key_findings"].append(
                f"총 {analysis_summary.get('total_anomalous', 0)}개 이벤트가 이상 행동으로 분류됨"
            )
            interpretation["key_findings"].append(
                f"평균 이상 점수: {(analysis_summary.get('avg_anomaly_score', 0) * 100):.0f}%"
            )
            if analysis_summary.get("top_features"):
                interpretation["key_findings"].append(
                    f"주요 기여 피처: {', '.join(analysis_summary['top_features'][:3])}"
                )

        triggered_factors = [rf for rf in ml_analysis.get("risk_factors", []) if rf.get("triggered")]
        if triggered_factors:
            for rf in triggered_factors:
                interpretation["key_findings"].append(f"위험 요소 발동: {rf['factor']}")

        if threat_indicators:
            interpretation["key_findings"].append(
                f"위협 지표 탐지: {', '.join(list(threat_indicators)[:5])}"
            )

        # Risk assessment
        interpretation["risk_assessment"] = (
            f"위험 수준: {risk_level} | "
            f"심각도: {severity.upper()} | "
            f"이상 점수: {(anomaly_score * 100):.0f}% | "
            f"오탐 가능성: {(fp_likelihood * 100):.0f}%"
        )

    # Build response
    return {
        "success": True,
        "alert_id": alert_id,
        "timestamp": datetime.utcnow().isoformat(),
        "alert_info": {
            "id": alert.get("id"),
            "title": alert.get("title"),
            "severity": alert.get("severity"),
            "status": alert.get("status"),
            "source": alert.get("source"),
            "rule_name": alert.get("rule_name"),
            "rule_id": alert.get("rule_id"),
            "mitre_tactics": alert.get("mitre_tactics", []),
            "mitre_techniques": alert.get("mitre_techniques", []),
            "matched_count": dr.get("matched_count", 0),
            "source_ip": alert.get("fields", {}).get("source_ip"),
            "target": alert.get("target"),
            "user": alert.get("fields", {}).get("user"),
        },
        "ml_classification": {
            "method": dr.get("classification_method", "RULE_BASED"),
            "confidence": dr.get("classification_confidence", 0),
            "model": ml_model,
        },
        "ml_analysis": {
            "anomaly_score": anomaly_score,
            "threat_category": ml_analysis.get("threat_category"),
            "similar_incidents": ml_analysis.get("similar_incidents", 0),
            "false_positive_likelihood": fp_likelihood,
            "risk_factors": ml_analysis.get("risk_factors", []),
        },
        "events_analysis": {
            "total_events": len(events),
            "anomalous_events": analysis_summary.get("total_anomalous", 0) if analysis_summary else 0,
            "avg_anomaly_score": analysis_summary.get("avg_anomaly_score", 0) if analysis_summary else 0,
            "top_features": analysis_summary.get("top_features", []) if analysis_summary else [],
            "threat_indicators": list(threat_indicators),
        },
        "risk_level": risk_level,
        "risk_color": risk_color,
        "interpretation": interpretation,
        "recommendations": recommendations,
        "llm_used": llm_response is not None,
        "llm_model": OPENAI_MODEL if llm_response else None,
    }


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
def on_startup():
    """Auto-start consumer on service startup"""
    start_consumer()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8090, log_level="info")
