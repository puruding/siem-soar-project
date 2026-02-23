"""
Pipeline Orchestrator Service
Integrates Detection → AI Triage → SOAR → Pipeline UI

Runs on port 8095
Consumes alerts from Kafka 'alerts' topic
Performs rule-based AI triage
Triggers SOAR playbooks
Broadcasts pipeline events via WebSocket
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import List, Dict, Any
from collections import defaultdict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from kafka import KafkaConsumer
from kafka.errors import KafkaError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

KAFKA_BOOTSTRAP = "localhost:9092"
ALERT_TOPIC = "alerts"
SOAR_URL = "http://localhost:8082"
PORT = 8095

# Playbook Mapping (rule_id -> playbook)
PLAYBOOK_MAPPING = {
    "FW-001": {
        "id": "pb-block-ip",
        "name": "Block IP at Firewall",
        "steps": 4
    },
    "FW-002": {
        "id": "pb-isolate-host",
        "name": "Isolate Compromised Host",
        "steps": 5
    },
    "FW-003": {
        "id": "pb-escalate",
        "name": "Escalate to SOC Tier 2",
        "steps": 2
    },
    "FW-004": {
        "id": "pb-investigate-port-scan",
        "name": "Investigate Port Scan Activity",
        "steps": 3
    },
    "FW-005": {
        "id": "pb-quarantine-malware",
        "name": "Quarantine Malware Detection",
        "steps": 6
    },
    "FW-006": {
        "id": "pb-reset-password",
        "name": "Force Password Reset",
        "steps": 4
    },
    "FW-007": {
        "id": "pb-forensic-capture",
        "name": "Capture Forensic Evidence",
        "steps": 7
    },
    "default": {
        "id": "pb-manual-review",
        "name": "Manual Security Review",
        "steps": 1
    }
}

# Classification Rules
CLASSIFICATION_RULES = {
    "FW-001": {
        "category": "Network Intrusion",
        "mitre_tactic": "TA0043",
        "mitre_technique": "T1595"
    },
    "FW-002": {
        "category": "Lateral Movement",
        "mitre_tactic": "TA0008",
        "mitre_technique": "T1021"
    },
    "FW-003": {
        "category": "Initial Access",
        "mitre_tactic": "TA0001",
        "mitre_technique": "T1190"
    },
    "FW-004": {
        "category": "Reconnaissance",
        "mitre_tactic": "TA0043",
        "mitre_technique": "T1046"
    },
    "FW-005": {
        "category": "Execution",
        "mitre_tactic": "TA0002",
        "mitre_technique": "T1204"
    },
    "FW-006": {
        "category": "Credential Access",
        "mitre_tactic": "TA0006",
        "mitre_technique": "T1110"
    },
    "FW-007": {
        "category": "Exfiltration",
        "mitre_tactic": "TA0010",
        "mitre_technique": "T1041"
    }
}

# ============================================================================
# MODELS
# ============================================================================

class PipelineEvent(BaseModel):
    id: str
    timestamp: str
    stage: str  # event_receive, classification, playbook_select, flow_execution
    alert_id: str
    data: Dict[str, Any]

class AlertTestRequest(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: str
    source_ip: str = "192.168.1.100"
    dest_ip: str = "10.0.0.50"
    message: str = "Test alert"

# ============================================================================
# WEBSOCKET CONNECTION MANAGER
# ============================================================================

class ConnectionManager:
    """Manages WebSocket connections and broadcasts events"""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        """Accept and store new WebSocket connection"""
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket connected. Total connections: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket"""
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients"""
        if not self.active_connections:
            logger.debug("No active WebSocket connections to broadcast to")
            return

        disconnected = []
        async with self._lock:
            for connection in self.active_connections:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error broadcasting to WebSocket: {e}")
                    disconnected.append(connection)

        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    if conn in self.active_connections:
                        self.active_connections.remove(conn)
            logger.info(f"Removed {len(disconnected)} dead connections")

# ============================================================================
# GLOBAL STATE
# ============================================================================

app = FastAPI(title="Pipeline Orchestrator", version="1.0.0")
manager = ConnectionManager()

# Pipeline statistics
stats = {
    "total_alerts": 0,
    "alerts_by_severity": defaultdict(int),
    "alerts_by_category": defaultdict(int),
    "playbooks_triggered": defaultdict(int),
    "last_alert_time": None
}

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# AI TRIAGE (RULE-BASED)
# ============================================================================

def classify_alert(alert: dict) -> dict:
    """
    Rule-based AI classification
    Maps rule_id to category, MITRE tactics, and priority
    """
    rule_id = alert.get("rule_id", "")
    rule_config = CLASSIFICATION_RULES.get(rule_id, {})
    severity = alert.get("severity", "medium")

    # Calculate priority score
    severity_scores = {
        "critical": 95,
        "high": 80,
        "medium": 50,
        "low": 20
    }
    priority_score = severity_scores.get(severity.lower(), 50)

    # Build classification result
    classification = {
        "label": rule_config.get("category", "Unknown"),
        "confidence": 0.85,
        "method": "RULE_BASED",
        "mitre_tactics": [rule_config.get("mitre_tactic")] if rule_config.get("mitre_tactic") else [],
        "mitre_techniques": [rule_config.get("mitre_technique")] if rule_config.get("mitre_technique") else [],
        "priority_score": priority_score,
        "priority_level": severity,
        "rule_id": rule_id
    }

    logger.info(f"Classified alert {alert.get('id')} as {classification['label']} "
                f"(priority: {priority_score})")

    return classification

# ============================================================================
# PLAYBOOK MATCHING
# ============================================================================

def match_playbook(alert: dict, classification: dict) -> dict:
    """
    Match alert to appropriate SOAR playbook
    Returns playbook details and match score
    """
    rule_id = alert.get("rule_id", "")
    playbook = PLAYBOOK_MAPPING.get(rule_id, PLAYBOOK_MAPPING.get("default"))

    # Generate trigger tags from classification
    category = classification.get("label", "unknown")
    trigger_tags = [category.lower().replace(" ", "-")]

    playbook_info = {
        "playbook_id": playbook["id"],
        "playbook_name": playbook["name"],
        "match_score": 0.92 if rule_id in PLAYBOOK_MAPPING else 0.50,
        "step_count": playbook["steps"],
        "trigger_tags": trigger_tags,
        "rule_id": rule_id
    }

    logger.info(f"Matched playbook {playbook_info['playbook_id']} "
                f"for alert {alert.get('id')} (score: {playbook_info['match_score']})")

    return playbook_info

# ============================================================================
# SOAR INTEGRATION
# ============================================================================

async def trigger_playbook(playbook_id: str, alert: dict) -> dict:
    """
    Trigger SOAR playbook execution
    Calls POST /api/v1/playbooks/{id}/execute
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{SOAR_URL}/api/v1/playbooks/{playbook_id}/execute",
                json={"alert": alert}
            )
            response.raise_for_status()
            result = response.json()

            logger.info(f"Playbook {playbook_id} executed successfully. "
                       f"Execution ID: {result.get('execution_id')}")

            return result

    except httpx.HTTPStatusError as e:
        logger.error(f"SOAR API error: {e.response.status_code} - {e.response.text}")
        return {
            "error": True,
            "message": f"SOAR execution failed: {e.response.status_code}",
            "execution_id": None
        }
    except httpx.RequestError as e:
        logger.error(f"SOAR connection error: {e}")
        return {
            "error": True,
            "message": f"SOAR connection failed: {str(e)}",
            "execution_id": None
        }
    except Exception as e:
        logger.error(f"Unexpected error triggering playbook: {e}")
        return {
            "error": True,
            "message": f"Unexpected error: {str(e)}",
            "execution_id": None
        }

# ============================================================================
# PIPELINE PROCESSING
# ============================================================================

async def process_alert(alert: dict):
    """
    Main pipeline processing flow:
    1. Event Receive
    2. AI Classification
    3. Playbook Selection
    4. Playbook Execution
    """
    try:
        alert_id = alert.get("id", str(uuid.uuid4()))

        # Update statistics
        stats["total_alerts"] += 1
        stats["alerts_by_severity"][alert.get("severity", "unknown")] += 1
        stats["last_alert_time"] = datetime.now().isoformat()

        logger.info(f"Processing alert {alert_id} (rule: {alert.get('rule_id')})")

        # Stage 1: Event Receive
        await manager.broadcast({
            "type": "pipeline_event",
            "stage": "event_receive",
            "alert_id": alert_id,
            "data": {
                "source": alert.get("rule_name"),
                "severity": alert.get("severity"),
                "rule_id": alert.get("rule_id"),
                "timestamp": datetime.now().isoformat()
            }
        })

        await asyncio.sleep(0.1)  # Small delay for UI smoothness

        # Stage 2: Classification
        classification = classify_alert(alert)
        stats["alerts_by_category"][classification["label"]] += 1

        await manager.broadcast({
            "type": "pipeline_event",
            "stage": "classification",
            "alert_id": alert_id,
            "data": classification
        })

        await asyncio.sleep(0.1)

        # Stage 3: Playbook Select
        playbook = match_playbook(alert, classification)

        await manager.broadcast({
            "type": "pipeline_event",
            "stage": "playbook_select",
            "alert_id": alert_id,
            "data": playbook
        })

        await asyncio.sleep(0.1)

        # Stage 4: Execute Playbook
        execution = await trigger_playbook(playbook["playbook_id"], alert)
        stats["playbooks_triggered"][playbook["playbook_id"]] += 1

        await manager.broadcast({
            "type": "pipeline_event",
            "stage": "flow_execution",
            "alert_id": alert_id,
            "data": {
                **execution,
                "playbook_id": playbook["playbook_id"],
                "playbook_name": playbook["playbook_name"]
            }
        })

        logger.info(f"Completed processing alert {alert_id}")

    except Exception as e:
        logger.error(f"Error processing alert {alert.get('id')}: {e}", exc_info=True)
        await manager.broadcast({
            "type": "pipeline_error",
            "alert_id": alert.get("id"),
            "error": str(e)
        })

# ============================================================================
# KAFKA CONSUMER
# ============================================================================

async def consume_alerts():
    """
    Kafka consumer loop
    Subscribes to 'alerts' topic and processes incoming alerts
    Uses poll() with timeout for non-blocking async operation
    """
    logger.info(f"Starting Kafka consumer for topic '{ALERT_TOPIC}'")

    consumer = None
    while True:
        try:
            if consumer is None:
                consumer = KafkaConsumer(
                    ALERT_TOPIC,
                    bootstrap_servers=KAFKA_BOOTSTRAP,
                    value_deserializer=lambda m: json.loads(m.decode('utf-8')),
                    auto_offset_reset='latest',
                    enable_auto_commit=True,
                    group_id='pipeline-orchestrator',
                    consumer_timeout_ms=1000  # 1 second timeout for non-blocking
                )
                logger.info("Kafka consumer connected successfully")

            # Poll for messages with timeout (non-blocking)
            records = consumer.poll(timeout_ms=500, max_records=10)

            for topic_partition, messages in records.items():
                for message in messages:
                    try:
                        alert = message.value
                        logger.info(f"Received alert from Kafka: {alert.get('id')}")
                        await process_alert(alert)
                    except Exception as e:
                        logger.error(f"Error processing Kafka message: {e}", exc_info=True)

            # Yield to event loop
            await asyncio.sleep(0.1)

        except KafkaError as e:
            logger.error(f"Kafka error: {e}. Retrying in 5 seconds...")
            consumer = None
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"Unexpected error in Kafka consumer: {e}. Retrying in 5 seconds...")
            consumer = None
            await asyncio.sleep(5)

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Start Kafka consumer on application startup"""
    asyncio.create_task(consume_alerts())
    logger.info("Pipeline Orchestrator started on port 8095")

@app.websocket("/ws/pipeline")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time pipeline events
    Clients connect here to receive pipeline updates
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle client messages if needed
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(websocket)

@app.get("/api/v1/pipeline/stats")
async def get_stats():
    """
    Get pipeline statistics
    Returns alert counts, category distribution, and playbook triggers
    """
    return {
        "total_alerts": stats["total_alerts"],
        "alerts_by_severity": dict(stats["alerts_by_severity"]),
        "alerts_by_category": dict(stats["alerts_by_category"]),
        "playbooks_triggered": dict(stats["playbooks_triggered"]),
        "last_alert_time": stats["last_alert_time"],
        "active_connections": len(manager.active_connections)
    }

@app.post("/api/v1/pipeline/test")
async def test_pipeline(alert: AlertTestRequest):
    """
    Manual test endpoint
    Allows triggering pipeline processing with custom alert
    """
    logger.info(f"Test alert triggered: {alert.rule_id}")

    alert_dict = {
        "id": alert.id,
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "dest_ip": alert.dest_ip,
        "message": alert.message,
        "timestamp": datetime.now().isoformat()
    }

    # Process in background
    asyncio.create_task(process_alert(alert_dict))

    return {
        "status": "accepted",
        "alert_id": alert.id,
        "message": "Test alert queued for processing"
    }

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "pipeline-orchestrator",
        "port": PORT,
        "kafka_topic": ALERT_TOPIC,
        "soar_url": SOAR_URL
    }

@app.get("/api/v1/playbooks")
async def list_playbooks():
    """List all available playbook mappings"""
    return {
        "playbooks": PLAYBOOK_MAPPING,
        "total": len(PLAYBOOK_MAPPING)
    }

@app.get("/api/v1/classifications")
async def list_classifications():
    """List all classification rules"""
    return {
        "rules": CLASSIFICATION_RULES,
        "total": len(CLASSIFICATION_RULES)
    }

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    logger.info("=" * 70)
    logger.info("Pipeline Orchestrator Service")
    logger.info("=" * 70)
    logger.info(f"Port: {PORT}")
    logger.info(f"Kafka: {KAFKA_BOOTSTRAP}")
    logger.info(f"Alert Topic: {ALERT_TOPIC}")
    logger.info(f"SOAR URL: {SOAR_URL}")
    logger.info(f"Playbook Mappings: {len(PLAYBOOK_MAPPING)}")
    logger.info(f"Classification Rules: {len(CLASSIFICATION_RULES)}")
    logger.info("=" * 70)

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT,
        log_level="info"
    )
