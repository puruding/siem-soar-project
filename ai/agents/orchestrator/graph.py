"""LangGraph workflow for SOC orchestration."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, TypedDict

from langgraph.graph import END, StateGraph

from common.logging import get_logger

from ..registry import AgentRegistry, get_registry


logger = get_logger(__name__)


class OrchestrationStage(str, Enum):
    """Stages in the orchestration workflow."""

    INTAKE = "intake"
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    ANALYSIS = "analysis"
    RESPONSE_PLANNING = "response_planning"
    APPROVAL = "approval"
    EXECUTION = "execution"
    VALIDATION = "validation"
    RECOVERY = "recovery"
    COMPLETE = "complete"


class OrchestrationState(TypedDict, total=False):
    """State for orchestration workflow."""

    # Incident data
    incident_id: str
    alert_id: str
    alert_data: dict[str, Any]

    # Stage tracking
    current_stage: OrchestrationStage
    stage_history: list[dict[str, Any]]

    # Results from each stage
    triage_result: dict[str, Any]
    investigation_result: dict[str, Any]
    analysis_result: dict[str, Any]
    response_plan: dict[str, Any]
    execution_result: dict[str, Any]
    validation_result: dict[str, Any]

    # Decision flags
    is_true_positive: bool
    severity: float
    confidence: float
    requires_human_approval: bool
    is_approved: bool

    # Control flow
    error: str | None
    should_retry: bool
    retry_count: int
    max_retries: int

    # Timing
    started_at: str
    completed_at: str | None


def intake_node(state: OrchestrationState) -> OrchestrationState:
    """Process incoming alert."""
    logger.info("intake_node", incident_id=state.get("incident_id"))

    alert = state.get("alert_data", {})

    # Extract initial severity
    severity_str = str(alert.get("severity", "medium")).lower()
    severity_map = {"critical": 9.0, "high": 7.0, "medium": 5.0, "low": 3.0, "info": 1.0}
    severity = severity_map.get(severity_str, 5.0)

    return {
        **state,
        "current_stage": OrchestrationStage.TRIAGE,
        "severity": severity,
        "confidence": 0.5,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.INTAKE.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": {"alert_processed": True},
        }],
    }


def triage_node(state: OrchestrationState) -> OrchestrationState:
    """Perform initial triage."""
    logger.info("triage_node", incident_id=state.get("incident_id"))

    alert = state.get("alert_data", {})
    alert_type = alert.get("alert_type", "unknown").lower()

    # Determine if true positive
    high_fidelity_types = ["ransomware", "apt", "data_exfil", "credential_theft"]
    is_true_positive = any(t in alert_type for t in high_fidelity_types)

    # Adjust confidence based on alert type
    confidence = 0.9 if is_true_positive else 0.7

    triage_result = {
        "alert_type": alert_type,
        "is_true_positive": is_true_positive,
        "initial_severity": state.get("severity", 5.0),
        "confidence": confidence,
        "category": _categorize_alert(alert_type),
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {
        **state,
        "current_stage": OrchestrationStage.INVESTIGATION,
        "triage_result": triage_result,
        "is_true_positive": is_true_positive,
        "confidence": confidence,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.TRIAGE.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": triage_result,
        }],
    }


def investigation_node(state: OrchestrationState) -> OrchestrationState:
    """Conduct investigation."""
    logger.info("investigation_node", incident_id=state.get("incident_id"))

    alert = state.get("alert_data", {})

    # Collect entities
    entities = _extract_entities(alert)

    # Build context
    investigation_result = {
        "entities": entities,
        "indicators": _extract_indicators(alert),
        "affected_assets": _identify_assets(alert),
        "timeline_events": [{
            "timestamp": alert.get("timestamp", datetime.utcnow().isoformat()),
            "event": "Initial alert generated",
            "source": "SIEM",
        }],
        "evidence_collected": True,
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {
        **state,
        "current_stage": OrchestrationStage.ANALYSIS,
        "investigation_result": investigation_result,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.INVESTIGATION.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": investigation_result,
        }],
    }


def analysis_node(state: OrchestrationState) -> OrchestrationState:
    """Perform threat analysis."""
    logger.info("analysis_node", incident_id=state.get("incident_id"))

    investigation = state.get("investigation_result", {})
    alert = state.get("alert_data", {})

    # Analyze threat
    threat_type = _classify_threat(alert)
    mitre_mapping = _map_to_mitre(alert)

    # Calculate impact
    affected_assets = investigation.get("affected_assets", [])
    impact_score = min(10.0, len(affected_assets) * 2 + state.get("severity", 5.0))

    # Determine if human approval needed
    requires_approval = impact_score >= 7.0 or state.get("severity", 5.0) >= 9.0

    analysis_result = {
        "threat_type": threat_type,
        "mitre_techniques": mitre_mapping,
        "impact_score": impact_score,
        "affected_assets": affected_assets,
        "root_cause": "Under investigation",
        "recommendations": _generate_recommendations(threat_type, impact_score),
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {
        **state,
        "current_stage": OrchestrationStage.RESPONSE_PLANNING,
        "analysis_result": analysis_result,
        "severity": max(state.get("severity", 5.0), impact_score),
        "requires_human_approval": requires_approval,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.ANALYSIS.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": analysis_result,
        }],
    }


def response_planning_node(state: OrchestrationState) -> OrchestrationState:
    """Plan response actions."""
    logger.info("response_planning_node", incident_id=state.get("incident_id"))

    analysis = state.get("analysis_result", {})

    # Generate response plan
    actions = []
    threat_type = analysis.get("threat_type", "unknown")

    # Containment actions
    if threat_type in ["malware", "ransomware"]:
        actions.append({
            "action_type": "isolate_host",
            "target": analysis.get("affected_assets", []),
            "risk_level": "medium",
            "reversible": True,
        })

    if threat_type in ["credential_theft", "unauthorized_access"]:
        actions.append({
            "action_type": "disable_account",
            "target": [],
            "risk_level": "low",
            "reversible": True,
        })

    # Block indicators
    actions.append({
        "action_type": "block_indicators",
        "target": analysis.get("mitre_techniques", []),
        "risk_level": "low",
        "reversible": True,
    })

    response_plan = {
        "actions": actions,
        "total_actions": len(actions),
        "estimated_duration_seconds": len(actions) * 30,
        "requires_approval": state.get("requires_human_approval", False),
        "timestamp": datetime.utcnow().isoformat(),
    }

    next_stage = (
        OrchestrationStage.APPROVAL
        if state.get("requires_human_approval")
        else OrchestrationStage.EXECUTION
    )

    return {
        **state,
        "current_stage": next_stage,
        "response_plan": response_plan,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.RESPONSE_PLANNING.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": response_plan,
        }],
    }


def approval_node(state: OrchestrationState) -> OrchestrationState:
    """Wait for human approval."""
    logger.info("approval_node", incident_id=state.get("incident_id"))

    # In a real system, this would wait for human input
    # For now, auto-approve low-risk actions
    response_plan = state.get("response_plan", {})
    actions = response_plan.get("actions", [])

    # Auto-approve if all actions are low risk
    all_low_risk = all(a.get("risk_level") == "low" for a in actions)

    return {
        **state,
        "current_stage": OrchestrationStage.EXECUTION,
        "is_approved": all_low_risk,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.APPROVAL.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": {"approved": all_low_risk, "auto_approved": all_low_risk},
        }],
    }


def execution_node(state: OrchestrationState) -> OrchestrationState:
    """Execute response actions."""
    logger.info("execution_node", incident_id=state.get("incident_id"))

    response_plan = state.get("response_plan", {})
    actions = response_plan.get("actions", [])

    # Execute actions (simulated)
    executed = []
    for action in actions:
        executed.append({
            **action,
            "status": "completed",
            "executed_at": datetime.utcnow().isoformat(),
        })

    execution_result = {
        "actions_executed": executed,
        "total_executed": len(executed),
        "total_failed": 0,
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {
        **state,
        "current_stage": OrchestrationStage.VALIDATION,
        "execution_result": execution_result,
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.EXECUTION.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": execution_result,
        }],
    }


def validation_node(state: OrchestrationState) -> OrchestrationState:
    """Validate response effectiveness."""
    logger.info("validation_node", incident_id=state.get("incident_id"))

    execution = state.get("execution_result", {})

    # Validate (simulated)
    validation_result = {
        "threat_contained": True,
        "systems_operational": True,
        "effectiveness_score": 0.85,
        "follow_up_required": False,
        "timestamp": datetime.utcnow().isoformat(),
    }

    return {
        **state,
        "current_stage": OrchestrationStage.COMPLETE,
        "validation_result": validation_result,
        "completed_at": datetime.utcnow().isoformat(),
        "stage_history": state.get("stage_history", []) + [{
            "stage": OrchestrationStage.VALIDATION.value,
            "timestamp": datetime.utcnow().isoformat(),
            "result": validation_result,
        }],
    }


def error_handler_node(state: OrchestrationState) -> OrchestrationState:
    """Handle errors in the workflow."""
    logger.error("error_handler_node", incident_id=state.get("incident_id"), error=state.get("error"))

    retry_count = state.get("retry_count", 0)
    max_retries = state.get("max_retries", 3)

    should_retry = retry_count < max_retries

    return {
        **state,
        "should_retry": should_retry,
        "retry_count": retry_count + 1,
    }


# Routing functions
def route_after_triage(state: OrchestrationState) -> Literal["investigation_node", "complete"]:
    """Route after triage based on true positive determination."""
    if state.get("is_true_positive", True):
        return "investigation_node"
    return "complete"


def route_after_planning(state: OrchestrationState) -> Literal["approval_node", "execution_node"]:
    """Route after response planning."""
    if state.get("requires_human_approval", False):
        return "approval_node"
    return "execution_node"


def route_after_approval(state: OrchestrationState) -> Literal["execution_node", "complete"]:
    """Route after approval."""
    if state.get("is_approved", False):
        return "execution_node"
    return "complete"


def route_after_error(state: OrchestrationState) -> Literal["intake_node", "complete"]:
    """Route after error handling."""
    if state.get("should_retry", False):
        return "intake_node"
    return "complete"


# Helper functions
def _categorize_alert(alert_type: str) -> str:
    """Categorize alert type."""
    categories = {
        "malware": ["malware", "virus", "trojan", "ransomware"],
        "intrusion": ["intrusion", "breach", "unauthorized"],
        "credential": ["credential", "brute", "password"],
        "data": ["data", "exfil", "leak"],
        "network": ["network", "ddos", "scan"],
    }

    for category, keywords in categories.items():
        if any(kw in alert_type for kw in keywords):
            return category
    return "unknown"


def _extract_entities(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract entities from alert."""
    entities = []

    if "source_ip" in alert:
        entities.append({"type": "ip", "value": alert["source_ip"], "role": "source"})
    if "dest_ip" in alert:
        entities.append({"type": "ip", "value": alert["dest_ip"], "role": "destination"})
    if "user" in alert:
        entities.append({"type": "user", "value": alert["user"], "role": "actor"})
    if "hostname" in alert:
        entities.append({"type": "host", "value": alert["hostname"], "role": "asset"})

    return entities


def _extract_indicators(alert: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract indicators of compromise."""
    indicators = []

    if "file_hash" in alert:
        indicators.append({"type": "hash", "value": alert["file_hash"]})
    if "domain" in alert:
        indicators.append({"type": "domain", "value": alert["domain"]})
    if "url" in alert:
        indicators.append({"type": "url", "value": alert["url"]})

    return indicators


def _identify_assets(alert: dict[str, Any]) -> list[str]:
    """Identify affected assets."""
    assets = []

    if "hostname" in alert:
        assets.append(alert["hostname"])
    if "dest_ip" in alert:
        assets.append(alert["dest_ip"])

    return assets


def _classify_threat(alert: dict[str, Any]) -> str:
    """Classify threat type."""
    alert_type = alert.get("alert_type", "").lower()

    if "ransomware" in alert_type:
        return "ransomware"
    elif "malware" in alert_type:
        return "malware"
    elif "phishing" in alert_type:
        return "phishing"
    elif "credential" in alert_type or "brute" in alert_type:
        return "credential_theft"
    elif "exfil" in alert_type or "data" in alert_type:
        return "data_exfiltration"
    elif "unauthorized" in alert_type or "intrusion" in alert_type:
        return "unauthorized_access"

    return "unknown"


def _map_to_mitre(alert: dict[str, Any]) -> list[str]:
    """Map to MITRE ATT&CK techniques."""
    alert_type = alert.get("alert_type", "").lower()
    techniques = []

    if "ransomware" in alert_type:
        techniques.extend(["T1486", "T1490"])  # Data Encrypted, Inhibit System Recovery
    elif "malware" in alert_type:
        techniques.extend(["T1059", "T1105"])  # Command Execution, Ingress Tool Transfer
    elif "phishing" in alert_type:
        techniques.extend(["T1566", "T1204"])  # Phishing, User Execution
    elif "credential" in alert_type:
        techniques.extend(["T1110", "T1078"])  # Brute Force, Valid Accounts
    elif "exfil" in alert_type:
        techniques.extend(["T1041", "T1048"])  # Exfiltration Over C2, Exfiltration Over Alt Protocol

    return techniques


def _generate_recommendations(threat_type: str, impact_score: float) -> list[str]:
    """Generate response recommendations."""
    recommendations = []

    if threat_type == "ransomware":
        recommendations = [
            "Isolate affected systems immediately",
            "Disable network shares",
            "Check backup integrity",
            "Engage incident response team",
        ]
    elif threat_type == "malware":
        recommendations = [
            "Quarantine infected systems",
            "Run full antivirus scan",
            "Check for lateral movement",
        ]
    elif threat_type == "credential_theft":
        recommendations = [
            "Force password reset for affected accounts",
            "Enable MFA if not already",
            "Review authentication logs",
        ]
    elif threat_type == "data_exfiltration":
        recommendations = [
            "Block exfiltration endpoints",
            "Review data access logs",
            "Assess data sensitivity",
        ]
    else:
        recommendations = [
            "Continue monitoring",
            "Gather additional evidence",
        ]

    if impact_score >= 8.0:
        recommendations.insert(0, "CRITICAL: Escalate to senior management")

    return recommendations


def create_orchestration_graph() -> StateGraph:
    """Create the orchestration state graph.

    Returns:
        Compiled state graph
    """
    # Create graph
    graph = StateGraph(OrchestrationState)

    # Add nodes
    graph.add_node("intake_node", intake_node)
    graph.add_node("triage_node", triage_node)
    graph.add_node("investigation_node", investigation_node)
    graph.add_node("analysis_node", analysis_node)
    graph.add_node("response_planning_node", response_planning_node)
    graph.add_node("approval_node", approval_node)
    graph.add_node("execution_node", execution_node)
    graph.add_node("validation_node", validation_node)
    graph.add_node("error_handler_node", error_handler_node)

    # Add edges
    graph.set_entry_point("intake_node")
    graph.add_edge("intake_node", "triage_node")
    graph.add_conditional_edges("triage_node", route_after_triage)
    graph.add_edge("investigation_node", "analysis_node")
    graph.add_edge("analysis_node", "response_planning_node")
    graph.add_conditional_edges("response_planning_node", route_after_planning)
    graph.add_conditional_edges("approval_node", route_after_approval)
    graph.add_edge("execution_node", "validation_node")
    graph.add_edge("validation_node", END)
    graph.add_conditional_edges("error_handler_node", route_after_error)

    return graph.compile()
