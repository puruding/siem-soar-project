"""Action suggester for incident response recommendations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ActionPriority(str, Enum):
    """Action priority levels."""

    CRITICAL = "critical"  # Do immediately
    HIGH = "high"  # Do within 1 hour
    MEDIUM = "medium"  # Do within 4 hours
    LOW = "low"  # Do within 24 hours
    OPTIONAL = "optional"  # Nice to have


class ActionCategory(str, Enum):
    """Categories of response actions."""

    IMMEDIATE = "immediate"
    CONTAINMENT = "containment"
    INVESTIGATION = "investigation"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    LESSONS_LEARNED = "lessons_learned"


class ActionStatus(str, Enum):
    """Action execution status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class SuggestedAction(BaseModel):
    """Suggested response action."""

    action_id: str = Field(description="Unique action ID")
    title: str = Field(description="Action title")
    description: str = Field(description="Detailed description")
    category: ActionCategory = Field(description="Action category")
    priority: ActionPriority = Field(description="Action priority")
    estimated_time: int = Field(description="Estimated time in minutes")
    automation_available: bool = Field(default=False)
    playbook_id: str | None = Field(default=None, description="Related playbook")
    prerequisites: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list, description="Dependent action IDs")
    tools_required: list[str] = Field(default_factory=list)
    mitre_mapping: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(ge=0, le=1, default=0.8)


class ActionPlan(BaseModel):
    """Complete action plan for incident response."""

    plan_id: str = Field(description="Plan unique ID")
    incident_id: str = Field(description="Related incident ID")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    actions: list[SuggestedAction] = Field(default_factory=list)
    total_estimated_time: int = Field(description="Total estimated time in minutes")
    risk_assessment: str = Field(description="Overall risk assessment")
    notes: list[str] = Field(default_factory=list)


class ActionSuggester(LoggerMixin):
    """LLM-enhanced action suggestion engine.

    Provides intelligent response action recommendations based on:
    - Incident type and severity
    - MITRE ATT&CK framework
    - Historical case data
    - Available automation capabilities
    - Organizational context
    """

    SYSTEM_PROMPT = """You are a security incident response expert. Suggest appropriate response actions
for security incidents based on the given context.

For each action, provide:
1. Clear, actionable title
2. Detailed steps
3. Priority level
4. Estimated time
5. Prerequisites
6. Required tools

Order actions by priority and dependencies."""

    # Standard response actions by incident type
    STANDARD_ACTIONS = {
        "malware": [
            SuggestedAction(
                action_id="mal-001",
                title="Isolate Infected System",
                description="Immediately isolate the infected system from the network to prevent spread",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.CRITICAL,
                estimated_time=5,
                automation_available=True,
                playbook_id="pb-002",
                tools_required=["EDR", "Network Security"],
            ),
            SuggestedAction(
                action_id="mal-002",
                title="Collect Memory Dump",
                description="Capture volatile memory for forensic analysis before shutdown",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=15,
                dependencies=["mal-001"],
                tools_required=["Forensic toolkit"],
            ),
            SuggestedAction(
                action_id="mal-003",
                title="Identify Malware Family",
                description="Analyze malware samples to identify family and capabilities",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=30,
                automation_available=True,
                playbook_id="pb-006",
                tools_required=["Sandbox", "YARA"],
            ),
            SuggestedAction(
                action_id="mal-004",
                title="Scan for Lateral Movement",
                description="Search for signs of lateral movement to other systems",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=60,
                tools_required=["EDR", "SIEM"],
            ),
            SuggestedAction(
                action_id="mal-005",
                title="Remove Malware",
                description="Remove malware from affected systems using appropriate tools",
                category=ActionCategory.ERADICATION,
                priority=ActionPriority.HIGH,
                estimated_time=30,
                dependencies=["mal-003"],
                tools_required=["AV/EDR"],
            ),
        ],
        "brute_force": [
            SuggestedAction(
                action_id="bf-001",
                title="Block Source IP",
                description="Block the attacking IP address at firewall level",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.CRITICAL,
                estimated_time=2,
                automation_available=True,
                playbook_id="pb-001",
                tools_required=["Firewall"],
            ),
            SuggestedAction(
                action_id="bf-002",
                title="Reset Affected Accounts",
                description="Force password reset for targeted accounts",
                category=ActionCategory.CONTAINMENT,
                priority=ActionPriority.HIGH,
                estimated_time=10,
                automation_available=True,
                playbook_id="pb-004",
                tools_required=["Active Directory"],
            ),
            SuggestedAction(
                action_id="bf-003",
                title="Enable Account Lockout",
                description="Ensure account lockout policy is enabled and properly configured",
                category=ActionCategory.CONTAINMENT,
                priority=ActionPriority.HIGH,
                estimated_time=15,
                tools_required=["Active Directory"],
            ),
            SuggestedAction(
                action_id="bf-004",
                title="Review Authentication Logs",
                description="Analyze authentication logs for successful compromises",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=30,
                tools_required=["SIEM"],
            ),
        ],
        "phishing": [
            SuggestedAction(
                action_id="ph-001",
                title="Quarantine Phishing Email",
                description="Remove phishing email from all mailboxes",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.CRITICAL,
                estimated_time=5,
                automation_available=True,
                playbook_id="pb-005",
                tools_required=["Email Security"],
            ),
            SuggestedAction(
                action_id="ph-002",
                title="Block Sender Domain",
                description="Block the phishing sender domain/address",
                category=ActionCategory.CONTAINMENT,
                priority=ActionPriority.HIGH,
                estimated_time=5,
                automation_available=True,
                tools_required=["Email Security"],
            ),
            SuggestedAction(
                action_id="ph-003",
                title="Identify Victims",
                description="Identify users who clicked links or opened attachments",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=20,
                tools_required=["Email Security", "SIEM"],
            ),
            SuggestedAction(
                action_id="ph-004",
                title="Scan Victim Systems",
                description="Scan systems of users who interacted with phishing content",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=30,
                dependencies=["ph-003"],
                tools_required=["EDR"],
            ),
            SuggestedAction(
                action_id="ph-005",
                title="User Awareness Notification",
                description="Send notification to all users about phishing campaign",
                category=ActionCategory.RECOVERY,
                priority=ActionPriority.MEDIUM,
                estimated_time=15,
                automation_available=True,
                tools_required=["Email"],
            ),
        ],
        "data_breach": [
            SuggestedAction(
                action_id="db-001",
                title="Identify Breach Scope",
                description="Determine what data was accessed or exfiltrated",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.CRITICAL,
                estimated_time=60,
                tools_required=["SIEM", "DLP"],
            ),
            SuggestedAction(
                action_id="db-002",
                title="Contain Breach",
                description="Stop ongoing data exfiltration if still active",
                category=ActionCategory.CONTAINMENT,
                priority=ActionPriority.CRITICAL,
                estimated_time=15,
                tools_required=["Firewall", "DLP"],
            ),
            SuggestedAction(
                action_id="db-003",
                title="Preserve Evidence",
                description="Collect and preserve forensic evidence",
                category=ActionCategory.INVESTIGATION,
                priority=ActionPriority.HIGH,
                estimated_time=120,
                tools_required=["Forensic toolkit"],
            ),
            SuggestedAction(
                action_id="db-004",
                title="Notify Legal Team",
                description="Inform legal team for compliance and notification requirements",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.HIGH,
                estimated_time=5,
                tools_required=["Communication"],
            ),
            SuggestedAction(
                action_id="db-005",
                title="Prepare Notification",
                description="Prepare data breach notification for affected parties",
                category=ActionCategory.RECOVERY,
                priority=ActionPriority.HIGH,
                estimated_time=240,
                dependencies=["db-001", "db-004"],
                tools_required=["Communication", "Legal"],
            ),
        ],
    }

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
    ) -> None:
        """Initialize the suggester.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model name
            api_key: API key
        """
        self.llm_endpoint = llm_endpoint or "http://localhost:8080/v1"
        self.model_name = model_name
        self.api_key = api_key
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
                headers={
                    "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def suggest_actions(
        self,
        incident_context: dict[str, Any],
        max_actions: int = 10,
        include_optional: bool = True,
    ) -> ActionPlan:
        """Suggest response actions for an incident.

        Args:
            incident_context: Incident data including type, severity, IOCs, etc.
            max_actions: Maximum number of actions to suggest
            include_optional: Include optional actions

        Returns:
            Action plan with suggested actions
        """
        self.logger.info(
            "suggesting_actions",
            incident_id=incident_context.get("id"),
            incident_type=incident_context.get("type"),
        )

        # Get standard actions for incident type
        incident_type = self._normalize_incident_type(incident_context)
        base_actions = self._get_standard_actions(incident_type)

        # Customize based on context
        customized_actions = self._customize_actions(base_actions, incident_context)

        # Enhance with LLM suggestions
        try:
            additional_actions = await self._llm_suggest_actions(incident_context, customized_actions)
            customized_actions.extend(additional_actions)
        except Exception as e:
            self.logger.warning("llm_suggestion_failed", error=str(e))

        # Filter and sort
        if not include_optional:
            customized_actions = [a for a in customized_actions if a.priority != ActionPriority.OPTIONAL]

        customized_actions = self._sort_actions(customized_actions)
        customized_actions = customized_actions[:max_actions]

        # Calculate totals
        total_time = sum(a.estimated_time for a in customized_actions)

        # Risk assessment
        risk = self._assess_risk(incident_context)

        return ActionPlan(
            plan_id=f"plan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            incident_id=incident_context.get("id", "unknown"),
            actions=customized_actions,
            total_estimated_time=total_time,
            risk_assessment=risk,
        )

    def _normalize_incident_type(self, context: dict[str, Any]) -> str:
        """Normalize incident type from various fields."""
        # Try different fields
        incident_type = (
            context.get("type") or
            context.get("incident_type") or
            context.get("alert_type") or
            ""
        ).lower()

        # Map to standard types
        type_mapping = {
            "malware": "malware",
            "ransomware": "malware",
            "virus": "malware",
            "trojan": "malware",
            "brute": "brute_force",
            "brute_force": "brute_force",
            "credential": "brute_force",
            "phishing": "phishing",
            "spam": "phishing",
            "email": "phishing",
            "breach": "data_breach",
            "exfiltration": "data_breach",
            "data_leak": "data_breach",
        }

        for keyword, mapped_type in type_mapping.items():
            if keyword in incident_type:
                return mapped_type

        return "generic"

    def _get_standard_actions(self, incident_type: str) -> list[SuggestedAction]:
        """Get standard actions for incident type."""
        actions = self.STANDARD_ACTIONS.get(incident_type, [])

        # Always include generic investigation actions
        generic_actions = [
            SuggestedAction(
                action_id="gen-001",
                title="Document Initial Findings",
                description="Record initial observations and timeline of discovery",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.HIGH,
                estimated_time=10,
            ),
            SuggestedAction(
                action_id="gen-002",
                title="Assign Incident Owner",
                description="Designate primary incident responder",
                category=ActionCategory.IMMEDIATE,
                priority=ActionPriority.HIGH,
                estimated_time=5,
            ),
        ]

        return list(actions) + generic_actions

    def _customize_actions(
        self,
        actions: list[SuggestedAction],
        context: dict[str, Any],
    ) -> list[SuggestedAction]:
        """Customize actions based on context."""
        customized = []
        severity = context.get("severity", "").lower()

        for action in actions:
            # Clone action
            customized_action = action.model_copy()

            # Adjust priority based on severity
            if severity == "critical":
                if action.priority == ActionPriority.MEDIUM:
                    customized_action.priority = ActionPriority.HIGH
                elif action.priority == ActionPriority.LOW:
                    customized_action.priority = ActionPriority.MEDIUM

            # Add context-specific details
            if context.get("affected_assets"):
                customized_action.description += f" (Affected: {', '.join(context['affected_assets'][:3])})"

            customized.append(customized_action)

        return customized

    async def _llm_suggest_actions(
        self,
        context: dict[str, Any],
        existing_actions: list[SuggestedAction],
    ) -> list[SuggestedAction]:
        """Use LLM to suggest additional actions."""
        client = await self._get_client()

        # Build context description
        context_desc = f"""
Incident Type: {context.get('type', 'Unknown')}
Severity: {context.get('severity', 'Unknown')}
Description: {context.get('description', 'N/A')[:200]}
Affected Systems: {', '.join(context.get('affected_assets', [])[:5])}
IOCs Found: {len(context.get('iocs', []))}
"""

        existing_titles = [a.title for a in existing_actions]
        prompt = f"""
{context_desc}

Existing planned actions:
{chr(10).join(f"- {t}" for t in existing_titles)}

Suggest 2-3 additional response actions that are NOT already in the list.
For each action, provide:
1. Title (one line)
2. Description (one sentence)
3. Priority (critical/high/medium/low)

Format: Title | Description | Priority
"""

        response = await client.post(
            f"{self.llm_endpoint}/chat/completions",
            json={
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "max_tokens": 300,
                "temperature": 0.3,
            },
        )
        response.raise_for_status()

        content = response.json()["choices"][0]["message"]["content"]

        # Parse suggestions
        additional_actions = []
        for line in content.split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 3:
                    title = parts[0].strip()
                    description = parts[1].strip()
                    priority_str = parts[2].strip().lower()

                    priority_map = {
                        "critical": ActionPriority.CRITICAL,
                        "high": ActionPriority.HIGH,
                        "medium": ActionPriority.MEDIUM,
                        "low": ActionPriority.LOW,
                    }
                    priority = priority_map.get(priority_str, ActionPriority.MEDIUM)

                    additional_actions.append(SuggestedAction(
                        action_id=f"llm-{len(additional_actions)+1:03d}",
                        title=title,
                        description=description,
                        category=ActionCategory.INVESTIGATION,
                        priority=priority,
                        estimated_time=30,
                        confidence=0.7,
                    ))

        return additional_actions[:3]

    def _sort_actions(self, actions: list[SuggestedAction]) -> list[SuggestedAction]:
        """Sort actions by priority and dependencies."""
        priority_order = {
            ActionPriority.CRITICAL: 0,
            ActionPriority.HIGH: 1,
            ActionPriority.MEDIUM: 2,
            ActionPriority.LOW: 3,
            ActionPriority.OPTIONAL: 4,
        }

        category_order = {
            ActionCategory.IMMEDIATE: 0,
            ActionCategory.CONTAINMENT: 1,
            ActionCategory.INVESTIGATION: 2,
            ActionCategory.ERADICATION: 3,
            ActionCategory.RECOVERY: 4,
            ActionCategory.LESSONS_LEARNED: 5,
        }

        def sort_key(action: SuggestedAction) -> tuple:
            return (
                priority_order.get(action.priority, 5),
                category_order.get(action.category, 5),
                len(action.dependencies),
            )

        return sorted(actions, key=sort_key)

    def _assess_risk(self, context: dict[str, Any]) -> str:
        """Assess incident risk level."""
        severity = context.get("severity", "").lower()
        affected_count = len(context.get("affected_assets", []))

        if severity == "critical" or affected_count > 10:
            return "Critical - Immediate executive attention required"
        elif severity == "high" or affected_count > 5:
            return "High - Escalate to security leadership"
        elif severity == "medium":
            return "Medium - Standard incident response procedures"
        else:
            return "Low - Monitor and document"
