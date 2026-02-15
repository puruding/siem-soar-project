"""Playbook recommendation engine for automated response."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TriggerType(str, Enum):
    """Playbook trigger types."""

    ALERT = "alert"
    INCIDENT = "incident"
    MANUAL = "manual"
    SCHEDULED = "scheduled"


class PlaybookCategory(str, Enum):
    """Playbook categories."""

    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    INVESTIGATION = "investigation"
    ENRICHMENT = "enrichment"
    NOTIFICATION = "notification"
    REMEDIATION = "remediation"


class PlaybookInfo(BaseModel):
    """Playbook information."""

    playbook_id: str = Field(description="Playbook unique ID")
    name: str = Field(description="Playbook name")
    description: str = Field(description="Playbook description")
    category: PlaybookCategory = Field(description="Playbook category")
    trigger_type: TriggerType = Field(description="Trigger type")
    applicable_alert_types: list[str] = Field(default_factory=list)
    applicable_severity: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    success_rate: float = Field(default=0.0, ge=0, le=1)
    avg_execution_time: int = Field(default=0, description="Average execution time in seconds")
    enabled: bool = Field(default=True)


class PlaybookRecommendation(BaseModel):
    """Playbook recommendation result."""

    playbook: PlaybookInfo = Field(description="Recommended playbook")
    confidence: float = Field(ge=0, le=1, description="Recommendation confidence")
    match_reasons: list[str] = Field(default_factory=list, description="Reasons for recommendation")
    estimated_impact: str = Field(description="Estimated impact")
    prerequisites: list[str] = Field(default_factory=list, description="Prerequisites to run")
    warnings: list[str] = Field(default_factory=list, description="Warnings or caveats")
    auto_execute: bool = Field(default=False, description="Can be auto-executed")


class RecommendationConfig(BaseModel):
    """Configuration for playbook recommendation."""

    max_recommendations: int = Field(default=5)
    min_confidence: float = Field(default=0.5, ge=0, le=1)
    include_disabled: bool = Field(default=False)
    prefer_high_success_rate: bool = Field(default=True)
    category_filter: list[PlaybookCategory] | None = Field(default=None)
    require_auto_executable: bool = Field(default=False)


class PlaybookRecommender(LoggerMixin):
    """LLM-enhanced playbook recommendation engine.

    Features:
    - Content-based matching (alert type, severity, MITRE mapping)
    - LLM-based semantic matching
    - Historical success rate consideration
    - Context-aware recommendations
    - Multi-step playbook orchestration
    """

    SYSTEM_PROMPT = """You are a security automation expert. Given an incident context and available playbooks,
recommend the most appropriate playbooks for automated response.

Consider:
1. Alert type and severity
2. MITRE ATT&CK tactics and techniques
3. Playbook success rates
4. Execution prerequisites
5. Potential impact and risks

Provide recommendations in order of relevance."""

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
    ) -> None:
        """Initialize the recommender.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model for semantic matching
            api_key: API key
        """
        self.llm_endpoint = llm_endpoint or "http://localhost:8080/v1"
        self.model_name = model_name
        self.api_key = api_key

        # Playbook registry
        self._playbooks: dict[str, PlaybookInfo] = {}
        self._client: httpx.AsyncClient | None = None

        # Load default playbooks
        self._load_default_playbooks()

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

    def register_playbook(self, playbook: PlaybookInfo) -> None:
        """Register a playbook.

        Args:
            playbook: Playbook to register
        """
        self._playbooks[playbook.playbook_id] = playbook
        self.logger.info("playbook_registered", playbook_id=playbook.playbook_id)

    def _load_default_playbooks(self) -> None:
        """Load default SIEM/SOAR playbooks."""
        default_playbooks = [
            PlaybookInfo(
                playbook_id="pb-001",
                name="Block Malicious IP",
                description="Block a malicious IP address on firewall and update threat intelligence",
                category=PlaybookCategory.CONTAINMENT,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["intrusion", "c2_communication", "port_scan"],
                applicable_severity=["high", "critical"],
                mitre_tactics=["Command and Control", "Initial Access"],
                steps=[
                    {"action": "validate_ip", "description": "Validate IP is external"},
                    {"action": "check_whitelist", "description": "Verify not in whitelist"},
                    {"action": "block_firewall", "description": "Add to firewall block list"},
                    {"action": "update_threat_intel", "description": "Add to threat intelligence"},
                    {"action": "notify_team", "description": "Send notification"},
                ],
                success_rate=0.92,
                avg_execution_time=45,
            ),
            PlaybookInfo(
                playbook_id="pb-002",
                name="Isolate Compromised Host",
                description="Network isolation of a potentially compromised endpoint",
                category=PlaybookCategory.CONTAINMENT,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["malware", "ransomware", "lateral_movement"],
                applicable_severity=["critical"],
                mitre_tactics=["Execution", "Lateral Movement"],
                steps=[
                    {"action": "verify_host", "description": "Verify host exists and is active"},
                    {"action": "snapshot_state", "description": "Take system snapshot"},
                    {"action": "isolate_network", "description": "Isolate from network via EDR"},
                    {"action": "collect_artifacts", "description": "Collect forensic artifacts"},
                    {"action": "notify_soc", "description": "Alert SOC team"},
                ],
                success_rate=0.88,
                avg_execution_time=120,
            ),
            PlaybookInfo(
                playbook_id="pb-003",
                name="Enrich IOC",
                description="Enrich indicators of compromise with threat intelligence",
                category=PlaybookCategory.ENRICHMENT,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["any"],
                applicable_severity=["low", "medium", "high", "critical"],
                steps=[
                    {"action": "extract_iocs", "description": "Extract IOCs from alert"},
                    {"action": "query_virustotal", "description": "Check VirusTotal"},
                    {"action": "query_shodan", "description": "Check Shodan for IPs"},
                    {"action": "query_otx", "description": "Check AlienVault OTX"},
                    {"action": "update_alert", "description": "Update alert with enrichment"},
                ],
                success_rate=0.95,
                avg_execution_time=30,
            ),
            PlaybookInfo(
                playbook_id="pb-004",
                name="Disable Compromised Account",
                description="Disable a potentially compromised user account",
                category=PlaybookCategory.CONTAINMENT,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["brute_force", "credential_theft", "suspicious_login"],
                applicable_severity=["high", "critical"],
                mitre_tactics=["Credential Access", "Initial Access"],
                steps=[
                    {"action": "verify_account", "description": "Verify account exists"},
                    {"action": "check_vip", "description": "Check if VIP/critical account"},
                    {"action": "disable_ad", "description": "Disable in Active Directory"},
                    {"action": "revoke_sessions", "description": "Revoke active sessions"},
                    {"action": "notify_user", "description": "Notify user and manager"},
                ],
                success_rate=0.90,
                avg_execution_time=60,
            ),
            PlaybookInfo(
                playbook_id="pb-005",
                name="Phishing Response",
                description="Comprehensive phishing incident response",
                category=PlaybookCategory.REMEDIATION,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["phishing", "spam", "malicious_email"],
                applicable_severity=["medium", "high", "critical"],
                mitre_tactics=["Initial Access"],
                mitre_techniques=["T1566"],
                steps=[
                    {"action": "quarantine_email", "description": "Quarantine phishing email"},
                    {"action": "identify_recipients", "description": "Find all recipients"},
                    {"action": "check_clicks", "description": "Check if links were clicked"},
                    {"action": "block_sender", "description": "Block sender domain"},
                    {"action": "scan_attachments", "description": "Sandbox attachments"},
                    {"action": "notify_users", "description": "Send awareness notification"},
                ],
                success_rate=0.87,
                avg_execution_time=180,
            ),
            PlaybookInfo(
                playbook_id="pb-006",
                name="Malware Triage",
                description="Initial malware analysis and triage",
                category=PlaybookCategory.INVESTIGATION,
                trigger_type=TriggerType.ALERT,
                applicable_alert_types=["malware", "suspicious_file", "av_detection"],
                applicable_severity=["medium", "high", "critical"],
                mitre_tactics=["Execution"],
                steps=[
                    {"action": "get_file_hash", "description": "Calculate file hashes"},
                    {"action": "check_signatures", "description": "Check AV signatures"},
                    {"action": "sandbox_analysis", "description": "Submit to sandbox"},
                    {"action": "yara_scan", "description": "Run YARA rules"},
                    {"action": "create_ioc", "description": "Create IOC entry"},
                ],
                success_rate=0.91,
                avg_execution_time=300,
            ),
            PlaybookInfo(
                playbook_id="pb-007",
                name="Incident Escalation",
                description="Escalate incident to appropriate team",
                category=PlaybookCategory.NOTIFICATION,
                trigger_type=TriggerType.INCIDENT,
                applicable_alert_types=["any"],
                applicable_severity=["high", "critical"],
                steps=[
                    {"action": "determine_team", "description": "Identify escalation team"},
                    {"action": "create_ticket", "description": "Create incident ticket"},
                    {"action": "send_notification", "description": "Send escalation notice"},
                    {"action": "schedule_bridge", "description": "Schedule incident bridge"},
                ],
                success_rate=0.99,
                avg_execution_time=15,
            ),
        ]

        for pb in default_playbooks:
            self._playbooks[pb.playbook_id] = pb

    async def recommend(
        self,
        context: dict[str, Any],
        config: RecommendationConfig | None = None,
    ) -> list[PlaybookRecommendation]:
        """Recommend playbooks for given context.

        Args:
            context: Alert/incident context including type, severity, IOCs, etc.
            config: Recommendation configuration

        Returns:
            List of playbook recommendations ordered by confidence
        """
        config = config or RecommendationConfig()

        self.logger.info(
            "recommending_playbooks",
            context_id=context.get("id"),
            alert_type=context.get("alert_type"),
        )

        # Get candidate playbooks
        candidates = self._get_candidates(context, config)

        if not candidates:
            self.logger.warning("no_candidate_playbooks")
            return []

        # Score playbooks
        scored = []
        for playbook in candidates:
            score, reasons = self._calculate_score(playbook, context)
            if score >= config.min_confidence:
                scored.append((playbook, score, reasons))

        # Sort by score
        scored.sort(key=lambda x: x[1], reverse=True)

        # Optionally enhance with LLM
        if len(scored) > 1:
            try:
                scored = await self._llm_rerank(scored, context)
            except Exception as e:
                self.logger.warning("llm_rerank_failed", error=str(e))

        # Build recommendations
        recommendations = []
        for playbook, score, reasons in scored[:config.max_recommendations]:
            recommendation = self._build_recommendation(playbook, score, reasons, context)
            recommendations.append(recommendation)

        return recommendations

    def _get_candidates(
        self,
        context: dict[str, Any],
        config: RecommendationConfig,
    ) -> list[PlaybookInfo]:
        """Get candidate playbooks based on filters."""
        candidates = []

        for playbook in self._playbooks.values():
            # Filter by enabled status
            if not config.include_disabled and not playbook.enabled:
                continue

            # Filter by category
            if config.category_filter and playbook.category not in config.category_filter:
                continue

            # Basic relevance check
            if self._is_potentially_relevant(playbook, context):
                candidates.append(playbook)

        return candidates

    def _is_potentially_relevant(self, playbook: PlaybookInfo, context: dict[str, Any]) -> bool:
        """Check if playbook is potentially relevant."""
        alert_type = context.get("alert_type", "").lower()
        severity = context.get("severity", "").lower()

        # Check alert type match
        if playbook.applicable_alert_types:
            if "any" not in playbook.applicable_alert_types:
                if not any(at.lower() in alert_type for at in playbook.applicable_alert_types):
                    return False

        # Check severity match
        if playbook.applicable_severity:
            if severity not in playbook.applicable_severity:
                return False

        return True

    def _calculate_score(
        self,
        playbook: PlaybookInfo,
        context: dict[str, Any],
    ) -> tuple[float, list[str]]:
        """Calculate playbook match score."""
        score = 0.0
        reasons = []

        # Alert type match (0.3)
        alert_type = context.get("alert_type", "").lower()
        for at in playbook.applicable_alert_types:
            if at.lower() in alert_type or alert_type in at.lower():
                score += 0.3
                reasons.append(f"Alert type match: {at}")
                break

        # Severity match (0.2)
        severity = context.get("severity", "").lower()
        if severity in playbook.applicable_severity:
            score += 0.2
            reasons.append(f"Severity match: {severity}")

        # MITRE tactic match (0.2)
        context_tactics = set(t.lower() for t in context.get("mitre_tactics", []))
        playbook_tactics = set(t.lower() for t in playbook.mitre_tactics)
        if context_tactics & playbook_tactics:
            score += 0.2
            matching = context_tactics & playbook_tactics
            reasons.append(f"MITRE tactic match: {', '.join(matching)}")

        # MITRE technique match (0.15)
        context_techniques = set(context.get("mitre_techniques", []))
        playbook_techniques = set(playbook.mitre_techniques)
        if context_techniques & playbook_techniques:
            score += 0.15
            matching = context_techniques & playbook_techniques
            reasons.append(f"MITRE technique match: {', '.join(matching)}")

        # Success rate bonus (0.15)
        if playbook.success_rate >= 0.9:
            score += 0.15
            reasons.append(f"High success rate: {playbook.success_rate:.0%}")
        elif playbook.success_rate >= 0.8:
            score += 0.1
            reasons.append(f"Good success rate: {playbook.success_rate:.0%}")

        return min(score, 1.0), reasons

    async def _llm_rerank(
        self,
        scored: list[tuple[PlaybookInfo, float, list[str]]],
        context: dict[str, Any],
    ) -> list[tuple[PlaybookInfo, float, list[str]]]:
        """Use LLM to rerank playbooks."""
        client = await self._get_client()

        # Build context description
        context_desc = f"""
Incident Context:
- Alert Type: {context.get('alert_type', 'Unknown')}
- Severity: {context.get('severity', 'Unknown')}
- Description: {context.get('description', 'N/A')[:200]}
- MITRE Tactics: {', '.join(context.get('mitre_tactics', []))}
- IOCs: {len(context.get('iocs', []))} indicators
"""

        # Build playbook list
        playbook_list = "\n".join([
            f"{i+1}. {pb.name} ({pb.category.value}) - {pb.description[:100]}"
            for i, (pb, _, _) in enumerate(scored[:10])
        ])

        prompt = f"""
{context_desc}

Available Playbooks:
{playbook_list}

Rank these playbooks from most to least appropriate for this incident.
Respond with just the numbers in order, e.g., "3, 1, 5, 2, 4"
"""

        try:
            response = await client.post(
                f"{self.llm_endpoint}/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 50,
                    "temperature": 0.0,
                },
            )
            response.raise_for_status()

            # Parse ranking
            content = response.json()["choices"][0]["message"]["content"]
            import re
            numbers = [int(n) - 1 for n in re.findall(r"\d+", content)]

            # Reorder
            reranked = []
            seen = set()
            for idx in numbers:
                if 0 <= idx < len(scored) and idx not in seen:
                    seen.add(idx)
                    pb, score, reasons = scored[idx]
                    # Adjust score based on LLM ranking
                    adjusted_score = score + (0.1 * (len(numbers) - len(reranked)) / len(numbers))
                    reranked.append((pb, min(adjusted_score, 1.0), reasons))

            # Add any missing
            for i, item in enumerate(scored):
                if i not in seen:
                    reranked.append(item)

            return reranked

        except Exception as e:
            self.logger.warning("llm_rerank_error", error=str(e))
            return scored

    def _build_recommendation(
        self,
        playbook: PlaybookInfo,
        score: float,
        reasons: list[str],
        context: dict[str, Any],
    ) -> PlaybookRecommendation:
        """Build a recommendation object."""
        # Determine prerequisites
        prerequisites = []
        if "isolate" in playbook.name.lower():
            prerequisites.append("EDR agent must be active on target host")
        if "block" in playbook.name.lower():
            prerequisites.append("Firewall API access configured")
        if "disable" in playbook.name.lower():
            prerequisites.append("Active Directory integration enabled")

        # Determine warnings
        warnings = []
        if playbook.category == PlaybookCategory.CONTAINMENT:
            warnings.append("This action may impact business operations")
        if context.get("severity") == "critical":
            warnings.append("Critical severity - consider manual approval")

        # Estimate impact
        if playbook.category == PlaybookCategory.CONTAINMENT:
            impact = "High - Will isolate or block resources"
        elif playbook.category == PlaybookCategory.ENRICHMENT:
            impact = "Low - Read-only operations"
        elif playbook.category == PlaybookCategory.NOTIFICATION:
            impact = "Low - Notification only"
        else:
            impact = "Medium - Mixed operations"

        # Determine if auto-executable
        auto_execute = (
            score >= 0.9 and
            playbook.success_rate >= 0.9 and
            playbook.category in [PlaybookCategory.ENRICHMENT, PlaybookCategory.NOTIFICATION]
        )

        return PlaybookRecommendation(
            playbook=playbook,
            confidence=score,
            match_reasons=reasons,
            estimated_impact=impact,
            prerequisites=prerequisites,
            warnings=warnings,
            auto_execute=auto_execute,
        )

    async def get_playbook_details(self, playbook_id: str) -> PlaybookInfo | None:
        """Get detailed playbook information.

        Args:
            playbook_id: Playbook ID

        Returns:
            Playbook info or None
        """
        return self._playbooks.get(playbook_id)

    async def update_playbook_stats(
        self,
        playbook_id: str,
        execution_success: bool,
        execution_time: int,
    ) -> None:
        """Update playbook statistics after execution.

        Args:
            playbook_id: Playbook ID
            execution_success: Whether execution was successful
            execution_time: Execution time in seconds
        """
        if playbook := self._playbooks.get(playbook_id):
            # Update success rate (exponential moving average)
            alpha = 0.1
            new_value = 1.0 if execution_success else 0.0
            playbook.success_rate = alpha * new_value + (1 - alpha) * playbook.success_rate

            # Update average execution time
            playbook.avg_execution_time = int(
                alpha * execution_time + (1 - alpha) * playbook.avg_execution_time
            )

            self.logger.info(
                "playbook_stats_updated",
                playbook_id=playbook_id,
                success_rate=playbook.success_rate,
            )
