"""Analyzer Agent - Main agent for security analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
from pydantic import Field

from common.models import BaseModel

from ..base import (
    AgentCapability,
    AgentConfig,
    AgentContext,
    AgentResult,
    AgentStatus,
    BaseAgent,
    ToolDefinition,
)
from ..memory import AgentMemory, MemoryType, MemoryImportance


class AnalyzerConfig(AgentConfig):
    """Configuration for Analyzer Agent."""

    llm_endpoint: str = Field(
        default="http://localhost:8080/v1",
        description="LLM API endpoint",
    )
    model_name: str = Field(
        default="solar-10.7b",
        description="LLM model name",
    )
    siem_endpoint: str = Field(default="http://localhost:8000/api/v1")
    enable_mitre_mapping: bool = Field(default=True)
    enable_root_cause: bool = Field(default=True)
    enable_impact_assessment: bool = Field(default=True)


class AnalysisResult(BaseModel):
    """Result of security analysis."""

    analysis_id: str = Field(description="Analysis ID")
    alert_id: str | None = Field(default=None)
    case_id: str | None = Field(default=None)

    # Root cause
    root_cause: dict[str, Any] | None = Field(default=None)
    cause_chain: list[dict[str, Any]] = Field(default_factory=list)

    # Impact
    impact_assessment: dict[str, Any] | None = Field(default=None)
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)

    # Classification
    threat_classification: dict[str, Any] | None = Field(default=None)
    mitre_mapping: list[dict[str, Any]] = Field(default_factory=list)

    # Summary
    summary: str = Field(default="")
    severity_score: float = Field(default=0.0, ge=0, le=10)
    confidence: float = Field(default=0.0, ge=0, le=1)

    # Recommendations
    recommendations: list[str] = Field(default_factory=list)

    # Metadata
    analyzed_at: datetime = Field(default_factory=datetime.utcnow)
    analysis_duration_ms: int = Field(default=0)


class AnalyzerAgent(BaseAgent):
    """Analyzer Agent for security incident analysis.

    Capabilities:
    - Root cause analysis
    - Impact assessment
    - Threat classification
    - MITRE ATT&CK mapping
    - Recommendation generation
    """

    SYSTEM_PROMPT = """You are an expert security analyst performing in-depth incident analysis.

Your responsibilities:
1. Analyze security incidents to determine root cause
2. Assess the impact and scope of incidents
3. Classify threats using MITRE ATT&CK framework
4. Provide actionable recommendations

Be thorough, precise, and evidence-based in your analysis."""

    def __init__(self, config: AnalyzerConfig) -> None:
        """Initialize the Analyzer Agent."""
        config.name = config.name or "Analyzer"
        config.capabilities = [
            AgentCapability.ANALYZE,
            AgentCapability.QUERY,
        ]

        super().__init__(config)
        self.config: AnalyzerConfig = config

        self._client: httpx.AsyncClient | None = None
        self._memory = AgentMemory(self.agent_id)

        self._setup_tools()

    def _setup_tools(self) -> None:
        """Setup analysis tools."""
        self.register_tool(
            ToolDefinition(
                name="query_events",
                description="Query events for analysis",
                parameters={
                    "query": {"type": "string"},
                    "time_range": {"type": "string"},
                },
                required_parameters=["query"],
            ),
            self._query_events,
        )

        self.register_tool(
            ToolDefinition(
                name="get_mitre_technique",
                description="Get MITRE ATT&CK technique details",
                parameters={
                    "technique_id": {"type": "string"},
                },
                required_parameters=["technique_id"],
            ),
            self._get_mitre_technique,
        )

        self.register_tool(
            ToolDefinition(
                name="get_asset_criticality",
                description="Get asset criticality information",
                parameters={
                    "asset_id": {"type": "string"},
                },
                required_parameters=["asset_id"],
            ),
            self._get_asset_criticality,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def initialize(self) -> None:
        """Initialize the agent."""
        self._status = AgentStatus.IDLE
        self.logger.info("analyzer_initialized", agent_id=self.agent_id)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def run(self, context: AgentContext) -> AgentResult:
        """Run analysis.

        Args:
            context: Analysis context with incident/investigation data

        Returns:
            Analysis results
        """
        self._current_context = context
        self._status = AgentStatus.RUNNING
        self._clear_steps()

        start_time = datetime.utcnow()

        try:
            data = context.data
            investigation_data = data.get("investigation", {})
            evidence = data.get("evidence", [])
            timeline = data.get("timeline", [])

            result = AnalysisResult(
                analysis_id=context.execution_id,
                alert_id=context.alert_id,
                case_id=context.case_id,
            )

            # Phase 1: Root Cause Analysis
            if self.config.enable_root_cause:
                self.logger.info("starting_root_cause_analysis")
                root_cause = await self._analyze_root_cause(
                    investigation_data,
                    evidence,
                    timeline,
                )
                result.root_cause = root_cause.get("root_cause")
                result.cause_chain = root_cause.get("cause_chain", [])

            # Phase 2: Impact Assessment
            if self.config.enable_impact_assessment:
                self.logger.info("starting_impact_assessment")
                impact = await self._assess_impact(
                    investigation_data,
                    evidence,
                )
                result.impact_assessment = impact.get("assessment")
                result.affected_assets = impact.get("affected_assets", [])

            # Phase 3: Threat Classification
            if self.config.enable_mitre_mapping:
                self.logger.info("starting_threat_classification")
                classification = await self._classify_threat(
                    investigation_data,
                    evidence,
                    timeline,
                )
                result.threat_classification = classification.get("classification")
                result.mitre_mapping = classification.get("mitre_mapping", [])

            # Phase 4: Generate Summary and Recommendations
            result.summary = await self._generate_summary(result)
            result.severity_score = self._calculate_severity(result)
            result.confidence = self._calculate_confidence(result)
            result.recommendations = await self._generate_recommendations(result)

            # Calculate duration
            end_time = datetime.utcnow()
            result.analysis_duration_ms = int(
                (end_time - start_time).total_seconds() * 1000
            )

            self._status = AgentStatus.COMPLETED

            return self._create_result(
                success=True,
                output=result.model_dump(),
            )

        except Exception as e:
            self.logger.error(
                "analysis_failed",
                agent_id=self.agent_id,
                error=str(e),
            )
            self._status = AgentStatus.FAILED

            return self._create_result(
                success=False,
                error=str(e),
            )

    async def _analyze_root_cause(
        self,
        investigation: dict[str, Any],
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze root cause of incident."""
        client = await self._get_client()

        # Build analysis prompt
        timeline_summary = "\n".join([
            f"- {e.get('timestamp')}: {e.get('title')}"
            for e in timeline[:20]
        ])

        evidence_summary = "\n".join([
            f"- [{e.get('type')}] {str(e.get('data', {}))[:100]}"
            for e in evidence[:10]
        ])

        prompt = f"""Analyze the root cause of this security incident.

Investigation Summary:
{investigation.get('summary', 'N/A')}

Timeline (first events):
{timeline_summary}

Key Evidence:
{evidence_summary}

Determine:
1. The most likely root cause
2. The chain of events leading to the incident
3. Contributing factors

Respond in JSON format with keys: root_cause, cause_chain, contributing_factors"""

        try:
            response = await client.post(
                f"{self.config.llm_endpoint}/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            import json
            import re

            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            self.logger.warning("root_cause_analysis_failed", error=str(e))

        return {
            "root_cause": {
                "description": "Unable to determine automatically",
                "confidence": 0.0,
            },
            "cause_chain": [],
        }

    async def _assess_impact(
        self,
        investigation: dict[str, Any],
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Assess incident impact."""
        client = await self._get_client()

        # Extract affected entities
        entities = set()
        for ev in evidence:
            data = ev.get("data", {})
            for field in ["hostname", "host", "username", "user", "source_ip", "destination_ip"]:
                if val := data.get(field):
                    entities.add(val)

        prompt = f"""Assess the impact of this security incident.

Investigation Summary:
{investigation.get('summary', 'N/A')}

Potentially Affected Entities: {list(entities)[:20]}

Evidence Count: {len(evidence)}

Assess:
1. Business impact (low/medium/high/critical)
2. Scope (single asset/multiple assets/network-wide)
3. Data at risk
4. Operational impact

Respond in JSON format with keys: impact_level, scope, data_risk, operational_impact, affected_systems"""

        try:
            response = await client.post(
                f"{self.config.llm_endpoint}/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 800,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            import json
            import re

            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                result = json.loads(json_match.group())
                return {
                    "assessment": result,
                    "affected_assets": [
                        {"entity": e, "type": "unknown"}
                        for e in list(entities)[:20]
                    ],
                }

        except Exception as e:
            self.logger.warning("impact_assessment_failed", error=str(e))

        return {
            "assessment": {
                "impact_level": "unknown",
                "scope": "unknown",
            },
            "affected_assets": [],
        }

    async def _classify_threat(
        self,
        investigation: dict[str, Any],
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Classify threat and map to MITRE ATT&CK."""
        client = await self._get_client()

        # Extract indicators
        alert_types = set()
        techniques_found = set()

        for ev in evidence:
            data = ev.get("data", {})
            if at := data.get("alert_type"):
                alert_types.add(at)
            if tech := data.get("mitre_technique"):
                techniques_found.add(tech)

        prompt = f"""Classify this threat and map to MITRE ATT&CK framework.

Investigation Summary:
{investigation.get('summary', 'N/A')}

Alert Types Observed: {list(alert_types)}
Techniques Already Identified: {list(techniques_found)}

Timeline Events: {len(timeline)}

Provide:
1. Threat classification (malware, APT, insider threat, etc.)
2. Threat actor type
3. MITRE ATT&CK tactics and techniques involved
4. Kill chain stage

Respond in JSON format with keys: threat_type, actor_type, mitre_tactics, mitre_techniques, kill_chain_stage"""

        try:
            response = await client.post(
                f"{self.config.llm_endpoint}/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 800,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            import json
            import re

            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                result = json.loads(json_match.group())

                # Build MITRE mapping
                mitre_mapping = []
                for tactic in result.get("mitre_tactics", []):
                    mitre_mapping.append({
                        "type": "tactic",
                        "id": tactic,
                        "name": tactic,
                    })
                for technique in result.get("mitre_techniques", []):
                    mitre_mapping.append({
                        "type": "technique",
                        "id": technique,
                        "name": technique,
                    })

                return {
                    "classification": result,
                    "mitre_mapping": mitre_mapping,
                }

        except Exception as e:
            self.logger.warning("threat_classification_failed", error=str(e))

        return {
            "classification": {
                "threat_type": "unknown",
                "actor_type": "unknown",
            },
            "mitre_mapping": [],
        }

    async def _generate_summary(self, result: AnalysisResult) -> str:
        """Generate analysis summary."""
        parts = [f"Analysis of incident {result.alert_id or result.case_id}"]

        if result.root_cause:
            parts.append(f"Root Cause: {result.root_cause.get('description', 'Unknown')}")

        if result.impact_assessment:
            parts.append(f"Impact: {result.impact_assessment.get('impact_level', 'Unknown')}")

        if result.threat_classification:
            parts.append(f"Threat Type: {result.threat_classification.get('threat_type', 'Unknown')}")

        parts.append(f"Affected Assets: {len(result.affected_assets)}")

        return ". ".join(parts)

    def _calculate_severity(self, result: AnalysisResult) -> float:
        """Calculate overall severity score (0-10)."""
        score = 5.0  # Base score

        # Adjust based on impact
        if result.impact_assessment:
            impact = result.impact_assessment.get("impact_level", "").lower()
            impact_scores = {
                "critical": 3.0,
                "high": 2.0,
                "medium": 0.5,
                "low": -1.0,
            }
            score += impact_scores.get(impact, 0)

        # Adjust based on threat classification
        if result.threat_classification:
            threat_type = result.threat_classification.get("threat_type", "").lower()
            threat_scores = {
                "apt": 2.0,
                "ransomware": 2.5,
                "insider": 1.5,
                "malware": 1.0,
            }
            for pattern, adjustment in threat_scores.items():
                if pattern in threat_type:
                    score += adjustment
                    break

        # Adjust based on affected assets
        asset_count = len(result.affected_assets)
        if asset_count > 10:
            score += 1.0
        elif asset_count > 5:
            score += 0.5

        return min(max(score, 0.0), 10.0)

    def _calculate_confidence(self, result: AnalysisResult) -> float:
        """Calculate analysis confidence (0-1)."""
        confidence = 0.5  # Base confidence

        # Increase if root cause found
        if result.root_cause and result.root_cause.get("description") != "Unable to determine automatically":
            confidence += 0.2

        # Increase if MITRE mapping found
        if result.mitre_mapping:
            confidence += 0.15

        # Increase if impact assessment complete
        if result.impact_assessment:
            confidence += 0.1

        # Increase if cause chain documented
        if result.cause_chain:
            confidence += 0.05 * min(len(result.cause_chain), 3)

        return min(confidence, 1.0)

    async def _generate_recommendations(self, result: AnalysisResult) -> list[str]:
        """Generate recommendations based on analysis."""
        recommendations = []

        # Based on impact
        if result.impact_assessment:
            impact = result.impact_assessment.get("impact_level", "").lower()
            if impact in ["critical", "high"]:
                recommendations.append("Immediate incident response required")
                recommendations.append("Notify security leadership")
            if result.impact_assessment.get("data_risk"):
                recommendations.append("Assess potential data breach notification requirements")

        # Based on threat classification
        if result.threat_classification:
            threat_type = result.threat_classification.get("threat_type", "").lower()
            if "ransomware" in threat_type:
                recommendations.append("Isolate affected systems immediately")
                recommendations.append("Do not pay ransom - engage incident response team")
            if "apt" in threat_type:
                recommendations.append("Engage threat intelligence team")
                recommendations.append("Conduct thorough network sweep")

        # Based on MITRE mapping
        for mapping in result.mitre_mapping:
            if mapping.get("id") in ["T1486", "T1490"]:  # Ransomware techniques
                recommendations.append("Verify backup integrity and availability")

        # Default recommendations
        if not recommendations:
            recommendations.append("Continue monitoring affected assets")
            recommendations.append("Review and update detection rules")

        return recommendations

    # Tool implementations

    async def _query_events(
        self,
        query: str,
        time_range: str = "last_24h",
    ) -> list[dict[str, Any]]:
        """Query events from SIEM."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.siem_endpoint}/query",
                json={"query": query, "time_range": time_range},
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception as e:
            self.logger.warning("query_events_failed", error=str(e))

        return []

    async def _get_mitre_technique(
        self,
        technique_id: str,
    ) -> dict[str, Any]:
        """Get MITRE ATT&CK technique details."""
        # Would integrate with MITRE ATT&CK API
        # Placeholder response
        return {
            "technique_id": technique_id,
            "name": f"Technique {technique_id}",
            "description": "Technique description",
            "tactics": [],
            "mitigations": [],
        }

    async def _get_asset_criticality(
        self,
        asset_id: str,
    ) -> dict[str, Any]:
        """Get asset criticality information."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.config.siem_endpoint}/assets/{asset_id}"
            )
            if response.status_code == 200:
                asset = response.json()
                return {
                    "asset_id": asset_id,
                    "criticality": asset.get("criticality", "medium"),
                    "business_unit": asset.get("business_unit"),
                    "data_classification": asset.get("data_classification"),
                }
        except Exception as e:
            self.logger.warning("get_asset_criticality_failed", error=str(e))

        return {"asset_id": asset_id, "criticality": "unknown"}
