"""Root Cause Analyzer - Determine the root cause of security incidents."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class CauseType(str, Enum):
    """Types of root causes."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    CREDENTIAL_COMPROMISE = "credential_compromise"
    SOCIAL_ENGINEERING = "social_engineering"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"
    ZERO_DAY = "zero_day"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN = "unknown"


class RootCause(BaseModel):
    """Root cause determination."""

    cause_id: str = Field(default_factory=lambda: str(uuid4()))
    cause_type: CauseType = Field(description="Type of root cause")
    description: str = Field(description="Root cause description")
    confidence: float = Field(ge=0, le=1, description="Confidence level")

    # Evidence
    supporting_evidence: list[str] = Field(default_factory=list)
    indicators: list[dict[str, Any]] = Field(default_factory=list)

    # Attribution
    entry_point: str | None = Field(default=None)
    initial_vector: str | None = Field(default=None)
    first_seen: datetime | None = Field(default=None)

    # Context
    related_vulnerabilities: list[str] = Field(default_factory=list)
    related_misconfigurations: list[str] = Field(default_factory=list)


class CauseChainLink(BaseModel):
    """A link in the cause chain."""

    link_id: str = Field(default_factory=lambda: str(uuid4()))
    sequence: int = Field(ge=1)
    event: str = Field(description="Event description")
    timestamp: datetime | None = Field(default=None)
    entity: str | None = Field(default=None)
    cause: str | None = Field(default=None)
    effect: str | None = Field(default=None)
    evidence_ids: list[str] = Field(default_factory=list)


class CauseChain(BaseModel):
    """Complete cause chain from root to impact."""

    chain_id: str = Field(default_factory=lambda: str(uuid4()))
    root_cause: RootCause = Field(description="Root cause")
    links: list[CauseChainLink] = Field(default_factory=list)
    final_impact: str | None = Field(default=None)
    total_duration_minutes: int | None = Field(default=None)


class RootCauseAnalyzer(LoggerMixin):
    """Analyzer for determining root cause of security incidents.

    Features:
    - Cause-effect chain analysis
    - Timeline correlation
    - Evidence-based determination
    - Confidence scoring
    """

    # Cause type patterns
    CAUSE_PATTERNS = {
        CauseType.VULNERABILITY: [
            "exploit", "cve", "vulnerability", "patch", "buffer overflow",
            "injection", "rce", "remote code execution",
        ],
        CauseType.MISCONFIGURATION: [
            "misconfiguration", "default password", "open port", "exposed",
            "public access", "weak permission", "insecure",
        ],
        CauseType.CREDENTIAL_COMPROMISE: [
            "credential", "password", "brute force", "spray", "stolen",
            "leaked", "harvested", "phished",
        ],
        CauseType.SOCIAL_ENGINEERING: [
            "phishing", "spear phishing", "vishing", "social engineering",
            "pretexting", "baiting",
        ],
        CauseType.INSIDER_THREAT: [
            "insider", "employee", "contractor", "privileged user",
            "data theft", "sabotage",
        ],
        CauseType.SUPPLY_CHAIN: [
            "supply chain", "third party", "vendor", "software update",
            "dependency", "package",
        ],
        CauseType.ZERO_DAY: [
            "zero day", "0-day", "unknown vulnerability", "novel",
        ],
    }

    def __init__(
        self,
        llm_endpoint: str = "http://localhost:8080/v1",
        model_name: str = "solar-10.7b",
    ) -> None:
        """Initialize root cause analyzer.

        Args:
            llm_endpoint: LLM API endpoint
            model_name: Model name
        """
        self.llm_endpoint = llm_endpoint
        self.model_name = model_name
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def analyze(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> CauseChain:
        """Analyze evidence and timeline to determine root cause.

        Args:
            evidence: List of evidence items
            timeline: List of timeline events
            context: Additional context

        Returns:
            Complete cause chain
        """
        self.logger.info(
            "analyzing_root_cause",
            evidence_count=len(evidence),
            timeline_events=len(timeline),
        )

        # Sort timeline
        sorted_timeline = sorted(
            timeline,
            key=lambda x: x.get("timestamp", ""),
        )

        # Find initial event (potential entry point)
        initial_event = sorted_timeline[0] if sorted_timeline else None

        # Analyze cause type
        cause_type = self._determine_cause_type(evidence, sorted_timeline)

        # Use LLM for detailed analysis
        llm_analysis = await self._llm_analyze(evidence, sorted_timeline, context)

        # Build root cause
        root_cause = RootCause(
            cause_type=cause_type,
            description=llm_analysis.get("root_cause_description", "Unable to determine"),
            confidence=llm_analysis.get("confidence", 0.5),
            supporting_evidence=self._extract_supporting_evidence(evidence),
            indicators=llm_analysis.get("indicators", []),
            entry_point=self._find_entry_point(sorted_timeline),
            initial_vector=llm_analysis.get("initial_vector"),
            first_seen=self._parse_timestamp(initial_event.get("timestamp")) if initial_event else None,
            related_vulnerabilities=llm_analysis.get("vulnerabilities", []),
            related_misconfigurations=llm_analysis.get("misconfigurations", []),
        )

        # Build cause chain
        chain = self._build_cause_chain(root_cause, sorted_timeline, llm_analysis)

        return chain

    def _determine_cause_type(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> CauseType:
        """Determine cause type from evidence patterns."""
        # Combine all text for pattern matching
        all_text = ""
        for ev in evidence:
            all_text += str(ev).lower() + " "
        for event in timeline:
            all_text += str(event).lower() + " "

        # Score each cause type
        scores = {}
        for cause_type, patterns in self.CAUSE_PATTERNS.items():
            score = sum(1 for p in patterns if p in all_text)
            scores[cause_type] = score

        # Return highest scoring type
        if max(scores.values()) > 0:
            return max(scores, key=scores.get)

        return CauseType.UNKNOWN

    async def _llm_analyze(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Use LLM for detailed root cause analysis."""
        client = await self._get_client()

        # Build summary
        timeline_summary = "\n".join([
            f"- {e.get('timestamp', 'N/A')}: {e.get('title', e.get('description', 'Event'))}"
            for e in timeline[:15]
        ])

        evidence_summary = "\n".join([
            f"- [{e.get('type', 'evidence')}]: {str(e.get('data', e))[:100]}"
            for e in evidence[:10]
        ])

        prompt = f"""Analyze this security incident to determine root cause.

Timeline (chronological):
{timeline_summary}

Evidence:
{evidence_summary}

Additional Context: {context or 'None provided'}

Determine:
1. Root cause description (detailed)
2. Initial attack vector
3. Confidence level (0-1)
4. Key indicators
5. Related vulnerabilities or misconfigurations

Respond in JSON format."""

        try:
            response = await client.post(
                f"{self.llm_endpoint}/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a security analyst expert in root cause analysis.",
                        },
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
                result = json.loads(json_match.group())
                return {
                    "root_cause_description": result.get("root_cause_description", result.get("root_cause")),
                    "initial_vector": result.get("initial_attack_vector", result.get("initial_vector")),
                    "confidence": result.get("confidence_level", result.get("confidence", 0.5)),
                    "indicators": result.get("key_indicators", result.get("indicators", [])),
                    "vulnerabilities": result.get("related_vulnerabilities", result.get("vulnerabilities", [])),
                    "misconfigurations": result.get("related_misconfigurations", result.get("misconfigurations", [])),
                    "cause_effect_chain": result.get("cause_effect_chain", []),
                }

        except Exception as e:
            self.logger.warning("llm_analysis_failed", error=str(e))

        return {"root_cause_description": "Analysis failed", "confidence": 0.0}

    def _extract_supporting_evidence(
        self,
        evidence: list[dict[str, Any]],
    ) -> list[str]:
        """Extract IDs of supporting evidence."""
        return [
            ev.get("evidence_id", ev.get("id", str(i)))
            for i, ev in enumerate(evidence[:20])
            if ev.get("relevance_score", 0.5) >= 0.6
        ]

    def _find_entry_point(self, timeline: list[dict[str, Any]]) -> str | None:
        """Find likely entry point from timeline."""
        if not timeline:
            return None

        # Look for initial access events
        entry_keywords = ["login", "access", "connection", "email", "download", "execute"]

        for event in timeline[:5]:
            title = event.get("title", "").lower()
            if any(kw in title for kw in entry_keywords):
                return event.get("title")

        # Default to first event
        return timeline[0].get("title")

    def _parse_timestamp(self, ts_str: str | None) -> datetime | None:
        """Parse timestamp string."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _build_cause_chain(
        self,
        root_cause: RootCause,
        timeline: list[dict[str, Any]],
        llm_analysis: dict[str, Any],
    ) -> CauseChain:
        """Build cause chain from analysis."""
        links = []

        # Use timeline events as chain links
        for i, event in enumerate(timeline[:10]):
            link = CauseChainLink(
                sequence=i + 1,
                event=event.get("title", event.get("description", "Event")),
                timestamp=self._parse_timestamp(event.get("timestamp")),
                entity=self._extract_entity_from_event(event),
                evidence_ids=event.get("evidence_ids", []),
            )

            # Add cause-effect from LLM analysis if available
            chain_analysis = llm_analysis.get("cause_effect_chain", [])
            if i < len(chain_analysis):
                link.cause = chain_analysis[i].get("cause")
                link.effect = chain_analysis[i].get("effect")

            links.append(link)

        # Calculate duration
        duration = None
        if len(links) >= 2 and links[0].timestamp and links[-1].timestamp:
            duration = int(
                (links[-1].timestamp - links[0].timestamp).total_seconds() / 60
            )

        return CauseChain(
            root_cause=root_cause,
            links=links,
            final_impact=self._determine_final_impact(timeline),
            total_duration_minutes=duration,
        )

    def _extract_entity_from_event(self, event: dict[str, Any]) -> str | None:
        """Extract primary entity from event."""
        entities = event.get("entities", [])
        if entities:
            return entities[0].get("value")

        # Check common fields
        for field in ["hostname", "user", "source_ip", "destination_ip"]:
            if val := event.get(field):
                return val

        return None

    def _determine_final_impact(self, timeline: list[dict[str, Any]]) -> str | None:
        """Determine final impact from timeline."""
        if not timeline:
            return None

        # Look at last events for impact
        impact_keywords = {
            "data": "data access/exfiltration",
            "encrypt": "ransomware encryption",
            "delete": "data destruction",
            "lateral": "lateral movement",
            "privilege": "privilege escalation",
            "persist": "persistence established",
        }

        for event in reversed(timeline[-5:]):
            title = event.get("title", "").lower()
            for kw, impact in impact_keywords.items():
                if kw in title:
                    return impact

        return "incident in progress"

    def correlate_multiple_incidents(
        self,
        cause_chains: list[CauseChain],
    ) -> dict[str, Any]:
        """Correlate multiple incidents to find common root causes.

        Args:
            cause_chains: List of cause chains from different incidents

        Returns:
            Correlation analysis
        """
        # Count cause types
        cause_type_counts = {}
        for chain in cause_chains:
            ct = chain.root_cause.cause_type.value
            cause_type_counts[ct] = cause_type_counts.get(ct, 0) + 1

        # Find common indicators
        all_indicators = []
        for chain in cause_chains:
            all_indicators.extend(chain.root_cause.indicators)

        indicator_counts = {}
        for ind in all_indicators:
            key = str(ind)
            indicator_counts[key] = indicator_counts.get(key, 0) + 1

        common_indicators = [
            ind for ind, count in indicator_counts.items()
            if count > 1
        ]

        # Find common entry points
        entry_points = [
            chain.root_cause.entry_point
            for chain in cause_chains
            if chain.root_cause.entry_point
        ]

        return {
            "total_incidents": len(cause_chains),
            "cause_type_distribution": cause_type_counts,
            "common_indicators": common_indicators,
            "entry_points": list(set(entry_points)),
            "potential_campaign": len(common_indicators) > 2,
        }
