"""Incident summarization model for automated report generation."""

from __future__ import annotations

import asyncio
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class SummaryLanguage(str, Enum):
    """Supported languages for summaries."""

    ENGLISH = "en"
    KOREAN = "ko"


class SummaryLength(str, Enum):
    """Summary length options."""

    BRIEF = "brief"  # 2-3 sentences
    STANDARD = "standard"  # 1 paragraph
    DETAILED = "detailed"  # Multiple paragraphs


class SummaryConfig(BaseModel):
    """Configuration for summary generation."""

    language: SummaryLanguage = Field(default=SummaryLanguage.ENGLISH)
    length: SummaryLength = Field(default=SummaryLength.STANDARD)
    include_iocs: bool = Field(default=True, description="Include IOC indicators")
    include_timeline: bool = Field(default=True, description="Include event timeline")
    include_recommendations: bool = Field(default=True, description="Include response recommendations")
    include_mitre: bool = Field(default=True, description="Include MITRE ATT&CK mapping")
    technical_level: str = Field(default="analyst", description="Target audience: executive, analyst, technical")


class IncidentSummary(BaseModel):
    """Generated incident summary."""

    incident_id: str = Field(description="Incident/case ID")
    title: str = Field(description="Summary title")
    executive_summary: str = Field(description="Brief executive summary")
    detailed_summary: str = Field(description="Detailed technical summary")
    key_findings: list[str] = Field(default_factory=list, description="Key findings")
    ioc_summary: list[dict[str, Any]] = Field(default_factory=list, description="IOC indicators")
    timeline_summary: list[dict[str, Any]] = Field(default_factory=list, description="Event timeline")
    mitre_mapping: list[dict[str, str]] = Field(default_factory=list, description="MITRE ATT&CK mapping")
    recommendations: list[str] = Field(default_factory=list, description="Response recommendations")
    severity: str = Field(description="Assessed severity")
    confidence: float = Field(ge=0, le=1, description="Summary confidence")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    language: SummaryLanguage = Field(default=SummaryLanguage.ENGLISH)


class IncidentSummarizer(LoggerMixin):
    """LLM-based incident summarization.

    Features:
    - Multi-language support (English, Korean)
    - Configurable summary length and detail
    - IOC extraction and summarization
    - Timeline generation
    - MITRE ATT&CK mapping
    - Response recommendations
    """

    SYSTEM_PROMPT_EN = """You are a security incident analyst expert. Your task is to summarize security incidents clearly and professionally.

Guidelines:
1. Be concise but comprehensive
2. Highlight critical information first
3. Use clear, professional language
4. Include specific technical details when relevant
5. Provide actionable recommendations
6. Reference MITRE ATT&CK tactics and techniques when applicable

Format your response as structured sections."""

    SYSTEM_PROMPT_KO = """당신은 보안 인시던트 분석 전문가입니다. 보안 인시던트를 명확하고 전문적으로 요약하는 것이 임무입니다.

지침:
1. 간결하면서도 포괄적으로 작성
2. 중요한 정보를 먼저 강조
3. 명확하고 전문적인 언어 사용
4. 관련 기술적 세부사항 포함
5. 실행 가능한 권장사항 제공
6. MITRE ATT&CK 전술 및 기술 참조

구조화된 섹션으로 응답을 작성하세요."""

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        """Initialize the summarizer.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model to use for generation
            api_key: API key for vLLM
            timeout: Request timeout in seconds
        """
        self.llm_endpoint = llm_endpoint or "http://localhost:8080/v1"
        self.model_name = model_name
        self.api_key = api_key
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout),
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

    async def summarize(
        self,
        incident_data: dict[str, Any],
        config: SummaryConfig | None = None,
    ) -> IncidentSummary:
        """Generate incident summary.

        Args:
            incident_data: Incident data including alerts, events, context
            config: Summary configuration

        Returns:
            Generated incident summary
        """
        config = config or SummaryConfig()

        self.logger.info(
            "summarizing_incident",
            incident_id=incident_data.get("id"),
            language=config.language,
        )

        # Build context from incident data
        context = self._build_context(incident_data)

        # Generate summary sections
        try:
            executive_summary = await self._generate_executive_summary(context, config)
            detailed_summary = await self._generate_detailed_summary(context, config)
            key_findings = await self._extract_key_findings(context, config)
            recommendations = await self._generate_recommendations(context, config)
        except Exception as e:
            self.logger.error("summarization_failed", error=str(e))
            # Fallback to template-based summary
            return self._fallback_summary(incident_data, config)

        # Extract IOCs if configured
        iocs = []
        if config.include_iocs:
            iocs = self._extract_iocs(incident_data)

        # Build timeline if configured
        timeline = []
        if config.include_timeline:
            timeline = self._build_timeline(incident_data)

        # Extract MITRE mapping if configured
        mitre = []
        if config.include_mitre:
            mitre = self._extract_mitre_mapping(incident_data)

        return IncidentSummary(
            incident_id=incident_data.get("id", "unknown"),
            title=self._generate_title(incident_data, config),
            executive_summary=executive_summary,
            detailed_summary=detailed_summary,
            key_findings=key_findings,
            ioc_summary=iocs,
            timeline_summary=timeline,
            mitre_mapping=mitre,
            recommendations=recommendations if config.include_recommendations else [],
            severity=incident_data.get("severity", "medium"),
            confidence=0.85,
            language=config.language,
        )

    def _build_context(self, incident_data: dict[str, Any]) -> str:
        """Build context string from incident data."""
        parts = []

        # Basic info
        parts.append(f"Incident ID: {incident_data.get('id', 'N/A')}")
        parts.append(f"Severity: {incident_data.get('severity', 'N/A')}")
        parts.append(f"Status: {incident_data.get('status', 'N/A')}")

        # Title/Description
        if incident_data.get("title"):
            parts.append(f"Title: {incident_data['title']}")
        if incident_data.get("description"):
            parts.append(f"Description: {incident_data['description']}")

        # Alerts
        if alerts := incident_data.get("alerts", []):
            parts.append(f"\nRelated Alerts ({len(alerts)}):")
            for i, alert in enumerate(alerts[:10], 1):
                parts.append(f"  {i}. [{alert.get('severity', 'N/A')}] {alert.get('title', 'N/A')}")

        # Events sample
        if events := incident_data.get("events", []):
            parts.append(f"\nRelated Events ({len(events)} total):")
            for i, event in enumerate(events[:5], 1):
                parts.append(f"  {i}. {event.get('event_type', 'N/A')} - {event.get('source_ip', 'N/A')}")

        # IOCs
        if iocs := incident_data.get("iocs", []):
            parts.append(f"\nIOC Indicators ({len(iocs)}):")
            for ioc in iocs[:10]:
                parts.append(f"  - {ioc.get('type', 'N/A')}: {ioc.get('value', 'N/A')}")

        # MITRE ATT&CK
        if mitre := incident_data.get("mitre_tactics"):
            parts.append(f"\nMITRE Tactics: {', '.join(mitre)}")
        if mitre := incident_data.get("mitre_techniques"):
            parts.append(f"MITRE Techniques: {', '.join(mitre)}")

        return "\n".join(parts)

    async def _generate_executive_summary(
        self,
        context: str,
        config: SummaryConfig,
    ) -> str:
        """Generate executive summary."""
        system_prompt = self.SYSTEM_PROMPT_KO if config.language == SummaryLanguage.KOREAN else self.SYSTEM_PROMPT_EN

        if config.language == SummaryLanguage.KOREAN:
            user_prompt = f"""다음 보안 인시던트 정보를 바탕으로 경영진을 위한 간단한 요약을 작성하세요.
2-3문장으로 핵심 내용만 포함하세요.

{context}

경영진 요약:"""
        else:
            user_prompt = f"""Based on the following security incident information, write a brief executive summary.
Include only key points in 2-3 sentences.

{context}

Executive Summary:"""

        return await self._call_llm(system_prompt, user_prompt)

    async def _generate_detailed_summary(
        self,
        context: str,
        config: SummaryConfig,
    ) -> str:
        """Generate detailed technical summary."""
        system_prompt = self.SYSTEM_PROMPT_KO if config.language == SummaryLanguage.KOREAN else self.SYSTEM_PROMPT_EN

        length_guidance = {
            SummaryLength.BRIEF: "1 paragraph",
            SummaryLength.STANDARD: "2-3 paragraphs",
            SummaryLength.DETAILED: "4-5 paragraphs",
        }

        if config.language == SummaryLanguage.KOREAN:
            user_prompt = f"""다음 보안 인시던트 정보를 바탕으로 기술적 상세 요약을 작성하세요.
길이: {length_guidance[config.length]}
대상: 보안 분석가

{context}

기술 요약:"""
        else:
            user_prompt = f"""Based on the following security incident information, write a detailed technical summary.
Length: {length_guidance[config.length]}
Audience: Security analysts

{context}

Technical Summary:"""

        return await self._call_llm(system_prompt, user_prompt)

    async def _extract_key_findings(
        self,
        context: str,
        config: SummaryConfig,
    ) -> list[str]:
        """Extract key findings from incident."""
        system_prompt = self.SYSTEM_PROMPT_KO if config.language == SummaryLanguage.KOREAN else self.SYSTEM_PROMPT_EN

        if config.language == SummaryLanguage.KOREAN:
            user_prompt = f"""다음 보안 인시던트에서 주요 발견사항을 5개 이내로 나열하세요.
각 항목은 한 문장으로 작성하세요.

{context}

주요 발견사항:
1."""
        else:
            user_prompt = f"""List up to 5 key findings from this security incident.
Each finding should be one sentence.

{context}

Key Findings:
1."""

        response = await self._call_llm(system_prompt, user_prompt)

        # Parse numbered list
        findings = []
        for line in response.split("\n"):
            line = line.strip()
            if line and line[0].isdigit():
                # Remove numbering
                import re
                clean = re.sub(r"^\d+[\.\)]\s*", "", line)
                if clean:
                    findings.append(clean)

        return findings[:5]

    async def _generate_recommendations(
        self,
        context: str,
        config: SummaryConfig,
    ) -> list[str]:
        """Generate response recommendations."""
        system_prompt = self.SYSTEM_PROMPT_KO if config.language == SummaryLanguage.KOREAN else self.SYSTEM_PROMPT_EN

        if config.language == SummaryLanguage.KOREAN:
            user_prompt = f"""다음 보안 인시던트에 대한 대응 권장사항을 5개 이내로 제안하세요.
우선순위 순으로 작성하세요.

{context}

권장 조치:
1."""
        else:
            user_prompt = f"""Suggest up to 5 response recommendations for this security incident.
Order by priority.

{context}

Recommended Actions:
1."""

        response = await self._call_llm(system_prompt, user_prompt)

        # Parse numbered list
        recommendations = []
        for line in response.split("\n"):
            line = line.strip()
            if line and line[0].isdigit():
                import re
                clean = re.sub(r"^\d+[\.\)]\s*", "", line)
                if clean:
                    recommendations.append(clean)

        return recommendations[:5]

    async def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call LLM API."""
        client = await self._get_client()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": 1024,
            "temperature": 0.3,
        }

        response = await client.post(
            f"{self.llm_endpoint}/chat/completions",
            json=payload,
        )
        response.raise_for_status()

        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    def _extract_iocs(self, incident_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract IOC indicators from incident data."""
        iocs = []

        # From explicit IOC field
        if incident_iocs := incident_data.get("iocs", []):
            iocs.extend(incident_iocs)

        # From events
        for event in incident_data.get("events", []):
            if src_ip := event.get("source_ip"):
                iocs.append({"type": "ip", "value": src_ip, "context": "source"})
            if dst_ip := event.get("dest_ip"):
                iocs.append({"type": "ip", "value": dst_ip, "context": "destination"})

        # Deduplicate
        seen = set()
        unique_iocs = []
        for ioc in iocs:
            key = (ioc.get("type"), ioc.get("value"))
            if key not in seen:
                seen.add(key)
                unique_iocs.append(ioc)

        return unique_iocs[:20]

    def _build_timeline(self, incident_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Build event timeline."""
        timeline = []

        # From events
        for event in incident_data.get("events", [])[:20]:
            timeline.append({
                "timestamp": event.get("timestamp"),
                "type": event.get("event_type"),
                "description": event.get("description", event.get("raw_log", "")[:100]),
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

        return timeline[:10]

    def _extract_mitre_mapping(self, incident_data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract MITRE ATT&CK mapping."""
        mapping = []

        tactics = incident_data.get("mitre_tactics", [])
        techniques = incident_data.get("mitre_techniques", [])

        for tactic in tactics:
            mapping.append({"type": "tactic", "id": tactic, "name": tactic})

        for technique in techniques:
            mapping.append({"type": "technique", "id": technique, "name": technique})

        return mapping

    def _generate_title(self, incident_data: dict[str, Any], config: SummaryConfig) -> str:
        """Generate summary title."""
        if title := incident_data.get("title"):
            return title

        severity = incident_data.get("severity", "").upper()
        incident_type = incident_data.get("type", "Security Incident")

        if config.language == SummaryLanguage.KOREAN:
            return f"[{severity}] {incident_type} 분석 보고서"
        return f"[{severity}] {incident_type} Analysis Report"

    def _fallback_summary(
        self,
        incident_data: dict[str, Any],
        config: SummaryConfig,
    ) -> IncidentSummary:
        """Generate fallback summary when LLM fails."""
        incident_id = incident_data.get("id", "unknown")
        severity = incident_data.get("severity", "medium")
        alert_count = len(incident_data.get("alerts", []))
        event_count = len(incident_data.get("events", []))

        if config.language == SummaryLanguage.KOREAN:
            exec_summary = f"인시던트 {incident_id}는 심각도 {severity}로 분류됩니다. 총 {alert_count}개의 경보와 {event_count}개의 이벤트가 관련되어 있습니다."
            detailed = f"이 인시던트는 {alert_count}개의 보안 경보와 {event_count}개의 관련 이벤트로 구성됩니다. 추가 분석이 필요합니다."
            findings = ["자동 요약 생성 실패로 수동 검토 필요"]
            recommendations = ["인시던트 수동 검토 권장"]
        else:
            exec_summary = f"Incident {incident_id} is classified as {severity} severity. It involves {alert_count} alerts and {event_count} events."
            detailed = f"This incident consists of {alert_count} security alerts and {event_count} related events. Further analysis is required."
            findings = ["Automatic summary generation failed; manual review needed"]
            recommendations = ["Manual review of incident recommended"]

        return IncidentSummary(
            incident_id=incident_id,
            title=self._generate_title(incident_data, config),
            executive_summary=exec_summary,
            detailed_summary=detailed,
            key_findings=findings,
            ioc_summary=self._extract_iocs(incident_data),
            timeline_summary=self._build_timeline(incident_data),
            mitre_mapping=self._extract_mitre_mapping(incident_data),
            recommendations=recommendations,
            severity=severity,
            confidence=0.5,
            language=config.language,
        )


async def summarize_multiple(
    summarizer: IncidentSummarizer,
    incidents: list[dict[str, Any]],
    config: SummaryConfig | None = None,
    max_concurrent: int = 5,
) -> list[IncidentSummary]:
    """Summarize multiple incidents concurrently.

    Args:
        summarizer: IncidentSummarizer instance
        incidents: List of incident data
        config: Summary configuration
        max_concurrent: Maximum concurrent summaries

    Returns:
        List of generated summaries
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    async def summarize_one(incident: dict[str, Any]) -> IncidentSummary:
        async with semaphore:
            return await summarizer.summarize(incident, config)

    tasks = [summarize_one(incident) for incident in incidents]
    return await asyncio.gather(*tasks)
