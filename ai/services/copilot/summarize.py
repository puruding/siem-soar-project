"""Summarization service for Security Copilot."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from models.summarizer import (
    IncidentSummarizer,
    IncidentSummary,
    SummaryConfig,
    SummaryLanguage,
    SummaryLength,
    KeyInfoExtractor,
    ExtractedInfo,
)


class SummarizeRequest(BaseModel):
    """Request for incident summarization."""

    incident_id: str = Field(description="Incident/case ID")
    incident_data: dict[str, Any] = Field(description="Full incident data")
    language: SummaryLanguage = Field(default=SummaryLanguage.ENGLISH)
    length: SummaryLength = Field(default=SummaryLength.STANDARD)
    include_iocs: bool = Field(default=True)
    include_timeline: bool = Field(default=True)
    include_recommendations: bool = Field(default=True)
    include_mitre: bool = Field(default=True)
    technical_level: str = Field(default="analyst")


class SummarizeResponse(BaseModel):
    """Response from summarization."""

    incident_id: str
    title: str
    executive_summary: str
    detailed_summary: str
    key_findings: list[str]
    ioc_summary: list[dict[str, Any]]
    timeline_summary: list[dict[str, Any]]
    mitre_mapping: list[dict[str, str]]
    recommendations: list[str]
    severity: str
    confidence: float
    language: str


class ExtractRequest(BaseModel):
    """Request for key information extraction."""

    incident_data: dict[str, Any] = Field(description="Incident data to extract from")


class ExtractResponse(BaseModel):
    """Response from key information extraction."""

    entities: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    attack_pattern: str | None
    affected_assets: list[str]
    attacker_indicators: list[str]
    victim_indicators: list[str]
    timeline_events: list[dict[str, Any]]


class SummarizeService(LoggerMixin):
    """Summarization service for Security Copilot.

    Provides:
    - Incident summarization
    - Key information extraction
    - Multi-language support
    - Configurable detail levels
    """

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model name
            api_key: API key
        """
        self.summarizer = IncidentSummarizer(
            llm_endpoint=llm_endpoint,
            model_name=model_name,
            api_key=api_key,
        )
        self.extractor = KeyInfoExtractor()

    async def close(self) -> None:
        """Close resources."""
        await self.summarizer.close()

    async def summarize(self, request: SummarizeRequest) -> SummarizeResponse:
        """Summarize an incident.

        Args:
            request: Summarization request

        Returns:
            Summarization response
        """
        self.logger.info(
            "summarizing_incident",
            incident_id=request.incident_id,
            language=request.language,
        )

        # Build config
        config = SummaryConfig(
            language=request.language,
            length=request.length,
            include_iocs=request.include_iocs,
            include_timeline=request.include_timeline,
            include_recommendations=request.include_recommendations,
            include_mitre=request.include_mitre,
            technical_level=request.technical_level,
        )

        # Add incident_id to data
        incident_data = request.incident_data.copy()
        incident_data["id"] = request.incident_id

        # Generate summary
        summary = await self.summarizer.summarize(incident_data, config)

        return SummarizeResponse(
            incident_id=summary.incident_id,
            title=summary.title,
            executive_summary=summary.executive_summary,
            detailed_summary=summary.detailed_summary,
            key_findings=summary.key_findings,
            ioc_summary=summary.ioc_summary,
            timeline_summary=summary.timeline_summary,
            mitre_mapping=summary.mitre_mapping,
            recommendations=summary.recommendations,
            severity=summary.severity,
            confidence=summary.confidence,
            language=summary.language.value if hasattr(summary.language, 'value') else str(summary.language),
        )

    async def extract(self, request: ExtractRequest) -> ExtractResponse:
        """Extract key information from incident data.

        Args:
            request: Extraction request

        Returns:
            Extracted information
        """
        self.logger.info("extracting_info")

        extracted = self.extractor.extract(request.incident_data)

        return ExtractResponse(
            entities=[e.model_dump() for e in extracted.entities],
            findings=[f.model_dump() for f in extracted.findings],
            attack_pattern=extracted.attack_pattern,
            affected_assets=extracted.affected_assets,
            attacker_indicators=extracted.attacker_indicators,
            victim_indicators=extracted.victim_indicators,
            timeline_events=extracted.timeline_events,
        )

    async def quick_summary(
        self,
        incident_data: dict[str, Any],
        language: str = "en",
    ) -> str:
        """Generate a quick one-paragraph summary.

        Args:
            incident_data: Incident data
            language: Output language

        Returns:
            Quick summary text
        """
        config = SummaryConfig(
            language=SummaryLanguage.KOREAN if language == "ko" else SummaryLanguage.ENGLISH,
            length=SummaryLength.BRIEF,
            include_iocs=False,
            include_timeline=False,
            include_recommendations=False,
            include_mitre=False,
        )

        summary = await self.summarizer.summarize(incident_data, config)
        return summary.executive_summary

    async def get_recommendations(
        self,
        incident_data: dict[str, Any],
        language: str = "en",
    ) -> list[str]:
        """Get response recommendations for incident.

        Args:
            incident_data: Incident data
            language: Output language

        Returns:
            List of recommendations
        """
        config = SummaryConfig(
            language=SummaryLanguage.KOREAN if language == "ko" else SummaryLanguage.ENGLISH,
            include_recommendations=True,
        )

        summary = await self.summarizer.summarize(incident_data, config)
        return summary.recommendations
