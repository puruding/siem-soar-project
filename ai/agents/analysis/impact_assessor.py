"""Impact Assessor - Assess the impact and scope of security incidents."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ImpactLevel(str, Enum):
    """Impact severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ImpactScope(str, Enum):
    """Scope of impact."""

    SINGLE_ASSET = "single_asset"
    MULTIPLE_ASSETS = "multiple_assets"
    DEPARTMENT = "department"
    BUSINESS_UNIT = "business_unit"
    ORGANIZATION_WIDE = "organization_wide"
    EXTERNAL = "external"


class DataClassification(str, Enum):
    """Data classification levels."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class AffectedAsset(BaseModel):
    """An affected asset."""

    asset_id: str = Field(default_factory=lambda: str(uuid4()))
    asset_type: str = Field(description="Type of asset")
    identifier: str = Field(description="Asset identifier (hostname, IP, etc.)")

    # Classification
    criticality: str = Field(default="medium")
    data_classification: DataClassification | None = Field(default=None)
    business_unit: str | None = Field(default=None)

    # Impact details
    impact_type: str | None = Field(default=None)
    status: str = Field(default="affected")
    first_affected: datetime | None = Field(default=None)

    # Recovery
    recovery_priority: int = Field(default=5, ge=1, le=10)
    estimated_recovery_hours: int | None = Field(default=None)


class BusinessImpact(BaseModel):
    """Business impact assessment."""

    operational_impact: str = Field(default="none")
    financial_impact: str | None = Field(default=None)
    reputational_impact: str = Field(default="none")
    regulatory_impact: str | None = Field(default=None)
    customer_impact: str | None = Field(default=None)


class ImpactAssessment(BaseModel):
    """Complete impact assessment."""

    assessment_id: str = Field(default_factory=lambda: str(uuid4()))

    # Overall assessment
    impact_level: ImpactLevel = Field(description="Overall impact level")
    impact_scope: ImpactScope = Field(description="Scope of impact")
    confidence: float = Field(ge=0, le=1, default=0.5)

    # Affected assets
    affected_assets: list[AffectedAsset] = Field(default_factory=list)
    total_affected_count: int = Field(default=0)

    # Data at risk
    data_at_risk: list[dict[str, Any]] = Field(default_factory=list)
    highest_data_classification: DataClassification | None = Field(default=None)
    potential_data_breach: bool = Field(default=False)

    # Business impact
    business_impact: BusinessImpact = Field(default_factory=BusinessImpact)

    # Timeline
    impact_started: datetime | None = Field(default=None)
    impact_contained: datetime | None = Field(default=None)
    impact_duration_hours: float | None = Field(default=None)

    # Summary
    summary: str = Field(default="")
    recommendations: list[str] = Field(default_factory=list)

    # Metadata
    assessed_at: datetime = Field(default_factory=datetime.utcnow)
    assessed_by: str = Field(default="ImpactAssessor")


class ImpactAssessor(LoggerMixin):
    """Assessor for determining impact and scope of security incidents.

    Features:
    - Asset impact analysis
    - Data risk assessment
    - Business impact evaluation
    - Scope determination
    - Recovery prioritization
    """

    # Asset criticality multipliers
    CRITICALITY_WEIGHTS = {
        "critical": 1.5,
        "high": 1.2,
        "medium": 1.0,
        "low": 0.7,
    }

    # Data classification risk scores
    DATA_RISK_SCORES = {
        DataClassification.TOP_SECRET: 10,
        DataClassification.RESTRICTED: 8,
        DataClassification.CONFIDENTIAL: 6,
        DataClassification.INTERNAL: 3,
        DataClassification.PUBLIC: 1,
    }

    def __init__(
        self,
        llm_endpoint: str = "http://localhost:8080/v1",
        model_name: str = "solar-10.7b",
        siem_endpoint: str = "http://localhost:8000/api/v1",
    ) -> None:
        """Initialize impact assessor.

        Args:
            llm_endpoint: LLM API endpoint
            model_name: Model name
            siem_endpoint: SIEM API endpoint
        """
        self.llm_endpoint = llm_endpoint
        self.model_name = model_name
        self.siem_endpoint = siem_endpoint
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

    async def assess(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> ImpactAssessment:
        """Assess impact of incident.

        Args:
            evidence: List of evidence items
            timeline: Timeline events
            context: Additional context

        Returns:
            Complete impact assessment
        """
        self.logger.info(
            "assessing_impact",
            evidence_count=len(evidence),
            timeline_events=len(timeline),
        )

        assessment = ImpactAssessment()

        # Identify affected assets
        affected_assets = await self._identify_affected_assets(evidence, timeline)
        assessment.affected_assets = affected_assets
        assessment.total_affected_count = len(affected_assets)

        # Determine scope
        assessment.impact_scope = self._determine_scope(affected_assets)

        # Assess data at risk
        data_risk = await self._assess_data_risk(evidence, affected_assets)
        assessment.data_at_risk = data_risk.get("data_items", [])
        assessment.highest_data_classification = data_risk.get("highest_classification")
        assessment.potential_data_breach = data_risk.get("potential_breach", False)

        # Evaluate business impact
        assessment.business_impact = await self._evaluate_business_impact(
            affected_assets,
            data_risk,
            context,
        )

        # Calculate overall impact level
        assessment.impact_level = self._calculate_impact_level(assessment)

        # Timeline analysis
        if timeline:
            assessment.impact_started = self._parse_timestamp(
                timeline[0].get("timestamp")
            )
            # Check if contained
            for event in reversed(timeline):
                if "contain" in event.get("title", "").lower():
                    assessment.impact_contained = self._parse_timestamp(
                        event.get("timestamp")
                    )
                    break

            if assessment.impact_started and assessment.impact_contained:
                delta = assessment.impact_contained - assessment.impact_started
                assessment.impact_duration_hours = delta.total_seconds() / 3600

        # Generate summary and recommendations
        assessment.summary = self._generate_summary(assessment)
        assessment.recommendations = self._generate_recommendations(assessment)
        assessment.confidence = self._calculate_confidence(assessment)

        return assessment

    async def _identify_affected_assets(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> list[AffectedAsset]:
        """Identify affected assets from evidence and timeline."""
        assets = {}  # Use dict to deduplicate

        # Extract from evidence
        for ev in evidence:
            data = ev.get("data", ev)

            # Extract hosts
            for field in ["hostname", "host", "computer_name"]:
                if host := data.get(field):
                    if host not in assets:
                        assets[host] = AffectedAsset(
                            asset_type="host",
                            identifier=host,
                            first_affected=self._parse_timestamp(data.get("timestamp")),
                        )

            # Extract IPs
            for field in ["source_ip", "destination_ip", "src_ip", "dst_ip"]:
                if ip := data.get(field):
                    if ip not in assets and not self._is_internal_only(ip):
                        assets[ip] = AffectedAsset(
                            asset_type="ip",
                            identifier=ip,
                        )

            # Extract users
            for field in ["username", "user", "account"]:
                if user := data.get(field):
                    if user not in assets:
                        assets[user] = AffectedAsset(
                            asset_type="user",
                            identifier=user,
                        )

        # Extract from timeline
        for event in timeline:
            entities = event.get("entities", [])
            for entity in entities:
                key = entity.get("value")
                if key and key not in assets:
                    assets[key] = AffectedAsset(
                        asset_type=entity.get("type", "unknown"),
                        identifier=key,
                        first_affected=self._parse_timestamp(event.get("timestamp")),
                    )

        # Enrich with asset information
        asset_list = list(assets.values())
        await self._enrich_assets(asset_list)

        return asset_list

    async def _enrich_assets(self, assets: list[AffectedAsset]) -> None:
        """Enrich assets with additional information."""
        client = await self._get_client()

        for asset in assets[:50]:  # Limit API calls
            if asset.asset_type in ["host", "ip"]:
                try:
                    response = await client.get(
                        f"{self.siem_endpoint}/assets/{asset.identifier}"
                    )
                    if response.status_code == 200:
                        info = response.json()
                        asset.criticality = info.get("criticality", "medium")
                        asset.business_unit = info.get("business_unit")
                        if dc := info.get("data_classification"):
                            try:
                                asset.data_classification = DataClassification(dc)
                            except ValueError:
                                pass
                except Exception:
                    pass

    def _determine_scope(self, assets: list[AffectedAsset]) -> ImpactScope:
        """Determine scope of impact."""
        count = len(assets)

        if count == 0:
            return ImpactScope.SINGLE_ASSET
        elif count == 1:
            return ImpactScope.SINGLE_ASSET
        elif count <= 5:
            return ImpactScope.MULTIPLE_ASSETS

        # Check business units
        business_units = set(
            a.business_unit for a in assets
            if a.business_unit
        )

        if len(business_units) > 3:
            return ImpactScope.ORGANIZATION_WIDE
        elif len(business_units) > 1:
            return ImpactScope.BUSINESS_UNIT
        elif business_units:
            return ImpactScope.DEPARTMENT
        elif count > 10:
            return ImpactScope.ORGANIZATION_WIDE

        return ImpactScope.MULTIPLE_ASSETS

    async def _assess_data_risk(
        self,
        evidence: list[dict[str, Any]],
        assets: list[AffectedAsset],
    ) -> dict[str, Any]:
        """Assess data at risk."""
        data_items = []
        classifications = []

        # Check asset classifications
        for asset in assets:
            if asset.data_classification:
                classifications.append(asset.data_classification)
                data_items.append({
                    "asset": asset.identifier,
                    "classification": asset.data_classification.value,
                    "type": asset.asset_type,
                })

        # Check evidence for data indicators
        data_keywords = ["database", "file", "document", "pii", "customer", "financial"]
        for ev in evidence:
            ev_str = str(ev).lower()
            for kw in data_keywords:
                if kw in ev_str:
                    data_items.append({
                        "indicator": kw,
                        "source": ev.get("source", "evidence"),
                    })
                    break

        # Determine highest classification
        highest = None
        if classifications:
            classification_order = list(DataClassification)
            highest = max(classifications, key=lambda c: classification_order.index(c))

        # Determine if potential breach
        potential_breach = (
            highest in [DataClassification.RESTRICTED, DataClassification.TOP_SECRET, DataClassification.CONFIDENTIAL]
            or len(data_items) > 5
        )

        return {
            "data_items": data_items,
            "highest_classification": highest,
            "potential_breach": potential_breach,
        }

    async def _evaluate_business_impact(
        self,
        assets: list[AffectedAsset],
        data_risk: dict[str, Any],
        context: dict[str, Any] | None,
    ) -> BusinessImpact:
        """Evaluate business impact."""
        impact = BusinessImpact()

        # Operational impact based on asset count and criticality
        critical_assets = [a for a in assets if a.criticality == "critical"]
        high_assets = [a for a in assets if a.criticality == "high"]

        if critical_assets:
            impact.operational_impact = "severe"
        elif high_assets or len(assets) > 10:
            impact.operational_impact = "significant"
        elif assets:
            impact.operational_impact = "moderate"
        else:
            impact.operational_impact = "minimal"

        # Financial impact estimation
        if len(critical_assets) > 0:
            impact.financial_impact = "high"
        elif data_risk.get("potential_breach"):
            impact.financial_impact = "medium-high"
        elif len(assets) > 5:
            impact.financial_impact = "medium"

        # Reputational impact
        if data_risk.get("potential_breach"):
            impact.reputational_impact = "high"
        elif len(assets) > 20:
            impact.reputational_impact = "medium"
        else:
            impact.reputational_impact = "low"

        # Regulatory impact
        if data_risk.get("highest_classification") in [
            DataClassification.RESTRICTED,
            DataClassification.TOP_SECRET,
        ]:
            impact.regulatory_impact = "high - potential reporting required"
        elif data_risk.get("potential_breach"):
            impact.regulatory_impact = "medium - assess notification requirements"

        # Customer impact
        customer_indicators = ["customer", "client", "user"]
        for item in data_risk.get("data_items", []):
            if any(ind in str(item).lower() for ind in customer_indicators):
                impact.customer_impact = "customers potentially affected"
                break

        return impact

    def _calculate_impact_level(self, assessment: ImpactAssessment) -> ImpactLevel:
        """Calculate overall impact level."""
        score = 0.0

        # Asset count contribution
        count = assessment.total_affected_count
        if count > 50:
            score += 4
        elif count > 20:
            score += 3
        elif count > 5:
            score += 2
        elif count > 0:
            score += 1

        # Scope contribution
        scope_scores = {
            ImpactScope.ORGANIZATION_WIDE: 4,
            ImpactScope.EXTERNAL: 4,
            ImpactScope.BUSINESS_UNIT: 3,
            ImpactScope.DEPARTMENT: 2,
            ImpactScope.MULTIPLE_ASSETS: 1,
            ImpactScope.SINGLE_ASSET: 0.5,
        }
        score += scope_scores.get(assessment.impact_scope, 1)

        # Data risk contribution
        if assessment.potential_data_breach:
            score += 3
        if assessment.highest_data_classification:
            score += self.DATA_RISK_SCORES.get(
                assessment.highest_data_classification, 0
            ) / 3

        # Business impact contribution
        bi = assessment.business_impact
        if bi.operational_impact == "severe":
            score += 2
        elif bi.operational_impact == "significant":
            score += 1

        if bi.regulatory_impact:
            score += 1

        # Map to impact level
        if score >= 10:
            return ImpactLevel.CRITICAL
        elif score >= 7:
            return ImpactLevel.HIGH
        elif score >= 4:
            return ImpactLevel.MEDIUM
        elif score > 0:
            return ImpactLevel.LOW
        else:
            return ImpactLevel.NONE

    def _calculate_confidence(self, assessment: ImpactAssessment) -> float:
        """Calculate assessment confidence."""
        confidence = 0.5

        # Increase for more data
        if assessment.total_affected_count > 0:
            confidence += 0.1

        if assessment.data_at_risk:
            confidence += 0.1

        if assessment.highest_data_classification:
            confidence += 0.1

        # Decrease if only estimates
        if assessment.total_affected_count == 0:
            confidence -= 0.2

        return max(min(confidence, 1.0), 0.0)

    def _generate_summary(self, assessment: ImpactAssessment) -> str:
        """Generate impact summary."""
        parts = [
            f"Impact Level: {assessment.impact_level.value.upper()}",
            f"Scope: {assessment.impact_scope.value.replace('_', ' ').title()}",
            f"Affected Assets: {assessment.total_affected_count}",
        ]

        if assessment.potential_data_breach:
            parts.append("POTENTIAL DATA BREACH DETECTED")

        if assessment.highest_data_classification:
            parts.append(
                f"Highest Data Classification: {assessment.highest_data_classification.value}"
            )

        bi = assessment.business_impact
        parts.append(f"Operational Impact: {bi.operational_impact}")

        if bi.regulatory_impact:
            parts.append(f"Regulatory: {bi.regulatory_impact}")

        return ". ".join(parts)

    def _generate_recommendations(
        self,
        assessment: ImpactAssessment,
    ) -> list[str]:
        """Generate recommendations based on assessment."""
        recommendations = []

        # Based on impact level
        if assessment.impact_level == ImpactLevel.CRITICAL:
            recommendations.append("IMMEDIATE: Activate incident response team")
            recommendations.append("IMMEDIATE: Notify executive leadership")
        elif assessment.impact_level == ImpactLevel.HIGH:
            recommendations.append("Escalate to senior security team")

        # Based on data risk
        if assessment.potential_data_breach:
            recommendations.append("Initiate data breach response protocol")
            recommendations.append("Assess regulatory notification requirements")
            recommendations.append("Preserve evidence for forensic analysis")

        # Based on scope
        if assessment.impact_scope in [
            ImpactScope.ORGANIZATION_WIDE,
            ImpactScope.EXTERNAL,
        ]:
            recommendations.append("Consider organization-wide containment measures")

        # Based on assets
        critical_assets = [
            a for a in assessment.affected_assets
            if a.criticality == "critical"
        ]
        if critical_assets:
            recommendations.append(
                f"Prioritize recovery of {len(critical_assets)} critical assets"
            )

        # Default
        if not recommendations:
            recommendations.append("Continue monitoring affected assets")
            recommendations.append("Document incident timeline")

        return recommendations

    def _parse_timestamp(self, ts_str: str | None) -> datetime | None:
        """Parse timestamp string."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def _is_internal_only(self, ip: str) -> bool:
        """Check if IP is internal only (skip as asset)."""
        # Skip localhost and common internal ranges
        internal_prefixes = ["127.", "169.254.", "0.", "255."]
        return any(ip.startswith(p) for p in internal_prefixes)

    def prioritize_recovery(
        self,
        assets: list[AffectedAsset],
    ) -> list[AffectedAsset]:
        """Prioritize assets for recovery.

        Args:
            assets: List of affected assets

        Returns:
            Sorted list by recovery priority
        """
        for asset in assets:
            priority = 5  # Default

            # Adjust by criticality
            crit_adjustments = {
                "critical": -3,
                "high": -2,
                "medium": 0,
                "low": 2,
            }
            priority += crit_adjustments.get(asset.criticality, 0)

            # Adjust by data classification
            if asset.data_classification:
                dc_adjustments = {
                    DataClassification.TOP_SECRET: -3,
                    DataClassification.RESTRICTED: -2,
                    DataClassification.CONFIDENTIAL: -1,
                }
                priority += dc_adjustments.get(asset.data_classification, 0)

            asset.recovery_priority = max(1, min(10, priority))

        return sorted(assets, key=lambda a: a.recovery_priority)
