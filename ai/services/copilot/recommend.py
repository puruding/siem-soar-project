"""Recommendation service for Security Copilot."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from models.recommender import (
    PlaybookRecommender,
    PlaybookRecommendation,
    RecommendationConfig,
    ActionSuggester,
    SuggestedAction,
    ActionPlan,
    SimilaritySearch,
    SimilarCase,
)


class PlaybookRecommendRequest(BaseModel):
    """Request for playbook recommendations."""

    context: dict[str, Any] = Field(description="Alert/incident context")
    max_recommendations: int = Field(default=5)
    min_confidence: float = Field(default=0.5, ge=0, le=1)
    require_auto_executable: bool = Field(default=False)


class PlaybookRecommendResponse(BaseModel):
    """Response with playbook recommendations."""

    recommendations: list[dict[str, Any]]
    total_found: int


class ActionSuggestRequest(BaseModel):
    """Request for action suggestions."""

    incident_context: dict[str, Any] = Field(description="Incident context")
    max_actions: int = Field(default=10)
    include_optional: bool = Field(default=True)


class ActionSuggestResponse(BaseModel):
    """Response with action suggestions."""

    plan_id: str
    actions: list[dict[str, Any]]
    total_estimated_time: int
    risk_assessment: str


class SimilarCaseRequest(BaseModel):
    """Request for similar case search."""

    query_context: dict[str, Any] = Field(description="Current case/incident context")
    max_results: int = Field(default=5)
    min_similarity: float = Field(default=0.5, ge=0, le=1)


class SimilarCaseResponse(BaseModel):
    """Response with similar cases."""

    cases: list[dict[str, Any]]
    resolution_suggestions: list[str]


class RecommendService(LoggerMixin):
    """Recommendation service for Security Copilot.

    Provides:
    - Playbook recommendations
    - Response action suggestions
    - Similar case search
    - Resolution suggestions
    """

    def __init__(
        self,
        llm_endpoint: str | None = None,
        embedding_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
    ) -> None:
        """Initialize the service.

        Args:
            llm_endpoint: vLLM API endpoint
            embedding_endpoint: Embedding API endpoint
            model_name: Model name
            api_key: API key
        """
        self.playbook_recommender = PlaybookRecommender(
            llm_endpoint=llm_endpoint,
            model_name=model_name,
            api_key=api_key,
        )
        self.action_suggester = ActionSuggester(
            llm_endpoint=llm_endpoint,
            model_name=model_name,
            api_key=api_key,
        )
        self.similarity_search = SimilaritySearch(
            embedding_endpoint=embedding_endpoint,
        )

    async def close(self) -> None:
        """Close resources."""
        await self.playbook_recommender.close()
        await self.action_suggester.close()
        await self.similarity_search.close()

    async def recommend_playbooks(
        self,
        request: PlaybookRecommendRequest,
    ) -> PlaybookRecommendResponse:
        """Recommend playbooks for incident.

        Args:
            request: Recommendation request

        Returns:
            Playbook recommendations
        """
        self.logger.info(
            "recommending_playbooks",
            alert_type=request.context.get("alert_type"),
        )

        config = RecommendationConfig(
            max_recommendations=request.max_recommendations,
            min_confidence=request.min_confidence,
            require_auto_executable=request.require_auto_executable,
        )

        recommendations = await self.playbook_recommender.recommend(
            request.context,
            config,
        )

        return PlaybookRecommendResponse(
            recommendations=[
                {
                    "playbook_id": r.playbook.playbook_id,
                    "name": r.playbook.name,
                    "description": r.playbook.description,
                    "category": r.playbook.category.value if hasattr(r.playbook.category, 'value') else str(r.playbook.category),
                    "confidence": r.confidence,
                    "match_reasons": r.match_reasons,
                    "estimated_impact": r.estimated_impact,
                    "prerequisites": r.prerequisites,
                    "warnings": r.warnings,
                    "auto_execute": r.auto_execute,
                    "success_rate": r.playbook.success_rate,
                    "avg_execution_time": r.playbook.avg_execution_time,
                }
                for r in recommendations
            ],
            total_found=len(recommendations),
        )

    async def suggest_actions(
        self,
        request: ActionSuggestRequest,
    ) -> ActionSuggestResponse:
        """Suggest response actions for incident.

        Args:
            request: Action suggestion request

        Returns:
            Action plan with suggestions
        """
        self.logger.info(
            "suggesting_actions",
            incident_type=request.incident_context.get("type"),
        )

        plan = await self.action_suggester.suggest_actions(
            request.incident_context,
            max_actions=request.max_actions,
            include_optional=request.include_optional,
        )

        return ActionSuggestResponse(
            plan_id=plan.plan_id,
            actions=[
                {
                    "action_id": a.action_id,
                    "title": a.title,
                    "description": a.description,
                    "category": a.category.value if hasattr(a.category, 'value') else str(a.category),
                    "priority": a.priority.value if hasattr(a.priority, 'value') else str(a.priority),
                    "estimated_time": a.estimated_time,
                    "automation_available": a.automation_available,
                    "playbook_id": a.playbook_id,
                    "prerequisites": a.prerequisites,
                    "dependencies": a.dependencies,
                    "tools_required": a.tools_required,
                }
                for a in plan.actions
            ],
            total_estimated_time=plan.total_estimated_time,
            risk_assessment=plan.risk_assessment,
        )

    async def find_similar_cases(
        self,
        request: SimilarCaseRequest,
    ) -> SimilarCaseResponse:
        """Find similar historical cases.

        Args:
            request: Similar case search request

        Returns:
            Similar cases and resolution suggestions
        """
        self.logger.info("finding_similar_cases")

        from models.recommender.similarity import SimilarityConfig

        config = SimilarityConfig(
            max_results=request.max_results,
            min_similarity=request.min_similarity,
        )

        similar_cases = await self.similarity_search.search(
            request.query_context,
            config,
        )

        resolution_suggestions = await self.similarity_search.get_resolution_suggestions(
            similar_cases
        )

        return SimilarCaseResponse(
            cases=[
                {
                    "case_id": c.case_id,
                    "title": c.title,
                    "description": c.description,
                    "similarity_score": c.similarity_score,
                    "match_reasons": c.match_reasons,
                    "resolution": c.resolution,
                    "playbooks_used": c.playbooks_used,
                    "time_to_resolve": c.time_to_resolve,
                    "severity": c.severity,
                    "incident_type": c.incident_type,
                }
                for c in similar_cases
            ],
            resolution_suggestions=resolution_suggestions,
        )

    async def get_playbook_details(self, playbook_id: str) -> dict[str, Any] | None:
        """Get detailed playbook information.

        Args:
            playbook_id: Playbook ID

        Returns:
            Playbook details or None
        """
        playbook = await self.playbook_recommender.get_playbook_details(playbook_id)
        if not playbook:
            return None

        return {
            "playbook_id": playbook.playbook_id,
            "name": playbook.name,
            "description": playbook.description,
            "category": playbook.category.value if hasattr(playbook.category, 'value') else str(playbook.category),
            "trigger_type": playbook.trigger_type.value if hasattr(playbook.trigger_type, 'value') else str(playbook.trigger_type),
            "applicable_alert_types": playbook.applicable_alert_types,
            "applicable_severity": playbook.applicable_severity,
            "mitre_tactics": playbook.mitre_tactics,
            "mitre_techniques": playbook.mitre_techniques,
            "steps": playbook.steps,
            "success_rate": playbook.success_rate,
            "avg_execution_time": playbook.avg_execution_time,
            "enabled": playbook.enabled,
        }
