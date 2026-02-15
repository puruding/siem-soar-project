"""NL2SQL service for Security Copilot."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from models.nl2sql import NL2SQLGenerator, QueryTarget, SQLQuery


class NL2SQLRequest(BaseModel):
    """Request for NL2SQL conversion."""

    query: str = Field(description="Natural language query")
    target: QueryTarget = Field(default=QueryTarget.CLICKHOUSE)
    context: dict[str, Any] = Field(default_factory=dict)
    language: str = Field(default="auto", description="Query language (auto, en, ko)")
    validate: bool = Field(default=True, description="Validate generated SQL")
    explain: bool = Field(default=False, description="Include explanation")


class NL2SQLResponse(BaseModel):
    """Response from NL2SQL conversion."""

    sql: str = Field(description="Generated SQL query")
    confidence: float = Field(ge=0, le=1)
    tables_used: list[str] = Field(default_factory=list)
    estimated_cost: str = Field(default="low")
    warnings: list[str] = Field(default_factory=list)
    explanation: str | None = Field(default=None)
    is_valid: bool = Field(default=True)
    validation_issues: list[str] = Field(default_factory=list)
    suggestions: list[str] = Field(default_factory=list, description="Related query suggestions")


class NL2SQLService(LoggerMixin):
    """NL2SQL service wrapper for Copilot API.

    Provides:
    - Natural language to SQL conversion
    - Query validation and optimization
    - Multi-language support (English, Korean)
    - Context-aware generation
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
        self.generator = NL2SQLGenerator(
            llm_endpoint=llm_endpoint,
            model_name=model_name,
            api_key=api_key,
        )

    async def close(self) -> None:
        """Close resources."""
        await self.generator.close()

    async def convert(self, request: NL2SQLRequest) -> NL2SQLResponse:
        """Convert natural language to SQL.

        Args:
            request: NL2SQL request

        Returns:
            NL2SQL response with SQL and metadata
        """
        self.logger.info(
            "nl2sql_convert",
            query=request.query[:100],
            target=request.target,
        )

        # Generate SQL
        result = await self.generator.generate(
            query=request.query,
            target=request.target,
            context=request.context,
            language=request.language,
        )

        # Get explanation if requested
        explanation = None
        if request.explain:
            explanation = await self.generator.explain_sql(
                result.sql,
                request.target,
                language=request.language,
            )

        # Get suggestions for related queries
        suggestions = []
        if result.confidence < 0.8:
            suggestions = await self.generator.suggest_queries(
                context=request.query,
                target=request.target,
                num_suggestions=3,
            )

        return NL2SQLResponse(
            sql=result.sql,
            confidence=result.confidence,
            tables_used=result.tables_used,
            estimated_cost=result.estimated_cost,
            warnings=result.warnings,
            explanation=explanation,
            is_valid=result.is_valid,
            validation_issues=result.validation_issues,
            suggestions=suggestions,
        )

    async def validate(
        self,
        sql: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
    ) -> tuple[bool, list[str]]:
        """Validate a SQL query.

        Args:
            sql: SQL query to validate
            target: Target database

        Returns:
            Tuple of (is_valid, issues)
        """
        return await self.generator.validate_sql(sql, target)

    async def optimize(
        self,
        sql: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
    ) -> str:
        """Optimize a SQL query.

        Args:
            sql: SQL query to optimize
            target: Target database

        Returns:
            Optimized SQL
        """
        return await self.generator.optimize_sql(sql, target)

    async def explain(
        self,
        sql: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
        language: str = "en",
    ) -> str:
        """Explain a SQL query in natural language.

        Args:
            sql: SQL query to explain
            target: Target database
            language: Output language

        Returns:
            Natural language explanation
        """
        return await self.generator.explain_sql(sql, target, language)

    async def suggest(
        self,
        context: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
        num_suggestions: int = 5,
    ) -> list[str]:
        """Suggest queries based on context.

        Args:
            context: Context for suggestions
            target: Target database
            num_suggestions: Number of suggestions

        Returns:
            List of query suggestions
        """
        return await self.generator.suggest_queries(context, target, num_suggestions)


# Common query templates for quick access
QUERY_TEMPLATES = {
    "critical_alerts": {
        "en": "Show all critical alerts from today",
        "ko": "오늘 발생한 심각한 경보 보여줘",
        "sql": "SELECT * FROM alerts WHERE severity = 'critical' AND created_at >= today() ORDER BY created_at DESC",
    },
    "top_ips": {
        "en": "What are the top 10 source IPs by event count?",
        "ko": "이벤트 수가 가장 많은 상위 10개 IP는?",
        "sql": "SELECT source_ip, COUNT(*) as cnt FROM events GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
    },
    "failed_logins": {
        "en": "Show failed login attempts in the last hour",
        "ko": "지난 1시간 동안의 로그인 실패 시도를 보여줘",
        "sql": "SELECT * FROM events WHERE event_type = 'authentication' AND status = 'failed' AND timestamp > now() - INTERVAL 1 HOUR",
    },
    "alerts_by_severity": {
        "en": "Count alerts by severity this week",
        "ko": "이번 주 심각도별 경보 수",
        "sql": "SELECT severity, COUNT(*) FROM alerts WHERE created_at >= today() - 7 GROUP BY severity ORDER BY COUNT(*) DESC",
    },
    "open_cases": {
        "en": "List all open cases",
        "ko": "진행 중인 모든 케이스 목록",
        "sql": "SELECT * FROM cases WHERE status IN ('open', 'in_progress') ORDER BY priority, created_at",
    },
}


def get_template_suggestions(language: str = "en") -> list[dict[str, str]]:
    """Get query template suggestions.

    Args:
        language: Language for suggestions

    Returns:
        List of template suggestions
    """
    suggestions = []
    lang_key = "ko" if language == "ko" else "en"

    for name, template in QUERY_TEMPLATES.items():
        suggestions.append({
            "name": name,
            "query": template[lang_key],
            "sql": template["sql"],
        })

    return suggestions
