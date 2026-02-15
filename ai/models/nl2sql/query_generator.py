"""Natural Language to SQL query generation model with LLM integration."""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .schema_encoder import EncodedSchema, SchemaEncoder, TableInfo
from .sql_decoder import DecodedSQL, SQLDecoder, SQLDialect


class QueryTarget(str, Enum):
    """Target database for query."""

    CLICKHOUSE = "clickhouse"
    POSTGRESQL = "postgresql"


class SQLQuery(BaseModel):
    """Generated SQL query result."""

    natural_language: str = Field(description="Original natural language query")
    sql: str = Field(description="Generated SQL query")
    target: QueryTarget = Field(description="Target database")
    confidence: float = Field(ge=0, le=1, description="Confidence score")
    explanation: str = Field(description="Explanation of the query")
    tables_used: list[str] = Field(description="Tables referenced in query")
    estimated_cost: str = Field(description="Estimated query cost/complexity")
    warnings: list[str] = Field(default_factory=list, description="Query warnings")
    is_valid: bool = Field(default=True, description="Whether query is valid")
    validation_issues: list[str] = Field(default_factory=list, description="Validation issues")


class TableSchema(BaseModel):
    """Database table schema information."""

    name: str = Field(description="Table name")
    description: str = Field(description="Table description")
    columns: list[dict[str, Any]] = Field(description="Column definitions")
    sample_queries: list[str] = Field(default_factory=list, description="Example queries")


class NL2SQLGenerator(LoggerMixin):
    """Natural Language to SQL query generator.

    Uses LLM with schema context to generate optimized SQL queries
    for both ClickHouse (OLAP) and PostgreSQL (OLTP).

    Features:
    - Schema-aware generation
    - Multi-dialect support (ClickHouse, PostgreSQL)
    - Query validation and optimization
    - Korean language support
    - Confidence scoring
    """

    # System prompt for SQL generation
    SYSTEM_PROMPT = """You are an expert SQL analyst specializing in security data analysis.
Your task is to convert natural language questions into accurate SQL queries.

Important guidelines:
1. Generate ONLY the SQL query, no explanations
2. Use the provided schema context
3. For ClickHouse: use ClickHouse-specific functions (toDateTime, arrayJoin, etc.)
4. For PostgreSQL: use standard PostgreSQL syntax
5. Always include appropriate WHERE clauses to limit data
6. Use LIMIT to prevent excessive data retrieval
7. Optimize for performance with proper indexing hints

Schema Context:
{schema}

Target Database: {dialect}
"""

    # Korean-specific prompt additions
    KOREAN_PROMPT_ADDITION = """
Korean language support:
- 한국어 질문을 이해하고 SQL로 변환합니다
- 보안 용어: 경보(alert), 이벤트(event), 사례(case), 심각도(severity)
- 시간 표현: 오늘(today), 어제(yesterday), 지난 주(last week)
"""

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        """Initialize the generator.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model to use for generation
            api_key: API key for vLLM
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.llm_endpoint = llm_endpoint or "http://localhost:8080/v1"
        self.model_name = model_name
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries

        # Initialize components
        self.schema_encoder = SchemaEncoder(max_tokens=1500)
        self.sql_decoders = {
            QueryTarget.CLICKHOUSE: SQLDecoder(dialect=SQLDialect.CLICKHOUSE),
            QueryTarget.POSTGRESQL: SQLDecoder(dialect=SQLDialect.POSTGRESQL),
        }

        # Schema storage
        self._schemas: dict[QueryTarget, list[TableInfo]] = {}

        # HTTP client
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

    async def load_schemas(self, target: QueryTarget, schemas: list[TableSchema]) -> None:
        """Load table schemas for context.

        Args:
            target: Target database
            schemas: List of table schemas
        """
        self.logger.info("loading_schemas", target=target, count=len(schemas))

        # Convert to TableInfo for encoder
        table_infos = []
        for schema in schemas:
            from .schema_encoder import ColumnInfo, ColumnType
            columns = [
                ColumnInfo(
                    name=col.get("name", ""),
                    type=ColumnType(col.get("type", "string")),
                    description=col.get("description", ""),
                )
                for col in schema.columns
            ]
            table_infos.append(TableInfo(
                name=schema.name,
                description=schema.description,
                columns=columns,
                sample_queries=schema.sample_queries,
            ))

        self._schemas[target] = table_infos

        # Register with encoder
        self.schema_encoder.register_schema(target.value, table_infos)

    async def generate(
        self,
        query: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
        context: dict[str, Any] | None = None,
        language: str = "auto",
    ) -> SQLQuery:
        """Generate SQL from natural language.

        Args:
            query: Natural language query
            target: Target database
            context: Additional context (time range, filters, etc.)
            language: Query language ("auto", "en", "ko")

        Returns:
            Generated SQL query with metadata
        """
        self.logger.info(
            "generating_sql",
            query=query,
            target=target,
            has_context=context is not None,
        )

        # Detect language if auto
        if language == "auto":
            language = self._detect_language(query)

        # Encode schema
        encoded_schema = self.schema_encoder.encode(
            database=target.value,
            format="compact",
            query_context=query,
        )

        # Build prompt
        system_prompt = self._build_system_prompt(encoded_schema, target, language)
        user_prompt = self._build_user_prompt(query, context)

        # Generate SQL via LLM
        try:
            raw_sql = await self._call_llm(system_prompt, user_prompt)
        except Exception as e:
            self.logger.error("llm_call_failed", error=str(e))
            # Fallback to template-based generation
            raw_sql = self._fallback_generation(query, target)

        # Decode and validate SQL
        decoder = self.sql_decoders[target]
        decoded = decoder.decode(raw_sql)

        # Calculate confidence
        confidence = self._calculate_confidence(decoded, query)

        # Build response
        return SQLQuery(
            natural_language=query,
            sql=decoded.sql,
            target=target,
            confidence=confidence,
            explanation=self._generate_explanation(decoded, query),
            tables_used=decoded.tables_referenced,
            estimated_cost=decoded.estimated_complexity,
            warnings=[i.message for i in decoded.issues if self._get_severity_value(i.severity) == "warning"],
            is_valid=decoded.is_valid,
            validation_issues=[i.message for i in decoded.issues if self._get_severity_value(i.severity) == "error"],
        )

    def _detect_language(self, text: str) -> str:
        """Detect query language."""
        # Simple Korean detection
        korean_chars = sum(1 for c in text if '\uAC00' <= c <= '\uD7AF')
        if korean_chars > len(text) * 0.3:
            return "ko"
        return "en"

    def _get_severity_value(self, severity: Any) -> str:
        """Get severity value as string, handling both enum and string types.

        Pydantic's use_enum_values=True converts enums to strings during
        serialization, so we need to handle both cases.
        """
        if isinstance(severity, str):
            return severity
        return severity.value if hasattr(severity, 'value') else str(severity)

    def _build_system_prompt(
        self,
        schema: EncodedSchema,
        target: QueryTarget,
        language: str,
    ) -> str:
        """Build system prompt with schema context."""
        prompt = self.SYSTEM_PROMPT.format(
            schema=schema.text,
            dialect=target.value,
        )

        if language == "ko":
            prompt += self.KOREAN_PROMPT_ADDITION

        return prompt

    def _build_user_prompt(
        self,
        query: str,
        context: dict[str, Any] | None,
    ) -> str:
        """Build user prompt with query and context."""
        prompt = f"Question: {query}\n"

        if context:
            if "time_range" in context:
                prompt += f"Time range: {context['time_range']}\n"
            if "filters" in context:
                prompt += f"Filters: {context['filters']}\n"
            if "tables" in context:
                prompt += f"Relevant tables: {context['tables']}\n"

        prompt += "\nSQL Query:"
        return prompt

    async def _call_llm(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> str:
        """Call LLM API to generate SQL.

        Args:
            system_prompt: System prompt with schema context
            user_prompt: User query

        Returns:
            Generated SQL string
        """
        client = await self._get_client()

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": 512,
            "temperature": 0.0,  # Deterministic for SQL
            "stop": ["\n\n", "Question:", "###"],
        }

        for attempt in range(self.max_retries):
            try:
                response = await client.post(
                    f"{self.llm_endpoint}/chat/completions",
                    json=payload,
                )
                response.raise_for_status()

                data = response.json()
                content = data["choices"][0]["message"]["content"]
                return content.strip()

            except httpx.HTTPStatusError as e:
                self.logger.warning(
                    "llm_request_failed",
                    attempt=attempt + 1,
                    status=e.response.status_code,
                )
                if attempt == self.max_retries - 1:
                    raise

            except Exception as e:
                self.logger.warning(
                    "llm_request_error",
                    attempt=attempt + 1,
                    error=str(e),
                )
                if attempt == self.max_retries - 1:
                    raise

            await asyncio.sleep(2 ** attempt)  # Exponential backoff

        raise RuntimeError("LLM call failed after retries")

    def _fallback_generation(self, query: str, target: QueryTarget) -> str:
        """Fallback template-based SQL generation."""
        query_lower = query.lower()

        # Simple pattern matching for common queries
        if "critical" in query_lower and "alert" in query_lower:
            return "SELECT * FROM alerts WHERE severity = 'critical' ORDER BY created_at DESC LIMIT 100"

        if "count" in query_lower and "event" in query_lower:
            return "SELECT COUNT(*) FROM events WHERE timestamp > now() - INTERVAL 1 DAY"

        if "top" in query_lower and "ip" in query_lower:
            return "SELECT source_ip, COUNT(*) as cnt FROM events GROUP BY source_ip ORDER BY cnt DESC LIMIT 10"

        # Default fallback
        return "SELECT * FROM events ORDER BY timestamp DESC LIMIT 100"

    def _calculate_confidence(self, decoded: DecodedSQL, original_query: str) -> float:
        """Calculate confidence score for generated SQL."""
        confidence = 1.0

        # Penalize validation issues
        for issue in decoded.issues:
            severity_val = self._get_severity_value(issue.severity)
            if severity_val == "error":
                confidence -= 0.3
            elif severity_val == "warning":
                confidence -= 0.1

        # Reward table matches with query terms
        query_terms = set(original_query.lower().split())
        for table in decoded.tables_referenced:
            if table.lower() in query_terms:
                confidence += 0.1

        # Penalize high complexity
        if decoded.estimated_complexity == "high":
            confidence -= 0.1

        return max(0.0, min(1.0, confidence))

    def _generate_explanation(self, decoded: DecodedSQL, original_query: str) -> str:
        """Generate human-readable explanation of the SQL."""
        parts = []

        parts.append(f"This query retrieves data from: {', '.join(decoded.tables_referenced)}")

        if decoded.query_type == "SELECT":
            parts.append("It performs a SELECT operation")
        elif decoded.query_type in ("COUNT", "SUM", "AVG"):
            parts.append(f"It calculates {decoded.query_type}")

        if decoded.estimated_complexity != "low":
            parts.append(f"Query complexity: {decoded.estimated_complexity}")

        if decoded.optimizations_applied:
            parts.append(f"Optimizations: {', '.join(decoded.optimizations_applied)}")

        return ". ".join(parts) + "."

    async def validate_sql(self, sql: str, target: QueryTarget) -> tuple[bool, list[str]]:
        """Validate generated SQL query.

        Args:
            sql: SQL query to validate
            target: Target database

        Returns:
            Tuple of (is_valid, list of errors/warnings)
        """
        self.logger.info("validating_sql", target=target)

        decoder = self.sql_decoders[target]
        decoded = decoder.decode(sql)

        issues = [f"[{self._get_severity_value(i.severity)}] {i.message}" for i in decoded.issues]
        return decoded.is_valid, issues

    async def optimize_sql(self, sql: str, target: QueryTarget) -> str:
        """Optimize a SQL query for better performance.

        Args:
            sql: SQL query to optimize
            target: Target database

        Returns:
            Optimized SQL query
        """
        self.logger.info("optimizing_sql", target=target)

        decoder = self.sql_decoders[target]
        decoded = decoder.decode(sql)

        return decoded.sql

    async def explain_sql(
        self,
        sql: str,
        target: QueryTarget,
        language: str = "en",
    ) -> str:
        """Generate natural language explanation of SQL.

        Args:
            sql: SQL query to explain
            target: Target database
            language: Output language

        Returns:
            Natural language explanation
        """
        system_prompt = """You are an SQL expert. Explain the following SQL query in simple terms.
Focus on what data it retrieves and any important conditions or aggregations."""

        if language == "ko":
            system_prompt += "\n\nPlease respond in Korean (한국어로 설명해주세요)."

        user_prompt = f"SQL Query:\n{sql}\n\nExplanation:"

        try:
            explanation = await self._call_llm(system_prompt, user_prompt)
            return explanation
        except Exception as e:
            self.logger.error("explain_failed", error=str(e))
            decoder = self.sql_decoders[target]
            decoded = decoder.decode(sql)
            return self._generate_explanation(decoded, "")

    async def suggest_queries(
        self,
        context: str,
        target: QueryTarget = QueryTarget.CLICKHOUSE,
        num_suggestions: int = 5,
    ) -> list[str]:
        """Suggest relevant queries based on context.

        Args:
            context: Context description (e.g., "investigating brute force attack")
            target: Target database
            num_suggestions: Number of suggestions

        Returns:
            List of suggested natural language queries
        """
        system_prompt = f"""You are a security analyst assistant.
Based on the given context, suggest {num_suggestions} useful natural language queries for the security analyst.
These queries will be converted to SQL for the {target.value} database.
Focus on practical, actionable queries."""

        user_prompt = f"Context: {context}\n\nSuggest {num_suggestions} queries:"

        try:
            response = await self._call_llm(system_prompt, user_prompt)
            # Parse suggestions from response
            suggestions = []
            for line in response.split("\n"):
                line = line.strip()
                if line and not line.startswith("#"):
                    # Remove numbering
                    import re
                    clean = re.sub(r"^\d+[\.\)]\s*", "", line)
                    if clean:
                        suggestions.append(clean)

            return suggestions[:num_suggestions]

        except Exception as e:
            self.logger.error("suggest_failed", error=str(e))
            # Fallback suggestions
            return [
                "Show all critical alerts from today",
                "What are the top 10 source IPs by event count?",
                "List recent events from suspicious IPs",
                "Show alerts grouped by severity",
                "Find failed authentication attempts",
            ][:num_suggestions]
