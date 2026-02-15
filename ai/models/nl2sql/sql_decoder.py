"""SQL decoder and validator for NL2SQL model."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class SQLDialect(str, Enum):
    """SQL dialects supported."""

    CLICKHOUSE = "clickhouse"
    POSTGRESQL = "postgresql"
    GENERIC = "generic"


class ValidationSeverity(str, Enum):
    """Severity levels for validation issues."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationIssue(BaseModel):
    """A validation issue found in SQL."""

    severity: ValidationSeverity = Field(description="Issue severity")
    message: str = Field(description="Issue description")
    line: int | None = Field(default=None, description="Line number if applicable")
    suggestion: str | None = Field(default=None, description="Suggested fix")


@dataclass
class DecodedSQL:
    """Decoded and validated SQL result."""

    sql: str
    dialect: SQLDialect
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    query_type: str = "unknown"  # SELECT, INSERT, UPDATE, DELETE, etc.
    tables_referenced: list[str] = field(default_factory=list)
    estimated_complexity: str = "low"  # low, medium, high
    optimizations_applied: list[str] = field(default_factory=list)


class SQLDecoder(LoggerMixin):
    """Decodes, validates, and optimizes SQL queries.

    Features:
    - SQL syntax validation
    - Dialect-specific validation (ClickHouse, PostgreSQL)
    - Query optimization suggestions
    - Security checks (SQL injection prevention)
    - Complexity estimation
    """

    # Dangerous patterns for security
    DANGEROUS_PATTERNS = [
        r";\s*DROP\s+",
        r";\s*DELETE\s+",
        r";\s*TRUNCATE\s+",
        r";\s*UPDATE\s+",
        r";\s*INSERT\s+",
        r"--\s*$",
        r"/\*.*\*/",
        r"UNION\s+ALL\s+SELECT",
        r"EXEC\s*\(",
        r"xp_",
    ]

    # ClickHouse specific functions
    CLICKHOUSE_FUNCTIONS = {
        "toDateTime", "toDate", "toYYYYMM", "toYYYYMMDD",
        "now", "today", "yesterday",
        "arrayJoin", "groupArray", "groupUniqArray",
        "quantile", "quantiles", "median",
        "argMax", "argMin",
        "topK", "uniq", "uniqExact",
        "multiIf", "if", "transform",
        "JSONExtract", "JSONExtractString", "JSONExtractInt",
        "IPv4NumToString", "IPv4StringToNum",
        "dictGet", "dictHas",
    }

    # PostgreSQL specific functions
    POSTGRESQL_FUNCTIONS = {
        "to_timestamp", "to_date", "date_trunc",
        "now", "current_timestamp", "current_date",
        "array_agg", "string_agg", "json_agg",
        "percentile_cont", "percentile_disc",
        "row_number", "rank", "dense_rank",
        "jsonb_extract_path", "jsonb_extract_path_text",
        "inet", "host", "network",
    }

    def __init__(
        self,
        dialect: SQLDialect = SQLDialect.CLICKHOUSE,
        strict_mode: bool = True,
        allowed_tables: list[str] | None = None,
    ) -> None:
        """Initialize the decoder.

        Args:
            dialect: SQL dialect to use
            strict_mode: Enable strict validation
            allowed_tables: Whitelist of allowed tables (None = all)
        """
        self.dialect = dialect
        self.strict_mode = strict_mode
        self.allowed_tables = set(allowed_tables) if allowed_tables else None

    def decode(self, raw_sql: str) -> DecodedSQL:
        """Decode and validate SQL from LLM output.

        Args:
            raw_sql: Raw SQL string (may contain markdown, explanations, etc.)

        Returns:
            Decoded SQL with validation results
        """
        # Extract SQL from potential markdown code blocks
        sql = self._extract_sql(raw_sql)

        # Basic cleanup
        sql = self._cleanup_sql(sql)

        # Detect query type
        query_type = self._detect_query_type(sql)

        # Extract tables
        tables = self._extract_tables(sql)

        # Validate
        issues = self._validate(sql, tables)

        # Estimate complexity
        complexity = self._estimate_complexity(sql)

        # Apply optimizations
        optimized_sql, optimizations = self._optimize(sql)

        is_valid = not any(i.severity == ValidationSeverity.ERROR for i in issues)

        return DecodedSQL(
            sql=optimized_sql if is_valid else sql,
            dialect=self.dialect,
            is_valid=is_valid,
            issues=issues,
            query_type=query_type,
            tables_referenced=tables,
            estimated_complexity=complexity,
            optimizations_applied=optimizations,
        )

    def _extract_sql(self, raw: str) -> str:
        """Extract SQL from raw LLM output."""
        # Try to find SQL in markdown code blocks
        sql_block_pattern = r"```(?:sql)?\s*\n?(.*?)```"
        matches = re.findall(sql_block_pattern, raw, re.DOTALL | re.IGNORECASE)

        if matches:
            return matches[0].strip()

        # Look for SELECT, INSERT, etc. statements
        statement_pattern = r"(SELECT|INSERT|UPDATE|DELETE|WITH|CREATE|ALTER|DROP)\s+.*"
        match = re.search(statement_pattern, raw, re.DOTALL | re.IGNORECASE)

        if match:
            return match.group(0).strip()

        return raw.strip()

    def _cleanup_sql(self, sql: str) -> str:
        """Clean up SQL string."""
        # Remove trailing semicolons (will add if needed)
        sql = sql.rstrip(";").strip()

        # Normalize whitespace
        sql = re.sub(r"\s+", " ", sql)

        # Fix common issues
        sql = re.sub(r"\s*,\s*", ", ", sql)
        sql = re.sub(r"\s*=\s*", " = ", sql)

        return sql

    def _detect_query_type(self, sql: str) -> str:
        """Detect the type of SQL query."""
        sql_upper = sql.upper().strip()

        if sql_upper.startswith("SELECT") or sql_upper.startswith("WITH"):
            return "SELECT"
        elif sql_upper.startswith("INSERT"):
            return "INSERT"
        elif sql_upper.startswith("UPDATE"):
            return "UPDATE"
        elif sql_upper.startswith("DELETE"):
            return "DELETE"
        elif sql_upper.startswith("CREATE"):
            return "CREATE"
        elif sql_upper.startswith("ALTER"):
            return "ALTER"
        elif sql_upper.startswith("DROP"):
            return "DROP"
        else:
            return "UNKNOWN"

    def _extract_tables(self, sql: str) -> list[str]:
        """Extract table names from SQL."""
        tables = set()

        # FROM clause
        from_pattern = r"\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        tables.update(re.findall(from_pattern, sql, re.IGNORECASE))

        # JOIN clauses
        join_pattern = r"\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        tables.update(re.findall(join_pattern, sql, re.IGNORECASE))

        # UPDATE/INSERT INTO
        update_pattern = r"\b(?:UPDATE|INSERT\s+INTO)\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        tables.update(re.findall(update_pattern, sql, re.IGNORECASE))

        return list(tables)

    def _validate(self, sql: str, tables: list[str]) -> list[ValidationIssue]:
        """Validate SQL query."""
        issues: list[ValidationIssue] = []

        # Security checks
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, sql, re.IGNORECASE):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Potentially dangerous SQL pattern detected: {pattern}",
                    suggestion="Remove dangerous operations or use parameterized queries",
                ))

        # Table whitelist check
        if self.allowed_tables:
            for table in tables:
                if table.lower() not in {t.lower() for t in self.allowed_tables}:
                    issues.append(ValidationIssue(
                        severity=ValidationSeverity.ERROR,
                        message=f"Table '{table}' is not in the allowed tables list",
                        suggestion=f"Use one of: {', '.join(self.allowed_tables)}",
                    ))

        # Basic syntax check
        if not self._basic_syntax_check(sql):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.ERROR,
                message="SQL syntax appears invalid",
                suggestion="Check for missing keywords or unmatched parentheses",
            ))

        # Dialect-specific validation
        if self.dialect == SQLDialect.CLICKHOUSE:
            issues.extend(self._validate_clickhouse(sql))
        elif self.dialect == SQLDialect.POSTGRESQL:
            issues.extend(self._validate_postgresql(sql))

        # Best practices warnings
        issues.extend(self._check_best_practices(sql))

        return issues

    def _basic_syntax_check(self, sql: str) -> bool:
        """Basic SQL syntax validation."""
        # Check parentheses balance
        if sql.count("(") != sql.count(")"):
            return False

        # Check quotes balance
        single_quotes = sql.count("'") - sql.count("\\'")
        if single_quotes % 2 != 0:
            return False

        # Must have valid starting keyword
        valid_starts = ["SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "CREATE", "ALTER", "DROP"]
        if not any(sql.upper().strip().startswith(kw) for kw in valid_starts):
            return False

        return True

    def _validate_clickhouse(self, sql: str) -> list[ValidationIssue]:
        """ClickHouse-specific validation."""
        issues = []

        # Check for PostgreSQL functions that don't exist in ClickHouse
        pg_only_funcs = ["to_timestamp", "date_trunc", "array_agg", "string_agg"]
        for func in pg_only_funcs:
            if re.search(rf"\b{func}\s*\(", sql, re.IGNORECASE):
                ch_alt = self._get_clickhouse_alternative(func)
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Function '{func}' is not available in ClickHouse",
                    suggestion=f"Use ClickHouse alternative: {ch_alt}",
                ))

        # Warn about LIMIT without ORDER BY
        if re.search(r"\bLIMIT\s+\d+", sql, re.IGNORECASE):
            if not re.search(r"\bORDER\s+BY\b", sql, re.IGNORECASE):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message="LIMIT without ORDER BY may return inconsistent results",
                    suggestion="Add ORDER BY clause for deterministic results",
                ))

        return issues

    def _validate_postgresql(self, sql: str) -> list[ValidationIssue]:
        """PostgreSQL-specific validation."""
        issues = []

        # Check for ClickHouse functions that don't exist in PostgreSQL
        ch_only_funcs = ["toDateTime", "toYYYYMM", "arrayJoin", "groupArray"]
        for func in ch_only_funcs:
            if re.search(rf"\b{func}\s*\(", sql, re.IGNORECASE):
                pg_alt = self._get_postgresql_alternative(func)
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.ERROR,
                    message=f"Function '{func}' is not available in PostgreSQL",
                    suggestion=f"Use PostgreSQL alternative: {pg_alt}",
                ))

        return issues

    def _check_best_practices(self, sql: str) -> list[ValidationIssue]:
        """Check SQL best practices."""
        issues = []

        # SELECT * warning
        if re.search(r"\bSELECT\s+\*", sql, re.IGNORECASE):
            issues.append(ValidationIssue(
                severity=ValidationSeverity.WARNING,
                message="SELECT * may fetch unnecessary columns",
                suggestion="Specify only required columns",
            ))

        # No WHERE clause on large tables
        if self._detect_query_type(sql) == "SELECT":
            if not re.search(r"\bWHERE\b", sql, re.IGNORECASE):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.WARNING,
                    message="No WHERE clause - query may scan entire table",
                    suggestion="Add filtering conditions",
                ))

        # No LIMIT on SELECT
        if self._detect_query_type(sql) == "SELECT":
            if not re.search(r"\bLIMIT\b", sql, re.IGNORECASE):
                issues.append(ValidationIssue(
                    severity=ValidationSeverity.INFO,
                    message="No LIMIT clause - consider adding for large tables",
                    suggestion="Add LIMIT to prevent excessive data retrieval",
                ))

        return issues

    def _estimate_complexity(self, sql: str) -> str:
        """Estimate query complexity."""
        score = 0

        # Subqueries
        score += sql.upper().count("SELECT") - 1  # Extra SELECTs indicate subqueries
        score += sql.upper().count("WITH")

        # Joins
        score += len(re.findall(r"\bJOIN\b", sql, re.IGNORECASE))

        # Aggregations
        agg_funcs = ["COUNT", "SUM", "AVG", "MAX", "MIN", "GROUP BY"]
        for func in agg_funcs:
            if func in sql.upper():
                score += 1

        # Window functions
        if re.search(r"\bOVER\s*\(", sql, re.IGNORECASE):
            score += 2

        if score <= 2:
            return "low"
        elif score <= 5:
            return "medium"
        else:
            return "high"

    def _optimize(self, sql: str) -> tuple[str, list[str]]:
        """Apply optimizations to SQL."""
        optimizations = []

        # ClickHouse specific optimizations
        if self.dialect == SQLDialect.CLICKHOUSE:
            # Add PREWHERE for better performance
            if re.search(r"\bWHERE\b", sql, re.IGNORECASE):
                # Check if there's a simple condition that could use PREWHERE
                where_match = re.search(
                    r"\bWHERE\s+(\w+\s*(?:=|>|<|>=|<=|IN)\s*[^AND]+)",
                    sql,
                    re.IGNORECASE
                )
                if where_match and "PREWHERE" not in sql.upper():
                    optimizations.append("Consider using PREWHERE for indexed columns")

            # Suggest FINAL for deduplication
            if re.search(r"\bReplacingMergeTree\b", sql, re.IGNORECASE):
                if "FINAL" not in sql.upper():
                    optimizations.append("Consider adding FINAL for ReplacingMergeTree")

        # Add semicolon at the end
        if not sql.rstrip().endswith(";"):
            sql = sql + ";"

        return sql, optimizations

    def _get_clickhouse_alternative(self, pg_func: str) -> str:
        """Get ClickHouse alternative for PostgreSQL function."""
        alternatives = {
            "to_timestamp": "toDateTime()",
            "date_trunc": "toStartOfHour/Day/Week/Month()",
            "array_agg": "groupArray()",
            "string_agg": "arrayStringConcat(groupArray())",
        }
        return alternatives.get(pg_func.lower(), "Check ClickHouse documentation")

    def _get_postgresql_alternative(self, ch_func: str) -> str:
        """Get PostgreSQL alternative for ClickHouse function."""
        alternatives = {
            "toDateTime": "to_timestamp()",
            "toYYYYMM": "to_char(date, 'YYYYMM')",
            "arrayJoin": "unnest()",
            "groupArray": "array_agg()",
        }
        return alternatives.get(ch_func, "Check PostgreSQL documentation")


class SQLOptimizer(LoggerMixin):
    """Advanced SQL query optimizer."""

    def __init__(self, dialect: SQLDialect = SQLDialect.CLICKHOUSE) -> None:
        """Initialize optimizer.

        Args:
            dialect: Target SQL dialect
        """
        self.dialect = dialect

    def optimize(
        self,
        sql: str,
        schema_info: dict[str, Any] | None = None,
    ) -> tuple[str, list[str]]:
        """Optimize SQL query.

        Args:
            sql: SQL query to optimize
            schema_info: Schema information for intelligent optimization

        Returns:
            Tuple of (optimized_sql, list of optimizations applied)
        """
        optimizations = []

        # Rewrite subqueries as JOINs where possible
        sql, opt = self._optimize_subqueries(sql)
        if opt:
            optimizations.append(opt)

        # Add index hints for ClickHouse
        if self.dialect == SQLDialect.CLICKHOUSE:
            sql, opt = self._add_index_hints(sql, schema_info)
            if opt:
                optimizations.append(opt)

        # Optimize GROUP BY ordering
        sql, opt = self._optimize_group_by(sql)
        if opt:
            optimizations.append(opt)

        return sql, optimizations

    def _optimize_subqueries(self, sql: str) -> tuple[str, str | None]:
        """Attempt to convert correlated subqueries to JOINs."""
        # This is a placeholder for complex subquery optimization
        # In practice, this would analyze the query structure
        return sql, None

    def _add_index_hints(
        self,
        sql: str,
        schema_info: dict[str, Any] | None,
    ) -> tuple[str, str | None]:
        """Add index hints for ClickHouse."""
        # Placeholder for index hint optimization
        return sql, None

    def _optimize_group_by(self, sql: str) -> tuple[str, str | None]:
        """Optimize GROUP BY column ordering."""
        # Placeholder for GROUP BY optimization
        return sql, None
