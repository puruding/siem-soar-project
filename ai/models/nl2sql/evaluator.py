"""Evaluator for NL2SQL model performance."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class EvaluationExample(BaseModel):
    """Single evaluation example."""

    natural_language: str = Field(description="Natural language query")
    gold_sql: str = Field(description="Ground truth SQL")
    predicted_sql: str | None = Field(default=None, description="Predicted SQL")
    execution_result: Any | None = Field(default=None, description="Execution result")
    gold_result: Any | None = Field(default=None, description="Ground truth result")


@dataclass
class EvaluationMetrics:
    """Evaluation metrics for NL2SQL."""

    # Exact match accuracy
    exact_match: float = 0.0

    # Execution accuracy (same results)
    execution_accuracy: float = 0.0

    # Component-level metrics
    table_accuracy: float = 0.0
    column_accuracy: float = 0.0
    condition_accuracy: float = 0.0
    aggregate_accuracy: float = 0.0

    # SQL validity
    syntax_validity: float = 0.0

    # Overall
    total_examples: int = 0
    successful_executions: int = 0

    # Per-query-type breakdown
    metrics_by_type: dict[str, dict[str, float]] = field(default_factory=dict)


class NL2SQLEvaluator(LoggerMixin):
    """Evaluator for NL2SQL model.

    Supports multiple evaluation strategies:
    - Exact match: Normalized SQL string comparison
    - Execution match: Compare query results
    - Component match: Compare SQL components (tables, columns, conditions)
    - Semantic match: Compare query intent
    """

    def __init__(
        self,
        db_connector: Any | None = None,
        execute_queries: bool = False,
    ) -> None:
        """Initialize the evaluator.

        Args:
            db_connector: Database connector for execution-based evaluation
            execute_queries: Whether to execute queries for evaluation
        """
        self.db_connector = db_connector
        self.execute_queries = execute_queries and db_connector is not None

    def evaluate(
        self,
        examples: list[EvaluationExample],
    ) -> EvaluationMetrics:
        """Evaluate model on a set of examples.

        Args:
            examples: List of evaluation examples with predictions

        Returns:
            Evaluation metrics
        """
        self.logger.info("starting_evaluation", num_examples=len(examples))

        metrics = EvaluationMetrics(total_examples=len(examples))

        exact_matches = 0
        execution_matches = 0
        valid_syntax = 0
        table_matches = 0
        column_matches = 0
        condition_matches = 0
        aggregate_matches = 0

        type_metrics: dict[str, dict[str, int]] = {}

        for example in examples:
            if example.predicted_sql is None:
                continue

            # Normalize SQL for comparison
            gold_normalized = self._normalize_sql(example.gold_sql)
            pred_normalized = self._normalize_sql(example.predicted_sql)

            # Exact match
            if gold_normalized == pred_normalized:
                exact_matches += 1

            # Syntax validity
            if self._check_syntax(example.predicted_sql):
                valid_syntax += 1

            # Component matching
            gold_components = self._extract_components(example.gold_sql)
            pred_components = self._extract_components(example.predicted_sql)

            if self._compare_tables(gold_components, pred_components):
                table_matches += 1
            if self._compare_columns(gold_components, pred_components):
                column_matches += 1
            if self._compare_conditions(gold_components, pred_components):
                condition_matches += 1
            if self._compare_aggregates(gold_components, pred_components):
                aggregate_matches += 1

            # Execution-based evaluation
            if self.execute_queries:
                try:
                    gold_result = self._execute_query(example.gold_sql)
                    pred_result = self._execute_query(example.predicted_sql)

                    if self._compare_results(gold_result, pred_result):
                        execution_matches += 1
                        metrics.successful_executions += 1

                except Exception as e:
                    self.logger.warning("execution_failed", error=str(e))

            # Track by query type
            query_type = self._detect_query_type(example.gold_sql)
            if query_type not in type_metrics:
                type_metrics[query_type] = {"total": 0, "exact": 0, "valid": 0}
            type_metrics[query_type]["total"] += 1
            if gold_normalized == pred_normalized:
                type_metrics[query_type]["exact"] += 1
            if self._check_syntax(example.predicted_sql):
                type_metrics[query_type]["valid"] += 1

        # Calculate final metrics
        n = len(examples)
        if n > 0:
            metrics.exact_match = exact_matches / n
            metrics.syntax_validity = valid_syntax / n
            metrics.table_accuracy = table_matches / n
            metrics.column_accuracy = column_matches / n
            metrics.condition_accuracy = condition_matches / n
            metrics.aggregate_accuracy = aggregate_matches / n

            if self.execute_queries:
                metrics.execution_accuracy = execution_matches / n

        # Calculate per-type metrics
        for query_type, counts in type_metrics.items():
            total = counts["total"]
            if total > 0:
                metrics.metrics_by_type[query_type] = {
                    "exact_match": counts["exact"] / total,
                    "syntax_validity": counts["valid"] / total,
                    "count": total,
                }

        self.logger.info(
            "evaluation_complete",
            exact_match=metrics.exact_match,
            execution_accuracy=metrics.execution_accuracy,
        )

        return metrics

    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL for comparison."""
        # Convert to lowercase
        sql = sql.lower()

        # Remove extra whitespace
        sql = " ".join(sql.split())

        # Remove trailing semicolon
        sql = sql.rstrip(";")

        # Normalize quotes
        sql = sql.replace('"', "'")

        # Normalize operators
        sql = re.sub(r"\s*=\s*", " = ", sql)
        sql = re.sub(r"\s*,\s*", ", ", sql)
        sql = re.sub(r"\s*\(\s*", "(", sql)
        sql = re.sub(r"\s*\)\s*", ")", sql)

        return sql.strip()

    def _check_syntax(self, sql: str) -> bool:
        """Check if SQL has valid syntax."""
        try:
            # Basic checks
            if not sql.strip():
                return False

            # Balanced parentheses
            if sql.count("(") != sql.count(")"):
                return False

            # Balanced quotes
            single_quotes = len(re.findall(r"(?<!\\)'", sql))
            if single_quotes % 2 != 0:
                return False

            # Has valid starting keyword
            valid_starts = {"select", "insert", "update", "delete", "with", "create"}
            first_word = sql.strip().split()[0].lower()
            if first_word not in valid_starts:
                return False

            return True

        except Exception:
            return False

    def _extract_components(self, sql: str) -> dict[str, Any]:
        """Extract SQL components for comparison."""
        components = {
            "tables": [],
            "columns": [],
            "conditions": [],
            "aggregates": [],
            "group_by": [],
            "order_by": [],
        }

        sql_upper = sql.upper()

        # Extract tables
        from_pattern = r"\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        components["tables"].extend(re.findall(from_pattern, sql, re.IGNORECASE))

        join_pattern = r"\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)"
        components["tables"].extend(re.findall(join_pattern, sql, re.IGNORECASE))

        # Extract columns (simplified)
        select_match = re.search(r"\bSELECT\s+(.+?)\s+FROM", sql, re.IGNORECASE | re.DOTALL)
        if select_match:
            cols = select_match.group(1)
            # Split by comma, handling functions
            components["columns"] = [c.strip() for c in cols.split(",")]

        # Extract conditions
        where_match = re.search(r"\bWHERE\s+(.+?)(?:GROUP|ORDER|LIMIT|$)", sql, re.IGNORECASE | re.DOTALL)
        if where_match:
            components["conditions"] = [where_match.group(1).strip()]

        # Extract aggregates
        agg_pattern = r"\b(COUNT|SUM|AVG|MIN|MAX)\s*\("
        components["aggregates"] = re.findall(agg_pattern, sql, re.IGNORECASE)

        # Extract GROUP BY
        group_match = re.search(r"\bGROUP\s+BY\s+(.+?)(?:HAVING|ORDER|LIMIT|$)", sql, re.IGNORECASE)
        if group_match:
            components["group_by"] = [g.strip() for g in group_match.group(1).split(",")]

        # Extract ORDER BY
        order_match = re.search(r"\bORDER\s+BY\s+(.+?)(?:LIMIT|$)", sql, re.IGNORECASE)
        if order_match:
            components["order_by"] = [o.strip() for o in order_match.group(1).split(",")]

        return components

    def _compare_tables(self, gold: dict, pred: dict) -> bool:
        """Compare table references."""
        gold_tables = set(t.lower() for t in gold.get("tables", []))
        pred_tables = set(t.lower() for t in pred.get("tables", []))
        return gold_tables == pred_tables

    def _compare_columns(self, gold: dict, pred: dict) -> bool:
        """Compare column references."""
        gold_cols = set(c.lower().strip() for c in gold.get("columns", []))
        pred_cols = set(c.lower().strip() for c in pred.get("columns", []))

        # Allow SELECT * to match specific columns
        if "*" in gold_cols or "*" in pred_cols:
            return True

        return gold_cols == pred_cols

    def _compare_conditions(self, gold: dict, pred: dict) -> bool:
        """Compare WHERE conditions."""
        gold_conds = gold.get("conditions", [])
        pred_conds = pred.get("conditions", [])

        if not gold_conds and not pred_conds:
            return True

        # Normalize and compare
        gold_normalized = " ".join(c.lower() for c in gold_conds)
        pred_normalized = " ".join(c.lower() for c in pred_conds)

        # Simple comparison - in practice would need semantic comparison
        return self._normalize_sql(gold_normalized) == self._normalize_sql(pred_normalized)

    def _compare_aggregates(self, gold: dict, pred: dict) -> bool:
        """Compare aggregate functions."""
        gold_aggs = set(a.upper() for a in gold.get("aggregates", []))
        pred_aggs = set(a.upper() for a in pred.get("aggregates", []))
        return gold_aggs == pred_aggs

    def _detect_query_type(self, sql: str) -> str:
        """Detect query type for breakdown."""
        sql_upper = sql.upper().strip()

        if "GROUP BY" in sql_upper:
            return "aggregation"
        elif "JOIN" in sql_upper:
            return "join"
        elif "COUNT" in sql_upper or "SUM" in sql_upper or "AVG" in sql_upper:
            return "aggregate_function"
        elif sql_upper.startswith("SELECT"):
            return "simple_select"
        else:
            return "other"

    def _execute_query(self, sql: str) -> Any:
        """Execute SQL query and return results."""
        if not self.db_connector:
            return None
        # Implementation depends on the database connector
        return self.db_connector.execute(sql)

    def _compare_results(self, gold_result: Any, pred_result: Any) -> bool:
        """Compare query execution results."""
        if gold_result is None or pred_result is None:
            return False

        # For list/tuple results, compare as sets for order-independence
        if isinstance(gold_result, (list, tuple)) and isinstance(pred_result, (list, tuple)):
            # Convert to comparable format
            gold_set = set(tuple(row) if isinstance(row, (list, tuple)) else row for row in gold_result)
            pred_set = set(tuple(row) if isinstance(row, (list, tuple)) else row for row in pred_result)
            return gold_set == pred_set

        return gold_result == pred_result


class NL2SQLBenchmark:
    """Benchmark suite for NL2SQL evaluation."""

    # Spider-style evaluation categories
    DIFFICULTY_LEVELS = ["easy", "medium", "hard", "extra"]

    # SIEM-specific test cases
    SIEM_TEST_CASES = [
        {
            "id": "siem_001",
            "nl": "Show all critical alerts from today",
            "sql": "SELECT * FROM alerts WHERE severity = 'critical' AND created_at >= today()",
            "difficulty": "easy",
            "category": "filter",
        },
        {
            "id": "siem_002",
            "nl": "Which source IPs have more than 100 events?",
            "sql": "SELECT source_ip, COUNT(*) as cnt FROM events GROUP BY source_ip HAVING cnt > 100",
            "difficulty": "medium",
            "category": "aggregation",
        },
        {
            "id": "siem_003",
            "nl": "Find alerts that triggered the same rule as case C-123",
            "sql": "SELECT a.* FROM alerts a WHERE a.rule_id IN (SELECT rule_id FROM alerts WHERE case_id = 'C-123')",
            "difficulty": "hard",
            "category": "subquery",
        },
        {
            "id": "siem_004",
            "nl": "Show the top 5 attack techniques with their tactics from alerts this week",
            "sql": "SELECT mitre_techniques, mitre_tactics, COUNT(*) as count FROM alerts WHERE created_at >= today() - 7 GROUP BY mitre_techniques, mitre_tactics ORDER BY count DESC LIMIT 5",
            "difficulty": "hard",
            "category": "complex_aggregation",
        },
        {
            "id": "siem_005",
            "nl": "List all events from the same host as alert A-456",
            "sql": "SELECT e.* FROM events e JOIN alerts a ON e.hostname = JSONExtractString(a.ioc_indicators, 'hostname') WHERE a.alert_id = 'A-456'",
            "difficulty": "extra",
            "category": "join",
        },
    ]

    def __init__(self) -> None:
        """Initialize benchmark."""
        self.test_cases = self.SIEM_TEST_CASES

    def load_spider_subset(self, filepath: str) -> list[dict]:
        """Load Spider benchmark subset."""
        # In practice, this would load from the Spider dataset
        return []

    def get_test_cases(
        self,
        difficulty: str | None = None,
        category: str | None = None,
    ) -> list[EvaluationExample]:
        """Get test cases with optional filtering.

        Args:
            difficulty: Filter by difficulty level
            category: Filter by query category

        Returns:
            List of evaluation examples
        """
        cases = self.test_cases

        if difficulty:
            cases = [c for c in cases if c.get("difficulty") == difficulty]

        if category:
            cases = [c for c in cases if c.get("category") == category]

        return [
            EvaluationExample(
                natural_language=c["nl"],
                gold_sql=c["sql"],
            )
            for c in cases
        ]

    def run_benchmark(
        self,
        evaluator: NL2SQLEvaluator,
        model_generate_fn: Any,
    ) -> dict[str, Any]:
        """Run full benchmark suite.

        Args:
            evaluator: NL2SQL evaluator
            model_generate_fn: Function to generate SQL from natural language

        Returns:
            Benchmark results
        """
        results = {
            "overall": {},
            "by_difficulty": {},
            "by_category": {},
        }

        # Generate predictions for all test cases
        examples = self.get_test_cases()
        for example in examples:
            example.predicted_sql = model_generate_fn(example.natural_language)

        # Overall evaluation
        results["overall"] = evaluator.evaluate(examples).__dict__

        # By difficulty
        for diff in self.DIFFICULTY_LEVELS:
            diff_examples = [e for e in examples if any(
                c.get("difficulty") == diff and c["nl"] == e.natural_language
                for c in self.test_cases
            )]
            if diff_examples:
                results["by_difficulty"][diff] = evaluator.evaluate(diff_examples).__dict__

        return results
