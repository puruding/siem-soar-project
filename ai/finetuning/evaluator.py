"""Evaluator for Korean security domain models."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from .dataset import SecurityDataset, TaskType, TrainingExample


class EvaluationMetrics(BaseModel):
    """Evaluation metrics for security domain tasks."""

    # Overall metrics
    accuracy: float = Field(default=0.0, ge=0, le=1)
    exact_match: float = Field(default=0.0, ge=0, le=1)

    # Task-specific metrics
    summarization_rouge: dict[str, float] = Field(default_factory=dict)
    nl2sql_accuracy: float = Field(default=0.0, ge=0, le=1)
    classification_f1: float = Field(default=0.0, ge=0, le=1)
    qa_accuracy: float = Field(default=0.0, ge=0, le=1)

    # Korean-specific metrics
    korean_term_accuracy: float = Field(default=0.0, ge=0, le=1)
    bilingual_consistency: float = Field(default=0.0, ge=0, le=1)

    # Per-task breakdown
    task_metrics: dict[str, dict[str, float]] = Field(default_factory=dict)

    # Counts
    total_examples: int = Field(default=0)
    correct_examples: int = Field(default=0)


@dataclass
class EvaluationResult:
    """Result for a single evaluation example."""

    example: TrainingExample
    prediction: str
    is_correct: bool
    score: float
    details: dict[str, Any] = field(default_factory=dict)


class KoreanEvaluator(LoggerMixin):
    """Evaluator for Korean security domain models.

    Features:
    - Multi-task evaluation (summarization, NL2SQL, QA, classification)
    - Korean language quality assessment
    - Security terminology accuracy
    - Bilingual consistency checking
    """

    # Korean security terms for vocabulary check
    KOREAN_SECURITY_TERMS = {
        "경보", "인시던트", "위협", "취약점", "공격", "침해", "악성코드",
        "랜섬웨어", "피싱", "무차별", "권한", "유출", "탐지", "대응",
        "격리", "복구", "분석", "조사", "심각", "높음", "중간", "낮음",
    }

    def __init__(self) -> None:
        """Initialize the evaluator."""
        self._results: list[EvaluationResult] = []

    def evaluate(
        self,
        examples: list[TrainingExample],
        predictions: list[str],
    ) -> EvaluationMetrics:
        """Evaluate model predictions.

        Args:
            examples: Test examples
            predictions: Model predictions

        Returns:
            Evaluation metrics
        """
        self.logger.info("evaluating", num_examples=len(examples))

        if len(examples) != len(predictions):
            raise ValueError("Number of examples and predictions must match")

        self._results = []
        task_results: dict[TaskType, list[EvaluationResult]] = {}

        for example, prediction in zip(examples, predictions):
            result = self._evaluate_single(example, prediction)
            self._results.append(result)

            if example.task_type not in task_results:
                task_results[example.task_type] = []
            task_results[example.task_type].append(result)

        # Calculate overall metrics
        metrics = self._calculate_metrics(task_results)

        self.logger.info(
            "evaluation_complete",
            accuracy=metrics.accuracy,
            total=metrics.total_examples,
        )

        return metrics

    def _evaluate_single(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Evaluate a single example."""
        if example.task_type == TaskType.NL2SQL:
            return self._evaluate_nl2sql(example, prediction)
        elif example.task_type == TaskType.SUMMARIZATION:
            return self._evaluate_summarization(example, prediction)
        elif example.task_type == TaskType.CLASSIFICATION:
            return self._evaluate_classification(example, prediction)
        elif example.task_type == TaskType.QA:
            return self._evaluate_qa(example, prediction)
        else:
            return self._evaluate_generic(example, prediction)

    def _evaluate_nl2sql(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Evaluate NL2SQL task."""
        gold_sql = self._normalize_sql(example.output_text)
        pred_sql = self._normalize_sql(prediction)

        # Exact match
        exact_match = gold_sql == pred_sql

        # Component-level matching
        gold_components = self._extract_sql_components(example.output_text)
        pred_components = self._extract_sql_components(prediction)

        component_scores = {
            "tables": self._jaccard_similarity(
                gold_components.get("tables", set()),
                pred_components.get("tables", set())
            ),
            "columns": self._jaccard_similarity(
                gold_components.get("columns", set()),
                pred_components.get("columns", set())
            ),
            "conditions": self._jaccard_similarity(
                gold_components.get("conditions", set()),
                pred_components.get("conditions", set())
            ),
        }

        avg_component_score = sum(component_scores.values()) / len(component_scores)
        score = 1.0 if exact_match else avg_component_score

        return EvaluationResult(
            example=example,
            prediction=prediction,
            is_correct=exact_match,
            score=score,
            details={
                "exact_match": exact_match,
                "component_scores": component_scores,
            },
        )

    def _evaluate_summarization(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Evaluate summarization task."""
        # ROUGE-like scoring (simplified)
        gold_tokens = set(example.output_text.lower().split())
        pred_tokens = set(prediction.lower().split())

        # ROUGE-1 (unigram overlap)
        overlap = gold_tokens & pred_tokens
        precision = len(overlap) / len(pred_tokens) if pred_tokens else 0
        recall = len(overlap) / len(gold_tokens) if gold_tokens else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        # Korean term coverage
        korean_term_score = self._check_korean_terms(prediction)

        score = (f1 + korean_term_score) / 2

        return EvaluationResult(
            example=example,
            prediction=prediction,
            is_correct=f1 > 0.5,
            score=score,
            details={
                "rouge1_f1": f1,
                "precision": precision,
                "recall": recall,
                "korean_term_score": korean_term_score,
            },
        )

    def _evaluate_classification(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Evaluate classification task."""
        gold_label = example.output_text.lower().strip()
        pred_label = prediction.lower().strip()

        # Extract label from prediction (may include explanation)
        pred_extracted = self._extract_label(pred_label)
        gold_extracted = self._extract_label(gold_label)

        is_correct = pred_extracted == gold_extracted or gold_extracted in pred_extracted

        return EvaluationResult(
            example=example,
            prediction=prediction,
            is_correct=is_correct,
            score=1.0 if is_correct else 0.0,
            details={
                "gold_label": gold_extracted,
                "pred_label": pred_extracted,
            },
        )

    def _evaluate_qa(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Evaluate QA task."""
        # Token overlap score
        gold_tokens = set(example.output_text.lower().split())
        pred_tokens = set(prediction.lower().split())

        overlap = gold_tokens & pred_tokens
        overlap_ratio = len(overlap) / len(gold_tokens) if gold_tokens else 0

        # Key concept coverage
        key_concepts = self._extract_key_concepts(example.output_text)
        concept_coverage = sum(1 for c in key_concepts if c.lower() in prediction.lower()) / len(key_concepts) if key_concepts else 0

        score = (overlap_ratio + concept_coverage) / 2
        is_correct = score > 0.5

        return EvaluationResult(
            example=example,
            prediction=prediction,
            is_correct=is_correct,
            score=score,
            details={
                "overlap_ratio": overlap_ratio,
                "concept_coverage": concept_coverage,
            },
        )

    def _evaluate_generic(
        self,
        example: TrainingExample,
        prediction: str,
    ) -> EvaluationResult:
        """Generic evaluation fallback."""
        gold_tokens = set(example.output_text.lower().split())
        pred_tokens = set(prediction.lower().split())

        overlap = gold_tokens & pred_tokens
        score = len(overlap) / len(gold_tokens) if gold_tokens else 0

        return EvaluationResult(
            example=example,
            prediction=prediction,
            is_correct=score > 0.5,
            score=score,
            details={},
        )

    def _calculate_metrics(
        self,
        task_results: dict[TaskType, list[EvaluationResult]],
    ) -> EvaluationMetrics:
        """Calculate aggregate metrics."""
        total = len(self._results)
        correct = sum(1 for r in self._results if r.is_correct)

        metrics = EvaluationMetrics(
            total_examples=total,
            correct_examples=correct,
            accuracy=correct / total if total > 0 else 0,
        )

        # Task-specific metrics
        for task_type, results in task_results.items():
            task_total = len(results)
            task_correct = sum(1 for r in results if r.is_correct)
            task_avg_score = sum(r.score for r in results) / task_total if task_total > 0 else 0

            metrics.task_metrics[task_type.value] = {
                "accuracy": task_correct / task_total if task_total > 0 else 0,
                "avg_score": task_avg_score,
                "count": task_total,
            }

            # Set specific metrics
            if task_type == TaskType.NL2SQL:
                metrics.nl2sql_accuracy = task_correct / task_total if task_total > 0 else 0
            elif task_type == TaskType.CLASSIFICATION:
                metrics.classification_f1 = task_avg_score
            elif task_type == TaskType.QA:
                metrics.qa_accuracy = task_correct / task_total if task_total > 0 else 0
            elif task_type == TaskType.SUMMARIZATION:
                metrics.summarization_rouge = {
                    "rouge1_f1": sum(r.details.get("rouge1_f1", 0) for r in results) / task_total if task_total > 0 else 0
                }

        # Korean metrics
        korean_scores = [self._check_korean_terms(r.prediction) for r in self._results]
        metrics.korean_term_accuracy = sum(korean_scores) / len(korean_scores) if korean_scores else 0

        return metrics

    def _normalize_sql(self, sql: str) -> str:
        """Normalize SQL for comparison."""
        sql = sql.lower().strip()
        sql = re.sub(r"\s+", " ", sql)
        sql = sql.rstrip(";")
        return sql

    def _extract_sql_components(self, sql: str) -> dict[str, set]:
        """Extract SQL components."""
        components = {
            "tables": set(),
            "columns": set(),
            "conditions": set(),
        }

        # Tables
        from_match = re.findall(r"\bfrom\s+(\w+)", sql, re.IGNORECASE)
        join_match = re.findall(r"\bjoin\s+(\w+)", sql, re.IGNORECASE)
        components["tables"].update(t.lower() for t in from_match + join_match)

        # Columns (simplified)
        select_match = re.search(r"select\s+(.+?)\s+from", sql, re.IGNORECASE | re.DOTALL)
        if select_match:
            cols = select_match.group(1).split(",")
            components["columns"].update(c.strip().lower() for c in cols)

        return components

    def _jaccard_similarity(self, set1: set, set2: set) -> float:
        """Calculate Jaccard similarity."""
        if not set1 and not set2:
            return 1.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0

    def _check_korean_terms(self, text: str) -> float:
        """Check Korean security term usage."""
        if not text:
            return 0.0

        found_terms = sum(1 for term in self.KOREAN_SECURITY_TERMS if term in text)
        # Normalize by expected number of terms (assume ~3 per output)
        return min(found_terms / 3, 1.0)

    def _extract_label(self, text: str) -> str:
        """Extract classification label from text."""
        # Common patterns
        patterns = [
            r"^(\w+)",  # First word
            r"(\w+)\s*\(",  # Word before parenthesis
        ]

        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(1)

        return text.split()[0] if text.split() else ""

    def _extract_key_concepts(self, text: str) -> list[str]:
        """Extract key concepts from text."""
        # Simple keyword extraction
        keywords = []

        # Security terms
        for term in self.KOREAN_SECURITY_TERMS:
            if term in text:
                keywords.append(term)

        # Numbered items
        numbered = re.findall(r"\d\)\s*(\w+)", text)
        keywords.extend(numbered)

        return keywords[:5]  # Limit to 5 key concepts

    def get_detailed_results(self) -> list[dict[str, Any]]:
        """Get detailed results for analysis."""
        return [
            {
                "task_type": r.example.task_type.value,
                "input": r.example.input_text[:100],
                "gold": r.example.output_text[:100],
                "prediction": r.prediction[:100],
                "is_correct": r.is_correct,
                "score": r.score,
                "details": r.details,
            }
            for r in self._results
        ]


def run_evaluation(
    model_generate_fn: Any,
    test_dataset: SecurityDataset,
) -> EvaluationMetrics:
    """Run evaluation on a test dataset.

    Args:
        model_generate_fn: Function to generate predictions
        test_dataset: Test dataset

    Returns:
        Evaluation metrics
    """
    evaluator = KoreanEvaluator()

    # Get test examples
    _, test_examples = test_dataset.get_train_test_split()

    # Generate predictions
    predictions = []
    for example in test_examples:
        prompt = f"{example.instruction}\n\n{example.input_text}"
        prediction = model_generate_fn(prompt)
        predictions.append(prediction)

    # Evaluate
    return evaluator.evaluate(test_examples, predictions)
