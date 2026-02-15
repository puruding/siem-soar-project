"""Model validation for deployment readiness."""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import numpy as np
import pandas as pd
import torch

from common.logging import LoggerMixin
from models.classifier.architecture import AlertClassifierModel
from training.metrics import ClassificationMetrics, AlertTriageMetrics


class ValidationStatus(str, Enum):
    """Validation result status."""

    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    PENDING = "pending"


@dataclass
class ValidationResult:
    """Result of model validation."""

    status: ValidationStatus
    version: str
    timestamp: datetime
    metrics: dict[str, float]
    thresholds: dict[str, float]
    failures: list[str]
    warnings: list[str]
    details: dict[str, Any]


class ModelValidator(LoggerMixin):
    """Validate model quality before deployment."""

    # Default thresholds
    DEFAULT_THRESHOLDS = {
        "severity_f1_macro": 0.80,
        "category_f1_macro": 0.75,
        "fp_detection_rate": 0.60,
        "fp_f1_binary": 0.70,
        "triage_score": 75.0,
        "severity_accuracy": 0.82,
        "latency_p99_ms": 100.0,
    }

    def __init__(
        self,
        thresholds: dict[str, float] | None = None,
    ) -> None:
        """Initialize the validator.

        Args:
            thresholds: Custom validation thresholds
        """
        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self._metrics = AlertTriageMetrics()

    async def validate_model(
        self,
        model: AlertClassifierModel,
        test_data: pd.DataFrame,
        version: str,
        test_loader: Any = None,
    ) -> ValidationResult:
        """Validate model against test data.

        Args:
            model: Model to validate
            test_data: Test dataset
            version: Model version
            test_loader: Optional pre-built data loader

        Returns:
            Validation result
        """
        self.logger.info("starting_validation", version=version)

        failures = []
        warnings = []
        metrics = {}

        # Run inference on test data
        predictions = await self._get_predictions(model, test_data, test_loader)

        # Calculate metrics
        all_metrics = self._metrics.compute_all(
            severity_pred=predictions["severity"],
            severity_labels=test_data["severity_encoded"].values,
            category_pred=predictions["category"],
            category_labels=test_data["category_encoded"].values,
            fp_pred=predictions["is_fp"],
            fp_labels=test_data["is_fp_encoded"].values,
        )

        metrics.update(all_metrics)

        # Check thresholds
        for metric_name, threshold in self.thresholds.items():
            if metric_name in metrics:
                value = metrics[metric_name]

                # For latency, lower is better
                if "latency" in metric_name:
                    if value > threshold:
                        failures.append(f"{metric_name}: {value:.3f} > {threshold}")
                else:
                    # For other metrics, higher is better
                    if value < threshold:
                        failures.append(f"{metric_name}: {value:.3f} < {threshold}")
                    elif value < threshold * 1.1:
                        warnings.append(f"{metric_name}: {value:.3f} near threshold {threshold}")

        # Determine status
        if failures:
            status = ValidationStatus.FAILED
        elif warnings:
            status = ValidationStatus.WARNING
        else:
            status = ValidationStatus.PASSED

        result = ValidationResult(
            status=status,
            version=version,
            timestamp=datetime.utcnow(),
            metrics=metrics,
            thresholds=self.thresholds,
            failures=failures,
            warnings=warnings,
            details={
                "test_samples": len(test_data),
                "predictions": {
                    "severity_distribution": np.bincount(predictions["severity"]).tolist(),
                    "fp_distribution": np.bincount(predictions["is_fp"]).tolist(),
                },
            },
        )

        self.logger.info(
            "validation_completed",
            status=status.value,
            version=version,
            num_failures=len(failures),
            num_warnings=len(warnings),
        )

        return result

    async def _get_predictions(
        self,
        model: AlertClassifierModel,
        test_data: pd.DataFrame,
        test_loader: Any = None,
    ) -> dict[str, np.ndarray]:
        """Get model predictions on test data.

        Args:
            model: Model to evaluate
            test_data: Test dataset
            test_loader: Optional data loader

        Returns:
            Dictionary of predictions
        """
        model.eval()
        device = next(model.parameters()).device

        all_severity = []
        all_category = []
        all_fp = []

        if test_loader:
            with torch.no_grad():
                for batch in test_loader:
                    batch = {
                        k: v.to(device) if isinstance(v, torch.Tensor) else v
                        for k, v in batch.items()
                    }

                    outputs = model(
                        input_ids=batch["input_ids"],
                        attention_mask=batch["attention_mask"],
                        numeric_features=batch.get("numeric_features"),
                        categorical_features=batch.get("categorical_features"),
                    )

                    all_severity.extend(
                        outputs["severity_logits"].argmax(dim=-1).cpu().tolist()
                    )
                    all_category.extend(
                        outputs["category_logits"].argmax(dim=-1).cpu().tolist()
                    )
                    all_fp.extend(
                        outputs["fp_logits"].argmax(dim=-1).cpu().tolist()
                    )

        return {
            "severity": np.array(all_severity),
            "category": np.array(all_category),
            "is_fp": np.array(all_fp),
        }

    async def validate_drift(
        self,
        model: AlertClassifierModel,
        reference_data: pd.DataFrame,
        current_data: pd.DataFrame,
        version: str,
    ) -> ValidationResult:
        """Validate for data drift.

        Args:
            model: Model to validate
            reference_data: Reference (training) data distribution
            current_data: Current production data distribution
            version: Model version

        Returns:
            Validation result
        """
        self.logger.info("validating_drift", version=version)

        failures = []
        warnings = []
        metrics = {}

        # Feature drift detection
        feature_cols = [c for c in reference_data.columns if c.endswith("_scaled")]

        for col in feature_cols:
            ref_values = reference_data[col].dropna().values
            cur_values = current_data[col].dropna().values

            if len(ref_values) < 10 or len(cur_values) < 10:
                continue

            # KS test for distribution shift
            from scipy.stats import ks_2samp
            stat, pvalue = ks_2samp(ref_values, cur_values)

            metrics[f"drift_{col}_ks"] = stat
            metrics[f"drift_{col}_pvalue"] = pvalue

            if pvalue < 0.01:
                warnings.append(f"Significant drift in {col}: KS={stat:.3f}, p={pvalue:.4f}")

        # Label drift detection
        for label_col in ["severity_encoded", "category_encoded"]:
            if label_col in reference_data.columns and label_col in current_data.columns:
                ref_dist = reference_data[label_col].value_counts(normalize=True)
                cur_dist = current_data[label_col].value_counts(normalize=True)

                # Align distributions
                all_labels = set(ref_dist.index) | set(cur_dist.index)
                ref_aligned = [ref_dist.get(l, 0) for l in sorted(all_labels)]
                cur_aligned = [cur_dist.get(l, 0) for l in sorted(all_labels)]

                # Jensen-Shannon divergence
                from scipy.spatial.distance import jensenshannon
                js_dist = jensenshannon(ref_aligned, cur_aligned)

                metrics[f"drift_{label_col}_js"] = js_dist

                if js_dist > 0.3:
                    failures.append(f"High label drift in {label_col}: JS={js_dist:.3f}")
                elif js_dist > 0.1:
                    warnings.append(f"Moderate label drift in {label_col}: JS={js_dist:.3f}")

        # Determine status
        if failures:
            status = ValidationStatus.FAILED
        elif warnings:
            status = ValidationStatus.WARNING
        else:
            status = ValidationStatus.PASSED

        return ValidationResult(
            status=status,
            version=version,
            timestamp=datetime.utcnow(),
            metrics=metrics,
            thresholds={},
            failures=failures,
            warnings=warnings,
            details={
                "reference_samples": len(reference_data),
                "current_samples": len(current_data),
            },
        )


class ABTestValidator(LoggerMixin):
    """Validate models through A/B testing."""

    def __init__(
        self,
        traffic_split: float = 0.1,
        min_samples: int = 1000,
    ) -> None:
        """Initialize A/B test validator.

        Args:
            traffic_split: Fraction of traffic for challenger model
            min_samples: Minimum samples before evaluation
        """
        self.traffic_split = traffic_split
        self.min_samples = min_samples

        self._champion_results: list[dict[str, Any]] = []
        self._challenger_results: list[dict[str, Any]] = []

    def record_result(
        self,
        model_variant: str,
        prediction: dict[str, Any],
        ground_truth: dict[str, Any] | None = None,
    ) -> None:
        """Record a prediction result.

        Args:
            model_variant: "champion" or "challenger"
            prediction: Model prediction
            ground_truth: Ground truth if available
        """
        result = {
            "prediction": prediction,
            "ground_truth": ground_truth,
            "timestamp": datetime.utcnow(),
        }

        if model_variant == "champion":
            self._champion_results.append(result)
        else:
            self._challenger_results.append(result)

    async def evaluate(self) -> dict[str, Any]:
        """Evaluate A/B test results.

        Returns:
            Evaluation summary
        """
        if len(self._challenger_results) < self.min_samples:
            return {
                "status": "insufficient_samples",
                "champion_samples": len(self._champion_results),
                "challenger_samples": len(self._challenger_results),
            }

        # Calculate metrics for both variants
        champion_metrics = self._calculate_metrics(self._champion_results)
        challenger_metrics = self._calculate_metrics(self._challenger_results)

        # Statistical significance test
        from scipy.stats import mannwhitneyu

        champion_scores = [r["prediction"].get("confidence", 0.5) for r in self._champion_results]
        challenger_scores = [r["prediction"].get("confidence", 0.5) for r in self._challenger_results]

        stat, pvalue = mannwhitneyu(champion_scores, challenger_scores, alternative="two-sided")

        # Determine winner
        challenger_better = (
            challenger_metrics.get("accuracy", 0) > champion_metrics.get("accuracy", 0) and
            pvalue < 0.05
        )

        return {
            "status": "completed",
            "champion_metrics": champion_metrics,
            "challenger_metrics": challenger_metrics,
            "pvalue": pvalue,
            "challenger_better": challenger_better,
            "recommendation": "deploy_challenger" if challenger_better else "keep_champion",
        }

    def _calculate_metrics(
        self, results: list[dict[str, Any]]
    ) -> dict[str, float]:
        """Calculate metrics from results.

        Args:
            results: List of prediction results

        Returns:
            Calculated metrics
        """
        # Only calculate if we have ground truth
        results_with_truth = [r for r in results if r.get("ground_truth")]

        if not results_with_truth:
            return {"samples": len(results)}

        correct = sum(
            1 for r in results_with_truth
            if r["prediction"].get("severity") == r["ground_truth"].get("severity")
        )

        return {
            "samples": len(results),
            "samples_with_truth": len(results_with_truth),
            "accuracy": correct / len(results_with_truth) if results_with_truth else 0,
        }
