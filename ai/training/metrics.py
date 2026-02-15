"""Evaluation metrics for alert classification."""

from typing import Any

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
    average_precision_score,
    matthews_corrcoef,
)

from common.logging import LoggerMixin


class ClassificationMetrics(LoggerMixin):
    """Compute classification metrics for model evaluation."""

    SEVERITY_LABELS = ["info", "low", "medium", "high", "critical"]
    CATEGORY_LABELS = [
        "malware", "intrusion", "data_exfiltration", "privilege_escalation",
        "lateral_movement", "credential_access", "reconnaissance",
        "command_and_control", "impact", "policy_violation", "anomaly", "other"
    ]

    def compute(
        self,
        predictions: list[int] | np.ndarray,
        labels: list[int] | np.ndarray,
        prefix: str = "",
        average: str = "macro",
    ) -> dict[str, float]:
        """Compute classification metrics.

        Args:
            predictions: Predicted class labels
            labels: Ground truth labels
            prefix: Prefix for metric names
            average: Averaging method for multi-class

        Returns:
            Dictionary of metrics
        """
        predictions = np.array(predictions)
        labels = np.array(labels)

        metrics = {}
        prefix = f"{prefix}_" if prefix else ""

        # Basic metrics
        metrics[f"{prefix}accuracy"] = accuracy_score(labels, predictions)

        metrics[f"{prefix}precision_{average}"] = precision_score(
            labels, predictions, average=average, zero_division=0
        )

        metrics[f"{prefix}recall_{average}"] = recall_score(
            labels, predictions, average=average, zero_division=0
        )

        metrics[f"{prefix}f1_{average}"] = f1_score(
            labels, predictions, average=average, zero_division=0
        )

        # Matthews Correlation Coefficient
        if len(np.unique(labels)) > 1:
            metrics[f"{prefix}mcc"] = matthews_corrcoef(labels, predictions)
        else:
            metrics[f"{prefix}mcc"] = 0.0

        # Per-class metrics (weighted)
        metrics[f"{prefix}precision_weighted"] = precision_score(
            labels, predictions, average="weighted", zero_division=0
        )
        metrics[f"{prefix}recall_weighted"] = recall_score(
            labels, predictions, average="weighted", zero_division=0
        )
        metrics[f"{prefix}f1_weighted"] = f1_score(
            labels, predictions, average="weighted", zero_division=0
        )

        return metrics

    def compute_detailed(
        self,
        predictions: list[int] | np.ndarray,
        labels: list[int] | np.ndarray,
        task: str = "severity",
    ) -> dict[str, Any]:
        """Compute detailed metrics including per-class breakdown.

        Args:
            predictions: Predicted class labels
            labels: Ground truth labels
            task: Task name for label lookup

        Returns:
            Detailed metrics dictionary
        """
        predictions = np.array(predictions)
        labels = np.array(labels)

        # Get label names
        if task == "severity":
            target_names = self.SEVERITY_LABELS
        elif task == "category":
            target_names = self.CATEGORY_LABELS
        elif task == "is_fp":
            target_names = ["true_positive", "false_positive"]
        else:
            target_names = None

        # Basic metrics
        metrics = self.compute(predictions, labels, prefix=task)

        # Confusion matrix
        cm = confusion_matrix(labels, predictions)
        metrics[f"{task}_confusion_matrix"] = cm.tolist()

        # Classification report (per-class metrics)
        report = classification_report(
            labels, predictions,
            target_names=target_names,
            output_dict=True,
            zero_division=0,
        )
        metrics[f"{task}_per_class"] = report

        return metrics

    def compute_multilabel(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        prefix: str = "",
        threshold: float = 0.5,
    ) -> dict[str, float]:
        """Compute metrics for multi-label classification.

        Args:
            predictions: Predicted probabilities [batch, num_classes]
            labels: Ground truth binary labels [batch, num_classes]
            prefix: Prefix for metric names
            threshold: Threshold for converting probabilities to labels

        Returns:
            Dictionary of metrics
        """
        predictions = np.array(predictions)
        labels = np.array(labels)

        # Convert probabilities to binary predictions
        binary_predictions = (predictions > threshold).astype(int)

        metrics = {}
        prefix = f"{prefix}_" if prefix else ""

        # Sample-averaged metrics
        metrics[f"{prefix}f1_samples"] = f1_score(
            labels, binary_predictions, average="samples", zero_division=0
        )

        # Macro-averaged metrics
        metrics[f"{prefix}precision_macro"] = precision_score(
            labels, binary_predictions, average="macro", zero_division=0
        )
        metrics[f"{prefix}recall_macro"] = recall_score(
            labels, binary_predictions, average="macro", zero_division=0
        )
        metrics[f"{prefix}f1_macro"] = f1_score(
            labels, binary_predictions, average="macro", zero_division=0
        )

        # Micro-averaged metrics
        metrics[f"{prefix}precision_micro"] = precision_score(
            labels, binary_predictions, average="micro", zero_division=0
        )
        metrics[f"{prefix}recall_micro"] = recall_score(
            labels, binary_predictions, average="micro", zero_division=0
        )
        metrics[f"{prefix}f1_micro"] = f1_score(
            labels, binary_predictions, average="micro", zero_division=0
        )

        # Hamming loss
        from sklearn.metrics import hamming_loss
        metrics[f"{prefix}hamming_loss"] = hamming_loss(labels, binary_predictions)

        # Average precision (mAP)
        if predictions.shape[1] > 1:
            try:
                metrics[f"{prefix}map"] = average_precision_score(
                    labels, predictions, average="macro"
                )
            except ValueError:
                metrics[f"{prefix}map"] = 0.0

        return metrics

    def compute_binary(
        self,
        predictions: list[int] | np.ndarray,
        labels: list[int] | np.ndarray,
        probabilities: list[float] | np.ndarray | None = None,
        prefix: str = "",
    ) -> dict[str, float]:
        """Compute metrics for binary classification.

        Args:
            predictions: Predicted class labels
            labels: Ground truth labels
            probabilities: Prediction probabilities for positive class
            prefix: Prefix for metric names

        Returns:
            Dictionary of metrics
        """
        predictions = np.array(predictions)
        labels = np.array(labels)

        metrics = self.compute(predictions, labels, prefix=prefix, average="binary")

        # Specificity (True Negative Rate)
        tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()
        metrics[f"{prefix}_specificity"] = tn / (tn + fp) if (tn + fp) > 0 else 0.0

        # AUC-ROC and AUC-PR if probabilities provided
        if probabilities is not None:
            probabilities = np.array(probabilities)
            try:
                metrics[f"{prefix}_auc_roc"] = roc_auc_score(labels, probabilities)
                metrics[f"{prefix}_auc_pr"] = average_precision_score(labels, probabilities)
            except ValueError:
                metrics[f"{prefix}_auc_roc"] = 0.5
                metrics[f"{prefix}_auc_pr"] = 0.5

        return metrics


class FalsePositiveMetrics(LoggerMixin):
    """Specialized metrics for false positive detection."""

    def compute_fp_reduction(
        self,
        predictions: np.ndarray,
        labels: np.ndarray,
        baseline_fp_rate: float | None = None,
    ) -> dict[str, float]:
        """Compute false positive reduction metrics.

        Args:
            predictions: Predicted FP labels (1 = FP)
            labels: Ground truth FP labels
            baseline_fp_rate: Baseline FP rate for comparison

        Returns:
            FP reduction metrics
        """
        predictions = np.array(predictions)
        labels = np.array(labels)

        # Count FPs correctly identified
        true_fp_count = np.sum(labels == 1)
        detected_fp_count = np.sum((predictions == 1) & (labels == 1))
        missed_fp_count = np.sum((predictions == 0) & (labels == 1))

        # FP detection rate
        fp_detection_rate = detected_fp_count / true_fp_count if true_fp_count > 0 else 0.0

        # False negative rate (missed FPs)
        fn_rate = missed_fp_count / true_fp_count if true_fp_count > 0 else 0.0

        # Wrongly flagged TPs as FPs
        wrongly_flagged = np.sum((predictions == 1) & (labels == 0))
        total_tp = np.sum(labels == 0)
        wrong_flag_rate = wrongly_flagged / total_tp if total_tp > 0 else 0.0

        metrics = {
            "fp_detection_rate": fp_detection_rate,
            "fp_miss_rate": fn_rate,
            "tp_wrong_flag_rate": wrong_flag_rate,
            "total_fps": int(true_fp_count),
            "detected_fps": int(detected_fp_count),
            "missed_fps": int(missed_fp_count),
        }

        # Compute FP reduction if baseline provided
        if baseline_fp_rate is not None:
            current_fp_rate = 1 - fp_detection_rate
            fp_reduction = (baseline_fp_rate - current_fp_rate) / baseline_fp_rate * 100
            metrics["fp_reduction_percent"] = fp_reduction

        return metrics


class AlertTriageMetrics(LoggerMixin):
    """Combined metrics for alert triage evaluation."""

    def __init__(self) -> None:
        self.classification_metrics = ClassificationMetrics()
        self.fp_metrics = FalsePositiveMetrics()

    def compute_all(
        self,
        severity_pred: np.ndarray,
        severity_labels: np.ndarray,
        category_pred: np.ndarray,
        category_labels: np.ndarray,
        fp_pred: np.ndarray,
        fp_labels: np.ndarray,
        risk_scores: np.ndarray | None = None,
        risk_labels: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """Compute all triage metrics.

        Args:
            severity_pred: Predicted severity labels
            severity_labels: Ground truth severity labels
            category_pred: Predicted category labels
            category_labels: Ground truth category labels
            fp_pred: Predicted FP labels
            fp_labels: Ground truth FP labels
            risk_scores: Predicted risk scores
            risk_labels: Ground truth risk scores

        Returns:
            Complete metrics dictionary
        """
        metrics = {}

        # Severity metrics
        severity_metrics = self.classification_metrics.compute_detailed(
            severity_pred, severity_labels, task="severity"
        )
        metrics.update(severity_metrics)

        # Category metrics
        category_metrics = self.classification_metrics.compute_detailed(
            category_pred, category_labels, task="category"
        )
        metrics.update(category_metrics)

        # FP detection metrics
        fp_detection = self.classification_metrics.compute_binary(
            fp_pred, fp_labels, prefix="fp"
        )
        metrics.update(fp_detection)

        # FP reduction metrics
        fp_reduction = self.fp_metrics.compute_fp_reduction(fp_pred, fp_labels)
        metrics.update(fp_reduction)

        # Risk score metrics
        if risk_scores is not None and risk_labels is not None:
            from sklearn.metrics import mean_absolute_error, mean_squared_error

            metrics["risk_mae"] = mean_absolute_error(risk_labels, risk_scores)
            metrics["risk_rmse"] = np.sqrt(mean_squared_error(risk_labels, risk_scores))
            metrics["risk_correlation"] = np.corrcoef(risk_labels, risk_scores)[0, 1]

        # Aggregate score
        metrics["triage_score"] = self._compute_triage_score(metrics)

        return metrics

    def _compute_triage_score(self, metrics: dict[str, Any]) -> float:
        """Compute aggregate triage effectiveness score.

        Args:
            metrics: Individual metrics

        Returns:
            Aggregate score (0-100)
        """
        # Weighted combination of key metrics
        weights = {
            "severity_f1_macro": 0.25,
            "category_f1_macro": 0.20,
            "fp_detection_rate": 0.30,
            "fp_f1_binary": 0.15,
            "severity_accuracy": 0.10,
        }

        score = 0.0
        for metric, weight in weights.items():
            value = metrics.get(metric, 0.0)
            if isinstance(value, (int, float)):
                score += value * weight * 100

        return min(100.0, max(0.0, score))
