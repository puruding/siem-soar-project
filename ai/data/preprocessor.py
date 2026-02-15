"""Data preprocessing for alert classification."""

import re
from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder

from common.logging import LoggerMixin


class AlertPreprocessor(LoggerMixin):
    """Preprocessor for alert data cleaning and transformation."""

    # Fields that require cleaning
    TEXT_FIELDS = ["title", "description", "rule_name", "message", "raw_log"]
    NUMERIC_FIELDS = [
        "bytes_sent", "bytes_received", "packet_count", "connection_duration",
        "event_count", "src_ip_alert_count_1h", "src_ip_alert_count_24h"
    ]
    CATEGORICAL_FIELDS = ["source_type", "protocol", "action"]

    # IP patterns
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    PRIVATE_IP_PATTERN = re.compile(
        r"\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.(?:\d{1,3}\.)\d{1,3}|"
        r"192\.168\.(?:\d{1,3}\.)\d{1,3})\b"
    )

    def __init__(
        self,
        fit_scalers: bool = True,
        mask_ips: bool = True,
        remove_timestamps: bool = True,
    ) -> None:
        """Initialize the preprocessor.

        Args:
            fit_scalers: Whether to fit scalers (training) or use existing
            mask_ips: Whether to mask IP addresses in text
            remove_timestamps: Whether to remove timestamps from text
        """
        self.fit_scalers = fit_scalers
        self.mask_ips = mask_ips
        self.remove_timestamps = remove_timestamps

        # Scalers and encoders
        self._numeric_scaler: StandardScaler | None = None
        self._label_encoders: dict[str, LabelEncoder] = {}
        self._is_fitted = False

    def fit(self, df: pd.DataFrame) -> "AlertPreprocessor":
        """Fit the preprocessor on training data.

        Args:
            df: Training DataFrame

        Returns:
            Self for chaining
        """
        self.logger.info("fitting_preprocessor", rows=len(df))

        # Fit numeric scaler
        numeric_data = df[self.NUMERIC_FIELDS].fillna(0).values
        self._numeric_scaler = StandardScaler()
        self._numeric_scaler.fit(np.log1p(numeric_data))

        # Fit label encoders for categorical fields
        for field in self.CATEGORICAL_FIELDS:
            if field in df.columns:
                encoder = LabelEncoder()
                values = df[field].fillna("unknown").astype(str)
                encoder.fit(values)
                self._label_encoders[field] = encoder

        self._is_fitted = True
        self.logger.info("preprocessor_fitted")
        return self

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform the data.

        Args:
            df: DataFrame to transform

        Returns:
            Transformed DataFrame
        """
        if not self._is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")

        df = df.copy()

        # Clean text fields
        for field in self.TEXT_FIELDS:
            if field in df.columns:
                df[field] = df[field].apply(self._clean_text)

        # Scale numeric fields
        numeric_data = df[self.NUMERIC_FIELDS].fillna(0).values
        scaled = self._numeric_scaler.transform(np.log1p(numeric_data))
        for i, field in enumerate(self.NUMERIC_FIELDS):
            df[f"{field}_scaled"] = scaled[:, i]

        # Encode categorical fields
        for field in self.CATEGORICAL_FIELDS:
            if field in df.columns and field in self._label_encoders:
                values = df[field].fillna("unknown").astype(str)
                # Handle unseen categories
                known_classes = set(self._label_encoders[field].classes_)
                values = values.apply(lambda x: x if x in known_classes else "unknown")
                df[f"{field}_encoded"] = self._label_encoders[field].transform(values)

        # Add derived features
        df = self._add_derived_features(df)

        self.logger.info("transformed_data", rows=len(df))
        return df

    def fit_transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit and transform in one step.

        Args:
            df: DataFrame to fit and transform

        Returns:
            Transformed DataFrame
        """
        return self.fit(df).transform(df)

    def _clean_text(self, text: Any) -> str:
        """Clean text field.

        Args:
            text: Raw text value

        Returns:
            Cleaned text
        """
        if pd.isna(text) or not isinstance(text, str):
            return ""

        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)

        # Mask IP addresses
        if self.mask_ips:
            text = self.PRIVATE_IP_PATTERN.sub("[PRIVATE_IP]", text)
            text = self.IP_PATTERN.sub("[IP]", text)

        # Remove timestamps
        if self.remove_timestamps:
            # ISO timestamps
            text = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?", "[TIMESTAMP]", text)
            # Unix timestamps
            text = re.sub(r"\b1[0-9]{9}\b", "[UNIX_TS]", text)

        # Remove hex values
        text = re.sub(r"0x[0-9a-fA-F]+", "[HEX]", text)

        # Remove file paths (but keep filename)
        text = re.sub(r"[A-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+", "[PATH]\\", text)
        text = re.sub(r"/(?:[^/\s]+/)+", "[PATH]/", text)

        # Remove long sequences of repeated characters
        text = re.sub(r"(.)\1{10,}", r"\1\1\1", text)

        return text.strip()

    def _add_derived_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add derived features.

        Args:
            df: DataFrame with base features

        Returns:
            DataFrame with derived features
        """
        # Traffic ratio
        if "bytes_sent" in df.columns and "bytes_received" in df.columns:
            total_bytes = df["bytes_sent"] + df["bytes_received"] + 1
            df["traffic_ratio"] = df["bytes_sent"] / total_bytes

        # Alert velocity
        if "src_ip_alert_count_1h" in df.columns and "src_ip_alert_count_24h" in df.columns:
            df["src_ip_alert_velocity"] = (
                df["src_ip_alert_count_1h"] / (df["src_ip_alert_count_24h"] + 1)
            )

        # Port features
        if "source_port" in df.columns:
            df["is_well_known_src_port"] = df["source_port"].apply(
                lambda x: 1 if x and x < 1024 else 0
            )
        if "dest_port" in df.columns:
            df["is_well_known_dst_port"] = df["dest_port"].apply(
                lambda x: 1 if x and x < 1024 else 0
            )
            # Common service ports
            df["is_web_port"] = df["dest_port"].apply(
                lambda x: 1 if x in (80, 443, 8080, 8443) else 0
            )
            df["is_mail_port"] = df["dest_port"].apply(
                lambda x: 1 if x in (25, 465, 587, 993, 995) else 0
            )
            df["is_remote_access_port"] = df["dest_port"].apply(
                lambda x: 1 if x in (22, 23, 3389, 5900) else 0
            )

        return df

    def save(self, path: str) -> None:
        """Save preprocessor state to file.

        Args:
            path: Output path
        """
        import joblib

        state = {
            "numeric_scaler": self._numeric_scaler,
            "label_encoders": self._label_encoders,
            "is_fitted": self._is_fitted,
            "mask_ips": self.mask_ips,
            "remove_timestamps": self.remove_timestamps,
        }
        joblib.dump(state, path)
        self.logger.info("saved_preprocessor", path=path)

    @classmethod
    def load(cls, path: str) -> "AlertPreprocessor":
        """Load preprocessor from file.

        Args:
            path: Input path

        Returns:
            Loaded preprocessor
        """
        import joblib

        state = joblib.load(path)
        preprocessor = cls(
            fit_scalers=False,
            mask_ips=state["mask_ips"],
            remove_timestamps=state["remove_timestamps"],
        )
        preprocessor._numeric_scaler = state["numeric_scaler"]
        preprocessor._label_encoders = state["label_encoders"]
        preprocessor._is_fitted = state["is_fitted"]

        return preprocessor


class TextNormalizer(LoggerMixin):
    """Normalize text for model input."""

    # Common replacements
    REPLACEMENTS = [
        (r"\bwin\b", "windows"),
        (r"\blinux\b", "linux"),
        (r"\bmac\b", "macos"),
        (r"\bcmd\.exe\b", "command_prompt"),
        (r"\bpowershell\.exe\b", "powershell"),
        (r"\bwscript\.exe\b", "windows_script"),
        (r"\bcscript\.exe\b", "console_script"),
        (r"\brundll32\.exe\b", "rundll32"),
        (r"\bregsvr32\.exe\b", "regsvr32"),
        (r"\bmshta\.exe\b", "mshta"),
    ]

    def __init__(self, lowercase: bool = True) -> None:
        """Initialize the normalizer.

        Args:
            lowercase: Whether to lowercase text
        """
        self.lowercase = lowercase
        self._patterns = [(re.compile(p, re.IGNORECASE), r) for p, r in self.REPLACEMENTS]

    def normalize(self, text: str) -> str:
        """Normalize text.

        Args:
            text: Input text

        Returns:
            Normalized text
        """
        if not text:
            return ""

        if self.lowercase:
            text = text.lower()

        # Apply replacements
        for pattern, replacement in self._patterns:
            text = pattern.sub(replacement, text)

        return text
