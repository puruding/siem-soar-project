"""Training data pipeline for alert classification."""

import asyncio
from datetime import datetime, timedelta
from typing import Any, AsyncIterator

import clickhouse_connect
import pandas as pd
from pydantic import Field

from common import get_settings
from common.logging import LoggerMixin
from common.models import BaseModel


class DataPipelineConfig(BaseModel):
    """Configuration for data pipeline."""

    # ClickHouse connection
    clickhouse_host: str = Field(default="localhost")
    clickhouse_port: int = Field(default=8123)
    clickhouse_database: str = Field(default="siemsoar")
    clickhouse_user: str = Field(default="default")
    clickhouse_password: str = Field(default="")

    # Data selection
    lookback_days: int = Field(default=90, description="Days of data to fetch")
    min_samples_per_class: int = Field(default=100, description="Min samples per class")
    max_samples_per_class: int = Field(default=10000, description="Max samples per class")

    # Train/val/test split
    train_ratio: float = Field(default=0.8)
    val_ratio: float = Field(default=0.1)
    test_ratio: float = Field(default=0.1)

    # Output
    output_dir: str = Field(default="data")
    output_format: str = Field(default="parquet")


class AlertDataPipeline(LoggerMixin):
    """Pipeline for extracting and preparing training data from ClickHouse."""

    ALERT_QUERY = """
        SELECT
            a.alert_id,
            a.title,
            a.description,
            a.rule_name,
            a.rule_id,
            a.source_type,
            a.severity as original_severity,
            a.category as original_category,
            a.timestamp,
            a.source_ip,
            a.dest_ip,
            a.source_port,
            a.dest_port,
            a.protocol,
            a.action,
            a.bytes_sent,
            a.bytes_received,
            a.packet_count,
            a.raw_log,
            a.mitre_tactics,
            a.mitre_techniques,
            -- Asset enrichment
            asset.criticality as asset_criticality,
            asset.is_server as asset_is_server,
            asset.has_pii as asset_has_pii,
            -- Labels from analyst feedback
            COALESCE(f.verified_severity, a.severity) as severity,
            COALESCE(f.verified_category, a.category) as category,
            COALESCE(f.is_false_positive, 0) as is_false_positive,
            COALESCE(f.risk_score, 50) as risk_score,
            f.mitre_tactics_verified,
            f.mitre_techniques_verified,
            -- Aggregations
            src_agg.alert_count_1h as src_ip_alert_count_1h,
            src_agg.alert_count_24h as src_ip_alert_count_24h,
            dst_agg.alert_count_1h as dst_ip_alert_count_1h,
            dst_agg.alert_count_24h as dst_ip_alert_count_24h
        FROM alerts a
        LEFT JOIN analyst_feedback f ON a.alert_id = f.alert_id
        LEFT JOIN assets asset ON a.asset_id = asset.asset_id
        LEFT JOIN (
            SELECT
                source_ip,
                countIf(timestamp > now() - INTERVAL 1 HOUR) as alert_count_1h,
                countIf(timestamp > now() - INTERVAL 24 HOUR) as alert_count_24h
            FROM alerts
            WHERE timestamp > now() - INTERVAL {lookback_days} DAY
            GROUP BY source_ip
        ) src_agg ON a.source_ip = src_agg.source_ip
        LEFT JOIN (
            SELECT
                dest_ip,
                countIf(timestamp > now() - INTERVAL 1 HOUR) as alert_count_1h,
                countIf(timestamp > now() - INTERVAL 24 HOUR) as alert_count_24h
            FROM alerts
            WHERE timestamp > now() - INTERVAL {lookback_days} DAY
            GROUP BY dest_ip
        ) dst_agg ON a.dest_ip = dst_agg.dest_ip
        WHERE a.timestamp > now() - INTERVAL {lookback_days} DAY
        ORDER BY a.timestamp
    """

    def __init__(self, config: DataPipelineConfig | None = None) -> None:
        """Initialize the data pipeline.

        Args:
            config: Pipeline configuration
        """
        self.config = config or DataPipelineConfig()
        self._client: clickhouse_connect.driver.Client | None = None

    async def connect(self) -> None:
        """Connect to ClickHouse."""
        self.logger.info(
            "connecting_to_clickhouse",
            host=self.config.clickhouse_host,
            database=self.config.clickhouse_database,
        )
        self._client = clickhouse_connect.get_client(
            host=self.config.clickhouse_host,
            port=self.config.clickhouse_port,
            database=self.config.clickhouse_database,
            username=self.config.clickhouse_user,
            password=self.config.clickhouse_password,
        )

    async def disconnect(self) -> None:
        """Disconnect from ClickHouse."""
        if self._client:
            self._client.close()
            self._client = None

    async def fetch_training_data(self) -> pd.DataFrame:
        """Fetch training data from ClickHouse.

        Returns:
            DataFrame with alert data and labels
        """
        if not self._client:
            await self.connect()

        self.logger.info(
            "fetching_training_data",
            lookback_days=self.config.lookback_days,
        )

        query = self.ALERT_QUERY.format(lookback_days=self.config.lookback_days)
        result = self._client.query(query)

        df = pd.DataFrame(result.result_rows, columns=result.column_names)
        self.logger.info("fetched_rows", count=len(df))

        return df

    async def balance_classes(self, df: pd.DataFrame) -> pd.DataFrame:
        """Balance classes with under/oversampling.

        Args:
            df: Raw training data

        Returns:
            Balanced DataFrame
        """
        self.logger.info("balancing_classes", original_size=len(df))

        balanced_dfs = []

        # Balance severity classes
        for severity in df["severity"].unique():
            class_df = df[df["severity"] == severity]
            n_samples = len(class_df)

            if n_samples < self.config.min_samples_per_class:
                # Oversample with replacement
                class_df = class_df.sample(
                    n=self.config.min_samples_per_class,
                    replace=True,
                    random_state=42,
                )
            elif n_samples > self.config.max_samples_per_class:
                # Undersample
                class_df = class_df.sample(
                    n=self.config.max_samples_per_class,
                    replace=False,
                    random_state=42,
                )

            balanced_dfs.append(class_df)

        balanced_df = pd.concat(balanced_dfs, ignore_index=True)
        self.logger.info("balanced_size", count=len(balanced_df))

        return balanced_df

    def split_data(
        self, df: pd.DataFrame
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """Split data into train/val/test sets.

        Args:
            df: Full dataset

        Returns:
            Tuple of (train_df, val_df, test_df)
        """
        # Sort by timestamp for temporal split
        df = df.sort_values("timestamp")

        n = len(df)
        train_end = int(n * self.config.train_ratio)
        val_end = int(n * (self.config.train_ratio + self.config.val_ratio))

        train_df = df.iloc[:train_end].copy()
        val_df = df.iloc[train_end:val_end].copy()
        test_df = df.iloc[val_end:].copy()

        self.logger.info(
            "data_split",
            train_size=len(train_df),
            val_size=len(val_df),
            test_size=len(test_df),
        )

        return train_df, val_df, test_df

    async def save_datasets(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
    ) -> dict[str, str]:
        """Save datasets to files.

        Args:
            train_df: Training data
            val_df: Validation data
            test_df: Test data

        Returns:
            Dictionary of file paths
        """
        import os
        os.makedirs(self.config.output_dir, exist_ok=True)

        paths = {}
        for name, df in [("train", train_df), ("val", val_df), ("test", test_df)]:
            path = f"{self.config.output_dir}/{name}.{self.config.output_format}"

            if self.config.output_format == "parquet":
                df.to_parquet(path, index=False)
            elif self.config.output_format == "csv":
                df.to_csv(path, index=False)
            else:
                raise ValueError(f"Unsupported format: {self.config.output_format}")

            paths[name] = path
            self.logger.info("saved_dataset", name=name, path=path, rows=len(df))

        return paths

    async def run(self) -> dict[str, str]:
        """Run the full data pipeline.

        Returns:
            Dictionary of output file paths
        """
        try:
            await self.connect()

            # Fetch data
            df = await self.fetch_training_data()

            # Balance classes
            df = await self.balance_classes(df)

            # Split data
            train_df, val_df, test_df = self.split_data(df)

            # Save datasets
            paths = await self.save_datasets(train_df, val_df, test_df)

            return paths

        finally:
            await self.disconnect()

    async def stream_alerts(
        self,
        batch_size: int = 1000,
        since: datetime | None = None,
    ) -> AsyncIterator[pd.DataFrame]:
        """Stream alerts in batches for incremental training.

        Args:
            batch_size: Number of alerts per batch
            since: Only fetch alerts after this timestamp

        Yields:
            DataFrames of alert batches
        """
        if not self._client:
            await self.connect()

        since = since or (datetime.utcnow() - timedelta(days=1))

        query = f"""
            SELECT *
            FROM alerts
            WHERE timestamp > toDateTime('{since.isoformat()}')
            ORDER BY timestamp
        """

        offset = 0
        while True:
            batch_query = f"{query} LIMIT {batch_size} OFFSET {offset}"
            result = self._client.query(batch_query)

            if not result.result_rows:
                break

            df = pd.DataFrame(result.result_rows, columns=result.column_names)
            yield df

            offset += batch_size
            await asyncio.sleep(0.1)  # Rate limiting


class LabelingPipeline(LoggerMixin):
    """Pipeline for labeling alerts using various sources."""

    SEVERITY_MAP = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    CATEGORY_MAP = {
        "malware": 0,
        "intrusion": 1,
        "data_exfiltration": 2,
        "privilege_escalation": 3,
        "lateral_movement": 4,
        "credential_access": 5,
        "reconnaissance": 6,
        "command_and_control": 7,
        "impact": 8,
        "policy_violation": 9,
        "anomaly": 10,
        "other": 11,
    }

    def encode_severity(self, severity: str) -> int:
        """Encode severity string to integer."""
        return self.SEVERITY_MAP.get(severity.lower(), 2)

    def encode_category(self, category: str) -> int:
        """Encode category string to integer."""
        return self.CATEGORY_MAP.get(category.lower(), 11)

    def encode_mitre_tactics(self, tactics: list[str]) -> list[int]:
        """Encode MITRE ATT&CK tactics to multi-hot vector."""
        # MITRE tactics IDs
        tactic_map = {
            "TA0001": 0, "TA0002": 1, "TA0003": 2, "TA0004": 3,
            "TA0005": 4, "TA0006": 5, "TA0007": 6, "TA0008": 7,
            "TA0009": 8, "TA0010": 9, "TA0011": 10, "TA0040": 11,
            "TA0042": 12, "TA0043": 13,
        }
        result = [0] * 14
        for tactic in tactics:
            if tactic in tactic_map:
                result[tactic_map[tactic]] = 1
        return result

    def label_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Add encoded labels to DataFrame.

        Args:
            df: DataFrame with raw labels

        Returns:
            DataFrame with encoded labels
        """
        df = df.copy()

        # Encode severity
        df["severity_encoded"] = df["severity"].apply(self.encode_severity)

        # Encode category
        df["category_encoded"] = df["category"].apply(self.encode_category)

        # Encode MITRE tactics
        df["mitre_tactics_encoded"] = df["mitre_tactics"].apply(
            lambda x: self.encode_mitre_tactics(x) if isinstance(x, list) else [0] * 14
        )

        # Binary FP label
        df["is_fp_encoded"] = df["is_false_positive"].astype(int)

        # Normalized risk score
        df["risk_score_normalized"] = df["risk_score"] / 100.0

        self.logger.info(
            "labeled_dataframe",
            rows=len(df),
            severity_classes=df["severity_encoded"].nunique(),
            category_classes=df["category_encoded"].nunique(),
        )

        return df
