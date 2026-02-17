"""Schema encoder for NL2SQL - encodes database schemas for LLM context."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ColumnType(str, Enum):
    """Database column types."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATETIME = "datetime"
    DATE = "date"
    UUID = "uuid"
    JSON = "json"
    ARRAY = "array"
    IP_ADDRESS = "ip_address"
    ENUM = "enum"


class IndexType(str, Enum):
    """Index types for query optimization hints."""

    PRIMARY = "primary"
    UNIQUE = "unique"
    INDEX = "index"
    FULLTEXT = "fulltext"
    NONE = "none"


class ColumnInfo(BaseModel):
    """Column information for schema encoding."""

    name: str = Field(description="Column name")
    type: ColumnType = Field(description="Data type")
    nullable: bool = Field(default=True, description="Whether column is nullable")
    description: str = Field(default="", description="Human-readable description")
    examples: list[str] = Field(default_factory=list, description="Example values")
    index_type: IndexType = Field(default=IndexType.NONE, description="Index type")
    foreign_key: str | None = Field(default=None, description="Foreign key reference (table.column)")
    enum_values: list[str] | None = Field(default=None, description="Possible values for enum types")


class TableInfo(BaseModel):
    """Table information for schema encoding."""

    name: str = Field(description="Table name")
    schema_name: str = Field(default="public", description="Schema name")
    description: str = Field(description="Table description for context")
    columns: list[ColumnInfo] = Field(description="Column definitions")
    primary_key: list[str] = Field(default_factory=list, description="Primary key columns")
    row_count_estimate: int | None = Field(default=None, description="Estimated row count")
    sample_queries: list[str] = Field(default_factory=list, description="Example SQL queries")
    relationships: list[str] = Field(default_factory=list, description="Related tables")
    partition_key: str | None = Field(default=None, description="Partition key for ClickHouse")
    order_by: list[str] | None = Field(default=None, description="ORDER BY for ClickHouse")


@dataclass
class EncodedSchema:
    """Encoded schema ready for LLM context."""

    text: str
    tables: list[str]
    token_estimate: int
    checksum: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SchemaEncoder(LoggerMixin):
    """Encodes database schemas into LLM-friendly formats.

    Supports multiple encoding strategies:
    - compact: Minimal schema representation
    - detailed: Full schema with examples and descriptions
    - sql_ddl: SQL DDL statements
    - markdown: Markdown formatted tables
    """

    # Token estimates per character (rough approximation)
    CHARS_PER_TOKEN = 4

    def __init__(
        self,
        max_tokens: int = 2048,
        include_examples: bool = True,
        include_relationships: bool = True,
    ) -> None:
        """Initialize the encoder.

        Args:
            max_tokens: Maximum tokens for schema context
            include_examples: Whether to include example values
            include_relationships: Whether to include table relationships
        """
        self.max_tokens = max_tokens
        self.include_examples = include_examples
        self.include_relationships = include_relationships

        # SIEM/SOAR specific schema
        self._schemas: dict[str, list[TableInfo]] = {}

    def register_schema(self, database: str, tables: list[TableInfo]) -> None:
        """Register a database schema.

        Args:
            database: Database identifier (e.g., "clickhouse", "postgresql")
            tables: List of table information
        """
        self._schemas[database] = tables
        self.logger.info("schema_registered", database=database, tables=len(tables))

    def get_default_siem_schema(self) -> list[TableInfo]:
        """Get default SIEM/SOAR schema definitions."""
        return [
            TableInfo(
                name="events",
                description="Security events and logs from various sources",
                columns=[
                    ColumnInfo(name="event_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="timestamp", type=ColumnType.DATETIME, nullable=False, index_type=IndexType.INDEX,
                               description="Event occurrence time"),
                    ColumnInfo(name="source_ip", type=ColumnType.IP_ADDRESS, description="Source IP address",
                               examples=["192.168.1.100", "10.0.0.50"]),
                    ColumnInfo(name="dest_ip", type=ColumnType.IP_ADDRESS, description="Destination IP address"),
                    ColumnInfo(name="source_port", type=ColumnType.INTEGER, description="Source port number"),
                    ColumnInfo(name="dest_port", type=ColumnType.INTEGER, description="Destination port number",
                               examples=["80", "443", "22"]),
                    ColumnInfo(name="protocol", type=ColumnType.STRING, description="Network protocol",
                               examples=["TCP", "UDP", "ICMP"]),
                    ColumnInfo(name="event_type", type=ColumnType.STRING, index_type=IndexType.INDEX,
                               description="Type of security event",
                               examples=["intrusion", "malware", "authentication"]),
                    ColumnInfo(name="severity", type=ColumnType.ENUM, enum_values=["low", "medium", "high", "critical"],
                               description="Event severity level"),
                    ColumnInfo(name="source_system", type=ColumnType.STRING, description="Originating system",
                               examples=["firewall", "ids", "endpoint"]),
                    ColumnInfo(name="raw_log", type=ColumnType.STRING, description="Original log message"),
                    ColumnInfo(name="parsed_data", type=ColumnType.JSON, description="Parsed event data"),
                    ColumnInfo(name="user_id", type=ColumnType.STRING, description="Associated user identifier"),
                    ColumnInfo(name="hostname", type=ColumnType.STRING, description="Source hostname"),
                ],
                primary_key=["event_id"],
                partition_key="toYYYYMM(timestamp)",
                order_by=["timestamp", "event_type"],
                sample_queries=[
                    "SELECT * FROM events WHERE severity = 'critical' AND timestamp > now() - INTERVAL 1 HOUR",
                    "SELECT source_ip, count() FROM events GROUP BY source_ip ORDER BY count() DESC LIMIT 10",
                ],
            ),
            TableInfo(
                name="alerts",
                description="Generated security alerts from correlation rules",
                columns=[
                    ColumnInfo(name="alert_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="created_at", type=ColumnType.DATETIME, nullable=False, index_type=IndexType.INDEX),
                    ColumnInfo(name="title", type=ColumnType.STRING, description="Alert title"),
                    ColumnInfo(name="description", type=ColumnType.STRING, description="Alert description"),
                    ColumnInfo(name="severity", type=ColumnType.ENUM, enum_values=["low", "medium", "high", "critical"]),
                    ColumnInfo(name="status", type=ColumnType.ENUM,
                               enum_values=["new", "in_progress", "resolved", "false_positive"]),
                    ColumnInfo(name="rule_id", type=ColumnType.UUID, foreign_key="correlation_rules.rule_id"),
                    ColumnInfo(name="source_events", type=ColumnType.ARRAY, description="Related event IDs"),
                    ColumnInfo(name="assigned_to", type=ColumnType.UUID, foreign_key="users.user_id"),
                    ColumnInfo(name="ioc_indicators", type=ColumnType.JSON, description="IOC indicators found"),
                    ColumnInfo(name="mitre_tactics", type=ColumnType.ARRAY, description="MITRE ATT&CK tactics"),
                    ColumnInfo(name="mitre_techniques", type=ColumnType.ARRAY, description="MITRE ATT&CK techniques"),
                ],
                primary_key=["alert_id"],
                relationships=["events", "correlation_rules", "cases"],
                sample_queries=[
                    "SELECT * FROM alerts WHERE status = 'new' AND severity IN ('high', 'critical')",
                    "SELECT severity, count() FROM alerts WHERE created_at > today() GROUP BY severity",
                ],
            ),
            TableInfo(
                name="cases",
                description="Investigation cases grouping related alerts",
                columns=[
                    ColumnInfo(name="case_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="created_at", type=ColumnType.DATETIME, nullable=False),
                    ColumnInfo(name="updated_at", type=ColumnType.DATETIME, nullable=False),
                    ColumnInfo(name="title", type=ColumnType.STRING, description="Case title"),
                    ColumnInfo(name="description", type=ColumnType.STRING, description="Case description"),
                    ColumnInfo(name="status", type=ColumnType.ENUM,
                               enum_values=["open", "in_progress", "pending", "closed"]),
                    ColumnInfo(name="priority", type=ColumnType.ENUM, enum_values=["p1", "p2", "p3", "p4"]),
                    ColumnInfo(name="assignee_id", type=ColumnType.UUID, foreign_key="users.user_id"),
                    ColumnInfo(name="alert_ids", type=ColumnType.ARRAY, description="Related alert IDs"),
                    ColumnInfo(name="tags", type=ColumnType.ARRAY, description="Case tags"),
                    ColumnInfo(name="tlp", type=ColumnType.ENUM, enum_values=["white", "green", "amber", "red"],
                               description="Traffic Light Protocol"),
                ],
                primary_key=["case_id"],
                relationships=["alerts", "users", "playbook_executions"],
            ),
            TableInfo(
                name="correlation_rules",
                description="Correlation rules for alert generation",
                columns=[
                    ColumnInfo(name="rule_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="name", type=ColumnType.STRING, description="Rule name"),
                    ColumnInfo(name="description", type=ColumnType.STRING),
                    ColumnInfo(name="query", type=ColumnType.STRING, description="Detection query"),
                    ColumnInfo(name="severity", type=ColumnType.ENUM, enum_values=["low", "medium", "high", "critical"]),
                    ColumnInfo(name="enabled", type=ColumnType.BOOLEAN),
                    ColumnInfo(name="mitre_mapping", type=ColumnType.JSON, description="MITRE ATT&CK mapping"),
                ],
                primary_key=["rule_id"],
            ),
            TableInfo(
                name="playbooks",
                description="SOAR playbooks for automated response",
                columns=[
                    ColumnInfo(name="playbook_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="name", type=ColumnType.STRING),
                    ColumnInfo(name="description", type=ColumnType.STRING),
                    ColumnInfo(name="trigger_type", type=ColumnType.STRING,
                               examples=["manual", "alert", "schedule"]),
                    ColumnInfo(name="steps", type=ColumnType.JSON, description="Playbook steps"),
                    ColumnInfo(name="enabled", type=ColumnType.BOOLEAN),
                ],
                primary_key=["playbook_id"],
            ),
            TableInfo(
                name="assets",
                description="IT assets inventory",
                columns=[
                    ColumnInfo(name="asset_id", type=ColumnType.UUID, nullable=False, index_type=IndexType.PRIMARY),
                    ColumnInfo(name="hostname", type=ColumnType.STRING, index_type=IndexType.INDEX),
                    ColumnInfo(name="ip_address", type=ColumnType.IP_ADDRESS, index_type=IndexType.INDEX),
                    ColumnInfo(name="mac_address", type=ColumnType.STRING),
                    ColumnInfo(name="asset_type", type=ColumnType.STRING,
                               examples=["server", "workstation", "network_device"]),
                    ColumnInfo(name="os", type=ColumnType.STRING, description="Operating system"),
                    ColumnInfo(name="criticality", type=ColumnType.ENUM,
                               enum_values=["low", "medium", "high", "critical"]),
                    ColumnInfo(name="owner", type=ColumnType.STRING),
                    ColumnInfo(name="department", type=ColumnType.STRING),
                ],
                primary_key=["asset_id"],
            ),
        ]

    def encode(
        self,
        database: str,
        format: str = "compact",
        tables: list[str] | None = None,
        query_context: str | None = None,
    ) -> EncodedSchema:
        """Encode schema for LLM context.

        Args:
            database: Database identifier
            format: Encoding format (compact, detailed, sql_ddl, markdown)
            tables: Specific tables to include (None = all)
            query_context: Natural language query for relevance filtering

        Returns:
            Encoded schema with metadata
        """
        schema_tables = self._schemas.get(database, self.get_default_siem_schema())

        if tables:
            schema_tables = [t for t in schema_tables if t.name in tables]

        if query_context:
            schema_tables = self._rank_tables_by_relevance(schema_tables, query_context)

        if format == "compact":
            text = self._encode_compact(schema_tables)
        elif format == "detailed":
            text = self._encode_detailed(schema_tables)
        elif format == "sql_ddl":
            text = self._encode_ddl(schema_tables)
        elif format == "markdown":
            text = self._encode_markdown(schema_tables)
        else:
            text = self._encode_compact(schema_tables)

        # Truncate if too long
        text = self._truncate_to_tokens(text, self.max_tokens)

        return EncodedSchema(
            text=text,
            tables=[t.name for t in schema_tables],
            token_estimate=len(text) // self.CHARS_PER_TOKEN,
            checksum=hashlib.md5(text.encode()).hexdigest()[:8],
        )

    def _get_enum_value(self, enum_or_str) -> str:
        """Get string value from enum or string (handles use_enum_values=True)."""
        if isinstance(enum_or_str, str):
            return enum_or_str
        return enum_or_str.value if hasattr(enum_or_str, 'value') else str(enum_or_str)

    def _encode_compact(self, tables: list[TableInfo]) -> str:
        """Encode schema in compact format."""
        lines = ["DATABASE SCHEMA:"]

        for table in tables:
            cols = ", ".join([f"{c.name}:{self._get_enum_value(c.type)}" for c in table.columns])
            lines.append(f"\n{table.name} ({cols})")
            if table.description:
                lines.append(f"  -- {table.description}")

        return "\n".join(lines)

    def _encode_detailed(self, tables: list[TableInfo]) -> str:
        """Encode schema with full details."""
        lines = ["DATABASE SCHEMA\n"]

        for table in tables:
            lines.append(f"TABLE: {table.name}")
            lines.append(f"Description: {table.description}")
            lines.append("Columns:")

            for col in table.columns:
                col_def = f"  - {col.name} ({self._get_enum_value(col.type)})"
                if not col.nullable:
                    col_def += " NOT NULL"
                index_val = self._get_enum_value(col.index_type)
                if index_val != "none":
                    col_def += f" [{index_val}]"
                if col.description:
                    col_def += f" -- {col.description}"
                lines.append(col_def)

                if self.include_examples and col.examples:
                    lines.append(f"    Examples: {', '.join(col.examples[:3])}")

            if self.include_relationships and table.relationships:
                lines.append(f"Related tables: {', '.join(table.relationships)}")

            if table.sample_queries:
                lines.append("Example queries:")
                for q in table.sample_queries[:2]:
                    lines.append(f"  {q}")

            lines.append("")

        return "\n".join(lines)

    def _encode_ddl(self, tables: list[TableInfo]) -> str:
        """Encode schema as SQL DDL statements."""
        lines = ["-- Database Schema DDL\n"]

        type_mapping = {
            "string": "VARCHAR(255)",
            "integer": "INTEGER",
            "float": "FLOAT",
            "boolean": "BOOLEAN",
            "datetime": "TIMESTAMP",
            "date": "DATE",
            "uuid": "UUID",
            "json": "JSON",
            "array": "ARRAY",
            "ip_address": "VARCHAR(45)",
            "enum": "VARCHAR(50)",
        }

        for table in tables:
            lines.append(f"-- {table.description}")
            lines.append(f"CREATE TABLE {table.name} (")

            col_defs = []
            for col in table.columns:
                col_type = self._get_enum_value(col.type)
                sql_type = type_mapping.get(col_type, "VARCHAR(255)")
                col_def = f"  {col.name} {sql_type}"
                if not col.nullable:
                    col_def += " NOT NULL"
                col_defs.append(col_def)

            if table.primary_key:
                col_defs.append(f"  PRIMARY KEY ({', '.join(table.primary_key)})")

            lines.append(",\n".join(col_defs))
            lines.append(");\n")

        return "\n".join(lines)

    def _encode_markdown(self, tables: list[TableInfo]) -> str:
        """Encode schema as markdown tables."""
        lines = ["# Database Schema\n"]

        for table in tables:
            lines.append(f"## {table.name}")
            lines.append(f"*{table.description}*\n")
            lines.append("| Column | Type | Description |")
            lines.append("|--------|------|-------------|")

            for col in table.columns:
                desc = col.description or ""
                if col.examples:
                    desc += f" (e.g., {', '.join(col.examples[:2])})"
                lines.append(f"| {col.name} | {self._get_enum_value(col.type)} | {desc} |")

            lines.append("")

        return "\n".join(lines)

    def _rank_tables_by_relevance(
        self,
        tables: list[TableInfo],
        query: str,
    ) -> list[TableInfo]:
        """Rank tables by relevance to the query."""
        query_lower = query.lower()

        def score_table(table: TableInfo) -> int:
            score = 0
            # Direct table name match
            if table.name.lower() in query_lower:
                score += 100
            # Column name matches
            for col in table.columns:
                if col.name.lower() in query_lower:
                    score += 50
            # Description match
            if any(word in table.description.lower() for word in query_lower.split()):
                score += 20
            return score

        return sorted(tables, key=score_table, reverse=True)

    def _truncate_to_tokens(self, text: str, max_tokens: int) -> str:
        """Truncate text to approximate token limit."""
        max_chars = max_tokens * self.CHARS_PER_TOKEN
        if len(text) <= max_chars:
            return text
        return text[:max_chars] + "\n... [schema truncated]"
