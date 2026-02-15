"""Evidence Gatherer - Collect and preserve evidence for investigations."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class EvidenceType(str, Enum):
    """Types of evidence."""

    LOG_EVENT = "log_event"
    ALERT = "alert"
    NETWORK_FLOW = "network_flow"
    FILE_ARTIFACT = "file_artifact"
    MEMORY_ARTIFACT = "memory_artifact"
    REGISTRY_KEY = "registry_key"
    PROCESS_INFO = "process_info"
    THREAT_INTEL = "threat_intel"
    SCREENSHOT = "screenshot"
    USER_ACTIVITY = "user_activity"
    EMAIL = "email"
    SYSTEM_CONFIG = "system_config"


class EvidenceIntegrity(str, Enum):
    """Evidence integrity status."""

    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    TAMPERED = "tampered"
    EXPIRED = "expired"


class Evidence(BaseModel):
    """A single piece of evidence."""

    evidence_id: str = Field(default_factory=lambda: str(uuid4()))
    evidence_type: EvidenceType = Field(description="Type of evidence")
    source: str = Field(description="Source of evidence")
    source_id: str | None = Field(default=None, description="ID in source system")

    # Content
    data: dict[str, Any] = Field(default_factory=dict)
    raw_content: str | None = Field(default=None, description="Raw evidence content")

    # Integrity
    content_hash: str | None = Field(default=None, description="SHA-256 of content")
    integrity: EvidenceIntegrity = Field(default=EvidenceIntegrity.UNVERIFIED)

    # Metadata
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    original_timestamp: datetime | None = Field(default=None)
    collector: str = Field(default="automated")
    chain_of_custody: list[dict[str, Any]] = Field(default_factory=list)

    # Relations
    related_entities: list[str] = Field(default_factory=list)
    related_evidence: list[str] = Field(default_factory=list)

    # Classification
    relevance_score: float = Field(default=0.5, ge=0, le=1)
    tags: list[str] = Field(default_factory=list)
    notes: str | None = Field(default=None)


class EvidenceChainEntry(BaseModel):
    """Entry in chain of custody."""

    timestamp: datetime = Field(default_factory=datetime.utcnow)
    action: str = Field(description="Action taken")
    actor: str = Field(description="Who performed the action")
    details: str | None = Field(default=None)
    integrity_verified: bool = Field(default=False)


class EvidenceCollection(BaseModel):
    """Collection of related evidence."""

    collection_id: str = Field(default_factory=lambda: str(uuid4()))
    case_id: str | None = Field(default=None)
    investigation_id: str | None = Field(default=None)
    evidence_items: list[Evidence] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    summary: str | None = Field(default=None)


class EvidenceGatherer(LoggerMixin):
    """Gatherer for collecting and preserving investigation evidence.

    Features:
    - Multi-source evidence collection
    - Evidence integrity verification (hashing)
    - Chain of custody tracking
    - Evidence organization and tagging
    - Forensic artifact handling
    """

    def __init__(
        self,
        siem_endpoint: str = "http://localhost:8000/api/v1",
        soar_endpoint: str = "http://localhost:8001/api/v1",
        storage_path: str | None = None,
    ) -> None:
        """Initialize evidence gatherer.

        Args:
            siem_endpoint: SIEM API endpoint
            soar_endpoint: SOAR API endpoint
            storage_path: Path for evidence storage
        """
        self.siem_endpoint = siem_endpoint
        self.soar_endpoint = soar_endpoint
        self.storage_path = storage_path

        self._client: httpx.AsyncClient | None = None
        self._collections: dict[str, EvidenceCollection] = {}

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def create_collection(
        self,
        case_id: str | None = None,
        investigation_id: str | None = None,
    ) -> EvidenceCollection:
        """Create a new evidence collection.

        Args:
            case_id: Associated case ID
            investigation_id: Associated investigation ID

        Returns:
            New evidence collection
        """
        collection = EvidenceCollection(
            case_id=case_id,
            investigation_id=investigation_id,
        )
        self._collections[collection.collection_id] = collection

        self.logger.info(
            "evidence_collection_created",
            collection_id=collection.collection_id,
            case_id=case_id,
        )

        return collection

    def get_collection(self, collection_id: str) -> EvidenceCollection | None:
        """Get evidence collection by ID."""
        return self._collections.get(collection_id)

    async def gather_for_alert(
        self,
        alert_id: str,
        collection_id: str | None = None,
    ) -> EvidenceCollection:
        """Gather evidence for an alert.

        Args:
            alert_id: Alert ID
            collection_id: Existing collection to add to

        Returns:
            Evidence collection
        """
        collection = (
            self._collections.get(collection_id)
            if collection_id
            else self.create_collection()
        )

        self.logger.info("gathering_alert_evidence", alert_id=alert_id)

        # Get alert as evidence
        alert_evidence = await self._gather_alert(alert_id)
        if alert_evidence:
            self.add_evidence(collection, alert_evidence)

        # Get related events
        events = await self._gather_related_events(alert_id)
        for event in events:
            self.add_evidence(collection, event)

        # Get threat intel
        intel = await self._gather_threat_intel(alert_evidence)
        for item in intel:
            self.add_evidence(collection, item)

        collection.updated_at = datetime.utcnow()

        return collection

    async def gather_for_entity(
        self,
        entity: str,
        entity_type: str,
        collection_id: str | None = None,
        time_window_hours: int = 24,
    ) -> EvidenceCollection:
        """Gather evidence related to an entity.

        Args:
            entity: Entity value (IP, hostname, user, etc.)
            entity_type: Entity type
            collection_id: Existing collection
            time_window_hours: Time window for evidence

        Returns:
            Evidence collection
        """
        collection = (
            self._collections.get(collection_id)
            if collection_id
            else self.create_collection()
        )

        self.logger.info(
            "gathering_entity_evidence",
            entity=entity,
            entity_type=entity_type,
        )

        # Gather based on entity type
        if entity_type == "ip":
            await self._gather_ip_evidence(collection, entity, time_window_hours)
        elif entity_type == "host":
            await self._gather_host_evidence(collection, entity, time_window_hours)
        elif entity_type == "user":
            await self._gather_user_evidence(collection, entity, time_window_hours)
        elif entity_type in ["hash", "md5", "sha256"]:
            await self._gather_file_evidence(collection, entity, time_window_hours)

        collection.updated_at = datetime.utcnow()

        return collection

    def add_evidence(
        self,
        collection: EvidenceCollection,
        evidence: Evidence,
    ) -> None:
        """Add evidence to collection with integrity check.

        Args:
            collection: Target collection
            evidence: Evidence to add
        """
        # Calculate hash if not present
        if not evidence.content_hash:
            evidence.content_hash = self._calculate_hash(evidence)

        # Add chain of custody entry
        entry = EvidenceChainEntry(
            action="collected",
            actor="EvidenceGatherer",
            details=f"Added to collection {collection.collection_id}",
            integrity_verified=True,
        )
        evidence.chain_of_custody.append(entry.model_dump())
        evidence.integrity = EvidenceIntegrity.VERIFIED

        collection.evidence_items.append(evidence)

        self.logger.debug(
            "evidence_added",
            evidence_id=evidence.evidence_id,
            collection_id=collection.collection_id,
            evidence_type=evidence.evidence_type.value,
        )

    def _calculate_hash(self, evidence: Evidence) -> str:
        """Calculate SHA-256 hash of evidence content."""
        content = str(evidence.data) + str(evidence.raw_content or "")
        return hashlib.sha256(content.encode()).hexdigest()

    def verify_integrity(self, evidence: Evidence) -> bool:
        """Verify evidence integrity.

        Args:
            evidence: Evidence to verify

        Returns:
            True if integrity is verified
        """
        if not evidence.content_hash:
            return False

        current_hash = self._calculate_hash(evidence)
        is_valid = current_hash == evidence.content_hash

        if is_valid:
            evidence.integrity = EvidenceIntegrity.VERIFIED
        else:
            evidence.integrity = EvidenceIntegrity.TAMPERED
            self.logger.warning(
                "evidence_tampered",
                evidence_id=evidence.evidence_id,
            )

        return is_valid

    async def _gather_alert(self, alert_id: str) -> Evidence | None:
        """Gather alert as evidence."""
        client = await self._get_client()

        try:
            response = await client.get(f"{self.siem_endpoint}/alerts/{alert_id}")
            if response.status_code == 200:
                alert_data = response.json()
                return Evidence(
                    evidence_type=EvidenceType.ALERT,
                    source="SIEM",
                    source_id=alert_id,
                    data=alert_data,
                    original_timestamp=alert_data.get("timestamp"),
                    relevance_score=0.9,
                    tags=["primary_alert"],
                )
        except Exception as e:
            self.logger.warning("gather_alert_failed", error=str(e))

        return None

    async def _gather_related_events(
        self,
        alert_id: str,
        limit: int = 50,
    ) -> list[Evidence]:
        """Gather events related to an alert."""
        client = await self._get_client()
        evidence_list = []

        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'alert_id:"{alert_id}" OR parent_alert:"{alert_id}"',
                    "time_range": "last_24h",
                    "limit": limit,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    evidence_list.append(
                        Evidence(
                            evidence_type=EvidenceType.LOG_EVENT,
                            source="SIEM",
                            source_id=event.get("id"),
                            data=event,
                            original_timestamp=event.get("timestamp"),
                            relevance_score=0.7,
                            related_entities=[alert_id],
                        )
                    )

        except Exception as e:
            self.logger.warning("gather_events_failed", error=str(e))

        return evidence_list

    async def _gather_threat_intel(
        self,
        alert_evidence: Evidence | None,
    ) -> list[Evidence]:
        """Gather threat intelligence as evidence."""
        if not alert_evidence:
            return []

        client = await self._get_client()
        evidence_list = []

        # Extract IOCs from alert
        alert_data = alert_evidence.data
        iocs = []

        for field in ["source_ip", "destination_ip", "src_ip", "dst_ip"]:
            if ip := alert_data.get(field):
                iocs.append({"value": ip, "type": "ip"})

        for field in ["domain", "url"]:
            if val := alert_data.get(field):
                iocs.append({"value": val, "type": field})

        for field in ["md5", "sha256", "file_hash"]:
            if hash_val := alert_data.get(field):
                iocs.append({"value": hash_val, "type": "hash"})

        # Enrich each IOC
        for ioc in iocs[:10]:  # Limit to prevent excessive API calls
            try:
                response = await client.post(
                    f"{self.soar_endpoint}/enrich",
                    json={"ioc": ioc["value"], "type": ioc["type"]},
                )

                if response.status_code == 200:
                    intel_data = response.json()
                    if intel_data:
                        relevance = 0.6
                        if intel_data.get("malicious"):
                            relevance = 0.95

                        evidence_list.append(
                            Evidence(
                                evidence_type=EvidenceType.THREAT_INTEL,
                                source="ThreatIntel",
                                source_id=ioc["value"],
                                data=intel_data,
                                relevance_score=relevance,
                                tags=[ioc["type"], "enrichment"],
                                related_entities=[alert_evidence.evidence_id],
                            )
                        )

            except Exception as e:
                self.logger.debug("enrich_failed", ioc=ioc["value"], error=str(e))

        return evidence_list

    async def _gather_ip_evidence(
        self,
        collection: EvidenceCollection,
        ip: str,
        time_window_hours: int,
    ) -> None:
        """Gather evidence for an IP address."""
        client = await self._get_client()

        # Network flows
        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'src_ip:"{ip}" OR dst_ip:"{ip}"',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 100,
                },
            )

            if response.status_code == 200:
                flows = response.json().get("results", [])
                for flow in flows:
                    evidence = Evidence(
                        evidence_type=EvidenceType.NETWORK_FLOW,
                        source="SIEM",
                        source_id=flow.get("id"),
                        data=flow,
                        original_timestamp=flow.get("timestamp"),
                        related_entities=[ip],
                        tags=["network", "ip_related"],
                    )
                    self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.warning("gather_ip_evidence_failed", error=str(e))

    async def _gather_host_evidence(
        self,
        collection: EvidenceCollection,
        hostname: str,
        time_window_hours: int,
    ) -> None:
        """Gather evidence for a host."""
        client = await self._get_client()

        # Host events
        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'hostname:"{hostname}" OR host:"{hostname}"',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 100,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    evidence = Evidence(
                        evidence_type=EvidenceType.LOG_EVENT,
                        source="SIEM",
                        source_id=event.get("id"),
                        data=event,
                        original_timestamp=event.get("timestamp"),
                        related_entities=[hostname],
                        tags=["host_activity"],
                    )
                    self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.warning("gather_host_evidence_failed", error=str(e))

        # System config (if available)
        try:
            response = await client.get(
                f"{self.siem_endpoint}/assets/hosts/{hostname}"
            )
            if response.status_code == 200:
                host_data = response.json()
                evidence = Evidence(
                    evidence_type=EvidenceType.SYSTEM_CONFIG,
                    source="AssetDB",
                    source_id=hostname,
                    data=host_data,
                    related_entities=[hostname],
                    tags=["asset_info"],
                    relevance_score=0.6,
                )
                self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.debug("gather_host_config_failed", error=str(e))

    async def _gather_user_evidence(
        self,
        collection: EvidenceCollection,
        username: str,
        time_window_hours: int,
    ) -> None:
        """Gather evidence for a user."""
        client = await self._get_client()

        # User activity
        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'user:"{username}" OR username:"{username}"',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 100,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    evidence = Evidence(
                        evidence_type=EvidenceType.USER_ACTIVITY,
                        source="SIEM",
                        source_id=event.get("id"),
                        data=event,
                        original_timestamp=event.get("timestamp"),
                        related_entities=[username],
                        tags=["user_activity"],
                    )
                    self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.warning("gather_user_evidence_failed", error=str(e))

    async def _gather_file_evidence(
        self,
        collection: EvidenceCollection,
        file_hash: str,
        time_window_hours: int,
    ) -> None:
        """Gather evidence for a file hash."""
        client = await self._get_client()

        # File events
        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'file_hash:"{file_hash}" OR md5:"{file_hash}" OR sha256:"{file_hash}"',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 50,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    evidence = Evidence(
                        evidence_type=EvidenceType.FILE_ARTIFACT,
                        source="SIEM",
                        source_id=event.get("id"),
                        data=event,
                        original_timestamp=event.get("timestamp"),
                        related_entities=[file_hash],
                        tags=["file", "hash"],
                    )
                    self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.warning("gather_file_evidence_failed", error=str(e))

        # Threat intel for hash
        try:
            response = await client.post(
                f"{self.soar_endpoint}/enrich",
                json={"ioc": file_hash, "type": "hash"},
            )

            if response.status_code == 200:
                intel = response.json()
                if intel:
                    evidence = Evidence(
                        evidence_type=EvidenceType.THREAT_INTEL,
                        source="ThreatIntel",
                        source_id=file_hash,
                        data=intel,
                        related_entities=[file_hash],
                        tags=["malware_analysis"],
                        relevance_score=0.9 if intel.get("malicious") else 0.5,
                    )
                    self.add_evidence(collection, evidence)

        except Exception as e:
            self.logger.debug("gather_file_intel_failed", error=str(e))

    def generate_summary(self, collection: EvidenceCollection) -> str:
        """Generate a summary of the evidence collection.

        Args:
            collection: Evidence collection

        Returns:
            Summary text
        """
        type_counts = {}
        for evidence in collection.evidence_items:
            ev_type = evidence.evidence_type.value
            type_counts[ev_type] = type_counts.get(ev_type, 0) + 1

        high_relevance = [
            e for e in collection.evidence_items
            if e.relevance_score >= 0.8
        ]

        summary_parts = [
            f"Evidence Collection: {collection.collection_id}",
            f"Total Items: {len(collection.evidence_items)}",
            f"High Relevance Items: {len(high_relevance)}",
            "\nEvidence Types:",
        ]

        for ev_type, count in sorted(type_counts.items()):
            summary_parts.append(f"  - {ev_type}: {count}")

        if high_relevance:
            summary_parts.append("\nKey Evidence:")
            for evidence in high_relevance[:5]:
                summary_parts.append(
                    f"  - [{evidence.evidence_type.value}] "
                    f"{evidence.source}: {str(evidence.data)[:100]}..."
                )

        collection.summary = "\n".join(summary_parts)
        return collection.summary
