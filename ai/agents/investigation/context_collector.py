"""Context Collector - Gather relevant context for investigation."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ContextSource(str, Enum):
    """Sources for context collection."""

    SIEM = "siem"
    SOAR = "soar"
    THREAT_INTEL = "threat_intel"
    ASSET_DB = "asset_db"
    USER_DIR = "user_directory"
    EDR = "edr"
    FIREWALL = "firewall"
    PROXY = "proxy"
    DNS = "dns"
    EMAIL = "email"


class ContextItem(BaseModel):
    """A single context item."""

    source: ContextSource = Field(description="Source of the context")
    context_type: str = Field(description="Type of context (e.g., alert, event, asset)")
    data: dict[str, Any] = Field(default_factory=dict)
    relevance_score: float = Field(default=0.5, ge=0, le=1)
    collected_at: datetime = Field(default_factory=datetime.utcnow)
    entity: str | None = Field(default=None)
    entity_type: str | None = Field(default=None)


class ContextCollectionConfig(BaseModel):
    """Configuration for context collection."""

    max_items_per_source: int = Field(default=50)
    time_window_hours: int = Field(default=24)
    parallel_sources: int = Field(default=5)
    timeout_seconds: int = Field(default=30)
    min_relevance: float = Field(default=0.3)


class ContextCollector(LoggerMixin):
    """Collector for gathering investigation context from multiple sources.

    Features:
    - Parallel collection from multiple sources
    - Entity-based context gathering
    - Relevance scoring
    - Deduplication
    """

    def __init__(
        self,
        siem_endpoint: str = "http://localhost:8000/api/v1",
        soar_endpoint: str = "http://localhost:8001/api/v1",
        config: ContextCollectionConfig | None = None,
    ) -> None:
        """Initialize context collector.

        Args:
            siem_endpoint: SIEM API endpoint
            soar_endpoint: SOAR API endpoint
            config: Collection configuration
        """
        self.siem_endpoint = siem_endpoint
        self.soar_endpoint = soar_endpoint
        self.config = config or ContextCollectionConfig()
        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.config.timeout_seconds)
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def collect(
        self,
        entities: list[dict[str, str]],
        sources: list[ContextSource] | None = None,
        time_window_hours: int | None = None,
    ) -> list[ContextItem]:
        """Collect context for given entities.

        Args:
            entities: List of entities (e.g., [{"type": "ip", "value": "1.2.3.4"}])
            sources: Sources to query (all if None)
            time_window_hours: Override time window

        Returns:
            List of collected context items
        """
        sources = sources or list(ContextSource)
        window = time_window_hours or self.config.time_window_hours

        self.logger.info(
            "collecting_context",
            entity_count=len(entities),
            sources=[s.value for s in sources],
        )

        # Create collection tasks
        tasks = []
        for entity in entities:
            for source in sources:
                tasks.append(
                    self._collect_from_source(
                        source=source,
                        entity=entity.get("value"),
                        entity_type=entity.get("type"),
                        time_window_hours=window,
                    )
                )

        # Execute in parallel with limit
        semaphore = asyncio.Semaphore(self.config.parallel_sources)

        async def bounded_collect(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(
            *[bounded_collect(task) for task in tasks],
            return_exceptions=True,
        )

        # Flatten and filter results
        context_items = []
        for result in results:
            if isinstance(result, Exception):
                self.logger.warning("collection_error", error=str(result))
                continue
            if isinstance(result, list):
                context_items.extend(result)
            elif result:
                context_items.append(result)

        # Filter by relevance
        filtered = [
            item for item in context_items
            if item.relevance_score >= self.config.min_relevance
        ]

        # Deduplicate
        unique = self._deduplicate(filtered)

        # Sort by relevance
        unique.sort(key=lambda x: x.relevance_score, reverse=True)

        self.logger.info(
            "context_collected",
            total_items=len(context_items),
            filtered_items=len(unique),
        )

        return unique[:self.config.max_items_per_source * len(sources)]

    async def _collect_from_source(
        self,
        source: ContextSource,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect context from a specific source."""
        collectors = {
            ContextSource.SIEM: self._collect_siem,
            ContextSource.SOAR: self._collect_soar,
            ContextSource.THREAT_INTEL: self._collect_threat_intel,
            ContextSource.ASSET_DB: self._collect_asset_db,
            ContextSource.USER_DIR: self._collect_user_dir,
            ContextSource.EDR: self._collect_edr,
            ContextSource.FIREWALL: self._collect_firewall,
            ContextSource.PROXY: self._collect_proxy,
            ContextSource.DNS: self._collect_dns,
            ContextSource.EMAIL: self._collect_email,
        }

        collector = collectors.get(source)
        if not collector:
            return []

        try:
            return await collector(entity, entity_type, time_window_hours)
        except Exception as e:
            self.logger.warning(
                "source_collection_failed",
                source=source.value,
                entity=entity,
                error=str(e),
            )
            return []

    async def _collect_siem(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from SIEM."""
        client = await self._get_client()
        items = []

        # Build query based on entity type
        field_mapping = {
            "ip": ["source_ip", "destination_ip", "src_ip", "dst_ip"],
            "user": ["user", "username", "user_name"],
            "host": ["host", "hostname", "computer_name"],
            "hash": ["file_hash", "md5", "sha256"],
        }

        fields = field_mapping.get(entity_type, [entity_type])

        for field in fields:
            try:
                response = await client.post(
                    f"{self.siem_endpoint}/query",
                    json={
                        "query": f'{field}:"{entity}"',
                        "time_range": f"last_{time_window_hours}h",
                        "limit": self.config.max_items_per_source,
                    },
                )

                if response.status_code == 200:
                    results = response.json().get("results", [])
                    for event in results:
                        items.append(
                            ContextItem(
                                source=ContextSource.SIEM,
                                context_type="event",
                                data=event,
                                relevance_score=self._calculate_relevance(event, entity),
                                entity=entity,
                                entity_type=entity_type,
                            )
                        )
            except Exception:
                continue

        return items

    async def _collect_soar(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from SOAR - cases and playbook executions."""
        client = await self._get_client()
        items = []

        try:
            # Get related cases
            response = await client.get(
                f"{self.soar_endpoint}/cases",
                params={"entity": entity, "hours": time_window_hours},
            )

            if response.status_code == 200:
                cases = response.json().get("cases", [])
                for case in cases:
                    items.append(
                        ContextItem(
                            source=ContextSource.SOAR,
                            context_type="case",
                            data=case,
                            relevance_score=0.8,  # Cases are highly relevant
                            entity=entity,
                            entity_type=entity_type,
                        )
                    )

            # Get playbook executions
            response = await client.get(
                f"{self.soar_endpoint}/playbook-executions",
                params={"entity": entity},
            )

            if response.status_code == 200:
                executions = response.json().get("executions", [])
                for execution in executions:
                    items.append(
                        ContextItem(
                            source=ContextSource.SOAR,
                            context_type="playbook_execution",
                            data=execution,
                            relevance_score=0.7,
                            entity=entity,
                            entity_type=entity_type,
                        )
                    )

        except Exception as e:
            self.logger.debug("soar_collection_error", error=str(e))

        return items

    async def _collect_threat_intel(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect threat intelligence."""
        client = await self._get_client()
        items = []

        if entity_type not in ["ip", "domain", "hash", "url"]:
            return items

        try:
            response = await client.post(
                f"{self.soar_endpoint}/enrich",
                json={"ioc": entity, "type": entity_type},
            )

            if response.status_code == 200:
                intel = response.json()
                if intel:
                    # Calculate relevance based on verdict
                    relevance = 0.5
                    if intel.get("malicious"):
                        relevance = 0.95
                    elif intel.get("suspicious"):
                        relevance = 0.8

                    items.append(
                        ContextItem(
                            source=ContextSource.THREAT_INTEL,
                            context_type="ioc_enrichment",
                            data=intel,
                            relevance_score=relevance,
                            entity=entity,
                            entity_type=entity_type,
                        )
                    )

        except Exception as e:
            self.logger.debug("threat_intel_error", error=str(e))

        return items

    async def _collect_asset_db(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from asset database."""
        client = await self._get_client()
        items = []

        if entity_type not in ["ip", "host"]:
            return items

        try:
            endpoint = "hosts" if entity_type == "host" else "ips"
            response = await client.get(f"{self.siem_endpoint}/assets/{endpoint}/{entity}")

            if response.status_code == 200:
                asset = response.json()
                items.append(
                    ContextItem(
                        source=ContextSource.ASSET_DB,
                        context_type="asset",
                        data=asset,
                        relevance_score=0.6,
                        entity=entity,
                        entity_type=entity_type,
                    )
                )

        except Exception as e:
            self.logger.debug("asset_db_error", error=str(e))

        return items

    async def _collect_user_dir(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from user directory (AD/LDAP)."""
        client = await self._get_client()
        items = []

        if entity_type != "user":
            return items

        try:
            response = await client.get(f"{self.siem_endpoint}/assets/users/{entity}")

            if response.status_code == 200:
                user = response.json()
                items.append(
                    ContextItem(
                        source=ContextSource.USER_DIR,
                        context_type="user_info",
                        data=user,
                        relevance_score=0.7,
                        entity=entity,
                        entity_type=entity_type,
                    )
                )

        except Exception as e:
            self.logger.debug("user_dir_error", error=str(e))

        return items

    async def _collect_edr(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from EDR."""
        # Placeholder - would integrate with EDR API
        return []

    async def _collect_firewall(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from firewall logs."""
        # Query SIEM for firewall events
        client = await self._get_client()
        items = []

        if entity_type != "ip":
            return items

        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'source:firewall AND (src_ip:"{entity}" OR dst_ip:"{entity}")',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 20,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    items.append(
                        ContextItem(
                            source=ContextSource.FIREWALL,
                            context_type="firewall_event",
                            data=event,
                            relevance_score=0.6,
                            entity=entity,
                            entity_type=entity_type,
                        )
                    )

        except Exception as e:
            self.logger.debug("firewall_error", error=str(e))

        return items

    async def _collect_proxy(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect from proxy logs."""
        client = await self._get_client()
        items = []

        if entity_type not in ["ip", "user", "domain"]:
            return items

        field = {"ip": "client_ip", "user": "user", "domain": "domain"}.get(entity_type)

        try:
            response = await client.post(
                f"{self.siem_endpoint}/query",
                json={
                    "query": f'source:proxy AND {field}:"{entity}"',
                    "time_range": f"last_{time_window_hours}h",
                    "limit": 20,
                },
            )

            if response.status_code == 200:
                events = response.json().get("results", [])
                for event in events:
                    items.append(
                        ContextItem(
                            source=ContextSource.PROXY,
                            context_type="proxy_event",
                            data=event,
                            relevance_score=0.5,
                            entity=entity,
                            entity_type=entity_type,
                        )
                    )

        except Exception as e:
            self.logger.debug("proxy_error", error=str(e))

        return items

    async def _collect_dns(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect DNS query logs."""
        # Placeholder
        return []

    async def _collect_email(
        self,
        entity: str,
        entity_type: str,
        time_window_hours: int,
    ) -> list[ContextItem]:
        """Collect email events."""
        # Placeholder
        return []

    def _calculate_relevance(
        self,
        event: dict[str, Any],
        entity: str,
    ) -> float:
        """Calculate relevance score for an event."""
        score = 0.5

        # Boost for severity
        severity = str(event.get("severity", "")).lower()
        if severity in ["critical", "high"]:
            score += 0.3
        elif severity == "medium":
            score += 0.1

        # Boost for alert type
        if event.get("alert_type"):
            score += 0.1

        # Boost for exact entity match
        event_str = str(event).lower()
        if entity.lower() in event_str:
            score += 0.1

        return min(score, 1.0)

    def _deduplicate(self, items: list[ContextItem]) -> list[ContextItem]:
        """Remove duplicate context items."""
        seen = set()
        unique = []

        for item in items:
            # Create key from important fields
            key = (
                item.source,
                item.context_type,
                str(item.data.get("id", "")),
                str(item.data.get("timestamp", "")),
            )

            if key not in seen:
                seen.add(key)
                unique.append(item)

        return unique

    async def collect_for_alert(
        self,
        alert: dict[str, Any],
    ) -> list[ContextItem]:
        """Collect context specifically for an alert.

        Args:
            alert: Alert data

        Returns:
            Context items related to the alert
        """
        # Extract entities from alert
        entities = []

        if src_ip := alert.get("source_ip") or alert.get("src_ip"):
            entities.append({"type": "ip", "value": src_ip})

        if dst_ip := alert.get("destination_ip") or alert.get("dst_ip"):
            entities.append({"type": "ip", "value": dst_ip})

        if hostname := alert.get("hostname") or alert.get("host"):
            entities.append({"type": "host", "value": hostname})

        if username := alert.get("username") or alert.get("user"):
            entities.append({"type": "user", "value": username})

        if not entities:
            return []

        return await self.collect(entities)
