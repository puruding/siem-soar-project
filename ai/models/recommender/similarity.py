"""Similarity search for finding related cases and incidents."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class SimilarityMethod(str, Enum):
    """Similarity search methods."""

    EMBEDDING = "embedding"
    KEYWORD = "keyword"
    HYBRID = "hybrid"


class SimilarCase(BaseModel):
    """Similar case/incident result."""

    case_id: str = Field(description="Case ID")
    title: str = Field(description="Case title")
    description: str = Field(description="Case description")
    similarity_score: float = Field(ge=0, le=1, description="Similarity score")
    match_reasons: list[str] = Field(default_factory=list)
    resolution: str | None = Field(default=None, description="How case was resolved")
    playbooks_used: list[str] = Field(default_factory=list)
    time_to_resolve: int | None = Field(default=None, description="Resolution time in minutes")
    severity: str = Field(description="Case severity")
    incident_type: str = Field(description="Incident type")
    created_at: datetime | None = Field(default=None)


class SimilarityConfig(BaseModel):
    """Configuration for similarity search."""

    method: SimilarityMethod = Field(default=SimilarityMethod.HYBRID)
    max_results: int = Field(default=5)
    min_similarity: float = Field(default=0.5, ge=0, le=1)
    time_window_days: int | None = Field(default=None, description="Only search within N days")
    same_severity_boost: float = Field(default=0.1)
    same_type_boost: float = Field(default=0.15)


class SimilaritySearch(LoggerMixin):
    """Search engine for finding similar cases and incidents.

    Features:
    - Vector similarity using embeddings
    - Keyword-based matching
    - Hybrid search combining both
    - Historical case resolution learning
    - Context-aware reranking
    """

    def __init__(
        self,
        embedding_endpoint: str | None = None,
        vector_db_endpoint: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """Initialize the similarity search.

        Args:
            embedding_endpoint: Text embedding API endpoint
            vector_db_endpoint: Vector database endpoint (Qdrant)
            api_key: API key
        """
        self.embedding_endpoint = embedding_endpoint or "http://localhost:8082"
        self.vector_db_endpoint = vector_db_endpoint or "http://localhost:6333"
        self.api_key = api_key

        # In-memory case store (for demo; production would use vector DB)
        self._case_store: dict[str, dict[str, Any]] = {}
        self._case_embeddings: dict[str, list[float]] = {}

        self._client: httpx.AsyncClient | None = None

        # Load sample cases
        self._load_sample_cases()

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(30.0),
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _load_sample_cases(self) -> None:
        """Load sample historical cases."""
        sample_cases = [
            {
                "case_id": "CASE-2024-001",
                "title": "Brute force attack on VPN server",
                "description": "Multiple failed login attempts from external IP targeting VPN server. Source IP showed patterns consistent with automated attack tool.",
                "severity": "high",
                "incident_type": "brute_force",
                "resolution": "Blocked source IP, implemented rate limiting, enabled MFA",
                "playbooks_used": ["pb-001", "pb-003"],
                "time_to_resolve": 45,
                "created_at": datetime(2024, 1, 15),
                "tags": ["vpn", "brute_force", "external_threat"],
            },
            {
                "case_id": "CASE-2024-002",
                "title": "Emotet malware infection via phishing",
                "description": "User clicked malicious link in phishing email, resulting in Emotet trojan download. Malware attempted lateral movement.",
                "severity": "critical",
                "incident_type": "malware",
                "resolution": "Isolated host, removed malware, reset credentials, blocked C2 domains",
                "playbooks_used": ["pb-002", "pb-005", "pb-006"],
                "time_to_resolve": 180,
                "created_at": datetime(2024, 1, 20),
                "tags": ["emotet", "phishing", "lateral_movement"],
            },
            {
                "case_id": "CASE-2024-003",
                "title": "Data exfiltration attempt detected",
                "description": "DLP alerts triggered on large file transfers to external cloud storage. Investigation revealed compromised service account.",
                "severity": "critical",
                "incident_type": "data_breach",
                "resolution": "Blocked transfers, disabled account, forensic analysis, legal notification",
                "playbooks_used": ["pb-007"],
                "time_to_resolve": 360,
                "created_at": datetime(2024, 1, 25),
                "tags": ["data_exfiltration", "insider_threat", "cloud"],
            },
            {
                "case_id": "CASE-2024-004",
                "title": "Phishing campaign targeting executives",
                "description": "Spear phishing emails sent to C-level executives impersonating board members. Sophisticated social engineering.",
                "severity": "high",
                "incident_type": "phishing",
                "resolution": "Quarantined emails, user awareness training, domain blocking",
                "playbooks_used": ["pb-005"],
                "time_to_resolve": 90,
                "created_at": datetime(2024, 2, 1),
                "tags": ["spear_phishing", "executive", "social_engineering"],
            },
            {
                "case_id": "CASE-2024-005",
                "title": "Cryptominer on development server",
                "description": "Unauthorized cryptocurrency mining software detected on development server. Entry via exposed Jenkins instance.",
                "severity": "medium",
                "incident_type": "malware",
                "resolution": "Removed miner, patched Jenkins, implemented network segmentation",
                "playbooks_used": ["pb-006"],
                "time_to_resolve": 120,
                "created_at": datetime(2024, 2, 5),
                "tags": ["cryptominer", "jenkins", "misconfiguration"],
            },
            {
                "case_id": "CASE-2024-006",
                "title": "Ransomware attempt blocked by EDR",
                "description": "Ryuk ransomware execution blocked by endpoint detection. Investigation showed initial access via RDP exposure.",
                "severity": "critical",
                "incident_type": "ransomware",
                "resolution": "Full incident response, network sweep, RDP hardening",
                "playbooks_used": ["pb-002", "pb-003", "pb-006"],
                "time_to_resolve": 480,
                "created_at": datetime(2024, 2, 10),
                "tags": ["ryuk", "ransomware", "rdp"],
            },
            {
                "case_id": "CASE-2024-007",
                "title": "SQL injection on web application",
                "description": "Automated SQL injection attacks detected on customer portal. WAF blocked most attempts but some succeeded.",
                "severity": "high",
                "incident_type": "intrusion",
                "resolution": "Patched application, enhanced WAF rules, code review",
                "playbooks_used": ["pb-001"],
                "time_to_resolve": 240,
                "created_at": datetime(2024, 2, 15),
                "tags": ["sql_injection", "web_application", "waf"],
            },
        ]

        for case in sample_cases:
            self._case_store[case["case_id"]] = case

    async def search(
        self,
        query_context: dict[str, Any],
        config: SimilarityConfig | None = None,
    ) -> list[SimilarCase]:
        """Search for similar cases.

        Args:
            query_context: Current incident/case context
            config: Search configuration

        Returns:
            List of similar cases ordered by similarity
        """
        config = config or SimilarityConfig()

        self.logger.info(
            "searching_similar_cases",
            method=config.method,
            incident_type=query_context.get("incident_type"),
        )

        if config.method == SimilarityMethod.EMBEDDING:
            results = await self._embedding_search(query_context, config)
        elif config.method == SimilarityMethod.KEYWORD:
            results = self._keyword_search(query_context, config)
        else:  # HYBRID
            embedding_results = await self._embedding_search(query_context, config)
            keyword_results = self._keyword_search(query_context, config)
            results = self._merge_results(embedding_results, keyword_results)

        # Apply boosts
        results = self._apply_boosts(results, query_context, config)

        # Filter and sort
        results = [r for r in results if r.similarity_score >= config.min_similarity]
        results.sort(key=lambda x: x.similarity_score, reverse=True)

        return results[:config.max_results]

    async def _embedding_search(
        self,
        query_context: dict[str, Any],
        config: SimilarityConfig,
    ) -> list[SimilarCase]:
        """Search using embedding similarity."""
        # Build query text
        query_text = self._build_query_text(query_context)

        # Get embedding
        try:
            query_embedding = await self._get_embedding(query_text)
        except Exception as e:
            self.logger.warning("embedding_failed", error=str(e))
            return []

        # Calculate similarities
        results = []
        for case_id, case_data in self._case_store.items():
            case_text = self._build_case_text(case_data)

            # Get or compute case embedding
            if case_id not in self._case_embeddings:
                try:
                    self._case_embeddings[case_id] = await self._get_embedding(case_text)
                except Exception:
                    continue

            # Cosine similarity
            similarity = self._cosine_similarity(query_embedding, self._case_embeddings[case_id])

            if similarity >= config.min_similarity:
                results.append(self._build_similar_case(case_data, similarity, ["Embedding similarity"]))

        return results

    def _keyword_search(
        self,
        query_context: dict[str, Any],
        config: SimilarityConfig,
    ) -> list[SimilarCase]:
        """Search using keyword matching."""
        # Extract keywords from query
        query_keywords = self._extract_keywords(query_context)

        results = []
        for case_id, case_data in self._case_store.items():
            case_keywords = self._extract_keywords(case_data)

            # Calculate Jaccard similarity
            intersection = query_keywords & case_keywords
            union = query_keywords | case_keywords

            if union:
                similarity = len(intersection) / len(union)
                match_reasons = [f"Matching keywords: {', '.join(intersection)}"]

                if similarity >= config.min_similarity * 0.5:  # Lower threshold for keywords
                    results.append(self._build_similar_case(case_data, similarity, match_reasons))

        return results

    def _merge_results(
        self,
        embedding_results: list[SimilarCase],
        keyword_results: list[SimilarCase],
        embedding_weight: float = 0.7,
    ) -> list[SimilarCase]:
        """Merge embedding and keyword results."""
        merged: dict[str, SimilarCase] = {}

        # Add embedding results
        for result in embedding_results:
            merged[result.case_id] = result

        # Merge keyword results
        keyword_weight = 1 - embedding_weight
        for result in keyword_results:
            if result.case_id in merged:
                # Combine scores
                existing = merged[result.case_id]
                combined_score = (
                    embedding_weight * existing.similarity_score +
                    keyword_weight * result.similarity_score
                )
                existing.similarity_score = combined_score
                existing.match_reasons.extend(result.match_reasons)
            else:
                result.similarity_score *= keyword_weight
                merged[result.case_id] = result

        return list(merged.values())

    def _apply_boosts(
        self,
        results: list[SimilarCase],
        query_context: dict[str, Any],
        config: SimilarityConfig,
    ) -> list[SimilarCase]:
        """Apply context-based score boosts."""
        query_severity = query_context.get("severity", "").lower()
        query_type = query_context.get("incident_type", "").lower()

        for result in results:
            boost = 0.0
            boost_reasons = []

            # Same severity boost
            if result.severity.lower() == query_severity:
                boost += config.same_severity_boost
                boost_reasons.append("Same severity")

            # Same incident type boost
            if result.incident_type.lower() == query_type:
                boost += config.same_type_boost
                boost_reasons.append("Same incident type")

            # Apply boost
            result.similarity_score = min(1.0, result.similarity_score + boost)
            if boost_reasons:
                result.match_reasons.extend(boost_reasons)

        return results

    async def _get_embedding(self, text: str) -> list[float]:
        """Get text embedding from API."""
        client = await self._get_client()

        response = await client.post(
            f"{self.embedding_endpoint}/embed",
            json={"inputs": text, "truncate": True},
        )
        response.raise_for_status()

        data = response.json()
        # Handle different response formats
        if isinstance(data, list):
            if isinstance(data[0], list):
                return data[0]
            return data
        elif isinstance(data, dict) and "embeddings" in data:
            return data["embeddings"][0]

        raise ValueError("Unexpected embedding response format")

    def _cosine_similarity(self, vec1: list[float], vec2: list[float]) -> float:
        """Calculate cosine similarity between vectors."""
        if len(vec1) != len(vec2):
            return 0.0

        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot_product / (norm1 * norm2)

    def _build_query_text(self, context: dict[str, Any]) -> str:
        """Build text representation of query context."""
        parts = []

        if title := context.get("title"):
            parts.append(title)
        if description := context.get("description"):
            parts.append(description)
        if incident_type := context.get("incident_type"):
            parts.append(f"Incident type: {incident_type}")
        if severity := context.get("severity"):
            parts.append(f"Severity: {severity}")
        if tags := context.get("tags"):
            parts.append(f"Tags: {', '.join(tags)}")

        return " ".join(parts)

    def _build_case_text(self, case_data: dict[str, Any]) -> str:
        """Build text representation of a case."""
        parts = [
            case_data.get("title", ""),
            case_data.get("description", ""),
            f"Type: {case_data.get('incident_type', '')}",
            f"Resolution: {case_data.get('resolution', '')}",
        ]
        if tags := case_data.get("tags"):
            parts.append(f"Tags: {', '.join(tags)}")

        return " ".join(parts)

    def _extract_keywords(self, data: dict[str, Any]) -> set[str]:
        """Extract keywords from data."""
        keywords = set()

        # From tags
        if tags := data.get("tags"):
            keywords.update(tag.lower() for tag in tags)

        # From incident type
        if incident_type := data.get("incident_type"):
            keywords.add(incident_type.lower())

        # From severity
        if severity := data.get("severity"):
            keywords.add(severity.lower())

        # From title and description
        text = f"{data.get('title', '')} {data.get('description', '')}"
        # Simple word extraction (in production, use proper NLP)
        words = text.lower().split()
        security_keywords = {
            "malware", "ransomware", "phishing", "brute", "force", "attack",
            "breach", "exfiltration", "lateral", "movement", "injection",
            "exploit", "vulnerability", "compromised", "suspicious"
        }
        keywords.update(w for w in words if w in security_keywords)

        return keywords

    def _build_similar_case(
        self,
        case_data: dict[str, Any],
        similarity: float,
        match_reasons: list[str],
    ) -> SimilarCase:
        """Build SimilarCase from case data."""
        return SimilarCase(
            case_id=case_data["case_id"],
            title=case_data["title"],
            description=case_data["description"],
            similarity_score=similarity,
            match_reasons=match_reasons,
            resolution=case_data.get("resolution"),
            playbooks_used=case_data.get("playbooks_used", []),
            time_to_resolve=case_data.get("time_to_resolve"),
            severity=case_data["severity"],
            incident_type=case_data["incident_type"],
            created_at=case_data.get("created_at"),
        )

    async def add_case(self, case_data: dict[str, Any]) -> None:
        """Add a new case to the store.

        Args:
            case_data: Case data to add
        """
        case_id = case_data.get("case_id")
        if not case_id:
            case_id = f"CASE-{hashlib.md5(str(case_data).encode()).hexdigest()[:8]}"
            case_data["case_id"] = case_id

        self._case_store[case_id] = case_data

        # Pre-compute embedding
        try:
            case_text = self._build_case_text(case_data)
            self._case_embeddings[case_id] = await self._get_embedding(case_text)
        except Exception as e:
            self.logger.warning("embedding_precompute_failed", case_id=case_id, error=str(e))

        self.logger.info("case_added", case_id=case_id)

    async def get_resolution_suggestions(
        self,
        similar_cases: list[SimilarCase],
    ) -> list[str]:
        """Get resolution suggestions based on similar cases.

        Args:
            similar_cases: List of similar cases

        Returns:
            List of resolution suggestions
        """
        suggestions = []

        for case in similar_cases:
            if case.resolution and case.similarity_score >= 0.7:
                suggestions.append(
                    f"[{case.similarity_score:.0%} match] {case.resolution}"
                )

        return suggestions[:5]
