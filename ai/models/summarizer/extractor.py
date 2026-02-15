"""Key information extractor for incident analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class EntityType(str, Enum):
    """Types of extractable entities."""

    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    FILE_HASH = "file_hash"
    CVE = "cve"
    USER = "user"
    HOSTNAME = "hostname"
    PORT = "port"
    PROCESS = "process"
    REGISTRY = "registry"
    FILE_PATH = "file_path"


class SeverityLevel(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExtractedEntity(BaseModel):
    """Extracted entity with context."""

    entity_type: EntityType = Field(description="Type of entity")
    value: str = Field(description="Entity value")
    context: str = Field(default="", description="Surrounding context")
    confidence: float = Field(ge=0, le=1, default=1.0)
    source: str = Field(default="", description="Source of extraction")
    metadata: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    """Key finding from analysis."""

    title: str = Field(description="Finding title")
    description: str = Field(description="Finding description")
    severity: SeverityLevel = Field(description="Severity level")
    evidence: list[str] = Field(default_factory=list, description="Supporting evidence")
    related_entities: list[ExtractedEntity] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)


class ExtractedInfo(BaseModel):
    """Complete extracted information from incident."""

    entities: list[ExtractedEntity] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    attack_pattern: str | None = Field(default=None, description="Identified attack pattern")
    affected_assets: list[str] = Field(default_factory=list)
    attacker_indicators: list[str] = Field(default_factory=list)
    victim_indicators: list[str] = Field(default_factory=list)
    timeline_events: list[dict[str, Any]] = Field(default_factory=list)


class KeyInfoExtractor(LoggerMixin):
    """Extract key information from incident data and raw logs.

    Features:
    - IOC extraction (IPs, domains, hashes, etc.)
    - Attack pattern identification
    - MITRE ATT&CK mapping
    - Entity relationship extraction
    - Timeline construction
    """

    # Regex patterns for entity extraction
    PATTERNS = {
        EntityType.IP_ADDRESS: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        ),
        EntityType.DOMAIN: re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"(?:[a-zA-Z]{2,})\b"
        ),
        EntityType.URL: re.compile(
            r"\bhttps?://[^\s<>\"'{}|\\^`\[\]]+\b"
        ),
        EntityType.EMAIL: re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
        ),
        EntityType.FILE_HASH: {
            "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
            "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
            "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        },
        EntityType.CVE: re.compile(
            r"\bCVE-\d{4}-\d{4,7}\b",
            re.IGNORECASE
        ),
        EntityType.PORT: re.compile(
            r"\bport[:\s]+(\d{1,5})\b|\b:(\d{1,5})\b",
            re.IGNORECASE
        ),
        EntityType.FILE_PATH: re.compile(
            r"(?:[A-Za-z]:\\|/)[^\s:*?\"<>|]+"
        ),
    }

    # Known attack patterns
    ATTACK_PATTERNS = {
        "brute_force": {
            "indicators": ["failed login", "authentication failure", "invalid password"],
            "mitre_technique": "T1110",
            "mitre_tactic": "Credential Access",
        },
        "lateral_movement": {
            "indicators": ["psexec", "wmi", "remote execution", "ssh tunnel"],
            "mitre_technique": "T1021",
            "mitre_tactic": "Lateral Movement",
        },
        "data_exfiltration": {
            "indicators": ["large transfer", "upload", "external connection", "c2"],
            "mitre_technique": "T1041",
            "mitre_tactic": "Exfiltration",
        },
        "malware_execution": {
            "indicators": ["suspicious process", "powershell", "cmd.exe", "script execution"],
            "mitre_technique": "T1059",
            "mitre_tactic": "Execution",
        },
        "privilege_escalation": {
            "indicators": ["admin", "root", "elevated", "privilege"],
            "mitre_technique": "T1068",
            "mitre_tactic": "Privilege Escalation",
        },
        "persistence": {
            "indicators": ["scheduled task", "registry", "startup", "service install"],
            "mitre_technique": "T1053",
            "mitre_tactic": "Persistence",
        },
    }

    # Private IP ranges for internal/external classification
    PRIVATE_IP_RANGES = [
        (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
        (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
    ]

    def __init__(
        self,
        enable_dns_lookup: bool = False,
        enable_reputation_check: bool = False,
    ) -> None:
        """Initialize the extractor.

        Args:
            enable_dns_lookup: Enable DNS lookups for domains
            enable_reputation_check: Enable reputation service lookups
        """
        self.enable_dns_lookup = enable_dns_lookup
        self.enable_reputation_check = enable_reputation_check

    def extract(self, incident_data: dict[str, Any]) -> ExtractedInfo:
        """Extract key information from incident data.

        Args:
            incident_data: Incident data including alerts, events, logs

        Returns:
            Extracted information
        """
        self.logger.info("extracting_info", incident_id=incident_data.get("id"))

        # Extract entities from various sources
        entities = []

        # From structured data
        entities.extend(self._extract_from_structured(incident_data))

        # From raw logs
        for event in incident_data.get("events", []):
            if raw_log := event.get("raw_log"):
                entities.extend(self._extract_from_text(raw_log, source="event_log"))

        # From alert descriptions
        for alert in incident_data.get("alerts", []):
            if desc := alert.get("description"):
                entities.extend(self._extract_from_text(desc, source="alert"))

        # Deduplicate entities
        entities = self._deduplicate_entities(entities)

        # Identify attack patterns
        attack_pattern = self._identify_attack_pattern(incident_data, entities)

        # Generate findings
        findings = self._generate_findings(incident_data, entities, attack_pattern)

        # Classify indicators
        attacker_indicators, victim_indicators = self._classify_indicators(entities, incident_data)

        # Build timeline
        timeline = self._build_timeline(incident_data)

        return ExtractedInfo(
            entities=entities,
            findings=findings,
            attack_pattern=attack_pattern,
            affected_assets=self._identify_affected_assets(incident_data),
            attacker_indicators=attacker_indicators,
            victim_indicators=victim_indicators,
            timeline_events=timeline,
        )

    def _extract_from_structured(self, data: dict[str, Any]) -> list[ExtractedEntity]:
        """Extract entities from structured data fields."""
        entities = []

        # Common fields to check
        ip_fields = ["source_ip", "dest_ip", "src_ip", "dst_ip", "ip_address", "remote_ip"]
        for field_name in ip_fields:
            if value := data.get(field_name):
                entities.append(ExtractedEntity(
                    entity_type=EntityType.IP_ADDRESS,
                    value=value,
                    context=f"From field: {field_name}",
                    source="structured",
                    confidence=1.0,
                ))

        # From events
        for event in data.get("events", []):
            for field_name in ip_fields:
                if value := event.get(field_name):
                    entities.append(ExtractedEntity(
                        entity_type=EntityType.IP_ADDRESS,
                        value=value,
                        context=f"Event {field_name}",
                        source="event_structured",
                        confidence=1.0,
                    ))

            if hostname := event.get("hostname"):
                entities.append(ExtractedEntity(
                    entity_type=EntityType.HOSTNAME,
                    value=hostname,
                    source="event_structured",
                    confidence=1.0,
                ))

            if user := event.get("user") or event.get("user_id"):
                entities.append(ExtractedEntity(
                    entity_type=EntityType.USER,
                    value=str(user),
                    source="event_structured",
                    confidence=1.0,
                ))

        return entities

    def _extract_from_text(self, text: str, source: str = "") -> list[ExtractedEntity]:
        """Extract entities from unstructured text."""
        entities = []

        # IP addresses
        for match in self.PATTERNS[EntityType.IP_ADDRESS].finditer(text):
            value = match.group()
            context = self._get_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type=EntityType.IP_ADDRESS,
                value=value,
                context=context,
                source=source,
            ))

        # Domains (excluding those that look like IPs)
        for match in self.PATTERNS[EntityType.DOMAIN].finditer(text):
            value = match.group()
            # Skip if it's an IP
            if self.PATTERNS[EntityType.IP_ADDRESS].match(value):
                continue
            # Skip common false positives
            if value.endswith(".exe") or value.endswith(".dll"):
                continue
            context = self._get_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type=EntityType.DOMAIN,
                value=value,
                context=context,
                source=source,
            ))

        # URLs
        for match in self.PATTERNS[EntityType.URL].finditer(text):
            value = match.group()
            context = self._get_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type=EntityType.URL,
                value=value,
                context=context,
                source=source,
            ))

        # Emails
        for match in self.PATTERNS[EntityType.EMAIL].finditer(text):
            value = match.group()
            context = self._get_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type=EntityType.EMAIL,
                value=value,
                context=context,
                source=source,
            ))

        # File hashes
        for hash_type, pattern in self.PATTERNS[EntityType.FILE_HASH].items():
            for match in pattern.finditer(text):
                value = match.group()
                # Validate it's likely a hash (not just hex string)
                context = self._get_context(text, match.start(), match.end())
                if "hash" in context.lower() or hash_type in context.lower():
                    entities.append(ExtractedEntity(
                        entity_type=EntityType.FILE_HASH,
                        value=value,
                        context=context,
                        source=source,
                        metadata={"hash_type": hash_type},
                    ))

        # CVEs
        for match in self.PATTERNS[EntityType.CVE].finditer(text):
            value = match.group().upper()
            context = self._get_context(text, match.start(), match.end())
            entities.append(ExtractedEntity(
                entity_type=EntityType.CVE,
                value=value,
                context=context,
                source=source,
            ))

        # File paths
        for match in self.PATTERNS[EntityType.FILE_PATH].finditer(text):
            value = match.group()
            if len(value) > 5:  # Skip very short paths
                context = self._get_context(text, match.start(), match.end())
                entities.append(ExtractedEntity(
                    entity_type=EntityType.FILE_PATH,
                    value=value,
                    context=context,
                    source=source,
                ))

        return entities

    def _get_context(self, text: str, start: int, end: int, window: int = 50) -> str:
        """Get surrounding context for a match."""
        ctx_start = max(0, start - window)
        ctx_end = min(len(text), end + window)
        context = text[ctx_start:ctx_end]
        if ctx_start > 0:
            context = "..." + context
        if ctx_end < len(text):
            context = context + "..."
        return context.replace("\n", " ").strip()

    def _deduplicate_entities(self, entities: list[ExtractedEntity]) -> list[ExtractedEntity]:
        """Deduplicate entities while preserving context."""
        seen: dict[tuple, ExtractedEntity] = {}

        for entity in entities:
            key = (entity.entity_type, entity.value)
            if key not in seen:
                seen[key] = entity
            else:
                # Merge context
                existing = seen[key]
                if entity.context and entity.context not in existing.context:
                    existing.context += f" | {entity.context}"
                # Keep higher confidence
                if entity.confidence > existing.confidence:
                    existing.confidence = entity.confidence

        return list(seen.values())

    def _identify_attack_pattern(
        self,
        incident_data: dict[str, Any],
        entities: list[ExtractedEntity],
    ) -> str | None:
        """Identify attack pattern from indicators."""
        text = self._collect_text(incident_data).lower()

        scores: dict[str, int] = {}

        for pattern_name, pattern_info in self.ATTACK_PATTERNS.items():
            score = 0
            for indicator in pattern_info["indicators"]:
                if indicator.lower() in text:
                    score += 1
            if score > 0:
                scores[pattern_name] = score

        if scores:
            return max(scores, key=scores.get)
        return None

    def _collect_text(self, incident_data: dict[str, Any]) -> str:
        """Collect all text from incident data."""
        parts = []

        if title := incident_data.get("title"):
            parts.append(title)
        if desc := incident_data.get("description"):
            parts.append(desc)

        for alert in incident_data.get("alerts", []):
            if title := alert.get("title"):
                parts.append(title)
            if desc := alert.get("description"):
                parts.append(desc)

        for event in incident_data.get("events", []):
            if log := event.get("raw_log"):
                parts.append(log)

        return " ".join(parts)

    def _generate_findings(
        self,
        incident_data: dict[str, Any],
        entities: list[ExtractedEntity],
        attack_pattern: str | None,
    ) -> list[Finding]:
        """Generate findings from extracted information."""
        findings = []

        # Finding: Attack pattern identified
        if attack_pattern:
            pattern_info = self.ATTACK_PATTERNS.get(attack_pattern, {})
            findings.append(Finding(
                title=f"Attack Pattern: {attack_pattern.replace('_', ' ').title()}",
                description=f"Indicators suggest a {attack_pattern.replace('_', ' ')} attack pattern",
                severity=SeverityLevel.HIGH,
                evidence=pattern_info.get("indicators", []),
                mitre_tactics=[pattern_info.get("mitre_tactic", "")],
                mitre_techniques=[pattern_info.get("mitre_technique", "")],
            ))

        # Finding: External IPs
        external_ips = [
            e for e in entities
            if e.entity_type == EntityType.IP_ADDRESS and not self._is_private_ip(e.value)
        ]
        if external_ips:
            findings.append(Finding(
                title=f"External IP Addresses Detected ({len(external_ips)})",
                description="External IP addresses found in the incident data",
                severity=SeverityLevel.MEDIUM,
                evidence=[ip.value for ip in external_ips[:5]],
                related_entities=external_ips,
            ))

        # Finding: Malicious hashes
        hashes = [e for e in entities if e.entity_type == EntityType.FILE_HASH]
        if hashes:
            findings.append(Finding(
                title=f"File Hashes Identified ({len(hashes)})",
                description="File hashes found that should be checked against threat intelligence",
                severity=SeverityLevel.MEDIUM,
                evidence=[h.value for h in hashes[:3]],
                related_entities=hashes,
            ))

        # Finding: CVEs mentioned
        cves = [e for e in entities if e.entity_type == EntityType.CVE]
        if cves:
            findings.append(Finding(
                title=f"CVE References ({len(cves)})",
                description="Vulnerability references found in incident data",
                severity=SeverityLevel.HIGH,
                evidence=[c.value for c in cves],
                related_entities=cves,
            ))

        return findings

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            ip_int = (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])

            for start, end in self.PRIVATE_IP_RANGES:
                if start <= ip_int <= end:
                    return True

            # Localhost
            if ip.startswith("127."):
                return True

            return False
        except Exception:
            return False

    def _classify_indicators(
        self,
        entities: list[ExtractedEntity],
        incident_data: dict[str, Any],
    ) -> tuple[list[str], list[str]]:
        """Classify indicators as attacker or victim."""
        attacker = []
        victim = []

        for entity in entities:
            if entity.entity_type == EntityType.IP_ADDRESS:
                # External IPs are likely attacker
                if not self._is_private_ip(entity.value):
                    attacker.append(entity.value)
                else:
                    # Internal IPs might be victims
                    victim.append(entity.value)

            elif entity.entity_type == EntityType.DOMAIN:
                # Domains are usually attacker infrastructure
                attacker.append(entity.value)

            elif entity.entity_type == EntityType.FILE_HASH:
                attacker.append(entity.value)

            elif entity.entity_type == EntityType.HOSTNAME:
                victim.append(entity.value)

            elif entity.entity_type == EntityType.USER:
                victim.append(entity.value)

        return list(set(attacker)), list(set(victim))

    def _identify_affected_assets(self, incident_data: dict[str, Any]) -> list[str]:
        """Identify affected assets."""
        assets = set()

        for event in incident_data.get("events", []):
            if hostname := event.get("hostname"):
                assets.add(hostname)
            if dest_ip := event.get("dest_ip"):
                if self._is_private_ip(dest_ip):
                    assets.add(dest_ip)

        return list(assets)

    def _build_timeline(self, incident_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Build event timeline."""
        timeline = []

        for event in incident_data.get("events", []):
            timeline.append({
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "source": event.get("source_ip"),
                "destination": event.get("dest_ip"),
                "description": event.get("description", "")[:100],
            })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp") or "")

        return timeline
