"""Threat Classifier - MITRE ATT&CK mapping and threat classification."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ThreatType(str, Enum):
    """Types of threats."""

    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    APT = "apt"
    INSIDER_THREAT = "insider_threat"
    DDOS = "ddos"
    PHISHING = "phishing"
    DATA_BREACH = "data_breach"
    CRYPTOMINER = "cryptominer"
    BOTNET = "botnet"
    UNKNOWN = "unknown"


class ThreatActorType(str, Enum):
    """Types of threat actors."""

    NATION_STATE = "nation_state"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    SCRIPT_KIDDIE = "script_kiddie"
    UNKNOWN = "unknown"


class MitreTactic(str, Enum):
    """MITRE ATT&CK tactics."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class MitreMapping(BaseModel):
    """MITRE ATT&CK mapping."""

    tactic: MitreTactic = Field(description="MITRE tactic")
    technique_id: str = Field(description="Technique ID (e.g., T1566)")
    technique_name: str = Field(description="Technique name")
    sub_technique_id: str | None = Field(default=None)
    sub_technique_name: str | None = Field(default=None)
    confidence: float = Field(ge=0, le=1, default=0.5)
    evidence: list[str] = Field(default_factory=list)


class ThreatClassification(BaseModel):
    """Complete threat classification."""

    classification_id: str = Field(default_factory=lambda: str(uuid4()))

    # Primary classification
    threat_type: ThreatType = Field(description="Type of threat")
    threat_type_confidence: float = Field(ge=0, le=1, default=0.5)

    # Threat actor
    actor_type: ThreatActorType = Field(default=ThreatActorType.UNKNOWN)
    actor_name: str | None = Field(default=None)
    actor_motivation: str | None = Field(default=None)

    # Kill chain
    kill_chain_stage: str | None = Field(default=None)
    kill_chain_progression: list[str] = Field(default_factory=list)

    # MITRE ATT&CK
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    tactics_observed: list[MitreTactic] = Field(default_factory=list)

    # Campaign
    is_targeted: bool = Field(default=False)
    potential_campaign: str | None = Field(default=None)

    # Severity
    severity_score: float = Field(ge=0, le=10, default=5.0)

    # Summary
    summary: str = Field(default="")
    indicators_of_compromise: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    classified_at: datetime = Field(default_factory=datetime.utcnow)


class ThreatClassifier(LoggerMixin):
    """Classifier for threats and MITRE ATT&CK mapping.

    Features:
    - Threat type classification
    - MITRE ATT&CK technique mapping
    - Kill chain analysis
    - Threat actor profiling
    - Campaign identification
    """

    # Technique patterns for automatic detection
    TECHNIQUE_PATTERNS = {
        # Initial Access
        "T1566": {
            "keywords": ["phishing", "spear phishing", "email attachment", "malicious link"],
            "tactic": MitreTactic.INITIAL_ACCESS,
            "name": "Phishing",
        },
        "T1190": {
            "keywords": ["exploit", "vulnerability", "cve", "rce", "public-facing"],
            "tactic": MitreTactic.INITIAL_ACCESS,
            "name": "Exploit Public-Facing Application",
        },
        "T1133": {
            "keywords": ["vpn", "rdp", "citrix", "remote service"],
            "tactic": MitreTactic.INITIAL_ACCESS,
            "name": "External Remote Services",
        },
        # Execution
        "T1059": {
            "keywords": ["powershell", "cmd", "bash", "script", "command"],
            "tactic": MitreTactic.EXECUTION,
            "name": "Command and Scripting Interpreter",
        },
        "T1204": {
            "keywords": ["user execution", "click", "open", "run"],
            "tactic": MitreTactic.EXECUTION,
            "name": "User Execution",
        },
        # Persistence
        "T1053": {
            "keywords": ["scheduled task", "cron", "at job"],
            "tactic": MitreTactic.PERSISTENCE,
            "name": "Scheduled Task/Job",
        },
        "T1547": {
            "keywords": ["startup", "autorun", "boot", "logon"],
            "tactic": MitreTactic.PERSISTENCE,
            "name": "Boot or Logon Autostart Execution",
        },
        "T1543": {
            "keywords": ["service", "daemon", "systemd"],
            "tactic": MitreTactic.PERSISTENCE,
            "name": "Create or Modify System Process",
        },
        # Privilege Escalation
        "T1548": {
            "keywords": ["uac", "bypass", "elevation", "sudo"],
            "tactic": MitreTactic.PRIVILEGE_ESCALATION,
            "name": "Abuse Elevation Control Mechanism",
        },
        # Defense Evasion
        "T1562": {
            "keywords": ["disable", "tamper", "antivirus", "defender", "security"],
            "tactic": MitreTactic.DEFENSE_EVASION,
            "name": "Impair Defenses",
        },
        "T1070": {
            "keywords": ["clear log", "delete log", "remove evidence"],
            "tactic": MitreTactic.DEFENSE_EVASION,
            "name": "Indicator Removal",
        },
        # Credential Access
        "T1003": {
            "keywords": ["credential dump", "mimikatz", "lsass", "sam"],
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "name": "OS Credential Dumping",
        },
        "T1110": {
            "keywords": ["brute force", "password spray", "credential stuff"],
            "tactic": MitreTactic.CREDENTIAL_ACCESS,
            "name": "Brute Force",
        },
        # Lateral Movement
        "T1021": {
            "keywords": ["rdp", "ssh", "smb", "winrm", "remote service"],
            "tactic": MitreTactic.LATERAL_MOVEMENT,
            "name": "Remote Services",
        },
        "T1570": {
            "keywords": ["lateral tool", "psexec", "wmi", "dcom"],
            "tactic": MitreTactic.LATERAL_MOVEMENT,
            "name": "Lateral Tool Transfer",
        },
        # Command and Control
        "T1071": {
            "keywords": ["http", "https", "dns", "c2", "beacon"],
            "tactic": MitreTactic.COMMAND_AND_CONTROL,
            "name": "Application Layer Protocol",
        },
        "T1573": {
            "keywords": ["encrypted", "ssl", "tls", "tunnel"],
            "tactic": MitreTactic.COMMAND_AND_CONTROL,
            "name": "Encrypted Channel",
        },
        # Exfiltration
        "T1041": {
            "keywords": ["exfiltration", "data transfer", "upload", "c2 channel"],
            "tactic": MitreTactic.EXFILTRATION,
            "name": "Exfiltration Over C2 Channel",
        },
        "T1567": {
            "keywords": ["cloud", "dropbox", "google drive", "web service"],
            "tactic": MitreTactic.EXFILTRATION,
            "name": "Exfiltration Over Web Service",
        },
        # Impact
        "T1486": {
            "keywords": ["encrypt", "ransom", "lock"],
            "tactic": MitreTactic.IMPACT,
            "name": "Data Encrypted for Impact",
        },
        "T1489": {
            "keywords": ["stop service", "service stop", "shutdown"],
            "tactic": MitreTactic.IMPACT,
            "name": "Service Stop",
        },
    }

    # Threat type patterns
    THREAT_PATTERNS = {
        ThreatType.RANSOMWARE: ["ransom", "encrypt", "bitcoin", "decrypt", "locker"],
        ThreatType.APT: ["apt", "advanced", "persistent", "nation", "targeted"],
        ThreatType.PHISHING: ["phishing", "spear", "credential", "harvest"],
        ThreatType.MALWARE: ["malware", "trojan", "virus", "worm", "backdoor"],
        ThreatType.CRYPTOMINER: ["miner", "crypto", "monero", "bitcoin", "cpu usage"],
        ThreatType.BOTNET: ["botnet", "bot", "zombie", "ddos", "c2"],
        ThreatType.DATA_BREACH: ["breach", "exfil", "steal", "dump", "leak"],
        ThreatType.INSIDER_THREAT: ["insider", "employee", "internal", "authorized"],
    }

    def __init__(
        self,
        llm_endpoint: str = "http://localhost:8080/v1",
        model_name: str = "solar-10.7b",
    ) -> None:
        """Initialize threat classifier.

        Args:
            llm_endpoint: LLM API endpoint
            model_name: Model name
        """
        self.llm_endpoint = llm_endpoint
        self.model_name = model_name
        self._client: httpx.AsyncClient | None = None

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

    async def classify(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        context: dict[str, Any] | None = None,
    ) -> ThreatClassification:
        """Classify threat from evidence and timeline.

        Args:
            evidence: List of evidence items
            timeline: Timeline events
            context: Additional context

        Returns:
            Complete threat classification
        """
        self.logger.info(
            "classifying_threat",
            evidence_count=len(evidence),
            timeline_events=len(timeline),
        )

        classification = ThreatClassification()

        # Collect all text for analysis
        all_text = self._collect_text(evidence, timeline)

        # Detect MITRE techniques
        mitre_mappings = self._detect_techniques(all_text)
        classification.mitre_mappings = mitre_mappings

        # Extract tactics
        tactics = list(set(m.tactic for m in mitre_mappings))
        classification.tactics_observed = tactics

        # Classify threat type
        threat_type, confidence = self._classify_threat_type(all_text, mitre_mappings)
        classification.threat_type = threat_type
        classification.threat_type_confidence = confidence

        # Analyze kill chain
        classification.kill_chain_stage = self._determine_kill_chain_stage(tactics)
        classification.kill_chain_progression = self._get_kill_chain_progression(tactics)

        # Use LLM for deeper analysis
        llm_analysis = await self._llm_classify(evidence, timeline, context)

        if llm_analysis:
            classification.actor_type = self._parse_actor_type(
                llm_analysis.get("actor_type")
            )
            classification.actor_name = llm_analysis.get("actor_name")
            classification.actor_motivation = llm_analysis.get("motivation")
            classification.is_targeted = llm_analysis.get("is_targeted", False)
            classification.potential_campaign = llm_analysis.get("campaign")

        # Extract IOCs
        classification.indicators_of_compromise = self._extract_iocs(evidence)

        # Calculate severity
        classification.severity_score = self._calculate_severity(classification)

        # Generate summary
        classification.summary = self._generate_summary(classification)

        return classification

    def _collect_text(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> str:
        """Collect all text for pattern matching."""
        text_parts = []

        for ev in evidence:
            text_parts.append(str(ev.get("data", ev)).lower())

        for event in timeline:
            text_parts.append(event.get("title", "").lower())
            text_parts.append(event.get("description", "").lower())

        return " ".join(text_parts)

    def _detect_techniques(self, text: str) -> list[MitreMapping]:
        """Detect MITRE techniques from text."""
        mappings = []

        for technique_id, info in self.TECHNIQUE_PATTERNS.items():
            matches = sum(1 for kw in info["keywords"] if kw in text)
            if matches > 0:
                confidence = min(matches / len(info["keywords"]) + 0.3, 1.0)
                mappings.append(
                    MitreMapping(
                        tactic=info["tactic"],
                        technique_id=technique_id,
                        technique_name=info["name"],
                        confidence=confidence,
                        evidence=[f"Matched {matches} keywords"],
                    )
                )

        # Sort by confidence
        mappings.sort(key=lambda m: m.confidence, reverse=True)

        return mappings[:15]  # Return top 15

    def _classify_threat_type(
        self,
        text: str,
        mitre_mappings: list[MitreMapping],
    ) -> tuple[ThreatType, float]:
        """Classify the threat type."""
        scores = {}

        # Pattern matching
        for threat_type, patterns in self.THREAT_PATTERNS.items():
            matches = sum(1 for p in patterns if p in text)
            scores[threat_type] = matches / len(patterns)

        # Boost based on MITRE techniques
        tactics = [m.tactic for m in mitre_mappings]

        if MitreTactic.IMPACT in tactics:
            scores[ThreatType.RANSOMWARE] = scores.get(ThreatType.RANSOMWARE, 0) + 0.3

        if MitreTactic.EXFILTRATION in tactics:
            scores[ThreatType.DATA_BREACH] = scores.get(ThreatType.DATA_BREACH, 0) + 0.3

        if MitreTactic.LATERAL_MOVEMENT in tactics and len(tactics) >= 4:
            scores[ThreatType.APT] = scores.get(ThreatType.APT, 0) + 0.2

        # Get top result
        if scores:
            best_type = max(scores, key=scores.get)
            confidence = min(scores[best_type] + 0.3, 1.0)
            if confidence >= 0.3:
                return best_type, confidence

        return ThreatType.UNKNOWN, 0.3

    def _determine_kill_chain_stage(
        self,
        tactics: list[MitreTactic],
    ) -> str:
        """Determine current kill chain stage."""
        # Lockheed Martin Cyber Kill Chain mapping
        stage_mapping = {
            MitreTactic.RECONNAISSANCE: "Reconnaissance",
            MitreTactic.RESOURCE_DEVELOPMENT: "Weaponization",
            MitreTactic.INITIAL_ACCESS: "Delivery",
            MitreTactic.EXECUTION: "Exploitation",
            MitreTactic.PERSISTENCE: "Installation",
            MitreTactic.COMMAND_AND_CONTROL: "Command & Control",
            MitreTactic.EXFILTRATION: "Actions on Objectives",
            MitreTactic.IMPACT: "Actions on Objectives",
        }

        # Return the furthest stage observed
        stage_order = [
            "Reconnaissance",
            "Weaponization",
            "Delivery",
            "Exploitation",
            "Installation",
            "Command & Control",
            "Actions on Objectives",
        ]

        observed_stages = []
        for tactic in tactics:
            if stage := stage_mapping.get(tactic):
                observed_stages.append(stage)

        if observed_stages:
            return max(observed_stages, key=lambda s: stage_order.index(s))

        return "Unknown"

    def _get_kill_chain_progression(
        self,
        tactics: list[MitreTactic],
    ) -> list[str]:
        """Get kill chain progression."""
        # Order tactics by kill chain
        tactic_order = [
            MitreTactic.RECONNAISSANCE,
            MitreTactic.RESOURCE_DEVELOPMENT,
            MitreTactic.INITIAL_ACCESS,
            MitreTactic.EXECUTION,
            MitreTactic.PERSISTENCE,
            MitreTactic.PRIVILEGE_ESCALATION,
            MitreTactic.DEFENSE_EVASION,
            MitreTactic.CREDENTIAL_ACCESS,
            MitreTactic.DISCOVERY,
            MitreTactic.LATERAL_MOVEMENT,
            MitreTactic.COLLECTION,
            MitreTactic.COMMAND_AND_CONTROL,
            MitreTactic.EXFILTRATION,
            MitreTactic.IMPACT,
        ]

        # Sort observed tactics by order
        observed = [t for t in tactic_order if t in tactics]
        return [t.value.replace("-", " ").title() for t in observed]

    async def _llm_classify(
        self,
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Use LLM for threat classification."""
        client = await self._get_client()

        # Build summary
        timeline_summary = "\n".join([
            f"- {e.get('timestamp', 'N/A')}: {e.get('title', '')}"
            for e in timeline[:10]
        ])

        prompt = f"""Analyze this security incident for threat classification.

Timeline:
{timeline_summary}

Evidence count: {len(evidence)}
Context: {context or 'None'}

Determine:
1. Threat actor type (nation_state, cybercriminal, hacktivist, insider, script_kiddie)
2. Actor name/group if identifiable
3. Motivation (financial, espionage, disruption, etc.)
4. Is this targeted attack?
5. Related campaign name if known

Respond in JSON format."""

        try:
            response = await client.post(
                f"{self.llm_endpoint}/chat/completions",
                json={
                    "model": self.model_name,
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are a threat intelligence analyst.",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 500,
                    "temperature": 0.2,
                },
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            import json
            import re

            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                return json.loads(json_match.group())

        except Exception as e:
            self.logger.warning("llm_classify_failed", error=str(e))

        return {}

    def _parse_actor_type(self, actor_str: str | None) -> ThreatActorType:
        """Parse actor type string to enum."""
        if not actor_str:
            return ThreatActorType.UNKNOWN

        actor_lower = actor_str.lower()

        if "nation" in actor_lower or "state" in actor_lower:
            return ThreatActorType.NATION_STATE
        if "criminal" in actor_lower:
            return ThreatActorType.CYBERCRIMINAL
        if "hacktivist" in actor_lower:
            return ThreatActorType.HACKTIVIST
        if "insider" in actor_lower:
            return ThreatActorType.INSIDER
        if "script" in actor_lower or "kiddie" in actor_lower:
            return ThreatActorType.SCRIPT_KIDDIE

        return ThreatActorType.UNKNOWN

    def _extract_iocs(self, evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Extract IOCs from evidence."""
        iocs = []
        seen = set()

        for ev in evidence:
            data = ev.get("data", ev)

            # Extract IPs
            for field in ["source_ip", "destination_ip", "src_ip", "dst_ip"]:
                if ip := data.get(field):
                    if ip not in seen:
                        seen.add(ip)
                        iocs.append({"type": "ip", "value": ip})

            # Extract hashes
            for field in ["md5", "sha256", "sha1", "file_hash"]:
                if hash_val := data.get(field):
                    if hash_val not in seen:
                        seen.add(hash_val)
                        iocs.append({"type": "hash", "value": hash_val})

            # Extract domains
            if domain := data.get("domain"):
                if domain not in seen:
                    seen.add(domain)
                    iocs.append({"type": "domain", "value": domain})

            # Extract URLs
            if url := data.get("url"):
                if url not in seen:
                    seen.add(url)
                    iocs.append({"type": "url", "value": url})

        return iocs[:50]

    def _calculate_severity(self, classification: ThreatClassification) -> float:
        """Calculate threat severity score."""
        score = 5.0  # Base

        # Adjust by threat type
        type_adjustments = {
            ThreatType.RANSOMWARE: 3.0,
            ThreatType.APT: 3.0,
            ThreatType.DATA_BREACH: 2.5,
            ThreatType.MALWARE: 1.5,
            ThreatType.INSIDER_THREAT: 2.0,
            ThreatType.PHISHING: 1.0,
        }
        score += type_adjustments.get(classification.threat_type, 0)

        # Adjust by actor type
        if classification.actor_type == ThreatActorType.NATION_STATE:
            score += 2.0
        elif classification.actor_type == ThreatActorType.CYBERCRIMINAL:
            score += 1.0

        # Adjust by kill chain progression
        progression_len = len(classification.kill_chain_progression)
        score += min(progression_len * 0.3, 2.0)

        # Adjust if targeted
        if classification.is_targeted:
            score += 1.0

        return min(score, 10.0)

    def _generate_summary(self, classification: ThreatClassification) -> str:
        """Generate classification summary."""
        parts = [
            f"Threat Type: {classification.threat_type.value}",
            f"Actor: {classification.actor_type.value}",
            f"Kill Chain: {classification.kill_chain_stage}",
            f"Tactics: {len(classification.tactics_observed)}",
            f"Techniques: {len(classification.mitre_mappings)}",
            f"IOCs: {len(classification.indicators_of_compromise)}",
        ]

        if classification.potential_campaign:
            parts.append(f"Campaign: {classification.potential_campaign}")

        return ". ".join(parts)

    def get_mitre_recommendations(
        self,
        mappings: list[MitreMapping],
    ) -> list[dict[str, Any]]:
        """Get recommendations based on MITRE mappings.

        Args:
            mappings: MITRE technique mappings

        Returns:
            Recommendations for each technique
        """
        recommendations = []

        # Common mitigations by technique
        mitigations = {
            "T1566": ["Email filtering", "User training", "Disable macros"],
            "T1059": ["Script execution policies", "Application whitelisting"],
            "T1003": ["Credential Guard", "LSASS protection", "Privileged access"],
            "T1021": ["Network segmentation", "MFA", "Jump servers"],
            "T1486": ["Offline backups", "Ransomware protection tools"],
        }

        for mapping in mappings:
            tech_id = mapping.technique_id
            if tech_id in mitigations:
                recommendations.append({
                    "technique": tech_id,
                    "technique_name": mapping.technique_name,
                    "mitigations": mitigations[tech_id],
                })

        return recommendations
