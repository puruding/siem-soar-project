"""Feature extraction for UEBA - extracts behavioral features from events."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class TemporalFeatures(BaseModel):
    """Temporal behavior features."""

    # Hour of day distribution (24 bins)
    hour_distribution: list[float] = Field(default_factory=lambda: [0.0] * 24)

    # Day of week distribution (7 bins)
    day_distribution: list[float] = Field(default_factory=lambda: [0.0] * 7)

    # Session patterns
    session_start_hour_mean: float = Field(default=0.0)
    session_start_hour_std: float = Field(default=0.0)
    session_duration_mean: float = Field(default=0.0)
    session_duration_std: float = Field(default=0.0)

    # Activity rhythm
    inter_event_time_mean: float = Field(default=0.0)
    inter_event_time_std: float = Field(default=0.0)
    activity_burst_count: int = Field(default=0)

    # Time-based anomaly indicators
    off_hours_activity_ratio: float = Field(default=0.0)
    weekend_activity_ratio: float = Field(default=0.0)


class AccessFeatures(BaseModel):
    """Resource access behavior features."""

    # System access
    unique_systems: int = Field(default=0)
    new_systems: int = Field(default=0)
    system_access_entropy: float = Field(default=0.0)

    # Application usage
    unique_applications: int = Field(default=0)
    new_applications: int = Field(default=0)
    application_usage_entropy: float = Field(default=0.0)

    # File access
    file_access_count: int = Field(default=0)
    sensitive_file_access_count: int = Field(default=0)
    file_types_accessed: list[str] = Field(default_factory=list)

    # Authentication
    login_count: int = Field(default=0)
    login_failure_count: int = Field(default=0)
    login_success_rate: float = Field(default=1.0)
    unique_login_locations: int = Field(default=0)

    # Privilege usage
    admin_action_count: int = Field(default=0)
    privilege_escalation_attempts: int = Field(default=0)


class NetworkFeatures(BaseModel):
    """Network behavior features."""

    # Connection patterns
    unique_destinations: int = Field(default=0)
    new_destinations: int = Field(default=0)
    destination_entropy: float = Field(default=0.0)

    # Ports and protocols
    unique_ports: int = Field(default=0)
    unusual_ports: list[int] = Field(default_factory=list)
    protocol_distribution: dict[str, float] = Field(default_factory=dict)

    # Data transfer
    bytes_sent: int = Field(default=0)
    bytes_received: int = Field(default=0)
    bytes_ratio: float = Field(default=1.0)
    large_transfer_count: int = Field(default=0)

    # DNS patterns
    dns_queries: int = Field(default=0)
    unique_domains: int = Field(default=0)
    suspicious_domain_count: int = Field(default=0)

    # Connection statistics
    connection_count: int = Field(default=0)
    connection_duration_mean: float = Field(default=0.0)
    failed_connection_count: int = Field(default=0)


class UEBAFeatureExtractor(LoggerMixin):
    """Extracts behavioral features from security events for UEBA model.

    Processes raw events and extracts:
    - Temporal features (time patterns)
    - Access features (resource usage)
    - Network features (connection patterns)

    Features are normalized and formatted for model input.
    """

    # Common sensitive file extensions
    SENSITIVE_EXTENSIONS = {
        ".pem", ".key", ".p12", ".pfx", ".cer", ".crt",
        ".sql", ".db", ".bak", ".dump",
        ".pst", ".ost", ".mbox",
        ".xls", ".xlsx", ".doc", ".docx", ".pdf",
        ".kdb", ".kdbx", ".wallet",
    }

    # Unusual/suspicious ports
    UNUSUAL_PORTS = {
        4444,  # Metasploit default
        5555,  # Common backdoor
        6666, 6667,  # IRC
        31337,  # Elite/leet
        12345, 12346,  # NetBus
        1337,  # Elite
        8080, 8443,  # Alternative HTTP/HTTPS
    }

    # Off-hours definition (for enterprise environments)
    OFF_HOURS_START = 22  # 10 PM
    OFF_HOURS_END = 6  # 6 AM

    def __init__(
        self,
        sequence_length: int = 24,
        feature_dim: int = 128,
        known_systems: set[str] | None = None,
        known_applications: set[str] | None = None,
    ):
        """Initialize feature extractor.

        Args:
            sequence_length: Length of sequence for temporal features
            feature_dim: Output feature dimension
            known_systems: Set of known legitimate systems
            known_applications: Set of known applications
        """
        self.sequence_length = sequence_length
        self.feature_dim = feature_dim
        self.known_systems = known_systems or set()
        self.known_applications = known_applications or set()

        # Statistics for normalization
        self._feature_stats: dict[str, dict[str, float]] = {}

    def extract_all_features(
        self,
        events: list[dict[str, Any]],
        profile_baseline: dict[str, Any] | None = None,
    ) -> tuple[TemporalFeatures, AccessFeatures, NetworkFeatures]:
        """Extract all feature types from events.

        Args:
            events: List of events
            profile_baseline: Optional baseline for comparison

        Returns:
            Tuple of (temporal, access, network) features
        """
        temporal = self.extract_temporal_features(events)
        access = self.extract_access_features(events, profile_baseline)
        network = self.extract_network_features(events)

        return temporal, access, network

    def extract_temporal_features(
        self,
        events: list[dict[str, Any]],
    ) -> TemporalFeatures:
        """Extract temporal behavior features.

        Args:
            events: List of events with timestamps

        Returns:
            Temporal features
        """
        features = TemporalFeatures()

        if not events:
            return features

        timestamps = []
        for event in events:
            ts = self._parse_timestamp(event.get("timestamp"))
            if ts:
                timestamps.append(ts)

        if not timestamps:
            return features

        timestamps.sort()

        # Hour distribution
        hour_counts = [0] * 24
        for ts in timestamps:
            hour_counts[ts.hour] += 1
        total = sum(hour_counts) or 1
        features.hour_distribution = [c / total for c in hour_counts]

        # Day distribution
        day_counts = [0] * 7
        for ts in timestamps:
            day_counts[ts.weekday()] += 1
        total = sum(day_counts) or 1
        features.day_distribution = [c / total for c in day_counts]

        # Inter-event times
        if len(timestamps) > 1:
            inter_times = []
            for i in range(1, len(timestamps)):
                delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
                if delta < 3600:  # Only consider gaps < 1 hour
                    inter_times.append(delta)

            if inter_times:
                features.inter_event_time_mean = float(np.mean(inter_times))
                features.inter_event_time_std = float(np.std(inter_times))

                # Activity bursts (many events in short time)
                bursts = sum(1 for t in inter_times if t < 1.0)  # < 1 second
                features.activity_burst_count = bursts

        # Off-hours activity
        off_hours_count = sum(
            1 for ts in timestamps
            if ts.hour >= self.OFF_HOURS_START or ts.hour < self.OFF_HOURS_END
        )
        features.off_hours_activity_ratio = off_hours_count / len(timestamps)

        # Weekend activity
        weekend_count = sum(1 for ts in timestamps if ts.weekday() >= 5)
        features.weekend_activity_ratio = weekend_count / len(timestamps)

        return features

    def extract_access_features(
        self,
        events: list[dict[str, Any]],
        baseline: dict[str, Any] | None = None,
    ) -> AccessFeatures:
        """Extract access pattern features.

        Args:
            events: List of events
            baseline: Optional baseline for comparison

        Returns:
            Access features
        """
        features = AccessFeatures()

        if not events:
            return features

        # Track unique entities
        systems = set()
        applications = set()
        login_locations = set()
        files_accessed = []

        login_success = 0
        login_failure = 0
        admin_actions = 0

        for event in events:
            # Systems
            if system := event.get("hostname") or event.get("system"):
                systems.add(system)

            # Applications
            if app := event.get("application") or event.get("process_name"):
                applications.add(app)

            # Login tracking
            event_type = str(event.get("event_type", "")).lower()
            if "login" in event_type or "auth" in event_type:
                if event.get("status") == "success":
                    login_success += 1
                else:
                    login_failure += 1

                if location := event.get("location") or event.get("source_ip"):
                    login_locations.add(location)

            # File access
            if file_path := event.get("file_path") or event.get("object_path"):
                files_accessed.append(file_path)

            # Admin actions
            if any(kw in event_type for kw in ["admin", "privilege", "sudo", "runas"]):
                admin_actions += 1

        features.unique_systems = len(systems)
        features.unique_applications = len(applications)
        features.unique_login_locations = len(login_locations)

        # New systems/apps (not in baseline)
        if baseline:
            known = set(baseline.get("known_systems", []))
            features.new_systems = len(systems - known)
            known_apps = set(baseline.get("known_applications", []))
            features.new_applications = len(applications - known_apps)
        else:
            features.new_systems = len(systems - self.known_systems)
            features.new_applications = len(applications - self.known_applications)

        # System access entropy
        features.system_access_entropy = self._calculate_entropy(list(systems))

        # File access
        features.file_access_count = len(files_accessed)
        features.sensitive_file_access_count = sum(
            1 for f in files_accessed
            if any(f.lower().endswith(ext) for ext in self.SENSITIVE_EXTENSIONS)
        )

        # File types
        extensions = set()
        for f in files_accessed:
            if "." in f:
                ext = "." + f.split(".")[-1].lower()
                extensions.add(ext)
        features.file_types_accessed = list(extensions)[:20]

        # Login statistics
        features.login_count = login_success + login_failure
        features.login_failure_count = login_failure
        if features.login_count > 0:
            features.login_success_rate = login_success / features.login_count

        features.admin_action_count = admin_actions

        return features

    def extract_network_features(
        self,
        events: list[dict[str, Any]],
    ) -> NetworkFeatures:
        """Extract network behavior features.

        Args:
            events: List of network-related events

        Returns:
            Network features
        """
        features = NetworkFeatures()

        if not events:
            return features

        destinations = set()
        ports = set()
        protocols = defaultdict(int)
        domains = set()

        total_bytes_sent = 0
        total_bytes_received = 0
        large_transfers = 0
        connection_count = 0
        failed_connections = 0

        for event in events:
            # Destinations
            if dest := event.get("destination_ip") or event.get("dest_ip"):
                destinations.add(dest)

            # Ports
            if port := event.get("destination_port") or event.get("dest_port"):
                ports.add(int(port))

            # Protocols
            if proto := event.get("protocol"):
                protocols[proto.upper()] += 1

            # Domains
            if domain := event.get("domain") or event.get("dns_query"):
                domains.add(domain)

            # Data transfer
            bytes_out = int(event.get("bytes_sent", 0) or event.get("bytes_out", 0))
            bytes_in = int(event.get("bytes_received", 0) or event.get("bytes_in", 0))
            total_bytes_sent += bytes_out
            total_bytes_received += bytes_in

            if bytes_out > 10 * 1024 * 1024:  # > 10 MB
                large_transfers += 1

            # Connection tracking
            if event.get("event_type") in ["connection", "network", "flow"]:
                connection_count += 1
                if event.get("status") == "failed":
                    failed_connections += 1

        features.unique_destinations = len(destinations)
        features.unique_ports = len(ports)
        features.unique_domains = len(domains)
        features.destination_entropy = self._calculate_entropy(list(destinations))

        # Unusual ports
        features.unusual_ports = list(ports & self.UNUSUAL_PORTS)

        # Protocol distribution
        total_proto = sum(protocols.values()) or 1
        features.protocol_distribution = {
            k: v / total_proto for k, v in protocols.items()
        }

        # Data transfer
        features.bytes_sent = total_bytes_sent
        features.bytes_received = total_bytes_received
        if total_bytes_received > 0:
            features.bytes_ratio = total_bytes_sent / total_bytes_received
        features.large_transfer_count = large_transfers

        # Connection stats
        features.connection_count = connection_count
        features.failed_connection_count = failed_connections

        # DNS stats
        features.dns_queries = len([
            e for e in events
            if e.get("event_type") == "dns" or "dns" in str(e.get("event_type", "")).lower()
        ])

        return features

    def to_sequence_tensor(
        self,
        events: list[dict[str, Any]],
        pad: bool = True,
    ) -> np.ndarray:
        """Convert events to sequence tensor for model input.

        Args:
            events: List of events
            pad: Whether to pad/truncate to sequence_length

        Returns:
            Numpy array of shape (sequence_length, feature_dim)
        """
        # Group events by hour
        hourly_events: dict[int, list[dict]] = defaultdict(list)

        for event in events:
            ts = self._parse_timestamp(event.get("timestamp"))
            if ts:
                hour_idx = ts.hour
                hourly_events[hour_idx].append(event)

        # Extract features for each hour
        sequence = []
        for hour in range(24):
            hour_events = hourly_events.get(hour, [])
            features = self._extract_hourly_features(hour_events)
            sequence.append(features)

        sequence = np.array(sequence, dtype=np.float32)

        # Pad or truncate
        if pad:
            if len(sequence) < self.sequence_length:
                padding = np.zeros(
                    (self.sequence_length - len(sequence), self.feature_dim),
                    dtype=np.float32,
                )
                sequence = np.concatenate([sequence, padding], axis=0)
            elif len(sequence) > self.sequence_length:
                sequence = sequence[:self.sequence_length]

        return sequence

    def _extract_hourly_features(
        self,
        events: list[dict[str, Any]],
    ) -> np.ndarray:
        """Extract features for a single hour."""
        features = np.zeros(self.feature_dim, dtype=np.float32)

        if not events:
            return features

        # Event count (normalized)
        features[0] = min(len(events) / 100, 1.0)

        # Unique IPs
        src_ips = set(e.get("source_ip") for e in events if e.get("source_ip"))
        dst_ips = set(e.get("destination_ip") for e in events if e.get("destination_ip"))
        features[1] = min(len(src_ips) / 10, 1.0)
        features[2] = min(len(dst_ips) / 10, 1.0)

        # Unique ports
        ports = set()
        for e in events:
            if port := e.get("destination_port"):
                ports.add(int(port))
        features[3] = min(len(ports) / 20, 1.0)

        # Login events
        logins = [e for e in events if "login" in str(e.get("event_type", "")).lower()]
        features[4] = min(len(logins) / 10, 1.0)

        # Failed logins
        failed = sum(1 for e in logins if e.get("status") != "success")
        features[5] = min(failed / 5, 1.0)

        # Bytes transferred
        bytes_out = sum(int(e.get("bytes_sent", 0) or 0) for e in events)
        bytes_in = sum(int(e.get("bytes_received", 0) or 0) for e in events)
        features[6] = min(bytes_out / (100 * 1024 * 1024), 1.0)  # Normalized to 100MB
        features[7] = min(bytes_in / (100 * 1024 * 1024), 1.0)

        # Severity distribution
        severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        severities = [
            severity_map.get(str(e.get("severity", "low")).lower(), 0.0)
            for e in events
        ]
        features[8] = np.mean(severities) if severities else 0.0
        features[9] = np.max(severities) if severities else 0.0

        # Fill remaining features with event type distribution
        event_types = defaultdict(int)
        for e in events:
            et = str(e.get("event_type", "other")).lower()[:20]
            event_types[et] += 1

        total = sum(event_types.values()) or 1
        for i, (et, count) in enumerate(sorted(event_types.items())[:self.feature_dim - 10]):
            features[10 + i] = count / total

        return features

    def _parse_timestamp(self, timestamp: Any) -> datetime | None:
        """Parse timestamp from various formats."""
        if timestamp is None:
            return None

        if isinstance(timestamp, datetime):
            return timestamp

        if isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            except ValueError:
                pass

            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp[:19], fmt)
                except ValueError:
                    continue

        if isinstance(timestamp, (int, float)):
            try:
                return datetime.fromtimestamp(timestamp)
            except (ValueError, OSError):
                pass

        return None

    def _calculate_entropy(self, items: list[Any]) -> float:
        """Calculate Shannon entropy of item distribution."""
        if not items:
            return 0.0

        counts = defaultdict(int)
        for item in items:
            counts[item] += 1

        total = len(items)
        probs = [count / total for count in counts.values()]

        entropy = -sum(p * np.log2(p) for p in probs if p > 0)

        # Normalize by max entropy
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1.0
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def combine_features(
        self,
        temporal: TemporalFeatures,
        access: AccessFeatures,
        network: NetworkFeatures,
    ) -> np.ndarray:
        """Combine all features into a single vector.

        Args:
            temporal: Temporal features
            access: Access features
            network: Network features

        Returns:
            Combined feature vector
        """
        features = []

        # Temporal features
        features.extend(temporal.hour_distribution)  # 24
        features.extend(temporal.day_distribution)  # 7
        features.append(temporal.inter_event_time_mean / 3600)  # Normalize to hours
        features.append(temporal.inter_event_time_std / 3600)
        features.append(min(temporal.activity_burst_count / 100, 1.0))
        features.append(temporal.off_hours_activity_ratio)
        features.append(temporal.weekend_activity_ratio)

        # Access features
        features.append(min(access.unique_systems / 100, 1.0))
        features.append(min(access.new_systems / 10, 1.0))
        features.append(access.system_access_entropy)
        features.append(min(access.unique_applications / 50, 1.0))
        features.append(min(access.file_access_count / 1000, 1.0))
        features.append(min(access.sensitive_file_access_count / 10, 1.0))
        features.append(min(access.login_count / 100, 1.0))
        features.append(min(access.login_failure_count / 10, 1.0))
        features.append(access.login_success_rate)
        features.append(min(access.admin_action_count / 10, 1.0))

        # Network features
        features.append(min(network.unique_destinations / 100, 1.0))
        features.append(network.destination_entropy)
        features.append(min(network.unique_ports / 50, 1.0))
        features.append(min(len(network.unusual_ports) / 5, 1.0))
        features.append(min(network.bytes_sent / (1024 * 1024 * 1024), 1.0))  # GB
        features.append(min(network.bytes_received / (1024 * 1024 * 1024), 1.0))
        features.append(min(network.large_transfer_count / 10, 1.0))
        features.append(min(network.connection_count / 1000, 1.0))
        features.append(min(network.failed_connection_count / 100, 1.0))

        # Pad to feature_dim
        if len(features) < self.feature_dim:
            features.extend([0.0] * (self.feature_dim - len(features)))
        elif len(features) > self.feature_dim:
            features = features[:self.feature_dim]

        return np.array(features, dtype=np.float32)
