"""Behavior profiling for UEBA - builds and manages user/entity baselines."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import numpy as np
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class ProfileType(str, Enum):
    """Types of behavior profiles."""

    USER = "user"
    HOST = "host"
    SERVICE_ACCOUNT = "service_account"
    APPLICATION = "application"
    NETWORK_SEGMENT = "network_segment"


class ProfileStatus(str, Enum):
    """Profile status."""

    LEARNING = "learning"  # Building baseline
    ACTIVE = "active"  # Ready for detection
    STALE = "stale"  # Needs update
    DISABLED = "disabled"  # Not in use


class ProfileFeatures(BaseModel):
    """Statistical features for a behavior profile."""

    # Activity patterns
    activity_hours: list[float] = Field(default_factory=lambda: [0.0] * 24)
    activity_days: list[float] = Field(default_factory=lambda: [0.0] * 7)

    # Access patterns
    unique_systems_accessed: int = Field(default=0)
    unique_applications_used: int = Field(default=0)
    average_session_duration: float = Field(default=0.0)
    average_events_per_day: float = Field(default=0.0)

    # Authentication patterns
    login_success_rate: float = Field(default=1.0)
    average_logins_per_day: float = Field(default=0.0)
    unique_login_locations: int = Field(default=0)

    # Network patterns
    average_data_volume: float = Field(default=0.0)
    unique_destinations: int = Field(default=0)
    common_ports: list[int] = Field(default_factory=list)

    # Resource usage
    average_cpu_usage: float = Field(default=0.0)
    average_memory_usage: float = Field(default=0.0)
    average_disk_io: float = Field(default=0.0)

    # Statistical moments
    feature_means: dict[str, float] = Field(default_factory=dict)
    feature_stds: dict[str, float] = Field(default_factory=dict)
    feature_mins: dict[str, float] = Field(default_factory=dict)
    feature_maxs: dict[str, float] = Field(default_factory=dict)


class BehaviorProfile(BaseModel):
    """Complete behavior profile for a user or entity."""

    profile_id: str = Field(description="Unique profile identifier")
    entity_id: str = Field(description="Entity this profile belongs to")
    entity_type: ProfileType = Field(description="Type of entity")
    entity_name: str = Field(default="", description="Human-readable name")

    # Status and lifecycle
    status: ProfileStatus = Field(default=ProfileStatus.LEARNING)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity_at: datetime | None = Field(default=None)

    # Learning progress
    samples_collected: int = Field(default=0)
    min_samples_required: int = Field(default=168)  # 1 week hourly

    # Profile data
    features: ProfileFeatures = Field(default_factory=ProfileFeatures)

    # Risk assessment
    baseline_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_factors: list[str] = Field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        """Check if profile has enough data for detection."""
        return (
            self.status == ProfileStatus.ACTIVE and
            self.samples_collected >= self.min_samples_required
        )

    @property
    def learning_progress(self) -> float:
        """Get learning progress as percentage."""
        return min(1.0, self.samples_collected / self.min_samples_required)


class ProfileManager(LoggerMixin):
    """Manages behavior profiles for users and entities.

    Responsibilities:
    - Create and update profiles
    - Build statistical baselines
    - Track profile lifecycle
    - Provide profile data for anomaly detection
    """

    def __init__(
        self,
        min_samples: int = 168,
        stale_threshold_hours: int = 72,
    ):
        """Initialize profile manager.

        Args:
            min_samples: Minimum samples for profile activation
            stale_threshold_hours: Hours after which inactive profile becomes stale
        """
        self.min_samples = min_samples
        self.stale_threshold = timedelta(hours=stale_threshold_hours)
        self._profiles: dict[str, BehaviorProfile] = {}

    def _generate_profile_id(self, entity_id: str, entity_type: ProfileType) -> str:
        """Generate unique profile ID."""
        data = f"{entity_id}:{entity_type.value}"
        return hashlib.md5(data.encode()).hexdigest()[:16]

    def get_or_create_profile(
        self,
        entity_id: str,
        entity_type: ProfileType,
        entity_name: str = "",
    ) -> BehaviorProfile:
        """Get existing profile or create new one.

        Args:
            entity_id: Entity identifier
            entity_type: Type of entity
            entity_name: Human-readable name

        Returns:
            Behavior profile
        """
        profile_id = self._generate_profile_id(entity_id, entity_type)

        if profile_id in self._profiles:
            return self._profiles[profile_id]

        # Create new profile
        profile = BehaviorProfile(
            profile_id=profile_id,
            entity_id=entity_id,
            entity_type=entity_type,
            entity_name=entity_name,
            min_samples_required=self.min_samples,
        )

        self._profiles[profile_id] = profile
        self.logger.info(
            "profile_created",
            profile_id=profile_id,
            entity_id=entity_id,
            entity_type=entity_type.value,
        )

        return profile

    def update_profile(
        self,
        profile_id: str,
        events: list[dict[str, Any]],
    ) -> BehaviorProfile:
        """Update profile with new events.

        Args:
            profile_id: Profile to update
            events: List of events to incorporate

        Returns:
            Updated profile
        """
        if profile_id not in self._profiles:
            raise ValueError(f"Profile not found: {profile_id}")

        profile = self._profiles[profile_id]
        profile.updated_at = datetime.utcnow()

        if events:
            profile.last_activity_at = datetime.utcnow()

            # Extract and update features
            features = self._extract_features_from_events(events)
            self._update_profile_features(profile, features)

            profile.samples_collected += len(events)

            # Transition to active if ready
            if (
                profile.status == ProfileStatus.LEARNING and
                profile.samples_collected >= profile.min_samples_required
            ):
                profile.status = ProfileStatus.ACTIVE
                self.logger.info("profile_activated", profile_id=profile_id)

        return profile

    def _extract_features_from_events(
        self,
        events: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Extract features from events for profile update."""
        features = {
            "activity_hours": [0] * 24,
            "activity_days": [0] * 7,
            "event_count": len(events),
            "unique_systems": set(),
            "unique_apps": set(),
            "login_success": 0,
            "login_total": 0,
            "data_volume": 0.0,
            "unique_destinations": set(),
            "ports_used": set(),
        }

        for event in events:
            # Parse timestamp
            timestamp = event.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except:
                    timestamp = datetime.utcnow()
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.utcnow()

            # Activity patterns
            features["activity_hours"][timestamp.hour] += 1
            features["activity_days"][timestamp.weekday()] += 1

            # Systems and applications
            if system := event.get("system") or event.get("hostname"):
                features["unique_systems"].add(system)
            if app := event.get("application") or event.get("process"):
                features["unique_apps"].add(app)

            # Authentication
            if event.get("event_type") in ["login", "authentication"]:
                features["login_total"] += 1
                if event.get("status") == "success":
                    features["login_success"] += 1

            # Network
            if bytes_sent := event.get("bytes_sent") or event.get("bytes_out"):
                features["data_volume"] += float(bytes_sent)
            if dest := event.get("destination_ip") or event.get("dest_ip"):
                features["unique_destinations"].add(dest)
            if port := event.get("destination_port") or event.get("dest_port"):
                features["ports_used"].add(int(port))

        # Convert sets to counts/lists
        features["unique_systems"] = len(features["unique_systems"])
        features["unique_apps"] = len(features["unique_apps"])
        features["unique_destinations"] = len(features["unique_destinations"])
        features["ports_used"] = list(features["ports_used"])[:10]  # Keep top 10

        return features

    def _update_profile_features(
        self,
        profile: BehaviorProfile,
        new_features: dict[str, Any],
    ) -> None:
        """Update profile features with new data using exponential moving average."""
        alpha = 0.1  # Smoothing factor

        pf = profile.features

        # Update activity patterns (normalize to distribution)
        total_hours = sum(new_features["activity_hours"]) or 1
        for i, count in enumerate(new_features["activity_hours"]):
            pf.activity_hours[i] = (
                (1 - alpha) * pf.activity_hours[i] +
                alpha * (count / total_hours)
            )

        total_days = sum(new_features["activity_days"]) or 1
        for i, count in enumerate(new_features["activity_days"]):
            pf.activity_days[i] = (
                (1 - alpha) * pf.activity_days[i] +
                alpha * (count / total_days)
            )

        # Update counts with EMA
        pf.unique_systems_accessed = int(
            (1 - alpha) * pf.unique_systems_accessed +
            alpha * new_features["unique_systems"]
        )
        pf.unique_applications_used = int(
            (1 - alpha) * pf.unique_applications_used +
            alpha * new_features["unique_apps"]
        )

        # Update login success rate
        if new_features["login_total"] > 0:
            new_rate = new_features["login_success"] / new_features["login_total"]
            pf.login_success_rate = (1 - alpha) * pf.login_success_rate + alpha * new_rate

        # Update network patterns
        pf.average_data_volume = (
            (1 - alpha) * pf.average_data_volume +
            alpha * new_features["data_volume"]
        )
        pf.unique_destinations = int(
            (1 - alpha) * pf.unique_destinations +
            alpha * new_features["unique_destinations"]
        )

        # Update common ports
        for port in new_features["ports_used"]:
            if port not in pf.common_ports:
                pf.common_ports.append(port)
        pf.common_ports = pf.common_ports[:20]  # Keep top 20

    def get_profile(self, profile_id: str) -> BehaviorProfile | None:
        """Get profile by ID."""
        return self._profiles.get(profile_id)

    def get_profile_by_entity(
        self,
        entity_id: str,
        entity_type: ProfileType,
    ) -> BehaviorProfile | None:
        """Get profile by entity ID and type."""
        profile_id = self._generate_profile_id(entity_id, entity_type)
        return self._profiles.get(profile_id)

    def get_all_profiles(
        self,
        status: ProfileStatus | None = None,
        entity_type: ProfileType | None = None,
    ) -> list[BehaviorProfile]:
        """Get all profiles with optional filtering."""
        profiles = list(self._profiles.values())

        if status is not None:
            profiles = [p for p in profiles if p.status == status]

        if entity_type is not None:
            profiles = [p for p in profiles if p.entity_type == entity_type]

        return profiles

    def check_stale_profiles(self) -> list[str]:
        """Check for stale profiles and update their status."""
        stale_ids = []
        now = datetime.utcnow()

        for profile_id, profile in self._profiles.items():
            if profile.status == ProfileStatus.ACTIVE:
                if profile.last_activity_at:
                    inactive_time = now - profile.last_activity_at
                    if inactive_time > self.stale_threshold:
                        profile.status = ProfileStatus.STALE
                        stale_ids.append(profile_id)

        if stale_ids:
            self.logger.info("stale_profiles_found", count=len(stale_ids))

        return stale_ids

    def get_profile_vector(
        self,
        profile_id: str,
    ) -> np.ndarray | None:
        """Get profile features as a numpy vector for model input.

        Args:
            profile_id: Profile to vectorize

        Returns:
            Feature vector or None if profile not found
        """
        profile = self.get_profile(profile_id)
        if not profile:
            return None

        pf = profile.features

        # Build feature vector
        features = []

        # Activity patterns (24 + 7 = 31 features)
        features.extend(pf.activity_hours)
        features.extend(pf.activity_days)

        # Counts (4 features)
        features.append(float(pf.unique_systems_accessed))
        features.append(float(pf.unique_applications_used))
        features.append(float(pf.unique_destinations))
        features.append(float(len(pf.common_ports)))

        # Rates and averages (6 features)
        features.append(pf.average_session_duration)
        features.append(pf.average_events_per_day)
        features.append(pf.login_success_rate)
        features.append(pf.average_logins_per_day)
        features.append(pf.average_data_volume)
        features.append(float(pf.unique_login_locations))

        return np.array(features, dtype=np.float32)

    def export_profiles(self) -> list[dict[str, Any]]:
        """Export all profiles as dictionaries."""
        return [p.model_dump() for p in self._profiles.values()]

    def import_profiles(self, profiles: list[dict[str, Any]]) -> int:
        """Import profiles from dictionaries.

        Returns:
            Number of profiles imported
        """
        count = 0
        for data in profiles:
            try:
                profile = BehaviorProfile(**data)
                self._profiles[profile.profile_id] = profile
                count += 1
            except Exception as e:
                self.logger.warning("profile_import_failed", error=str(e))

        return count
