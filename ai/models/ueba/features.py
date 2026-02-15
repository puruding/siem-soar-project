"""UEBA Features - Additional feature extraction utilities.

This module provides supplementary feature extraction utilities that work
alongside the main feature_extractor module.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from pydantic import Field

from common.models import BaseModel


class SessionFeatures(BaseModel):
    """Features extracted from user sessions."""

    session_id: str = Field(default="")
    entity_id: str = Field(default="")

    # Session timing
    start_time: datetime | None = Field(default=None)
    end_time: datetime | None = Field(default=None)
    duration_seconds: float = Field(default=0.0)

    # Activity counts
    event_count: int = Field(default=0)
    unique_actions: int = Field(default=0)
    unique_resources: int = Field(default=0)

    # Access patterns
    systems_accessed: list[str] = Field(default_factory=list)
    applications_used: list[str] = Field(default_factory=list)
    files_accessed: int = Field(default=0)
    network_connections: int = Field(default=0)

    # Authentication
    login_attempts: int = Field(default=0)
    failed_logins: int = Field(default=0)

    # Risk indicators
    off_hours_activity: bool = Field(default=False)
    unusual_location: bool = Field(default=False)
    privilege_escalation: bool = Field(default=False)


class TimeSeriesFeatures(BaseModel):
    """Time-series features for sequential analysis."""

    # Activity over time bins
    hourly_activity: list[float] = Field(default_factory=lambda: [0.0] * 24)
    daily_activity: list[float] = Field(default_factory=lambda: [0.0] * 7)

    # Trends
    activity_trend: float = Field(default=0.0, description="Positive=increasing, Negative=decreasing")
    volatility: float = Field(default=0.0)

    # Periodicity
    periodicity_score: float = Field(default=0.0)
    dominant_period_hours: int = Field(default=0)


class ContextualRiskFeatures(BaseModel):
    """Contextual features for risk assessment."""

    # Entity context
    entity_type: str = Field(default="user")
    department: str = Field(default="")
    role: str = Field(default="")
    clearance_level: int = Field(default=0)

    # Historical risk
    past_incidents: int = Field(default=0)
    past_violations: int = Field(default=0)
    baseline_risk_score: float = Field(default=0.0)

    # Current state
    is_terminated: bool = Field(default=False)
    is_on_leave: bool = Field(default=False)
    notice_period: bool = Field(default=False)

    # Peer comparison
    deviation_from_peer_norm: float = Field(default=0.0)


def extract_session_features(
    events: list[dict[str, Any]],
    entity_id: str,
    session_threshold_minutes: int = 30,
) -> list[SessionFeatures]:
    """Extract session-based features from events.

    Groups events into sessions based on time gaps.

    Args:
        events: List of events
        entity_id: Entity identifier
        session_threshold_minutes: Max gap between events in same session

    Returns:
        List of session features
    """
    if not events:
        return []

    # Sort events by timestamp
    def get_timestamp(event: dict) -> datetime:
        ts = event.get("timestamp") or event.get("created_at")
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except:
                return datetime.min
        elif isinstance(ts, datetime):
            return ts
        return datetime.min

    sorted_events = sorted(events, key=get_timestamp)

    # Group into sessions
    sessions: list[list[dict]] = []
    current_session: list[dict] = []
    last_time: datetime | None = None

    threshold = timedelta(minutes=session_threshold_minutes)

    for event in sorted_events:
        event_time = get_timestamp(event)
        if event_time == datetime.min:
            continue

        if last_time is None or (event_time - last_time) > threshold:
            if current_session:
                sessions.append(current_session)
            current_session = [event]
        else:
            current_session.append(event)

        last_time = event_time

    if current_session:
        sessions.append(current_session)

    # Extract features for each session
    session_features = []
    for i, session in enumerate(sessions):
        features = _extract_single_session_features(
            session,
            entity_id,
            session_id=f"{entity_id}_{i}",
        )
        session_features.append(features)

    return session_features


def _extract_single_session_features(
    events: list[dict[str, Any]],
    entity_id: str,
    session_id: str,
) -> SessionFeatures:
    """Extract features from a single session."""
    features = SessionFeatures(
        session_id=session_id,
        entity_id=entity_id,
        event_count=len(events),
    )

    if not events:
        return features

    # Timing
    timestamps = []
    for event in events:
        ts = event.get("timestamp") or event.get("created_at")
        if isinstance(ts, str):
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except:
                pass
        elif isinstance(ts, datetime):
            timestamps.append(ts)

    if timestamps:
        features.start_time = min(timestamps)
        features.end_time = max(timestamps)
        features.duration_seconds = (features.end_time - features.start_time).total_seconds()

        # Off-hours check (before 6 AM or after 10 PM)
        for ts in timestamps:
            if ts.hour < 6 or ts.hour >= 22:
                features.off_hours_activity = True
                break

    # Unique actions and resources
    actions = set()
    resources = set()
    systems = set()
    applications = set()

    login_attempts = 0
    failed_logins = 0
    file_access = 0
    network_connections = 0
    privilege_events = 0

    for event in events:
        # Actions
        if action := event.get("action") or event.get("event_type"):
            actions.add(str(action).lower())

        # Resources
        if resource := event.get("resource") or event.get("object_path"):
            resources.add(str(resource))

        # Systems
        if system := event.get("hostname") or event.get("system"):
            systems.add(str(system))

        # Applications
        if app := event.get("application") or event.get("process_name"):
            applications.add(str(app))

        # Login tracking
        event_type = str(event.get("event_type", "")).lower()
        if "login" in event_type or "auth" in event_type:
            login_attempts += 1
            if event.get("status") != "success":
                failed_logins += 1

        # File access
        if event.get("file_path") or "file" in event_type:
            file_access += 1

        # Network
        if event.get("destination_ip") or "network" in event_type or "connection" in event_type:
            network_connections += 1

        # Privilege escalation
        if any(kw in event_type for kw in ["privilege", "sudo", "runas", "admin"]):
            privilege_events += 1

    features.unique_actions = len(actions)
    features.unique_resources = len(resources)
    features.systems_accessed = list(systems)
    features.applications_used = list(applications)
    features.login_attempts = login_attempts
    features.failed_logins = failed_logins
    features.files_accessed = file_access
    features.network_connections = network_connections
    features.privilege_escalation = privilege_events > 0

    return features


def extract_timeseries_features(
    events: list[dict[str, Any]],
    lookback_days: int = 7,
) -> TimeSeriesFeatures:
    """Extract time-series features from events.

    Args:
        events: List of events
        lookback_days: Number of days to analyze

    Returns:
        Time-series features
    """
    features = TimeSeriesFeatures()

    if not events:
        return features

    # Parse timestamps
    timestamps = []
    for event in events:
        ts = event.get("timestamp") or event.get("created_at")
        if isinstance(ts, str):
            try:
                timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
            except:
                pass
        elif isinstance(ts, datetime):
            timestamps.append(ts)

    if not timestamps:
        return features

    # Hourly distribution
    hour_counts = [0] * 24
    day_counts = [0] * 7

    for ts in timestamps:
        hour_counts[ts.hour] += 1
        day_counts[ts.weekday()] += 1

    total_hours = sum(hour_counts) or 1
    total_days = sum(day_counts) or 1

    features.hourly_activity = [c / total_hours for c in hour_counts]
    features.daily_activity = [c / total_days for c in day_counts]

    # Activity trend (compare first half vs second half)
    sorted_ts = sorted(timestamps)
    mid = len(sorted_ts) // 2
    if mid > 0:
        first_half = len(sorted_ts[:mid])
        second_half = len(sorted_ts[mid:])
        total = first_half + second_half
        features.activity_trend = (second_half - first_half) / total

    # Volatility (standard deviation of hourly counts)
    features.volatility = float(np.std(hour_counts))

    # Simple periodicity detection
    if len(hour_counts) > 0:
        # Find dominant period using autocorrelation
        from scipy.signal import correlate

        hour_array = np.array(hour_counts)
        if hour_array.std() > 0:
            autocorr = correlate(hour_array, hour_array, mode="full")
            autocorr = autocorr[len(autocorr) // 2:]

            # Find first significant peak after lag 0
            for i in range(1, min(len(autocorr), 24)):
                if autocorr[i] > autocorr[0] * 0.5:
                    features.dominant_period_hours = i
                    features.periodicity_score = float(autocorr[i] / autocorr[0])
                    break

    return features


def calculate_peer_deviation(
    entity_features: np.ndarray,
    peer_features: np.ndarray,
    method: str = "mahalanobis",
) -> float:
    """Calculate deviation of entity from peer group.

    Args:
        entity_features: Feature vector for target entity
        peer_features: Feature matrix for peer group (n_peers, n_features)
        method: Deviation method ('mahalanobis', 'zscore', 'percentile')

    Returns:
        Deviation score (higher = more anomalous)
    """
    if len(peer_features) == 0:
        return 0.0

    if method == "mahalanobis":
        # Mahalanobis distance
        mean = np.mean(peer_features, axis=0)
        cov = np.cov(peer_features.T)

        # Add small regularization
        cov += np.eye(len(mean)) * 1e-6

        try:
            cov_inv = np.linalg.inv(cov)
            diff = entity_features - mean
            distance = np.sqrt(diff @ cov_inv @ diff.T)
            return float(distance)
        except:
            # Fall back to Euclidean
            return float(np.linalg.norm(entity_features - mean))

    elif method == "zscore":
        # Average absolute z-score
        mean = np.mean(peer_features, axis=0)
        std = np.std(peer_features, axis=0)
        std = np.where(std == 0, 1, std)
        zscores = np.abs((entity_features - mean) / std)
        return float(np.mean(zscores))

    elif method == "percentile":
        # Average percentile rank
        percentiles = []
        for i, val in enumerate(entity_features):
            peer_vals = peer_features[:, i]
            percentile = np.sum(peer_vals < val) / len(peer_vals)
            percentiles.append(abs(percentile - 0.5) * 2)  # Distance from median
        return float(np.mean(percentiles))

    else:
        return 0.0


def features_to_vector(
    session_features: SessionFeatures | None = None,
    timeseries_features: TimeSeriesFeatures | None = None,
    contextual_features: ContextualRiskFeatures | None = None,
    target_dim: int = 64,
) -> np.ndarray:
    """Combine all feature types into a single vector.

    Args:
        session_features: Session-based features
        timeseries_features: Time-series features
        contextual_features: Contextual risk features
        target_dim: Target vector dimension

    Returns:
        Combined feature vector
    """
    features = []

    # Session features
    if session_features:
        features.extend([
            min(session_features.duration_seconds / 3600, 10) / 10,  # Hours, capped at 10
            min(session_features.event_count / 100, 1),
            min(session_features.unique_actions / 20, 1),
            min(session_features.unique_resources / 50, 1),
            min(len(session_features.systems_accessed) / 10, 1),
            min(len(session_features.applications_used) / 20, 1),
            min(session_features.login_attempts / 10, 1),
            session_features.failed_logins / max(session_features.login_attempts, 1),
            min(session_features.files_accessed / 100, 1),
            min(session_features.network_connections / 50, 1),
            1.0 if session_features.off_hours_activity else 0.0,
            1.0 if session_features.unusual_location else 0.0,
            1.0 if session_features.privilege_escalation else 0.0,
        ])

    # Time-series features
    if timeseries_features:
        features.extend(timeseries_features.hourly_activity)  # 24
        features.extend(timeseries_features.daily_activity)  # 7
        features.extend([
            (timeseries_features.activity_trend + 1) / 2,  # Normalize to 0-1
            min(timeseries_features.volatility / 10, 1),
            timeseries_features.periodicity_score,
            min(timeseries_features.dominant_period_hours / 24, 1),
        ])

    # Contextual features
    if contextual_features:
        features.extend([
            min(contextual_features.past_incidents / 5, 1),
            min(contextual_features.past_violations / 5, 1),
            contextual_features.baseline_risk_score,
            1.0 if contextual_features.is_terminated else 0.0,
            1.0 if contextual_features.is_on_leave else 0.0,
            1.0 if contextual_features.notice_period else 0.0,
            min(contextual_features.deviation_from_peer_norm / 3, 1),
        ])

    # Pad or truncate to target dimension
    if len(features) < target_dim:
        features.extend([0.0] * (target_dim - len(features)))
    elif len(features) > target_dim:
        features = features[:target_dim]

    return np.array(features, dtype=np.float32)
