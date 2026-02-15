"""Agent Supervisor - Monitor and supervise agent operations."""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel

from ..base import AgentStatus, BaseAgent
from ..registry import AgentRegistry


class HealthStatus(str, Enum):
    """Health status of agents."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class AgentHealth(BaseModel):
    """Health information for an agent."""

    agent_id: str
    agent_name: str
    status: AgentStatus
    health: HealthStatus
    last_active: datetime | None = None
    error_count: int = 0
    success_rate: float = 1.0
    avg_response_time_ms: float = 0.0


class SupervisionReport(BaseModel):
    """Report from supervision check."""

    report_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Agent stats
    total_agents: int = Field(default=0)
    healthy_agents: int = Field(default=0)
    degraded_agents: int = Field(default=0)
    unhealthy_agents: int = Field(default=0)

    # Agent details
    agent_health: list[AgentHealth] = Field(default_factory=list)

    # Issues
    issues: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)

    # Overall health
    overall_health: HealthStatus = Field(default=HealthStatus.UNKNOWN)


class AgentSupervisor(LoggerMixin):
    """Supervisor for monitoring agent health and performance.

    Features:
    - Health monitoring
    - Performance tracking
    - Automatic recovery
    - Alerting on issues
    """

    def __init__(
        self,
        registry: AgentRegistry | None = None,
        health_check_interval_seconds: int = 60,
        error_threshold: int = 5,
        success_rate_threshold: float = 0.8,
    ) -> None:
        """Initialize supervisor.

        Args:
            registry: Agent registry
            health_check_interval_seconds: Health check interval
            error_threshold: Errors before degraded
            success_rate_threshold: Min success rate for healthy
        """
        self.registry = registry or AgentRegistry.get_instance()
        self.health_check_interval = health_check_interval_seconds
        self.error_threshold = error_threshold
        self.success_rate_threshold = success_rate_threshold

        self._agent_stats: dict[str, dict[str, Any]] = {}
        self._last_check: datetime | None = None

    def record_execution(
        self,
        agent_id: str,
        success: bool,
        duration_ms: float,
        error: str | None = None,
    ) -> None:
        """Record an agent execution.

        Args:
            agent_id: Agent ID
            success: Whether execution succeeded
            duration_ms: Duration in milliseconds
            error: Error message if failed
        """
        if agent_id not in self._agent_stats:
            self._agent_stats[agent_id] = {
                "executions": 0,
                "successes": 0,
                "errors": 0,
                "total_duration_ms": 0,
                "recent_errors": [],
                "last_active": None,
            }

        stats = self._agent_stats[agent_id]
        stats["executions"] += 1
        stats["total_duration_ms"] += duration_ms
        stats["last_active"] = datetime.utcnow()

        if success:
            stats["successes"] += 1
        else:
            stats["errors"] += 1
            stats["recent_errors"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "error": error,
            })
            # Keep only recent errors
            stats["recent_errors"] = stats["recent_errors"][-10:]

    def check_health(self) -> SupervisionReport:
        """Perform health check on all agents.

        Returns:
            Supervision report
        """
        report = SupervisionReport()
        agents = self.registry.get_all_agents()
        report.total_agents = len(agents)

        for agent in agents:
            health = self._assess_agent_health(agent)
            report.agent_health.append(health)

            if health.health == HealthStatus.HEALTHY:
                report.healthy_agents += 1
            elif health.health == HealthStatus.DEGRADED:
                report.degraded_agents += 1
                report.issues.append(f"Agent {agent.name} is degraded")
            elif health.health == HealthStatus.UNHEALTHY:
                report.unhealthy_agents += 1
                report.issues.append(f"Agent {agent.name} is unhealthy")

        # Determine overall health
        if report.unhealthy_agents > 0:
            report.overall_health = HealthStatus.UNHEALTHY
        elif report.degraded_agents > 0:
            report.overall_health = HealthStatus.DEGRADED
        elif report.healthy_agents == report.total_agents:
            report.overall_health = HealthStatus.HEALTHY
        else:
            report.overall_health = HealthStatus.UNKNOWN

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report)

        self._last_check = datetime.utcnow()

        self.logger.info(
            "health_check_complete",
            overall=report.overall_health.value,
            healthy=report.healthy_agents,
            degraded=report.degraded_agents,
            unhealthy=report.unhealthy_agents,
        )

        return report

    def _assess_agent_health(self, agent: BaseAgent) -> AgentHealth:
        """Assess health of a single agent."""
        stats = self._agent_stats.get(agent.agent_id, {})

        executions = stats.get("executions", 0)
        successes = stats.get("successes", 0)
        errors = stats.get("errors", 0)
        total_duration = stats.get("total_duration_ms", 0)

        success_rate = successes / executions if executions > 0 else 1.0
        avg_response = total_duration / executions if executions > 0 else 0.0

        # Determine health
        health = HealthStatus.UNKNOWN

        if agent.status == AgentStatus.FAILED:
            health = HealthStatus.UNHEALTHY
        elif errors >= self.error_threshold:
            health = HealthStatus.UNHEALTHY
        elif success_rate < self.success_rate_threshold:
            health = HealthStatus.DEGRADED
        elif agent.status in [AgentStatus.IDLE, AgentStatus.RUNNING]:
            health = HealthStatus.HEALTHY
        else:
            health = HealthStatus.DEGRADED

        return AgentHealth(
            agent_id=agent.agent_id,
            agent_name=agent.name,
            status=agent.status,
            health=health,
            last_active=stats.get("last_active"),
            error_count=errors,
            success_rate=success_rate,
            avg_response_time_ms=avg_response,
        )

    def _generate_recommendations(
        self,
        report: SupervisionReport,
    ) -> list[str]:
        """Generate recommendations based on report."""
        recommendations = []

        for health in report.agent_health:
            if health.health == HealthStatus.UNHEALTHY:
                recommendations.append(
                    f"Consider restarting agent {health.agent_name}"
                )

            if health.success_rate < 0.5:
                recommendations.append(
                    f"Review errors for agent {health.agent_name}"
                )

            if health.avg_response_time_ms > 30000:  # 30 seconds
                recommendations.append(
                    f"Agent {health.agent_name} has high latency - check resources"
                )

        if report.unhealthy_agents > report.total_agents / 2:
            recommendations.append(
                "Multiple agents unhealthy - consider system-wide investigation"
            )

        return recommendations

    async def recover_agent(self, agent_id: str) -> bool:
        """Attempt to recover an unhealthy agent.

        Args:
            agent_id: Agent to recover

        Returns:
            True if recovery succeeded
        """
        agent = self.registry.get_agent(agent_id)
        if not agent:
            return False

        self.logger.info("attempting_recovery", agent_id=agent_id)

        try:
            # Cleanup and reinitialize
            await agent.cleanup()
            await agent.initialize()

            # Reset stats
            if agent_id in self._agent_stats:
                self._agent_stats[agent_id]["errors"] = 0
                self._agent_stats[agent_id]["recent_errors"] = []

            self.logger.info("recovery_succeeded", agent_id=agent_id)
            return True

        except Exception as e:
            self.logger.error(
                "recovery_failed",
                agent_id=agent_id,
                error=str(e),
            )
            return False

    def get_agent_stats(self, agent_id: str) -> dict[str, Any]:
        """Get stats for an agent."""
        return self._agent_stats.get(agent_id, {})

    def clear_stats(self, agent_id: str | None = None) -> None:
        """Clear agent stats.

        Args:
            agent_id: Agent ID or None for all
        """
        if agent_id:
            self._agent_stats.pop(agent_id, None)
        else:
            self._agent_stats.clear()
