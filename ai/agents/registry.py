"""Agent Registry - Central registry for managing AI agents."""

from __future__ import annotations

import asyncio
from typing import Type

from common.logging import LoggerMixin

from .base import (
    AgentCapability,
    AgentConfig,
    AgentStatus,
    BaseAgent,
)


class AgentRegistry(LoggerMixin):
    """Central registry for managing AI agents.

    Features:
    - Agent registration and discovery
    - Capability-based lookup
    - Lifecycle management
    - Agent health monitoring
    """

    _instance: AgentRegistry | None = None

    def __init__(self) -> None:
        """Initialize the registry."""
        self._agents: dict[str, BaseAgent] = {}
        self._agent_types: dict[str, Type[BaseAgent]] = {}
        self._capability_index: dict[AgentCapability, set[str]] = {}
        self._initialized = False

    @classmethod
    def get_instance(cls) -> AgentRegistry:
        """Get singleton instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register_agent_type(
        self,
        agent_type: str,
        agent_class: Type[BaseAgent],
    ) -> None:
        """Register an agent type for factory creation.

        Args:
            agent_type: Type identifier
            agent_class: Agent class
        """
        self._agent_types[agent_type] = agent_class
        self.logger.info(
            "agent_type_registered",
            agent_type=agent_type,
            agent_class=agent_class.__name__,
        )

    def create_agent(
        self,
        agent_type: str,
        config: AgentConfig,
    ) -> BaseAgent:
        """Create an agent from registered type.

        Args:
            agent_type: Type of agent to create
            config: Agent configuration

        Returns:
            Created agent instance
        """
        if agent_type not in self._agent_types:
            raise ValueError(f"Unknown agent type: {agent_type}")

        agent_class = self._agent_types[agent_type]
        agent = agent_class(config)

        self.register_agent(agent)
        return agent

    def register_agent(self, agent: BaseAgent) -> None:
        """Register an agent instance.

        Args:
            agent: Agent to register
        """
        self._agents[agent.agent_id] = agent

        # Update capability index
        for capability in agent.capabilities:
            if capability not in self._capability_index:
                self._capability_index[capability] = set()
            self._capability_index[capability].add(agent.agent_id)

        self.logger.info(
            "agent_registered",
            agent_id=agent.agent_id,
            name=agent.name,
            capabilities=[c.value for c in agent.capabilities],
        )

    def unregister_agent(self, agent_id: str) -> bool:
        """Unregister an agent.

        Args:
            agent_id: Agent ID to unregister

        Returns:
            True if agent was unregistered
        """
        if agent_id not in self._agents:
            return False

        agent = self._agents.pop(agent_id)

        # Update capability index
        for capability in agent.capabilities:
            if capability in self._capability_index:
                self._capability_index[capability].discard(agent_id)

        self.logger.info("agent_unregistered", agent_id=agent_id)
        return True

    def get_agent(self, agent_id: str) -> BaseAgent | None:
        """Get agent by ID.

        Args:
            agent_id: Agent ID

        Returns:
            Agent instance or None
        """
        return self._agents.get(agent_id)

    def get_agents_by_capability(
        self,
        capability: AgentCapability,
        only_available: bool = True,
    ) -> list[BaseAgent]:
        """Get agents with specific capability.

        Args:
            capability: Required capability
            only_available: Only return available agents

        Returns:
            List of matching agents
        """
        agent_ids = self._capability_index.get(capability, set())
        agents = []

        for agent_id in agent_ids:
            agent = self._agents.get(agent_id)
            if agent:
                if only_available:
                    if agent.status in [AgentStatus.IDLE, AgentStatus.PAUSED]:
                        agents.append(agent)
                else:
                    agents.append(agent)

        return agents

    def get_all_agents(self) -> list[BaseAgent]:
        """Get all registered agents."""
        return list(self._agents.values())

    def get_agent_status(self, agent_id: str) -> AgentStatus | None:
        """Get agent status.

        Args:
            agent_id: Agent ID

        Returns:
            Agent status or None if not found
        """
        agent = self._agents.get(agent_id)
        return agent.status if agent else None

    async def initialize_all(self) -> None:
        """Initialize all registered agents."""
        if self._initialized:
            return

        self.logger.info("initializing_agents", count=len(self._agents))

        tasks = [agent.initialize() for agent in self._agents.values()]
        await asyncio.gather(*tasks, return_exceptions=True)

        self._initialized = True
        self.logger.info("agents_initialized")

    async def cleanup_all(self) -> None:
        """Cleanup all registered agents."""
        self.logger.info("cleaning_up_agents", count=len(self._agents))

        tasks = [agent.cleanup() for agent in self._agents.values()]
        await asyncio.gather(*tasks, return_exceptions=True)

        self._initialized = False
        self.logger.info("agents_cleanup_complete")

    def get_registry_stats(self) -> dict:
        """Get registry statistics."""
        status_counts = {}
        for agent in self._agents.values():
            status = agent.status.value
            status_counts[status] = status_counts.get(status, 0) + 1

        capability_counts = {
            cap.value: len(agent_ids)
            for cap, agent_ids in self._capability_index.items()
        }

        return {
            "total_agents": len(self._agents),
            "total_types": len(self._agent_types),
            "status_distribution": status_counts,
            "capability_distribution": capability_counts,
            "initialized": self._initialized,
        }


def get_registry() -> AgentRegistry:
    """Get the global agent registry instance."""
    return AgentRegistry.get_instance()
