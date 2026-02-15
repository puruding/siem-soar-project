"""Investigator Agent - Main agent for automated threat investigation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

import httpx
from pydantic import Field

from common.models import BaseModel

from ..base import (
    AgentCapability,
    AgentConfig,
    AgentContext,
    AgentResult,
    AgentStatus,
    BaseAgent,
    ToolDefinition,
)
from ..memory import AgentMemory, MemoryType, MemoryImportance
from ..state import AgentState, StateManager


class InvestigatorConfig(AgentConfig):
    """Configuration for Investigator Agent."""

    llm_endpoint: str = Field(
        default="http://localhost:8080/v1",
        description="LLM API endpoint",
    )
    model_name: str = Field(
        default="solar-10.7b",
        description="LLM model name",
    )
    max_context_items: int = Field(default=50)
    max_evidence_items: int = Field(default=100)
    timeline_window_hours: int = Field(default=24)
    siem_endpoint: str = Field(default="http://localhost:8000/api/v1")
    soar_endpoint: str = Field(default="http://localhost:8001/api/v1")


class InvestigationPlan(BaseModel):
    """Plan for investigation."""

    objectives: list[str] = Field(default_factory=list)
    hypotheses: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    queries: list[dict[str, Any]] = Field(default_factory=list)
    priority: str = Field(default="normal")


class InvestigatorAgent(BaseAgent):
    """Investigator Agent for automated threat investigation.

    Capabilities:
    - Automatic context collection from multiple sources
    - Evidence gathering and preservation
    - Timeline construction
    - Hypothesis generation and testing
    - Automated queries to SIEM/SOAR
    """

    SYSTEM_PROMPT = """You are an expert security investigator analyzing a security incident.

Your job is to:
1. Understand the incident context and severity
2. Generate hypotheses about the incident
3. Plan data collection to validate hypotheses
4. Analyze collected evidence
5. Build a timeline of events
6. Identify root cause and affected assets

Be thorough but efficient. Focus on actionable findings.
Always explain your reasoning."""

    def __init__(self, config: InvestigatorConfig) -> None:
        """Initialize the Investigator Agent."""
        config.name = config.name or "Investigator"
        config.capabilities = [
            AgentCapability.INVESTIGATE,
            AgentCapability.QUERY,
            AgentCapability.ANALYZE,
        ]

        super().__init__(config)
        self.config: InvestigatorConfig = config

        self._client: httpx.AsyncClient | None = None
        self._memory = AgentMemory(self.agent_id)
        self._state_manager = StateManager()

        self._setup_tools()

    def _setup_tools(self) -> None:
        """Setup investigation tools."""
        # Query SIEM tool
        self.register_tool(
            ToolDefinition(
                name="query_siem",
                description="Query SIEM for security events",
                parameters={
                    "query": {"type": "string", "description": "Search query"},
                    "time_range": {"type": "string", "description": "Time range (e.g., last_24h)"},
                    "limit": {"type": "integer", "description": "Max results"},
                },
                required_parameters=["query"],
                risk_level="low",
            ),
            self._query_siem,
        )

        # Get alert details tool
        self.register_tool(
            ToolDefinition(
                name="get_alert_details",
                description="Get detailed information about an alert",
                parameters={
                    "alert_id": {"type": "string", "description": "Alert ID"},
                },
                required_parameters=["alert_id"],
                risk_level="low",
            ),
            self._get_alert_details,
        )

        # Get related alerts tool
        self.register_tool(
            ToolDefinition(
                name="get_related_alerts",
                description="Find alerts related to an entity or indicator",
                parameters={
                    "entity": {"type": "string", "description": "Entity to search for"},
                    "entity_type": {"type": "string", "description": "Type (ip, user, host, hash)"},
                    "time_range": {"type": "string", "description": "Time range"},
                },
                required_parameters=["entity"],
                risk_level="low",
            ),
            self._get_related_alerts,
        )

        # Enrich IOC tool
        self.register_tool(
            ToolDefinition(
                name="enrich_ioc",
                description="Enrich an indicator of compromise with threat intel",
                parameters={
                    "ioc": {"type": "string", "description": "IOC value"},
                    "ioc_type": {"type": "string", "description": "Type (ip, domain, hash, url)"},
                },
                required_parameters=["ioc", "ioc_type"],
                risk_level="low",
            ),
            self._enrich_ioc,
        )

        # Get host info tool
        self.register_tool(
            ToolDefinition(
                name="get_host_info",
                description="Get information about a host",
                parameters={
                    "hostname": {"type": "string", "description": "Hostname or IP"},
                },
                required_parameters=["hostname"],
                risk_level="low",
            ),
            self._get_host_info,
        )

        # Get user info tool
        self.register_tool(
            ToolDefinition(
                name="get_user_info",
                description="Get information about a user",
                parameters={
                    "username": {"type": "string", "description": "Username"},
                },
                required_parameters=["username"],
                risk_level="low",
            ),
            self._get_user_info,
        )

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
        return self._client

    async def initialize(self) -> None:
        """Initialize the agent."""
        self._status = AgentStatus.IDLE
        self.logger.info("investigator_initialized", agent_id=self.agent_id)

    async def cleanup(self) -> None:
        """Cleanup resources."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def run(self, context: AgentContext) -> AgentResult:
        """Run investigation.

        Args:
            context: Investigation context with alert/incident details

        Returns:
            Investigation results
        """
        self._current_context = context
        self._status = AgentStatus.RUNNING
        self._clear_steps()

        # Create execution state
        exec_state = self._state_manager.create_state(
            execution_id=context.execution_id,
            agent_id=self.agent_id,
            input_data=context.data,
        )

        try:
            # Phase 1: Initial assessment
            self._state_manager.transition(
                context.execution_id,
                AgentState.INITIALIZING,
                trigger="start_investigation",
            )

            initial_assessment = await self._initial_assessment(context)
            self._memory.add(
                initial_assessment,
                MemoryType.WORKING,
                importance=MemoryImportance.HIGH,
                key="initial_assessment",
            )

            # Phase 2: Plan investigation
            self._state_manager.transition(
                context.execution_id,
                AgentState.PLANNING,
                trigger="assessment_complete",
            )

            plan = await self._plan_investigation(context, initial_assessment)

            # Phase 3: Collect context
            self._state_manager.transition(
                context.execution_id,
                AgentState.INVESTIGATING,
                trigger="plan_ready",
            )

            collected_context = await self._collect_context(context, plan)

            # Phase 4: Gather evidence
            evidence = await self._gather_evidence(context, collected_context)

            # Phase 5: Build timeline
            timeline = await self._build_timeline(evidence)

            # Phase 6: Analyze and conclude
            self._state_manager.transition(
                context.execution_id,
                AgentState.ANALYZING,
                trigger="data_collected",
            )

            analysis = await self._analyze_findings(
                context,
                initial_assessment,
                collected_context,
                evidence,
                timeline,
            )

            # Complete
            self._status = AgentStatus.COMPLETED
            self._state_manager.complete(context.execution_id, output=analysis)

            return self._create_result(
                success=True,
                output={
                    "assessment": initial_assessment,
                    "plan": plan.model_dump() if isinstance(plan, BaseModel) else plan,
                    "context": collected_context,
                    "evidence_count": len(evidence),
                    "timeline": timeline,
                    "analysis": analysis,
                },
            )

        except Exception as e:
            self.logger.error(
                "investigation_failed",
                agent_id=self.agent_id,
                error=str(e),
            )
            self._status = AgentStatus.FAILED
            self._state_manager.set_error(context.execution_id, str(e))

            return self._create_result(
                success=False,
                error=str(e),
            )

    async def _initial_assessment(self, context: AgentContext) -> dict[str, Any]:
        """Perform initial incident assessment."""
        self.logger.info("starting_initial_assessment", execution_id=context.execution_id)

        data = context.data
        alert_id = data.get("alert_id") or context.alert_id
        severity = data.get("severity", "unknown")
        alert_type = data.get("alert_type", "unknown")

        # Get alert details if available
        alert_details = {}
        if alert_id:
            result = await self.execute_tool("get_alert_details", {"alert_id": alert_id})
            if result.get("success"):
                alert_details = result.get("result", {})

        assessment = {
            "alert_id": alert_id,
            "severity": severity,
            "alert_type": alert_type,
            "description": data.get("description", ""),
            "affected_entities": self._extract_entities(data),
            "initial_iocs": self._extract_iocs(data),
            "assessment_time": datetime.utcnow().isoformat(),
            "priority": self._determine_priority(severity, alert_type),
            "alert_details": alert_details,
        }

        return assessment

    def _extract_entities(self, data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract entities from incident data."""
        entities = []

        # Check common fields for entities
        if src_ip := data.get("source_ip") or data.get("src_ip"):
            entities.append({"type": "ip", "value": src_ip, "role": "source"})

        if dst_ip := data.get("destination_ip") or data.get("dst_ip"):
            entities.append({"type": "ip", "value": dst_ip, "role": "destination"})

        if hostname := data.get("hostname") or data.get("host"):
            entities.append({"type": "host", "value": hostname})

        if username := data.get("username") or data.get("user"):
            entities.append({"type": "user", "value": username})

        return entities

    def _extract_iocs(self, data: dict[str, Any]) -> list[dict[str, str]]:
        """Extract IOCs from incident data."""
        iocs = []

        # Check for hashes
        for hash_type in ["md5", "sha1", "sha256"]:
            if hash_val := data.get(hash_type) or data.get(f"file_{hash_type}"):
                iocs.append({"type": hash_type, "value": hash_val})

        # Check for URLs/domains
        if url := data.get("url"):
            iocs.append({"type": "url", "value": url})

        if domain := data.get("domain"):
            iocs.append({"type": "domain", "value": domain})

        return iocs

    def _determine_priority(self, severity: str, alert_type: str) -> str:
        """Determine investigation priority."""
        high_priority_types = ["ransomware", "apt", "data_exfil", "lateral_movement"]
        critical_severity = ["critical", "high"]

        if severity.lower() in critical_severity:
            return "high"
        if any(t in alert_type.lower() for t in high_priority_types):
            return "high"
        return "normal"

    async def _plan_investigation(
        self,
        context: AgentContext,
        assessment: dict[str, Any],
    ) -> InvestigationPlan:
        """Create investigation plan using LLM."""
        client = await self._get_client()

        prompt = f"""Based on this security incident assessment, create an investigation plan.

Assessment:
- Alert Type: {assessment.get('alert_type')}
- Severity: {assessment.get('severity')}
- Description: {assessment.get('description')}
- Affected Entities: {assessment.get('affected_entities')}
- Initial IOCs: {assessment.get('initial_iocs')}

Create:
1. Investigation objectives (what we need to determine)
2. Hypotheses (possible explanations)
3. Data sources to query
4. Specific queries to run

Respond in JSON format with keys: objectives, hypotheses, data_sources, queries"""

        try:
            response = await client.post(
                f"{self.config.llm_endpoint}/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.3,
                },
            )
            response.raise_for_status()

            content = response.json()["choices"][0]["message"]["content"]

            # Parse JSON from response
            import json
            import re

            json_match = re.search(r"\{[\s\S]*\}", content)
            if json_match:
                plan_data = json.loads(json_match.group())
                return InvestigationPlan(**plan_data)

        except Exception as e:
            self.logger.warning("llm_planning_failed", error=str(e))

        # Default plan
        return InvestigationPlan(
            objectives=["Determine scope of incident", "Identify root cause"],
            hypotheses=["Potential security breach", "Possible false positive"],
            data_sources=["SIEM logs", "Threat intelligence"],
            queries=[
                {"type": "related_alerts", "entity": assessment.get("affected_entities", [])},
            ],
        )

    async def _collect_context(
        self,
        context: AgentContext,
        plan: InvestigationPlan,
    ) -> dict[str, Any]:
        """Collect context based on investigation plan."""
        collected = {
            "related_alerts": [],
            "threat_intel": [],
            "host_info": [],
            "user_info": [],
        }

        # Get entities from initial assessment
        assessment = self._memory.get("initial_assessment")
        entities = []
        if assessment:
            entities = assessment.content.get("affected_entities", [])

        # Query for each entity
        for entity in entities[:self.config.max_context_items]:
            entity_type = entity.get("type")
            entity_value = entity.get("value")

            if entity_type == "ip":
                # Get related alerts
                result = await self.execute_tool(
                    "get_related_alerts",
                    {"entity": entity_value, "entity_type": "ip"},
                )
                if result.get("success"):
                    collected["related_alerts"].extend(result.get("result", []))

                # Enrich IP
                result = await self.execute_tool(
                    "enrich_ioc",
                    {"ioc": entity_value, "ioc_type": "ip"},
                )
                if result.get("success"):
                    collected["threat_intel"].append(result.get("result"))

            elif entity_type == "host":
                result = await self.execute_tool(
                    "get_host_info",
                    {"hostname": entity_value},
                )
                if result.get("success"):
                    collected["host_info"].append(result.get("result"))

            elif entity_type == "user":
                result = await self.execute_tool(
                    "get_user_info",
                    {"username": entity_value},
                )
                if result.get("success"):
                    collected["user_info"].append(result.get("result"))

        return collected

    async def _gather_evidence(
        self,
        context: AgentContext,
        collected_context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Gather and organize evidence."""
        evidence = []

        # Add related alerts as evidence
        for alert in collected_context.get("related_alerts", []):
            evidence.append({
                "type": "alert",
                "source": "SIEM",
                "data": alert,
                "timestamp": alert.get("timestamp"),
            })

        # Add threat intel as evidence
        for intel in collected_context.get("threat_intel", []):
            if intel:
                evidence.append({
                    "type": "threat_intel",
                    "source": "TI",
                    "data": intel,
                })

        # Add host info as evidence
        for host in collected_context.get("host_info", []):
            if host:
                evidence.append({
                    "type": "host",
                    "source": "Asset DB",
                    "data": host,
                })

        return evidence[:self.config.max_evidence_items]

    async def _build_timeline(
        self,
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Build incident timeline from evidence."""
        timeline = []

        for item in evidence:
            timestamp = item.get("timestamp")
            if timestamp:
                timeline.append({
                    "timestamp": timestamp,
                    "event_type": item.get("type"),
                    "description": self._summarize_evidence(item),
                    "source": item.get("source"),
                })

        # Sort by timestamp
        timeline.sort(key=lambda x: x.get("timestamp", ""))

        return timeline

    def _summarize_evidence(self, evidence: dict[str, Any]) -> str:
        """Create brief summary of evidence item."""
        ev_type = evidence.get("type")
        data = evidence.get("data", {})

        if ev_type == "alert":
            return f"Alert: {data.get('alert_type', 'Unknown')} - {data.get('description', '')[:100]}"
        elif ev_type == "threat_intel":
            return f"TI: {data.get('verdict', 'Unknown')} - {data.get('source', 'Unknown')}"
        elif ev_type == "host":
            return f"Host: {data.get('hostname', 'Unknown')}"
        else:
            return f"{ev_type}: {str(data)[:100]}"

    async def _analyze_findings(
        self,
        context: AgentContext,
        assessment: dict[str, Any],
        collected_context: dict[str, Any],
        evidence: list[dict[str, Any]],
        timeline: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyze findings and generate conclusions."""
        client = await self._get_client()

        prompt = f"""Analyze these investigation findings and provide conclusions.

Initial Assessment:
{assessment}

Evidence Count: {len(evidence)}
Timeline Events: {len(timeline)}

Related Alerts: {len(collected_context.get('related_alerts', []))}
Threat Intel Matches: {len([t for t in collected_context.get('threat_intel', []) if t])}

Provide:
1. Summary of findings
2. Likely root cause
3. Affected assets/scope
4. Severity assessment (1-10)
5. Recommendations

Respond in JSON format with keys: summary, root_cause, affected_scope, severity_score, recommendations"""

        try:
            response = await client.post(
                f"{self.config.llm_endpoint}/chat/completions",
                json={
                    "model": self.config.model_name,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "max_tokens": 1000,
                    "temperature": 0.3,
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
            self.logger.warning("llm_analysis_failed", error=str(e))

        # Default analysis
        return {
            "summary": "Investigation completed with limited analysis",
            "root_cause": "Unable to determine automatically",
            "affected_scope": [e.get("value") for e in assessment.get("affected_entities", [])],
            "severity_score": 5,
            "recommendations": ["Manual review recommended"],
        }

    # Tool implementations

    async def _query_siem(
        self,
        query: str,
        time_range: str = "last_24h",
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Query SIEM for events."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.siem_endpoint}/query",
                json={"query": query, "time_range": time_range, "limit": limit},
            )
            if response.status_code == 200:
                return response.json().get("results", [])
        except Exception as e:
            self.logger.warning("siem_query_failed", error=str(e))

        return []

    async def _get_alert_details(self, alert_id: str) -> dict[str, Any]:
        """Get alert details from SIEM."""
        client = await self._get_client()

        try:
            response = await client.get(f"{self.config.siem_endpoint}/alerts/{alert_id}")
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning("get_alert_failed", error=str(e))

        return {}

    async def _get_related_alerts(
        self,
        entity: str,
        entity_type: str = "ip",
        time_range: str = "last_7d",
    ) -> list[dict[str, Any]]:
        """Get alerts related to an entity."""
        query = f'{entity_type}:"{entity}"'
        return await self._query_siem(query, time_range)

    async def _enrich_ioc(self, ioc: str, ioc_type: str) -> dict[str, Any]:
        """Enrich IOC with threat intelligence."""
        client = await self._get_client()

        try:
            response = await client.post(
                f"{self.config.soar_endpoint}/enrich",
                json={"ioc": ioc, "type": ioc_type},
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning("enrich_failed", error=str(e))

        return {}

    async def _get_host_info(self, hostname: str) -> dict[str, Any]:
        """Get host information."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.config.siem_endpoint}/assets/hosts/{hostname}"
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning("get_host_failed", error=str(e))

        return {}

    async def _get_user_info(self, username: str) -> dict[str, Any]:
        """Get user information."""
        client = await self._get_client()

        try:
            response = await client.get(
                f"{self.config.siem_endpoint}/assets/users/{username}"
            )
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            self.logger.warning("get_user_failed", error=str(e))

        return {}
