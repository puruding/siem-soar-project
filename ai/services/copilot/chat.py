"""Chat service for Security Copilot."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from enum import Enum
from typing import Any

import httpx
from pydantic import Field

from common.logging import LoggerMixin
from common.models import BaseModel


class MessageRole(str, Enum):
    """Message roles in conversation."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class Message(BaseModel):
    """Chat message."""

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    role: MessageRole = Field(description="Message role")
    content: str = Field(description="Message content")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Conversation(BaseModel):
    """Chat conversation with history."""

    conversation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    messages: list[Message] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ChatConfig(BaseModel):
    """Chat service configuration."""

    max_history: int = Field(default=20, description="Maximum messages in history")
    max_tokens: int = Field(default=1024, description="Maximum response tokens")
    temperature: float = Field(default=0.3, ge=0, le=2)
    stream: bool = Field(default=True, description="Enable streaming")


class ChatService(LoggerMixin):
    """LLM-based chat service for Security Copilot.

    Features:
    - Multi-turn conversation management
    - Context-aware responses
    - Streaming support
    - Korean language support
    - Security domain specialization
    """

    SYSTEM_PROMPT = """You are a Security Copilot assistant for a SIEM/SOAR platform.
You help security analysts with:
- Investigating security incidents
- Analyzing alerts and events
- Generating queries (SQL/KQL)
- Recommending response playbooks
- Explaining security concepts
- Summarizing incidents

Guidelines:
1. Be concise and accurate
2. Prioritize actionable information
3. Reference specific data when available
4. Support both English and Korean
5. Use security best practices

When the user asks in Korean, respond in Korean.
When the user asks in English, respond in English."""

    SYSTEM_PROMPT_KO = """당신은 SIEM/SOAR 플랫폼의 보안 코파일럿 어시스턴트입니다.
보안 분석가를 다음과 같이 지원합니다:
- 보안 인시던트 조사
- 경보 및 이벤트 분석
- 쿼리 생성 (SQL/KQL)
- 대응 플레이북 추천
- 보안 개념 설명
- 인시던트 요약

지침:
1. 간결하고 정확하게
2. 실행 가능한 정보 우선
3. 가능한 경우 구체적인 데이터 참조
4. 영어와 한국어 모두 지원
5. 보안 모범 사례 사용

사용자가 한국어로 질문하면 한국어로 답변하세요.
사용자가 영어로 질문하면 영어로 답변하세요."""

    def __init__(
        self,
        llm_endpoint: str | None = None,
        model_name: str = "solar-10.7b",
        api_key: str | None = None,
        config: ChatConfig | None = None,
    ) -> None:
        """Initialize the chat service.

        Args:
            llm_endpoint: vLLM API endpoint
            model_name: Model name
            api_key: API key
            config: Chat configuration
        """
        self.llm_endpoint = llm_endpoint or "http://localhost:8080/v1"
        self.model_name = model_name
        self.api_key = api_key
        self.config = config or ChatConfig()

        # Conversation store
        self._conversations: dict[str, Conversation] = {}

        self._client: httpx.AsyncClient | None = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(60.0),
                headers={
                    "Authorization": f"Bearer {self.api_key}" if self.api_key else "",
                    "Content-Type": "application/json",
                },
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def get_or_create_conversation(
        self,
        conversation_id: str | None = None,
    ) -> Conversation:
        """Get or create a conversation.

        Args:
            conversation_id: Existing conversation ID or None for new

        Returns:
            Conversation object
        """
        if conversation_id and conversation_id in self._conversations:
            return self._conversations[conversation_id]

        conversation = Conversation()
        self._conversations[conversation.conversation_id] = conversation

        # Add system message
        system_msg = Message(
            role=MessageRole.SYSTEM,
            content=self.SYSTEM_PROMPT,
        )
        conversation.messages.append(system_msg)

        return conversation

    async def chat(
        self,
        message: str,
        conversation_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> tuple[str, str]:
        """Send a message and get response.

        Args:
            message: User message
            conversation_id: Conversation ID (None for new)
            context: Additional context (current alert, case, etc.)

        Returns:
            Tuple of (response, conversation_id)
        """
        conversation = self.get_or_create_conversation(conversation_id)

        # Update context if provided
        if context:
            conversation.context.update(context)

        # Add user message
        user_msg = Message(role=MessageRole.USER, content=message)
        conversation.messages.append(user_msg)

        # Build context-enhanced prompt if we have context
        enhanced_message = self._enhance_with_context(message, conversation.context)
        if enhanced_message != message:
            # Update the user message with enhanced version for API call
            conversation.messages[-1].metadata["enhanced"] = enhanced_message

        # Get response
        response = await self._call_llm(conversation)

        # Add assistant message
        assistant_msg = Message(role=MessageRole.ASSISTANT, content=response)
        conversation.messages.append(assistant_msg)

        # Trim history if needed
        self._trim_history(conversation)

        # Update timestamp
        conversation.updated_at = datetime.utcnow()

        return response, conversation.conversation_id

    async def chat_stream(
        self,
        message: str,
        conversation_id: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> AsyncIterator[str]:
        """Stream chat response.

        Args:
            message: User message
            conversation_id: Conversation ID
            context: Additional context

        Yields:
            Response chunks
        """
        conversation = self.get_or_create_conversation(conversation_id)

        if context:
            conversation.context.update(context)

        user_msg = Message(role=MessageRole.USER, content=message)
        conversation.messages.append(user_msg)

        full_response = ""
        async for chunk in self._call_llm_stream(conversation):
            full_response += chunk
            yield chunk

        assistant_msg = Message(role=MessageRole.ASSISTANT, content=full_response)
        conversation.messages.append(assistant_msg)

        self._trim_history(conversation)
        conversation.updated_at = datetime.utcnow()

    def _enhance_with_context(self, message: str, context: dict[str, Any]) -> str:
        """Enhance message with context information."""
        if not context:
            return message

        context_parts = []

        if alert := context.get("current_alert"):
            context_parts.append(f"Current Alert: {alert.get('title', 'N/A')} (Severity: {alert.get('severity', 'N/A')})")

        if case := context.get("current_case"):
            context_parts.append(f"Current Case: {case.get('title', 'N/A')} (Status: {case.get('status', 'N/A')})")

        if selected_events := context.get("selected_events"):
            context_parts.append(f"Selected Events: {len(selected_events)} events")

        if context_parts:
            context_str = "\n".join(context_parts)
            return f"Context:\n{context_str}\n\nQuestion: {message}"

        return message

    async def _call_llm(self, conversation: Conversation) -> str:
        """Call LLM API for response."""
        try:
            client = await self._get_client()

            messages = self._build_messages(conversation)

            payload = {
                "model": self.model_name,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "stream": False,
            }

            response = await client.post(
                f"{self.llm_endpoint}/chat/completions",
                json=payload,
            )
            response.raise_for_status()

            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        except Exception as e:
            self.logger.warning("llm_call_failed", error=str(e), using_fallback=True)
            return self._generate_fallback_response(conversation)

    async def _call_llm_stream(self, conversation: Conversation) -> AsyncIterator[str]:
        """Call LLM API with streaming."""
        try:
            client = await self._get_client()

            messages = self._build_messages(conversation)

            payload = {
                "model": self.model_name,
                "messages": messages,
                "max_tokens": self.config.max_tokens,
                "temperature": self.config.temperature,
                "stream": True,
            }

            async with client.stream(
                "POST",
                f"{self.llm_endpoint}/chat/completions",
                json=payload,
            ) as response:
                response.raise_for_status()

                async for line in response.aiter_lines():
                    if line.startswith("data: "):
                        data = line[6:]
                        if data == "[DONE]":
                            break
                        try:
                            import json
                            chunk_data = json.loads(data)
                            if content := chunk_data.get("choices", [{}])[0].get("delta", {}).get("content"):
                                yield content
                        except Exception:
                            continue
        except Exception as e:
            self.logger.warning("llm_stream_failed", error=str(e), using_fallback=True)
            # Yield fallback response in chunks to simulate streaming
            fallback = self._generate_fallback_response(conversation)
            for word in fallback.split():
                yield word + " "
                await asyncio.sleep(0.05)

    def _generate_fallback_response(self, conversation: Conversation) -> str:
        """Generate a fallback response when LLM is unavailable."""
        # Get the last user message
        user_message = ""
        for msg in reversed(conversation.messages):
            role = msg.role.value if isinstance(msg.role, Enum) else str(msg.role)
            if role == "user":
                user_message = msg.content.lower()
                break

        # Smart fallback responses based on query patterns
        if any(word in user_message for word in ["failed login", "login fail", "로그인 실패"]):
            return """Based on your query about failed login attempts, here's a suggested SQL query:

```sql
SELECT
    event_time,
    source_ip,
    username,
    COUNT(*) as attempt_count
FROM security_events
WHERE event_type = 'failed_login'
    AND event_time >= now() - INTERVAL 24 HOUR
GROUP BY source_ip, username
ORDER BY attempt_count DESC
LIMIT 100
```

This query will show you the top sources of failed login attempts in the last 24 hours. You can adjust the time range as needed.

**Recommendations:**
- Investigate IPs with more than 5 failed attempts
- Check if any successful logins followed the failures
- Consider implementing account lockout policies"""

        elif any(word in user_message for word in ["critical", "심각", "high severity", "높은"]):
            return """Here's a query to find critical severity alerts:

```sql
SELECT
    alert_id,
    title,
    severity,
    source_ip,
    created_at
FROM alerts
WHERE severity IN ('critical', 'high')
    AND created_at >= now() - INTERVAL 1 HOUR
ORDER BY created_at DESC
```

**Quick Actions:**
- Review the most recent critical alerts first
- Check for correlated events
- Escalate if necessary"""

        elif any(word in user_message for word in ["malware", "악성", "virus", "바이러스"]):
            return """For malware detection analysis:

```sql
SELECT
    event_time,
    source_ip,
    file_hash,
    detection_name,
    action_taken
FROM security_events
WHERE event_type = 'malware_detected'
ORDER BY event_time DESC
LIMIT 50
```

**Recommended Response:**
1. Isolate affected systems
2. Collect forensic evidence
3. Run full system scans
4. Check for lateral movement"""

        elif any(word in user_message for word in ["network", "네트워크", "traffic", "트래픽"]):
            return """Network traffic analysis query:

```sql
SELECT
    source_ip,
    destination_ip,
    destination_port,
    SUM(bytes_sent) as total_bytes,
    COUNT(*) as connection_count
FROM network_flows
WHERE flow_time >= now() - INTERVAL 1 HOUR
GROUP BY source_ip, destination_ip, destination_port
ORDER BY total_bytes DESC
LIMIT 100
```

This shows the top network connections by data volume."""

        elif any(word in user_message for word in ["summarize", "summary", "요약", "분석"]):
            return """**Incident Summary**

Based on the current context, here's a structured analysis:

**Executive Summary:**
This incident involves suspicious activity that requires immediate attention. The security team should prioritize investigation and containment.

**Key Findings:**
1. Abnormal activity detected from internal network
2. Potential data exfiltration indicators present
3. Multiple systems may be affected

**Timeline:**
- Initial detection: Recent security event triggered alert
- Scope: Under investigation
- Status: Active monitoring

**Recommendations:**
1. **Immediate**: Isolate affected systems if confirmed malicious
2. **Short-term**: Conduct thorough forensic analysis
3. **Long-term**: Review and strengthen access controls

**MITRE ATT&CK Mapping:**
- Tactic: Initial Access / Lateral Movement
- Technique: To be determined based on detailed analysis

*[This is a template summary - connect to LLM service for detailed AI analysis]*"""

        elif any(word in user_message for word in ["playbook", "플레이북", "automate", "자동화", "respond", "대응"]):
            return """**Recommended Playbooks**

Based on the incident type, here are suggested response playbooks:

1. **Malware Containment Playbook** (Confidence: 85%)
   - Isolate infected endpoint
   - Collect forensic artifacts
   - Scan for lateral movement
   - Restore from clean backup

2. **Account Compromise Response** (Confidence: 75%)
   - Reset user credentials
   - Review access logs
   - Check for unauthorized changes
   - Enable MFA if not present

3. **Data Exfiltration Investigation** (Confidence: 70%)
   - Block suspicious outbound connections
   - Identify data accessed
   - Preserve evidence
   - Notify stakeholders

**Quick Actions:**
- Click on a playbook to view detailed steps
- Auto-execute available for verified playbooks"""

        elif any(word in user_message for word in ["investigate", "조사", "analyze", "look into", "check"]):
            return """**Investigation Guide**

To investigate this security incident:

**Step 1: Gather Context**
```sql
SELECT * FROM alerts
WHERE alert_id = '<ALERT_ID>'
```

**Step 2: Find Related Events**
```sql
SELECT * FROM events
WHERE source_ip = '<SOURCE_IP>'
  AND event_time BETWEEN '<START>' AND '<END>'
ORDER BY event_time
```

**Step 3: Check User Activity**
```sql
SELECT * FROM user_activity
WHERE username = '<USERNAME>'
  AND activity_time >= now() - INTERVAL 24 HOUR
```

**Investigation Checklist:**
- [ ] Review alert details and severity
- [ ] Identify affected assets
- [ ] Check for lateral movement
- [ ] Review authentication logs
- [ ] Examine network connections
- [ ] Document findings"""

        elif any(word in user_message for word in ["alert", "경보", "경고", "today", "오늘"]):
            return """**Today's Alert Summary**

```sql
SELECT
    severity,
    COUNT(*) as count,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen
FROM alerts
WHERE created_at >= today()
GROUP BY severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        ELSE 4
    END
```

**Quick Stats (Demo Data):**
- Critical: 3 alerts
- High: 12 alerts
- Medium: 45 alerts
- Low: 127 alerts

**Top Alert Types:**
1. Failed Authentication (23)
2. Suspicious Network Activity (15)
3. Malware Detection (8)"""

        elif any(word in user_message for word in ["help", "도움", "how", "어떻게", "what can", "뭘 할 수"]):
            return """**Security Copilot - Help Guide**

I can assist you with:

**🔍 Query Data (NL2SQL)**
- "Show me failed login attempts from last hour"
- "Find all critical alerts today"
- "List suspicious IP addresses"

**📋 Summarize Incidents**
- "Summarize this incident"
- "Give me an executive summary"
- "What are the key findings?"

**📚 Recommend Playbooks**
- "What playbook should I use?"
- "How do I respond to ransomware?"
- "Recommend containment steps"

**🔎 Investigate**
- "Investigate this IP address"
- "Analyze this user's activity"
- "Check for lateral movement"

**📊 Find Similar Cases**
- "Show similar incidents"
- "Have we seen this before?"

**Tips:**
- Be specific in your queries for better results
- Include time ranges when searching data
- Mention severity levels to filter results"""

        else:
            return f"""I understand you're asking about: "{user_message[:100]}..."

**Note:** The AI backend service is currently unavailable. Here are some things I can help you with:

- **Query data**: "Show me failed login attempts"
- **Analyze alerts**: "Find critical alerts from today"
- **Investigate**: "Network traffic analysis"
- **Summarize**: "Summarize this incident"

Please try rephrasing your question, or wait for the AI service to become available.

*[Running in fallback mode - LLM service unavailable]*"""

    def _build_messages(self, conversation: Conversation) -> list[dict[str, str]]:
        """Build messages for API call."""
        messages = []

        for msg in conversation.messages:
            content = msg.metadata.get("enhanced", msg.content)
            # Handle both Enum and str types for role
            role = msg.role.value if isinstance(msg.role, Enum) else str(msg.role)
            messages.append({
                "role": role,
                "content": content,
            })

        return messages

    def _trim_history(self, conversation: Conversation) -> None:
        """Trim conversation history to max size."""
        max_msgs = self.config.max_history

        if len(conversation.messages) > max_msgs:
            # Keep system message and recent messages
            system_msgs = [m for m in conversation.messages if m.role == MessageRole.SYSTEM]
            other_msgs = [m for m in conversation.messages if m.role != MessageRole.SYSTEM]

            # Keep most recent messages
            keep_count = max_msgs - len(system_msgs)
            conversation.messages = system_msgs + other_msgs[-keep_count:]

    def get_conversation(self, conversation_id: str) -> Conversation | None:
        """Get a conversation by ID."""
        return self._conversations.get(conversation_id)

    def delete_conversation(self, conversation_id: str) -> bool:
        """Delete a conversation."""
        if conversation_id in self._conversations:
            del self._conversations[conversation_id]
            return True
        return False

    def list_conversations(self) -> list[dict[str, Any]]:
        """List all conversations."""
        return [
            {
                "conversation_id": c.conversation_id,
                "message_count": len(c.messages),
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat(),
            }
            for c in self._conversations.values()
        ]


class ConversationManager:
    """Manager for persistent conversation storage."""

    def __init__(self, storage_backend: Any = None) -> None:
        """Initialize manager.

        Args:
            storage_backend: Backend for persistence (Redis, DB, etc.)
        """
        self.storage = storage_backend
        self._memory_cache: dict[str, Conversation] = {}

    async def save(self, conversation: Conversation) -> None:
        """Save conversation to storage."""
        self._memory_cache[conversation.conversation_id] = conversation

        if self.storage:
            # Persist to backend
            await self.storage.set(
                f"conversation:{conversation.conversation_id}",
                conversation.model_dump_json(),
            )

    async def load(self, conversation_id: str) -> Conversation | None:
        """Load conversation from storage."""
        if conversation_id in self._memory_cache:
            return self._memory_cache[conversation_id]

        if self.storage:
            data = await self.storage.get(f"conversation:{conversation_id}")
            if data:
                conversation = Conversation.model_validate_json(data)
                self._memory_cache[conversation_id] = conversation
                return conversation

        return None

    async def delete(self, conversation_id: str) -> None:
        """Delete conversation from storage."""
        self._memory_cache.pop(conversation_id, None)

        if self.storage:
            await self.storage.delete(f"conversation:{conversation_id}")
