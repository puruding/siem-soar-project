"""Security Copilot Service - AI assistant for security analysts."""

from contextlib import asynccontextmanager
from enum import Enum
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import Field

from common import get_logger, get_settings, setup_logging
from common.models import BaseModel, BaseRequest, BaseResponse, HealthResponse

from .chat import ChatService, ChatConfig
from .nl2sql import NL2SQLService, NL2SQLRequest, NL2SQLResponse, get_template_suggestions
from .summarize import SummarizeService, SummarizeRequest, SummarizeResponse, ExtractRequest, ExtractResponse
from .recommend import RecommendService, PlaybookRecommendRequest, PlaybookRecommendResponse, ActionSuggestRequest, ActionSuggestResponse, SimilarCaseRequest, SimilarCaseResponse
from .context import ContextManager, ContextType

settings = get_settings()
logger = get_logger(__name__)


class QueryType(str, Enum):
    """Types of copilot queries."""

    INVESTIGATION = "investigation"
    QUERY = "query"
    PLAYBOOK = "playbook"
    EXPLANATION = "explanation"
    RECOMMENDATION = "recommendation"
    SUMMARIZATION = "summarization"


class CopilotRequest(BaseRequest):
    """Request for copilot assistance."""

    message: str = Field(description="User message/question")
    query_type: QueryType | None = Field(default=None, description="Type of query")
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")
    conversation_id: str | None = Field(default=None, description="Conversation ID for context")
    session_id: str | None = Field(default=None, description="Session ID for context management")
    stream: bool = Field(default=False, description="Enable streaming response")


class CopilotResponse(BaseModel):
    """Response from copilot."""

    message: str = Field(description="Copilot response")
    query_type: QueryType = Field(description="Detected query type")
    conversation_id: str = Field(description="Conversation ID")
    suggestions: list[str] = Field(default_factory=list, description="Follow-up suggestions")
    generated_query: str | None = Field(default=None, description="Generated SQL/KQL query")
    generated_playbook: dict[str, Any] | None = Field(default=None, description="Generated playbook")
    sources: list[str] = Field(default_factory=list, description="Information sources")
    confidence: float = Field(ge=0, le=1, description="Response confidence")


# Global service instances
chat_service: ChatService | None = None
nl2sql_service: NL2SQLService | None = None
summarize_service: SummarizeService | None = None
recommend_service: RecommendService | None = None
context_manager: ContextManager | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    global chat_service, nl2sql_service, summarize_service, recommend_service, context_manager

    setup_logging(
        level=settings.log_level,
        format=settings.log_format,
        service_name="ai-copilot",
    )

    logger.info("starting_service", environment=settings.environment)

    # Initialize services
    api_key = settings.openai_api_key.get_secret_value() if settings.openai_api_key else None

    logger.info(
        "llm_config",
        endpoint=settings.vllm_endpoint,
        model=settings.llm_model,
        api_key_set=api_key is not None,
        api_key_prefix=api_key[:20] if api_key else "None",
    )

    chat_service = ChatService(
        llm_endpoint=settings.vllm_endpoint,
        model_name=settings.llm_model,
        api_key=api_key,
        config=ChatConfig(
            max_tokens=settings.max_tokens,
            temperature=settings.temperature,
        ),
    )

    nl2sql_service = NL2SQLService(
        llm_endpoint=settings.vllm_endpoint,
        model_name=settings.llm_model,
        api_key=api_key,
    )

    summarize_service = SummarizeService(
        llm_endpoint=settings.vllm_endpoint,
        model_name=settings.llm_model,
        api_key=api_key,
    )

    recommend_service = RecommendService(
        llm_endpoint=settings.vllm_endpoint,
        model_name=settings.llm_model,
        api_key=api_key,
    )

    context_manager = ContextManager()

    yield

    # Cleanup
    if chat_service:
        await chat_service.close()
    if nl2sql_service:
        await nl2sql_service.close()
    if summarize_service:
        await summarize_service.close()
    if recommend_service:
        await recommend_service.close()

    logger.info("shutting_down_service")


app = FastAPI(
    title="Security Copilot Service",
    description="AI assistant for security analysts with NL2SQL, summarization, and recommendations",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="ai-copilot",
        version="0.2.0",
        checks={
            "chat_service": chat_service is not None,
            "nl2sql_service": nl2sql_service is not None,
            "summarize_service": summarize_service is not None,
            "recommend_service": recommend_service is not None,
        },
    )


@app.post("/api/v1/chat", response_model=BaseResponse[CopilotResponse])
async def chat(request: CopilotRequest) -> BaseResponse[CopilotResponse]:
    """Process a copilot chat message."""
    try:
        # Detect query type if not specified
        query_type = request.query_type or _detect_query_type(request.message)

        # Build context from session
        context = request.context.copy()
        if request.session_id and context_manager:
            context_str = context_manager.build_context_string(request.session_id)
            if context_str:
                context["session_context"] = context_str

        # Generate response
        response_text, conversation_id = await chat_service.chat(
            message=request.message,
            conversation_id=request.conversation_id,
            context=context,
        )

        # Handle special query types
        generated_query = None
        suggestions = []

        if query_type == QueryType.QUERY:
            # Generate SQL query
            nl2sql_request = NL2SQLRequest(
                query=request.message,
                context=context,
            )
            sql_response = await nl2sql_service.convert(nl2sql_request)
            generated_query = sql_response.sql
            suggestions = sql_response.suggestions

        elif query_type == QueryType.RECOMMENDATION:
            # Get playbook recommendations
            playbook_request = PlaybookRecommendRequest(
                context=context,
                max_recommendations=3,
            )
            playbook_response = await recommend_service.recommend_playbooks(playbook_request)
            suggestions = [
                f"Run playbook: {r['name']}"
                for r in playbook_response.recommendations[:3]
            ]

        response = CopilotResponse(
            message=response_text,
            query_type=query_type,
            conversation_id=conversation_id,
            suggestions=suggestions or _get_follow_up_suggestions(query_type),
            generated_query=generated_query,
            confidence=0.85,
        )

        return BaseResponse.success_response(request.request_id, response)

    except Exception as e:
        logger.error("chat_failed", error=str(e))
        return BaseResponse.error_response(request.request_id, str(e))


@app.websocket("/api/v1/chat/stream")
async def chat_stream(websocket: WebSocket):
    """WebSocket endpoint for streaming chat responses."""
    await websocket.accept()

    try:
        while True:
            data = await websocket.receive_json()

            message = data.get("message", "")
            conversation_id = data.get("conversation_id")
            context = data.get("context", {})

            async for chunk in chat_service.chat_stream(
                message=message,
                conversation_id=conversation_id,
                context=context,
            ):
                await websocket.send_json({
                    "type": "chunk",
                    "content": chunk,
                })

            await websocket.send_json({
                "type": "done",
                "conversation_id": conversation_id,
            })

    except WebSocketDisconnect:
        logger.info("websocket_disconnected")
    except Exception as e:
        logger.error("websocket_error", error=str(e))
        await websocket.close(code=1011)


@app.post("/api/v1/nl2sql", response_model=BaseResponse[NL2SQLResponse])
async def convert_nl2sql(request: NL2SQLRequest) -> BaseResponse[NL2SQLResponse]:
    """Convert natural language to SQL."""
    try:
        response = await nl2sql_service.convert(request)
        return BaseResponse(
            request_id=request.request_id if hasattr(request, 'request_id') else None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("nl2sql_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/nl2sql/templates")
async def get_query_templates(language: str = "en") -> dict[str, Any]:
    """Get query template suggestions."""
    return {"templates": get_template_suggestions(language)}


@app.post("/api/v1/summarize", response_model=BaseResponse[SummarizeResponse])
async def summarize_incident(request: SummarizeRequest) -> BaseResponse[SummarizeResponse]:
    """Summarize an incident."""
    try:
        response = await summarize_service.summarize(request)
        return BaseResponse(
            request_id=None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("summarize_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/extract", response_model=BaseResponse[ExtractResponse])
async def extract_info(request: ExtractRequest) -> BaseResponse[ExtractResponse]:
    """Extract key information from incident data."""
    try:
        response = await summarize_service.extract(request)
        return BaseResponse(
            request_id=None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("extract_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/recommend/playbooks", response_model=BaseResponse[PlaybookRecommendResponse])
async def recommend_playbooks(request: PlaybookRecommendRequest) -> BaseResponse[PlaybookRecommendResponse]:
    """Get playbook recommendations."""
    try:
        response = await recommend_service.recommend_playbooks(request)
        return BaseResponse(
            request_id=None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("recommend_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/recommend/playbooks/{playbook_id}")
async def get_playbook(playbook_id: str) -> dict[str, Any]:
    """Get playbook details."""
    playbook = await recommend_service.get_playbook_details(playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return playbook


@app.post("/api/v1/recommend/actions", response_model=BaseResponse[ActionSuggestResponse])
async def suggest_actions(request: ActionSuggestRequest) -> BaseResponse[ActionSuggestResponse]:
    """Get action suggestions for incident."""
    try:
        response = await recommend_service.suggest_actions(request)
        return BaseResponse(
            request_id=None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("suggest_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/similar", response_model=BaseResponse[SimilarCaseResponse])
async def find_similar_cases(request: SimilarCaseRequest) -> BaseResponse[SimilarCaseResponse]:
    """Find similar historical cases."""
    try:
        response = await recommend_service.find_similar_cases(request)
        return BaseResponse(
            request_id=None,
            success=True,
            data=response,
        )
    except Exception as e:
        logger.error("similar_failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/context/{session_id}")
async def set_context(
    session_id: str,
    context_type: ContextType,
    data: dict[str, Any],
) -> dict[str, Any]:
    """Set context for a session."""
    item_id = context_manager.add_context(session_id, context_type, data)
    return {"item_id": item_id, "session_id": session_id}


@app.get("/api/v1/context/{session_id}")
async def get_context(session_id: str) -> dict[str, Any]:
    """Get session context summary."""
    return context_manager.get_session_summary(session_id)


@app.delete("/api/v1/context/{session_id}")
async def clear_context(session_id: str, context_type: ContextType | None = None) -> dict[str, Any]:
    """Clear session context."""
    count = context_manager.clear_context(session_id, context_type)
    return {"cleared": count}


def _detect_query_type(message: str) -> QueryType:
    """Detect the type of query from the message."""
    message_lower = message.lower()

    if any(word in message_lower for word in ["investigate", "analyze", "look into"]):
        return QueryType.INVESTIGATION
    elif any(word in message_lower for word in ["query", "search", "find", "show me", "how many", "count", "list"]):
        return QueryType.QUERY
    elif any(word in message_lower for word in ["playbook", "automate", "respond", "recommend"]):
        return QueryType.PLAYBOOK
    elif any(word in message_lower for word in ["summarize", "summary", "요약"]):
        return QueryType.SUMMARIZATION
    elif any(word in message_lower for word in ["explain", "what is", "why", "설명"]):
        return QueryType.EXPLANATION
    else:
        return QueryType.RECOMMENDATION


def _get_follow_up_suggestions(query_type: QueryType) -> list[str]:
    """Get follow-up suggestions based on query type."""
    suggestions = {
        QueryType.INVESTIGATION: [
            "Show related alerts",
            "Find similar incidents",
            "What playbooks apply?",
        ],
        QueryType.QUERY: [
            "Refine the search",
            "Show trends over time",
            "Export results",
        ],
        QueryType.PLAYBOOK: [
            "Execute the playbook",
            "Show playbook steps",
            "Find alternative playbooks",
        ],
        QueryType.SUMMARIZATION: [
            "More details",
            "Show recommendations",
            "Find similar cases",
        ],
        QueryType.EXPLANATION: [
            "Show examples",
            "Related concepts",
            "Best practices",
        ],
        QueryType.RECOMMENDATION: [
            "Why this recommendation?",
            "Alternative approaches",
            "Implement suggestion",
        ],
    }
    return suggestions.get(query_type, ["How can I help further?"])


def main() -> None:
    """Run the service."""
    import uvicorn

    uvicorn.run(
        "services.copilot.main:app",
        host=settings.host,
        port=8001,
        workers=settings.workers,
        reload=settings.debug,
    )


if __name__ == "__main__":
    main()
