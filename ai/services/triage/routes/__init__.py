"""Routes for Triage service."""

from ai.services.triage.routes.classify import router as classify_router
from ai.services.triage.routes.dga import router as dga_router

__all__ = ["classify_router", "dga_router"]
