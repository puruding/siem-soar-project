"""Safety Module - Guardrails and approval mechanisms for autonomous operations.

This module provides safety mechanisms:
- Guardrails: Action constraints and validation
- Approval Gate: Human approval workflow
- Rollback: Undo mechanisms
- Audit: Comprehensive logging
- Limits: Execution constraints
"""

from .guardrails import (
    Guardrail,
    GuardrailResult,
    GuardrailEngine,
    ActionConstraint,
    RiskLevel,
)
from .approval_gate import (
    ApprovalGate,
    ApprovalRequest,
    ApprovalDecision,
    ApprovalStatus,
)
from .rollback import (
    RollbackManager,
    RollbackAction,
    RollbackResult,
    ActionSnapshot,
)
from .audit import (
    AuditLogger,
    AuditEvent,
    AuditEventType,
    AuditTrail,
)
from .limits import (
    ExecutionLimiter,
    RateLimitConfig,
    ResourceLimit,
    LimitExceededError,
)

__all__ = [
    # Guardrails
    "Guardrail",
    "GuardrailResult",
    "GuardrailEngine",
    "ActionConstraint",
    "RiskLevel",
    # Approval
    "ApprovalGate",
    "ApprovalRequest",
    "ApprovalDecision",
    "ApprovalStatus",
    # Rollback
    "RollbackManager",
    "RollbackAction",
    "RollbackResult",
    "ActionSnapshot",
    # Audit
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "AuditTrail",
    # Limits
    "ExecutionLimiter",
    "RateLimitConfig",
    "ResourceLimit",
    "LimitExceededError",
]
