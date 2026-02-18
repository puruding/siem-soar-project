// Node execution status type
export type NodeExecutionStatus =
  | 'pending'
  | 'queued'
  | 'running'
  | 'success'
  | 'error'
  | 'skipped'
  | 'cancelled'
  | 'awaiting_approval';

// Single node execution result
export interface NodeExecutionResult {
  nodeId: string;
  nodeName: string;
  status: NodeExecutionStatus;
  executionOrder?: number;  // index of when this node started (0, 1, 2...)
  startedAt?: Date;
  completedAt?: Date;
  duration?: number;
  input?: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: {
    message: string;
    code?: string;
    stack?: string;
  };
}

// Overall execution state
export interface ExecutionState {
  executionId: string;
  status: 'idle' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';
  startedAt?: Date;
  completedAt?: Date;
  currentNodeId?: string;
  nodeResults: Map<string, NodeExecutionResult>;
  progress: number;
}

// WebSocket message types
export type WSMessageType =
  | 'execution:start'
  | 'execution:pause'
  | 'execution:resume'
  | 'execution:cancel'
  | 'execution:complete'
  | 'node:start'
  | 'node:complete'
  | 'node:error'
  | 'item:start'
  | 'item:complete'
  | 'item:error'
  | 'metrics:update'
  | 'approval:required'
  | 'approval:response';

export interface WSMessage<T = unknown> {
  type: WSMessageType;
  executionId: string;
  timestamp: number;
  payload: T;
}

export interface WSNodeStartPayload {
  nodeId: string;
  nodeName: string;
  input: Record<string, unknown>;
}

export interface WSNodeCompletePayload {
  nodeId: string;
  nodeName: string;
  output: Record<string, unknown>;
  duration: number;
}

export interface WSNodeErrorPayload {
  nodeId: string;
  nodeName: string;
  error: {
    message: string;
    code?: string;
    stack?: string;
  };
}

export interface WSApprovalRequiredPayload {
  nodeId: string;
  nodeName: string;
  executionId: string;
  requestedAt: string;
  description?: string;
}

export interface WSApprovalResponsePayload {
  nodeId: string;
  nodeName: string;
  executionId: string;
  approved: boolean;
  respondedBy?: string;
  comment?: string;
  respondedAt: string;
}
