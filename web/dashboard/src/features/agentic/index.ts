/**
 * Agentic Feature Module - Autonomous SOC Dashboard
 *
 * Components for visualizing and controlling AI agents.
 */

export { AgentDashboard } from './components/AgentDashboard';
export type { AgentStats, SystemHealth } from './components/AgentDashboard';

export { AgentList } from './components/AgentList';
export type { Agent, AgentStatus, AgentCapability } from './components/AgentList';

export { AgentDetail } from './components/AgentDetail';
export type { AgentExecution, AgentMetrics } from './components/AgentDetail';

export { ExecutionTimeline } from './components/ExecutionTimeline';
export type {
  Execution,
  ExecutionStep,
  ExecutionStage,
  ExecutionStatus,
} from './components/ExecutionTimeline';

export { ApprovalQueue } from './components/ApprovalQueue';
export type {
  ApprovalRequest,
  ApprovalStatus,
  RiskLevel,
} from './components/ApprovalQueue';
