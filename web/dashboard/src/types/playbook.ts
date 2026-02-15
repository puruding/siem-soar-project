/**
 * Playbook type definitions for SOAR automation
 */

export type PlaybookStatus = 'draft' | 'active' | 'disabled' | 'archived';

export type PlaybookTriggerType = 'alert' | 'schedule' | 'webhook' | 'manual' | 'case';

export type NodeType = 'trigger' | 'action' | 'decision' | 'integration' | 'loop' | 'delay' | 'notification' | 'enrichment';

export interface PlaybookTrigger {
  type: PlaybookTriggerType;
  config: {
    alertSeverity?: string[];
    alertSource?: string[];
    schedule?: string; // Cron expression
    webhookPath?: string;
    caseStatus?: string[];
    conditions?: PlaybookCondition[];
  };
}

export interface PlaybookCondition {
  field: string;
  operator: 'equals' | 'not_equals' | 'contains' | 'not_contains' | 'greater_than' | 'less_than' | 'regex' | 'in' | 'not_in';
  value: string | number | boolean | string[];
}

export interface PlaybookNodeData {
  label: string;
  description?: string;
  nodeType: NodeType;
  status?: 'idle' | 'active' | 'disabled' | 'error';
  config?: Record<string, unknown>;
}

export interface TriggerNodeConfig extends PlaybookNodeData {
  nodeType: 'trigger';
  triggerType: PlaybookTriggerType;
  conditions?: PlaybookCondition[];
}

export interface ActionNodeConfig extends PlaybookNodeData {
  nodeType: 'action';
  actionType: string;
  integration?: string;
  parameters: Record<string, unknown>;
  timeout?: number;
  retries?: number;
  continueOnError?: boolean;
}

export interface DecisionNodeConfig extends PlaybookNodeData {
  nodeType: 'decision';
  conditions: {
    id: string;
    label: string;
    condition: PlaybookCondition;
  }[];
  defaultBranch?: string;
}

export interface IntegrationNodeConfig extends PlaybookNodeData {
  nodeType: 'integration';
  integrationId: string;
  integrationName: string;
  operation: string;
  parameters: Record<string, unknown>;
  credentials?: string;
}

export interface LoopNodeConfig extends PlaybookNodeData {
  nodeType: 'loop';
  loopType: 'foreach' | 'while' | 'until';
  iterableField?: string;
  maxIterations?: number;
  condition?: PlaybookCondition;
}

export interface DelayNodeConfig extends PlaybookNodeData {
  nodeType: 'delay';
  delayType: 'fixed' | 'until';
  duration?: number; // Seconds
  untilTime?: string;
}

export interface NotificationNodeConfig extends PlaybookNodeData {
  nodeType: 'notification';
  channel: 'email' | 'slack' | 'teams' | 'webhook' | 'sms';
  recipients: string[];
  template?: string;
  message?: string;
  priority?: 'low' | 'normal' | 'high' | 'urgent';
}

export interface EnrichmentNodeConfig extends PlaybookNodeData {
  nodeType: 'enrichment';
  enrichmentType: 'geoip' | 'threat_intel' | 'asset' | 'user' | 'whois' | 'dns' | 'custom';
  targetField: string;
  outputField: string;
  sources?: string[];
}

export interface PlaybookNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: PlaybookNodeData;
}

export interface PlaybookEdge {
  id: string;
  source: string;
  target: string;
  sourceHandle?: string;
  targetHandle?: string;
  label?: string;
  type?: string;
  animated?: boolean;
  data?: {
    condition?: string;
    label?: string;
  };
}

export interface PlaybookVersion {
  version: number;
  createdAt: Date;
  createdBy: string;
  changeLog?: string;
  nodes: PlaybookNode[];
  edges: PlaybookEdge[];
}

export interface PlaybookExecution {
  id: string;
  playbookId: string;
  version: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused';
  startedAt: Date;
  completedAt?: Date;
  triggeredBy: string;
  triggerType: PlaybookTriggerType;
  context: Record<string, unknown>;
  currentNode?: string;
  nodeResults: {
    nodeId: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
    startedAt?: Date;
    completedAt?: Date;
    output?: Record<string, unknown>;
    error?: string;
  }[];
  error?: string;
}

export interface Playbook {
  id: string;
  name: string;
  description: string;
  status: PlaybookStatus;
  category: string;
  tags: string[];
  trigger: PlaybookTrigger;
  nodes: PlaybookNode[];
  edges: PlaybookEdge[];
  variables: {
    name: string;
    type: 'string' | 'number' | 'boolean' | 'array' | 'object';
    defaultValue?: unknown;
    description?: string;
  }[];
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  updatedBy: string;
  version: number;
  versions: PlaybookVersion[];
  executionCount: number;
  lastExecutedAt?: Date;
  averageExecutionTime?: number;
  successRate?: number;
  requiresApproval?: boolean;
  approvers?: string[];
}

export interface PlaybookFilter {
  status?: PlaybookStatus[];
  category?: string[];
  triggerType?: PlaybookTriggerType[];
  search?: string;
  tags?: string[];
  createdBy?: string;
}

export interface PlaybookStats {
  total: number;
  active: number;
  totalExecutions: number;
  successfulExecutions: number;
  failedExecutions: number;
  averageExecutionTime: number;
  byCategory: Record<string, number>;
  byStatus: Record<PlaybookStatus, number>;
  recentExecutions: PlaybookExecution[];
}

export interface PlaybookCreatePayload {
  name: string;
  description: string;
  category: string;
  trigger: PlaybookTrigger;
  nodes: PlaybookNode[];
  edges: PlaybookEdge[];
  variables?: Playbook['variables'];
  tags?: string[];
  requiresApproval?: boolean;
  approvers?: string[];
}

export interface PlaybookUpdatePayload {
  name?: string;
  description?: string;
  status?: PlaybookStatus;
  category?: string;
  trigger?: PlaybookTrigger;
  nodes?: PlaybookNode[];
  edges?: PlaybookEdge[];
  variables?: Playbook['variables'];
  tags?: string[];
  requiresApproval?: boolean;
  approvers?: string[];
  changeLog?: string;
}
