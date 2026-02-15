/**
 * API type definitions for the SOC Dashboard
 */

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: ApiMeta;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  timestamp: string;
  requestId?: string;
}

export interface ApiMeta {
  page?: number;
  pageSize?: number;
  totalItems?: number;
  totalPages?: number;
  hasMore?: boolean;
}

export interface PaginationParams {
  page?: number;
  pageSize?: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface TimeRangeParams {
  startTime?: string;
  endTime?: string;
  relativeTime?: string; // e.g., '1h', '24h', '7d', '30d'
}

export interface SearchParams {
  query?: string;
  fields?: string[];
}

// WebSocket message types
export type WebSocketMessageType =
  | 'alert'
  | 'case_update'
  | 'playbook_status'
  | 'metric'
  | 'notification'
  | 'chat_response'
  | 'system'
  | 'error';

export interface WebSocketMessage<T = unknown> {
  type: WebSocketMessageType;
  timestamp: string;
  payload: T;
  correlationId?: string;
}

export interface AlertWebSocketPayload {
  alertId: string;
  action: 'created' | 'updated' | 'deleted';
  alert?: unknown;
}

export interface CaseWebSocketPayload {
  caseId: string;
  action: 'created' | 'updated' | 'deleted' | 'assigned' | 'status_changed';
  case?: unknown;
}

export interface PlaybookWebSocketPayload {
  executionId: string;
  playbookId: string;
  status: string;
  currentNode?: string;
  progress?: number;
  result?: Record<string, unknown>;
  error?: string;
}

export interface MetricWebSocketPayload {
  metricName: string;
  value: number;
  timestamp: string;
  labels?: Record<string, string>;
}

export interface NotificationWebSocketPayload {
  id: string;
  type: 'info' | 'warning' | 'error' | 'success';
  title: string;
  message: string;
  action?: {
    label: string;
    url: string;
  };
}

export interface ChatWebSocketPayload {
  messageId: string;
  conversationId: string;
  type: 'chunk' | 'done' | 'sql' | 'error';
  content?: string;
  sql?: string;
  results?: unknown[];
  columns?: string[];
  totalRows?: number;
  executionTime?: number;
}

// Copilot API types
export interface CopilotChatRequest {
  message: string;
  conversationId?: string;
  context?: Record<string, unknown>;
  sessionId?: string;
  language?: 'en' | 'ko' | 'auto';
}

export interface CopilotChatResponse {
  conversationId: string;
  message: string;
  queryType?: 'nl2sql' | 'summary' | 'recommendation' | 'similar_cases' | 'general';
  confidence?: number;
  generatedQuery?: string;
  queryResults?: {
    columns: string[];
    rows: Record<string, unknown>[];
    totalRows: number;
    executionTime: number;
  };
  suggestedPlaybooks?: string[];
  relatedAlerts?: string[];
  sources?: string[];
}

// Query API types
export interface QueryExecuteRequest {
  query: string;
  queryType?: 'sql' | 'kql' | 'spl' | 'eql';
  limit?: number;
  timeout?: number;
  explain?: boolean;
}

export interface QueryExecuteResponse {
  queryId: string;
  columns: string[];
  rows: Record<string, unknown>[];
  totalRows: number;
  executionTime: number;
  warnings?: string[];
  explain?: {
    plan: string;
    estimatedRows: number;
    estimatedCost: number;
  };
}

export interface QueryHistory {
  id: string;
  query: string;
  queryType: string;
  executedAt: Date;
  executedBy: string;
  rowCount: number;
  executionTime: number;
  status: 'completed' | 'failed' | 'cancelled';
  error?: string;
}

// Dashboard API types
export interface DashboardStats {
  activeAlerts: number;
  eps: number;
  openCases: number;
  detectionRate: number;
  mttd: number;
  mttr: number;
  falsePositiveRate: number;
}

export interface DashboardTrend {
  timestamp: Date;
  alerts: number;
  cases: number;
  events: number;
}

export interface ThreatMapData {
  locations: {
    id: string;
    lat: number;
    lng: number;
    country: string;
    threatLevel: 'critical' | 'high' | 'medium' | 'low';
    count: number;
  }[];
  connections: {
    sourceId: string;
    targetId: string;
    count: number;
  }[];
}

// Auth types
export interface User {
  id: string;
  username: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
  avatar?: string;
  department?: string;
  lastLogin?: Date;
}

export interface AuthToken {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  mfaCode?: string;
}

export interface LoginResponse {
  user: User;
  tokens: AuthToken;
  mfaRequired?: boolean;
}

// Integration types
export interface Integration {
  id: string;
  name: string;
  type: 'siem' | 'edr' | 'soar' | 'ticketing' | 'communication' | 'threat_intel' | 'custom';
  status: 'connected' | 'disconnected' | 'error' | 'configuring';
  config: Record<string, unknown>;
  capabilities: string[];
  lastSync?: Date;
  errorMessage?: string;
}

export interface IntegrationTestResult {
  success: boolean;
  latency?: number;
  message?: string;
  capabilities?: string[];
}
