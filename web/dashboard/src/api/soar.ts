/**
 * SOAR API Client - Handles SOAR execution history and playbook execution APIs
 */

import { apiClient } from './client';

/**
 * SOAR Execution status types
 */
export type SOARExecutionStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timed_out'
  | 'waiting_approval'
  | 'paused';

/**
 * SOAR Execution trigger types
 */
export type SOARTriggerType =
  | 'manual'
  | 'automatic'
  | 'scheduled'
  | 'webhook'
  | 'alert'
  | 'incident';

/**
 * Step result from execution
 */
export interface StepResult {
  step_id: string;
  step_name: string;
  step_type: string;
  status: SOARExecutionStatus;
  started_at: string;
  completed_at?: string;
  duration_ms: number;
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  error?: string;
  retries?: number;
}

/**
 * SOAR Execution record
 */
export interface SOARExecution {
  id: string;
  tenant_id: string;
  playbook_id: string;
  playbook_name: string;
  playbook_version?: number;
  status: SOARExecutionStatus;
  workflow_id?: string;
  run_id?: string;
  trigger_type: SOARTriggerType;
  trigger_info?: Record<string, unknown>;
  alert_id?: string;
  case_id?: string;
  inputs?: Record<string, unknown>;
  outputs?: Record<string, unknown>;
  current_step?: string;
  step_results?: StepResult[];
  error?: string;
  executed_by?: string;
  trace_id?: string;
  started_at: string;
  completed_at?: string;
  created_at?: string;
  updated_at?: string;
}

/**
 * Execution list response
 */
export interface ExecutionListResponse {
  executions: SOARExecution[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

/**
 * Alert executions response
 */
export interface AlertExecutionsResponse {
  executions: SOARExecution[];
  total: number;
  alert_id: string;
}

/**
 * Execution filter options
 */
export interface ExecutionFilter {
  playbook_id?: string;
  alert_id?: string;
  case_id?: string;
  tenant_id?: string;
  status?: SOARExecutionStatus;
  limit?: number;
  offset?: number;
}

/**
 * Execute playbook request
 */
export interface ExecutePlaybookRequest {
  playbook_id: string;
  alert_id?: string;
  case_id?: string;
  inputs?: Record<string, unknown>;
  async?: boolean;
}

/**
 * Execute playbook response
 */
export interface ExecutePlaybookResponse {
  execution_id: string;
  playbook_id: string;
  status: string;
  message: string;
}

/**
 * SOAR API client
 */
export const soarApi = {
  /**
   * Get executions for a specific alert
   */
  getAlertExecutions: async (alertId: string): Promise<SOARExecution[]> => {
    const response = await apiClient.get<AlertExecutionsResponse>(
      `/alerts/${alertId}/executions`
    );
    if (response.success && response.data) {
      return response.data.executions || [];
    }
    console.warn('Failed to fetch alert executions:', response.error);
    return [];
  },

  /**
   * Get a single execution by ID
   */
  getExecution: async (executionId: string): Promise<SOARExecution | null> => {
    const response = await apiClient.get<SOARExecution>(
      `/executions/${executionId}`
    );
    if (response.success && response.data) {
      return response.data;
    }
    console.warn('Failed to fetch execution:', response.error);
    return null;
  },

  /**
   * List executions with optional filters
   */
  listExecutions: async (
    filter?: ExecutionFilter
  ): Promise<ExecutionListResponse> => {
    const params: Record<string, string | number | boolean | undefined> = {};
    if (filter) {
      if (filter.playbook_id) params.playbook_id = filter.playbook_id;
      if (filter.alert_id) params.alert_id = filter.alert_id;
      if (filter.case_id) params.case_id = filter.case_id;
      if (filter.tenant_id) params.tenant_id = filter.tenant_id;
      if (filter.status) params.status = filter.status;
      if (filter.limit) params.limit = filter.limit;
      if (filter.offset) params.offset = filter.offset;
    }

    const response = await apiClient.get<ExecutionListResponse>('/executions', {
      params,
    });

    if (response.success && response.data) {
      return response.data;
    }

    console.warn('Failed to list executions:', response.error);
    return {
      executions: [],
      total: 0,
      limit: 100,
      offset: 0,
      has_more: false,
    };
  },

  /**
   * Execute a playbook
   */
  executePlaybook: async (
    request: ExecutePlaybookRequest
  ): Promise<ExecutePlaybookResponse | null> => {
    const response = await apiClient.post<ExecutePlaybookResponse>(
      `/playbooks/${request.playbook_id}/execute`,
      {
        alert_id: request.alert_id,
        case_id: request.case_id,
        inputs: request.inputs,
        async: request.async ?? true,
      }
    );

    if (response.success && response.data) {
      return response.data;
    }

    console.warn('Failed to execute playbook:', response.error);
    return null;
  },

  /**
   * Get the latest execution status for an alert
   * Returns the most recent execution if any exists
   */
  getLatestAlertExecution: async (
    alertId: string
  ): Promise<SOARExecution | null> => {
    const executions = await soarApi.getAlertExecutions(alertId);
    if (executions.length === 0) {
      return null;
    }
    // Executions are already sorted by created_at DESC from the API
    const latest = executions[0];
    return latest ?? null;
  },

  /**
   * Calculate progress percentage from execution
   */
  calculateProgress: (execution: SOARExecution): number => {
    if (execution.status === 'completed') return 100;
    if (execution.status === 'failed' || execution.status === 'cancelled') {
      const steps = execution.step_results || [];
      const completed = steps.filter(
        (s) => s.status === 'completed' || s.status === 'failed'
      ).length;
      return steps.length > 0 ? (completed / steps.length) * 100 : 0;
    }
    if (execution.status === 'pending') return 0;

    // For running executions, estimate progress
    const steps = execution.step_results || [];
    const completed = steps.filter((s) => s.status === 'completed').length;
    // Assume at least one more step remaining
    return steps.length > 0 ? (completed / (steps.length + 1)) * 100 : 10;
  },
};

export default soarApi;
