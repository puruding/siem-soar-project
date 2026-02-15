/**
 * Alerts API - API functions for alert management
 */

import { apiClient } from './client';
import type {
  Alert,
  AlertFilter,
  AlertStats,
  AlertUpdatePayload,
} from '@/types/alert';
import type { ApiResponse, PaginationParams, TimeRangeParams } from '@/types/api';

interface GetAlertsParams extends PaginationParams, TimeRangeParams {
  filter?: AlertFilter;
}

interface GetAlertsResponse {
  alerts: Alert[];
  total: number;
  page: number;
  pageSize: number;
}

export const alertsApi = {
  /**
   * Get paginated list of alerts with optional filtering
   */
  async getAlerts(params?: GetAlertsParams): Promise<ApiResponse<GetAlertsResponse>> {
    const queryParams: Record<string, string | number | undefined> = {
      page: params?.page,
      pageSize: params?.pageSize,
      sortBy: params?.sortBy,
      sortOrder: params?.sortOrder,
      startTime: params?.startTime,
      endTime: params?.endTime,
      relativeTime: params?.relativeTime,
    };

    if (params?.filter) {
      if (params.filter.severity?.length) {
        queryParams.severity = params.filter.severity.join(',');
      }
      if (params.filter.status?.length) {
        queryParams.status = params.filter.status.join(',');
      }
      if (params.filter.search) {
        queryParams.search = params.filter.search;
      }
      if (params.filter.tags?.length) {
        queryParams.tags = params.filter.tags.join(',');
      }
      if (params.filter.assignee) {
        queryParams.assignee = params.filter.assignee;
      }
      if (params.filter.source?.length) {
        queryParams.source = params.filter.source.join(',');
      }
      if (params.filter.hasCase !== undefined) {
        queryParams.hasCase = params.filter.hasCase.toString();
      }
    }

    return apiClient.get<GetAlertsResponse>('/alerts', { params: queryParams });
  },

  /**
   * Get a single alert by ID
   */
  async getAlert(alertId: string): Promise<ApiResponse<Alert>> {
    return apiClient.get<Alert>(`/alerts/${alertId}`);
  },

  /**
   * Update an alert
   */
  async updateAlert(alertId: string, payload: AlertUpdatePayload): Promise<ApiResponse<Alert>> {
    return apiClient.patch<Alert>(`/alerts/${alertId}`, payload);
  },

  /**
   * Acknowledge an alert
   */
  async acknowledgeAlert(alertId: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${alertId}/acknowledge`);
  },

  /**
   * Close an alert
   */
  async closeAlert(alertId: string, reason?: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${alertId}/close`, { reason });
  },

  /**
   * Escalate an alert
   */
  async escalateAlert(alertId: string, message?: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${alertId}/escalate`, { message });
  },

  /**
   * Create a case from an alert
   */
  async createCaseFromAlert(alertId: string, caseTitle?: string): Promise<ApiResponse<{ caseId: string }>> {
    return apiClient.post<{ caseId: string }>(`/alerts/${alertId}/create-case`, { title: caseTitle });
  },

  /**
   * Run a playbook on an alert
   */
  async runPlaybook(alertId: string, playbookId: string): Promise<ApiResponse<{ executionId: string }>> {
    return apiClient.post<{ executionId: string }>(`/alerts/${alertId}/run-playbook`, { playbookId });
  },

  /**
   * Assign an alert to a user
   */
  async assignAlert(alertId: string, assigneeId: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${alertId}/assign`, { assigneeId });
  },

  /**
   * Add a note to an alert
   */
  async addNote(alertId: string, note: string): Promise<ApiResponse<Alert>> {
    return apiClient.post<Alert>(`/alerts/${alertId}/notes`, { note });
  },

  /**
   * Get alert statistics
   */
  async getStats(timeRange?: TimeRangeParams): Promise<ApiResponse<AlertStats>> {
    return apiClient.get<AlertStats>('/alerts/stats', {
      params: {
        startTime: timeRange?.startTime,
        endTime: timeRange?.endTime,
        relativeTime: timeRange?.relativeTime,
      },
    });
  },

  /**
   * Get alert timeline/events
   */
  async getAlertEvents(alertId: string): Promise<ApiResponse<Alert['events']>> {
    return apiClient.get<Alert['events']>(`/alerts/${alertId}/events`);
  },

  /**
   * Get related alerts
   */
  async getRelatedAlerts(alertId: string, limit?: number): Promise<ApiResponse<Alert[]>> {
    return apiClient.get<Alert[]>(`/alerts/${alertId}/related`, {
      params: { limit },
    });
  },

  /**
   * Bulk update alerts
   */
  async bulkUpdate(alertIds: string[], payload: AlertUpdatePayload): Promise<ApiResponse<{ updated: number }>> {
    return apiClient.post<{ updated: number }>('/alerts/bulk-update', {
      alertIds,
      ...payload,
    });
  },

  /**
   * Bulk acknowledge alerts
   */
  async bulkAcknowledge(alertIds: string[]): Promise<ApiResponse<{ acknowledged: number }>> {
    return apiClient.post<{ acknowledged: number }>('/alerts/bulk-acknowledge', { alertIds });
  },

  /**
   * Bulk close alerts
   */
  async bulkClose(alertIds: string[], reason?: string): Promise<ApiResponse<{ closed: number }>> {
    return apiClient.post<{ closed: number }>('/alerts/bulk-close', { alertIds, reason });
  },
};

export default alertsApi;
