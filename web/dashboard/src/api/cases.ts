/**
 * Cases API - API functions for case/incident management
 */

import { apiClient } from './client';
import type {
  Case,
  CaseFilter,
  CaseStats,
  CaseCreatePayload,
  CaseUpdatePayload,
  CaseArtifact,
  CaseTimeline,
} from '@/types/case';
import type { ApiResponse, PaginationParams, TimeRangeParams } from '@/types/api';

interface GetCasesParams extends PaginationParams, TimeRangeParams {
  filter?: CaseFilter;
}

interface GetCasesResponse {
  cases: Case[];
  total: number;
  page: number;
  pageSize: number;
}

export const casesApi = {
  /**
   * Get paginated list of cases with optional filtering
   */
  async getCases(params?: GetCasesParams): Promise<ApiResponse<GetCasesResponse>> {
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
      if (params.filter.priority?.length) {
        queryParams.priority = params.filter.priority.join(',');
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
      if (params.filter.hasAlerts !== undefined) {
        queryParams.hasAlerts = params.filter.hasAlerts.toString();
      }
    }

    return apiClient.get<GetCasesResponse>('/cases', { params: queryParams });
  },

  /**
   * Get a single case by ID
   */
  async getCase(caseId: string): Promise<ApiResponse<Case>> {
    return apiClient.get<Case>(`/cases/${caseId}`);
  },

  /**
   * Create a new case
   */
  async createCase(payload: CaseCreatePayload): Promise<ApiResponse<Case>> {
    return apiClient.post<Case>('/cases', payload);
  },

  /**
   * Update a case
   */
  async updateCase(caseId: string, payload: CaseUpdatePayload): Promise<ApiResponse<Case>> {
    return apiClient.patch<Case>(`/cases/${caseId}`, payload);
  },

  /**
   * Delete a case
   */
  async deleteCase(caseId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/cases/${caseId}`);
  },

  /**
   * Assign a case to a user
   */
  async assignCase(caseId: string, assigneeId: string): Promise<ApiResponse<Case>> {
    return apiClient.post<Case>(`/cases/${caseId}/assign`, { assigneeId });
  },

  /**
   * Change case status
   */
  async changeStatus(caseId: string, status: Case['status'], comment?: string): Promise<ApiResponse<Case>> {
    return apiClient.post<Case>(`/cases/${caseId}/status`, { status, comment });
  },

  /**
   * Add an alert to a case
   */
  async addAlert(caseId: string, alertId: string): Promise<ApiResponse<Case>> {
    return apiClient.post<Case>(`/cases/${caseId}/alerts`, { alertId });
  },

  /**
   * Remove an alert from a case
   */
  async removeAlert(caseId: string, alertId: string): Promise<ApiResponse<Case>> {
    return apiClient.delete<Case>(`/cases/${caseId}/alerts/${alertId}`);
  },

  /**
   * Add an artifact to a case
   */
  async addArtifact(caseId: string, artifact: Omit<CaseArtifact, 'id' | 'addedAt' | 'addedBy'>): Promise<ApiResponse<CaseArtifact>> {
    return apiClient.post<CaseArtifact>(`/cases/${caseId}/artifacts`, artifact);
  },

  /**
   * Remove an artifact from a case
   */
  async removeArtifact(caseId: string, artifactId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/cases/${caseId}/artifacts/${artifactId}`);
  },

  /**
   * Get case timeline
   */
  async getTimeline(caseId: string): Promise<ApiResponse<CaseTimeline[]>> {
    return apiClient.get<CaseTimeline[]>(`/cases/${caseId}/timeline`);
  },

  /**
   * Add a comment to case timeline
   */
  async addComment(caseId: string, comment: string): Promise<ApiResponse<CaseTimeline>> {
    return apiClient.post<CaseTimeline>(`/cases/${caseId}/comments`, { comment });
  },

  /**
   * Run a playbook on a case
   */
  async runPlaybook(caseId: string, playbookId: string): Promise<ApiResponse<{ executionId: string }>> {
    return apiClient.post<{ executionId: string }>(`/cases/${caseId}/run-playbook`, { playbookId });
  },

  /**
   * Get case statistics
   */
  async getStats(timeRange?: TimeRangeParams): Promise<ApiResponse<CaseStats>> {
    return apiClient.get<CaseStats>('/cases/stats', {
      params: {
        startTime: timeRange?.startTime,
        endTime: timeRange?.endTime,
        relativeTime: timeRange?.relativeTime,
      },
    });
  },

  /**
   * Get related cases
   */
  async getRelatedCases(caseId: string, limit?: number): Promise<ApiResponse<Case[]>> {
    return apiClient.get<Case[]>(`/cases/${caseId}/related`, {
      params: { limit },
    });
  },

  /**
   * Merge cases
   */
  async mergeCases(targetCaseId: string, sourceCaseIds: string[]): Promise<ApiResponse<Case>> {
    return apiClient.post<Case>(`/cases/${targetCaseId}/merge`, { sourceCaseIds });
  },

  /**
   * Export case report
   */
  async exportReport(caseId: string, format: 'pdf' | 'html' | 'json'): Promise<ApiResponse<{ url: string }>> {
    return apiClient.get<{ url: string }>(`/cases/${caseId}/export`, {
      params: { format },
    });
  },

  /**
   * Upload attachment
   */
  async uploadAttachment(caseId: string, file: File, description?: string): Promise<ApiResponse<Case['attachments'][0]>> {
    const formData = new FormData();
    formData.append('file', file);
    if (description) {
      formData.append('description', description);
    }

    // Use fetch directly for file upload
    const response = await fetch(`${import.meta.env.VITE_API_URL || 'http://localhost:8080/api/v1'}/cases/${caseId}/attachments`, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      return {
        success: false,
        error: {
          code: `HTTP_${response.status}`,
          message: response.statusText,
          timestamp: new Date().toISOString(),
        },
      };
    }

    const data = await response.json();
    return { success: true, data };
  },
};

export default casesApi;
