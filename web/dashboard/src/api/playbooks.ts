/**
 * Playbooks API - API functions for playbook/automation management
 */

import { apiClient } from './client';
import type {
  Playbook,
  PlaybookFilter,
  PlaybookStats,
  PlaybookCreatePayload,
  PlaybookUpdatePayload,
  PlaybookExecution,
  PlaybookVersion,
} from '@/types/playbook';
import type { ApiResponse, PaginationParams } from '@/types/api';

interface GetPlaybooksParams extends PaginationParams {
  filter?: PlaybookFilter;
}

interface GetPlaybooksResponse {
  playbooks: Playbook[];
  total: number;
  page: number;
  pageSize: number;
}

interface GetExecutionsParams extends PaginationParams {
  playbookId?: string;
  status?: PlaybookExecution['status'][];
}

interface GetExecutionsResponse {
  executions: PlaybookExecution[];
  total: number;
  page: number;
  pageSize: number;
}

export const playbooksApi = {
  /**
   * Get paginated list of playbooks with optional filtering
   */
  async getPlaybooks(params?: GetPlaybooksParams): Promise<ApiResponse<GetPlaybooksResponse>> {
    const queryParams: Record<string, string | number | undefined> = {
      page: params?.page,
      pageSize: params?.pageSize,
      sortBy: params?.sortBy,
      sortOrder: params?.sortOrder,
    };

    if (params?.filter) {
      if (params.filter.status?.length) {
        queryParams.status = params.filter.status.join(',');
      }
      if (params.filter.category?.length) {
        queryParams.category = params.filter.category.join(',');
      }
      if (params.filter.triggerType?.length) {
        queryParams.triggerType = params.filter.triggerType.join(',');
      }
      if (params.filter.search) {
        queryParams.search = params.filter.search;
      }
      if (params.filter.tags?.length) {
        queryParams.tags = params.filter.tags.join(',');
      }
      if (params.filter.createdBy) {
        queryParams.createdBy = params.filter.createdBy;
      }
    }

    return apiClient.get<GetPlaybooksResponse>('/playbooks', { params: queryParams });
  },

  /**
   * Get a single playbook by ID
   */
  async getPlaybook(playbookId: string): Promise<ApiResponse<Playbook>> {
    return apiClient.get<Playbook>(`/playbooks/${playbookId}`);
  },

  /**
   * Create a new playbook
   */
  async createPlaybook(payload: PlaybookCreatePayload): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>('/playbooks', payload);
  },

  /**
   * Update a playbook
   */
  async updatePlaybook(playbookId: string, payload: PlaybookUpdatePayload): Promise<ApiResponse<Playbook>> {
    return apiClient.patch<Playbook>(`/playbooks/${playbookId}`, payload);
  },

  /**
   * Delete a playbook
   */
  async deletePlaybook(playbookId: string): Promise<ApiResponse<void>> {
    return apiClient.delete<void>(`/playbooks/${playbookId}`);
  },

  /**
   * Activate a playbook
   */
  async activatePlaybook(playbookId: string): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>(`/playbooks/${playbookId}/activate`);
  },

  /**
   * Deactivate a playbook
   */
  async deactivatePlaybook(playbookId: string): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>(`/playbooks/${playbookId}/deactivate`);
  },

  /**
   * Duplicate a playbook
   */
  async duplicatePlaybook(playbookId: string, newName?: string): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>(`/playbooks/${playbookId}/duplicate`, { name: newName });
  },

  /**
   * Execute a playbook manually
   */
  async executePlaybook(
    playbookId: string,
    context?: Record<string, unknown>
  ): Promise<ApiResponse<PlaybookExecution>> {
    return apiClient.post<PlaybookExecution>(`/playbooks/${playbookId}/execute`, { context });
  },

  /**
   * Test/dry-run a playbook
   */
  async testPlaybook(
    playbookId: string,
    context?: Record<string, unknown>
  ): Promise<ApiResponse<{ valid: boolean; errors: string[] }>> {
    return apiClient.post<{ valid: boolean; errors: string[] }>(`/playbooks/${playbookId}/test`, { context });
  },

  /**
   * Get playbook versions
   */
  async getVersions(playbookId: string): Promise<ApiResponse<PlaybookVersion[]>> {
    return apiClient.get<PlaybookVersion[]>(`/playbooks/${playbookId}/versions`);
  },

  /**
   * Get a specific version
   */
  async getVersion(playbookId: string, version: number): Promise<ApiResponse<PlaybookVersion>> {
    return apiClient.get<PlaybookVersion>(`/playbooks/${playbookId}/versions/${version}`);
  },

  /**
   * Restore a previous version
   */
  async restoreVersion(playbookId: string, version: number): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>(`/playbooks/${playbookId}/versions/${version}/restore`);
  },

  /**
   * Get playbook executions
   */
  async getExecutions(params?: GetExecutionsParams): Promise<ApiResponse<GetExecutionsResponse>> {
    const queryParams: Record<string, string | number | undefined> = {
      page: params?.page,
      pageSize: params?.pageSize,
      sortBy: params?.sortBy,
      sortOrder: params?.sortOrder,
      playbookId: params?.playbookId,
    };

    if (params?.status?.length) {
      queryParams.status = params.status.join(',');
    }

    return apiClient.get<GetExecutionsResponse>('/playbooks/executions', { params: queryParams });
  },

  /**
   * Get a specific execution
   */
  async getExecution(executionId: string): Promise<ApiResponse<PlaybookExecution>> {
    return apiClient.get<PlaybookExecution>(`/playbooks/executions/${executionId}`);
  },

  /**
   * Cancel an execution
   */
  async cancelExecution(executionId: string): Promise<ApiResponse<PlaybookExecution>> {
    return apiClient.post<PlaybookExecution>(`/playbooks/executions/${executionId}/cancel`);
  },

  /**
   * Retry a failed execution
   */
  async retryExecution(executionId: string, fromNode?: string): Promise<ApiResponse<PlaybookExecution>> {
    return apiClient.post<PlaybookExecution>(`/playbooks/executions/${executionId}/retry`, { fromNode });
  },

  /**
   * Get playbook statistics
   */
  async getStats(): Promise<ApiResponse<PlaybookStats>> {
    return apiClient.get<PlaybookStats>('/playbooks/stats');
  },

  /**
   * Get available categories
   */
  async getCategories(): Promise<ApiResponse<string[]>> {
    return apiClient.get<string[]>('/playbooks/categories');
  },

  /**
   * Get available integrations for playbook actions
   */
  async getIntegrations(): Promise<ApiResponse<{ id: string; name: string; actions: string[] }[]>> {
    return apiClient.get<{ id: string; name: string; actions: string[] }[]>('/playbooks/integrations');
  },

  /**
   * Import a playbook from JSON
   */
  async importPlaybook(playbookJson: Playbook): Promise<ApiResponse<Playbook>> {
    return apiClient.post<Playbook>('/playbooks/import', playbookJson);
  },

  /**
   * Export a playbook to JSON
   */
  async exportPlaybook(playbookId: string): Promise<ApiResponse<Playbook>> {
    return apiClient.get<Playbook>(`/playbooks/${playbookId}/export`);
  },
};

export default playbooksApi;
