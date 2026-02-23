/**
 * Rules API - Detection Service API client for Sigma rules management
 */

import apiClient from '@/api/client';
import type { ApiResponse, PaginationParams } from '@/types/api';

// API Response type (snake_case from backend)
interface RuleApiResponse {
  id: string;
  name: string;
  description?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'enabled' | 'disabled';
  content?: string;
  author?: string;
  tags?: string[] | null;
  mitre_tactics?: string[] | null;
  mitre_techniques?: string[] | null;
  created_at: string;
  updated_at: string;
  hit_count?: number;
  last_hit_at?: string | null;
}

// Rule type definition for frontend (camelCase)
export interface Rule {
  id: string;
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'enabled' | 'disabled';
  content: string; // Sigma YAML
  author: string;
  tags: string[];
  mitreTactics: string[];
  mitreTechniques: string[];
  createdAt: string;
  updatedAt: string;
  hitCount: number;
  lastHitAt: string | null;
}

// Transform API response to frontend format
function transformRuleResponse(apiRule: RuleApiResponse): Rule {
  return {
    id: apiRule.id,
    name: apiRule.name,
    description: apiRule.description || '',
    severity: apiRule.severity,
    status: apiRule.status,
    content: apiRule.content || '',
    author: apiRule.author || 'Unknown',
    tags: apiRule.tags || [],
    mitreTactics: apiRule.mitre_tactics || [],
    mitreTechniques: apiRule.mitre_techniques || [],
    createdAt: apiRule.created_at,
    updatedAt: apiRule.updated_at,
    hitCount: apiRule.hit_count || 0,
    lastHitAt: apiRule.last_hit_at ?? null,
  };
}

// Request/Response types
export interface RuleListParams extends PaginationParams {
  status?: 'enabled' | 'disabled';
  severity?: 'low' | 'medium' | 'high' | 'critical';
  tactic?: string;
  search?: string;
  tags?: string[];
}

export interface RuleListResponse {
  rules: Rule[];
  total: number;
  page: number;
  pageSize: number;
}

export interface CreateRuleRequest {
  name: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  content: string; // Sigma YAML
  author: string;
  tags?: string[];
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

export interface UpdateRuleRequest {
  name?: string;
  description?: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  content?: string;
  author?: string;
  tags?: string[];
  mitreTactics?: string[];
  mitreTechniques?: string[];
}

export interface RuleTestRequest {
  ruleContent: string; // Sigma YAML to test
  sampleEvents: Record<string, unknown>[]; // Events to test against
}

export interface RuleTestMatch {
  eventIndex: number;
  matchedConditions: string[];
  event: Record<string, unknown>;
}

export interface RuleTestResponse {
  success: boolean;
  matchedEvents: number;
  totalEvents: number;
  matches: RuleTestMatch[];
  executionTime: number;
  error?: string;
}

export interface RuleStats {
  ruleId: string;
  totalHits: number;
  hitsByDay: { date: string; count: number }[];
  hitsBySeverity: Record<string, number>;
  averageHitsPerDay: number;
  lastHitAt: string | null;
  falsePositiveRate: number;
  truePositiveRate: number;
}

// API functions
const RULES_ENDPOINT = '/rules';

// API List Response type (snake_case from backend)
interface RuleListApiResponse {
  rules: RuleApiResponse[];
  total: number;
  page?: number;
  pageSize?: number;
}

/**
 * List all rules with optional filtering and pagination
 */
export async function listRules(
  params?: RuleListParams
): Promise<ApiResponse<RuleListResponse>> {
  const queryParams: Record<string, string | number | boolean | undefined> = {};

  if (params) {
    if (params.page !== undefined) queryParams.page = params.page;
    if (params.pageSize !== undefined) queryParams.pageSize = params.pageSize;
    if (params.sortBy) queryParams.sortBy = params.sortBy;
    if (params.sortOrder) queryParams.sortOrder = params.sortOrder;
    if (params.status) queryParams.status = params.status;
    if (params.severity) queryParams.severity = params.severity;
    if (params.tactic) queryParams.tactic = params.tactic;
    if (params.search) queryParams.search = params.search;
    if (params.tags && params.tags.length > 0) {
      queryParams.tags = params.tags.join(',');
    }
  }

  const response = await apiClient.get<RuleListApiResponse>(RULES_ENDPOINT, { params: queryParams });

  // Transform snake_case response to camelCase
  if (response.success && response.data) {
    return {
      success: true,
      data: {
        rules: response.data.rules.map(transformRuleResponse),
        total: response.data.total,
        page: response.data.page || 1,
        pageSize: response.data.pageSize || 20,
      },
    };
  }

  return {
    success: false,
    error: response.error || {
      code: 'RULES_FETCH_ERROR',
      message: 'Failed to fetch rules',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Get a specific rule by ID
 */
export async function getRule(id: string): Promise<ApiResponse<Rule>> {
  const response = await apiClient.get<RuleApiResponse>(`${RULES_ENDPOINT}/${id}`);
  if (response.success && response.data) {
    return { success: true, data: transformRuleResponse(response.data) };
  }
  return {
    success: false,
    error: response.error || {
      code: 'RULE_FETCH_ERROR',
      message: 'Failed to fetch rule',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Create a new rule from Sigma YAML
 */
export async function createRule(
  data: CreateRuleRequest
): Promise<ApiResponse<Rule>> {
  const response = await apiClient.post<RuleApiResponse>(RULES_ENDPOINT, data);
  if (response.success && response.data) {
    return { success: true, data: transformRuleResponse(response.data) };
  }
  return {
    success: false,
    error: response.error || {
      code: 'RULE_CREATE_ERROR',
      message: 'Failed to create rule',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Update an existing rule
 */
export async function updateRule(
  id: string,
  data: UpdateRuleRequest
): Promise<ApiResponse<Rule>> {
  const response = await apiClient.put<RuleApiResponse>(`${RULES_ENDPOINT}/${id}`, data);
  if (response.success && response.data) {
    return { success: true, data: transformRuleResponse(response.data) };
  }
  return {
    success: false,
    error: response.error || {
      code: 'RULE_UPDATE_ERROR',
      message: 'Failed to update rule',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Delete a rule
 */
export async function deleteRule(id: string): Promise<ApiResponse<void>> {
  return apiClient.delete<void>(`${RULES_ENDPOINT}/${id}`);
}

/**
 * Enable a rule
 */
export async function enableRule(id: string): Promise<ApiResponse<Rule>> {
  const response = await apiClient.post<RuleApiResponse>(`${RULES_ENDPOINT}/${id}/enable`);
  if (response.success && response.data) {
    return { success: true, data: transformRuleResponse(response.data) };
  }
  return {
    success: false,
    error: response.error || {
      code: 'RULE_ENABLE_ERROR',
      message: 'Failed to enable rule',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Disable a rule
 */
export async function disableRule(id: string): Promise<ApiResponse<Rule>> {
  const response = await apiClient.post<RuleApiResponse>(`${RULES_ENDPOINT}/${id}/disable`);
  if (response.success && response.data) {
    return { success: true, data: transformRuleResponse(response.data) };
  }
  return {
    success: false,
    error: response.error || {
      code: 'RULE_DISABLE_ERROR',
      message: 'Failed to disable rule',
      timestamp: new Date().toISOString(),
    },
  };
}

/**
 * Test a rule against sample events
 */
export async function testRule(
  data: RuleTestRequest
): Promise<ApiResponse<RuleTestResponse>> {
  return apiClient.post<RuleTestResponse>(`${RULES_ENDPOINT}/test`, data);
}

/**
 * Test a specific rule by ID against sample events
 */
export async function testRuleById(
  id: string,
  sampleEvents: Record<string, unknown>[]
): Promise<ApiResponse<RuleTestResponse>> {
  return apiClient.post<RuleTestResponse>(`${RULES_ENDPOINT}/${id}/test`, {
    sampleEvents,
  });
}

/**
 * Get rule statistics
 */
export async function getRuleStats(id: string): Promise<ApiResponse<RuleStats>> {
  return apiClient.get<RuleStats>(`${RULES_ENDPOINT}/${id}/stats`);
}

/**
 * Bulk enable rules
 */
export async function bulkEnableRules(
  ids: string[]
): Promise<ApiResponse<{ updated: number; failed: string[] }>> {
  return apiClient.post<{ updated: number; failed: string[] }>(
    `${RULES_ENDPOINT}/bulk/enable`,
    { ids }
  );
}

/**
 * Bulk disable rules
 */
export async function bulkDisableRules(
  ids: string[]
): Promise<ApiResponse<{ updated: number; failed: string[] }>> {
  return apiClient.post<{ updated: number; failed: string[] }>(
    `${RULES_ENDPOINT}/bulk/disable`,
    { ids }
  );
}

/**
 * Bulk delete rules
 */
export async function bulkDeleteRules(
  ids: string[]
): Promise<ApiResponse<{ deleted: number; failed: string[] }>> {
  return apiClient.post<{ deleted: number; failed: string[] }>(
    `${RULES_ENDPOINT}/bulk/delete`,
    { ids }
  );
}

/**
 * Import rules from YAML content (supports multiple rules)
 */
export async function importRules(
  yamlContent: string
): Promise<ApiResponse<{ imported: Rule[]; errors: { line: number; message: string }[] }>> {
  return apiClient.post<{ imported: Rule[]; errors: { line: number; message: string }[] }>(
    `${RULES_ENDPOINT}/import`,
    { content: yamlContent }
  );
}

/**
 * Export rules to YAML format
 */
export async function exportRules(
  ids?: string[]
): Promise<ApiResponse<{ content: string; count: number }>> {
  const params: Record<string, string | undefined> = {};
  if (ids && ids.length > 0) {
    params.ids = ids.join(',');
  }
  return apiClient.get<{ content: string; count: number }>(
    `${RULES_ENDPOINT}/export`,
    { params }
  );
}

// Export all functions as a namespace object for convenience
export const rulesApi = {
  list: listRules,
  get: getRule,
  create: createRule,
  update: updateRule,
  delete: deleteRule,
  enable: enableRule,
  disable: disableRule,
  test: testRule,
  testById: testRuleById,
  getStats: getRuleStats,
  bulkEnable: bulkEnableRules,
  bulkDisable: bulkDisableRules,
  bulkDelete: bulkDeleteRules,
  import: importRules,
  export: exportRules,
};

export default rulesApi;
