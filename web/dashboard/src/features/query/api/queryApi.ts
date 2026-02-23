/**
 * Query API - API module for the Query Console service
 *
 * Provides endpoints for:
 * - Query execution (SQL, KQL, SPL)
 * - Query history management
 * - Saved queries management
 * - Schema discovery
 * - Query validation
 */

import { apiClient } from '@/api/client';
import type { ApiResponse } from '@/types/api';

// ============================================================================
// Types
// ============================================================================

export type QueryLanguage = 'sql' | 'kql' | 'spl';

export interface QueryRequest {
  query: string;
  language: QueryLanguage;
  limit?: number;
  offset?: number;
  timeout?: number;
}

export interface QueryResponseData {
  columns: string[];
  rows: unknown[][];
  total: number;
  executionTimeMs: number;
}

export interface QueryResponse {
  success: boolean;
  data: QueryResponseData;
  error?: string;
}

export interface SavedQuery {
  id: string;
  name: string;
  description: string;
  query: string;
  language: QueryLanguage;
  createdAt: string;
  createdBy: string;
  updatedAt?: string;
  tags?: string[];
  isPublic?: boolean;
}

export interface SaveQueryRequest {
  name: string;
  description: string;
  query: string;
  language: QueryLanguage;
  tags?: string[];
  isPublic?: boolean;
}

export interface UpdateSavedQueryRequest {
  name?: string;
  description?: string;
  query?: string;
  language?: QueryLanguage;
  tags?: string[];
  isPublic?: boolean;
}

export interface QueryHistoryItem {
  id: string;
  query: string;
  language: QueryLanguage;
  status: 'success' | 'error';
  rowCount: number;
  executionTimeMs: number;
  executedAt: string;
  executedBy?: string;
  errorMessage?: string;
}

export interface QueryHistoryParams {
  page?: number;
  pageSize?: number;
  status?: 'success' | 'error' | 'all';
  language?: QueryLanguage;
  startDate?: string;
  endDate?: string;
}

export interface QueryHistoryResponse {
  items: QueryHistoryItem[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}

export interface SchemaField {
  name: string;
  type: string;
  description: string;
  table: string;
  nullable?: boolean;
  isPrimaryKey?: boolean;
  isForeignKey?: boolean;
  references?: string;
}

export interface SchemaTable {
  name: string;
  description: string;
  rowCount?: number;
  columns: SchemaField[];
}

export interface SchemaResponse {
  tables: SchemaTable[];
  version?: string;
  lastUpdated?: string;
}

export interface ValidationError {
  code: string;
  message: string;
  line?: number;
  column?: number;
  position?: number;
  severity: 'error' | 'warning';
  suggestion?: string;
}

export interface ValidateQueryRequest {
  query: string;
  language: QueryLanguage;
}

export interface ValidateQueryResponse {
  valid: boolean;
  errors: ValidationError[];
  warnings: ValidationError[];
  normalizedQuery?: string;
  estimatedCost?: number;
  estimatedRowCount?: number;
}

// ============================================================================
// API Functions
// ============================================================================

const QUERY_API_BASE = '/query';

/**
 * Execute a query
 * POST /api/v1/query
 */
export async function executeQuery(request: QueryRequest): Promise<ApiResponse<QueryResponse>> {
  const response = await apiClient.post<QueryResponse>(QUERY_API_BASE, {
    query: request.query,
    language: request.language,
    limit: request.limit ?? 1000,
    offset: request.offset ?? 0,
    timeout: request.timeout ?? 30000,
  });

  return response;
}

/**
 * Get query execution history
 * GET /api/v1/query/history
 */
export async function getQueryHistory(
  params?: QueryHistoryParams
): Promise<ApiResponse<QueryHistoryResponse>> {
  return apiClient.get<QueryHistoryResponse>(`${QUERY_API_BASE}/history`, {
    params: {
      page: params?.page ?? 1,
      pageSize: params?.pageSize ?? 50,
      status: params?.status !== 'all' ? params?.status : undefined,
      language: params?.language,
      startDate: params?.startDate,
      endDate: params?.endDate,
    },
  });
}

/**
 * Clear query history
 * DELETE /api/v1/query/history
 */
export async function clearQueryHistory(): Promise<ApiResponse<{ deleted: number }>> {
  return apiClient.delete<{ deleted: number }>(`${QUERY_API_BASE}/history`);
}

/**
 * Delete a specific history item
 * DELETE /api/v1/query/history/{id}
 */
export async function deleteHistoryItem(id: string): Promise<ApiResponse<void>> {
  return apiClient.delete<void>(`${QUERY_API_BASE}/history/${id}`);
}

/**
 * Save a query
 * POST /api/v1/query/save
 */
export async function saveQuery(request: SaveQueryRequest): Promise<ApiResponse<SavedQuery>> {
  return apiClient.post<SavedQuery>(`${QUERY_API_BASE}/save`, request);
}

/**
 * Get all saved queries
 * GET /api/v1/query/saved
 */
export async function getSavedQueries(params?: {
  page?: number;
  pageSize?: number;
  tags?: string[];
  search?: string;
}): Promise<ApiResponse<{ items: SavedQuery[]; total: number }>> {
  return apiClient.get<{ items: SavedQuery[]; total: number }>(`${QUERY_API_BASE}/saved`, {
    params: {
      page: params?.page ?? 1,
      pageSize: params?.pageSize ?? 50,
      tags: params?.tags?.join(','),
      search: params?.search,
    },
  });
}

/**
 * Get a specific saved query
 * GET /api/v1/query/saved/{id}
 */
export async function getSavedQuery(id: string): Promise<ApiResponse<SavedQuery>> {
  return apiClient.get<SavedQuery>(`${QUERY_API_BASE}/saved/${id}`);
}

/**
 * Update a saved query
 * PUT /api/v1/query/saved/{id}
 */
export async function updateSavedQuery(
  id: string,
  request: UpdateSavedQueryRequest
): Promise<ApiResponse<SavedQuery>> {
  return apiClient.put<SavedQuery>(`${QUERY_API_BASE}/saved/${id}`, request);
}

/**
 * Delete a saved query
 * DELETE /api/v1/query/saved/{id}
 */
export async function deleteSavedQuery(id: string): Promise<ApiResponse<void>> {
  return apiClient.delete<void>(`${QUERY_API_BASE}/saved/${id}`);
}

/**
 * Get database schema (available tables and fields)
 * GET /api/v1/query/schema
 */
export async function getSchema(params?: {
  refresh?: boolean;
  tables?: string[];
}): Promise<ApiResponse<SchemaResponse>> {
  return apiClient.get<SchemaResponse>(`${QUERY_API_BASE}/schema`, {
    params: {
      refresh: params?.refresh,
      tables: params?.tables?.join(','),
    },
  });
}

/**
 * Get schema for a specific table
 * GET /api/v1/query/schema/{table}
 */
export async function getTableSchema(table: string): Promise<ApiResponse<SchemaTable>> {
  return apiClient.get<SchemaTable>(`${QUERY_API_BASE}/schema/${table}`);
}

/**
 * Validate query syntax
 * POST /api/v1/query/validate
 */
export async function validateQuery(
  request: ValidateQueryRequest
): Promise<ApiResponse<ValidateQueryResponse>> {
  return apiClient.post<ValidateQueryResponse>(`${QUERY_API_BASE}/validate`, request);
}

/**
 * Get query explain plan
 * POST /api/v1/query/explain
 */
export async function explainQuery(request: QueryRequest): Promise<ApiResponse<{
  plan: string;
  estimatedRows: number;
  estimatedCost: number;
  steps: Array<{
    operation: string;
    table?: string;
    rows?: number;
    cost?: number;
  }>;
}>> {
  return apiClient.post(`${QUERY_API_BASE}/explain`, {
    query: request.query,
    language: request.language,
  });
}

/**
 * Export query results
 * POST /api/v1/query/export
 */
export async function exportQueryResults(params: {
  query: string;
  language: QueryLanguage;
  format: 'csv' | 'json' | 'xlsx';
  filename?: string;
}): Promise<Blob> {
  const response = await fetch(`/api/v1${QUERY_API_BASE}/export`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      query: params.query,
      language: params.language,
      format: params.format,
      filename: params.filename,
    }),
  });

  if (!response.ok) {
    throw new Error(`Export failed: ${response.statusText}`);
  }

  return response.blob();
}

/**
 * Cancel a running query
 * POST /api/v1/query/cancel/{queryId}
 */
export async function cancelQuery(queryId: string): Promise<ApiResponse<{ cancelled: boolean }>> {
  return apiClient.post<{ cancelled: boolean }>(`${QUERY_API_BASE}/cancel/${queryId}`);
}

// ============================================================================
// React Query Hooks (Optional - for use with @tanstack/react-query)
// ============================================================================

/**
 * Query keys for React Query cache management
 */
export const queryKeys = {
  all: ['query'] as const,
  history: (params?: QueryHistoryParams) => [...queryKeys.all, 'history', params] as const,
  saved: (params?: { page?: number; pageSize?: number; tags?: string[] }) =>
    [...queryKeys.all, 'saved', params] as const,
  savedById: (id: string) => [...queryKeys.all, 'saved', id] as const,
  schema: (params?: { tables?: string[] }) => [...queryKeys.all, 'schema', params] as const,
  tableSchema: (table: string) => [...queryKeys.all, 'schema', 'table', table] as const,
};

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Convert query response rows from array format to object format
 */
export function rowsToObjects(
  columns: string[],
  rows: unknown[][]
): Record<string, unknown>[] {
  return rows.map((row) => {
    const obj: Record<string, unknown> = {};
    columns.forEach((col, idx) => {
      obj[col] = row[idx];
    });
    return obj;
  });
}

/**
 * Download query results as a file
 */
export async function downloadQueryResults(params: {
  query: string;
  language: QueryLanguage;
  format: 'csv' | 'json' | 'xlsx';
  filename?: string;
}): Promise<void> {
  const blob = await exportQueryResults(params);
  const url = URL.createObjectURL(blob);
  const extension = params.format === 'xlsx' ? 'xlsx' : params.format;
  const filename = params.filename || `query_results_${Date.now()}.${extension}`;

  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/**
 * Format execution time for display
 */
export function formatExecutionTime(ms: number): string {
  if (ms < 1000) {
    return `${ms}ms`;
  }
  if (ms < 60000) {
    return `${(ms / 1000).toFixed(2)}s`;
  }
  const minutes = Math.floor(ms / 60000);
  const seconds = ((ms % 60000) / 1000).toFixed(0);
  return `${minutes}m ${seconds}s`;
}

/**
 * Estimate query complexity based on query text
 */
export function estimateQueryComplexity(
  query: string
): 'simple' | 'moderate' | 'complex' {
  const normalizedQuery = query.toLowerCase();

  // Complex indicators
  const complexPatterns = [
    /\bjoin\b.*\bjoin\b/i,  // Multiple JOINs
    /\bwith\b.*\bas\b/i,     // CTEs
    /\bunion\b/i,            // UNIONs
    /\bexists\b/i,           // Subqueries with EXISTS
    /\bcase\b.*\bwhen\b.*\bwhen\b/i, // Multiple CASE WHENs
  ];

  // Moderate indicators
  const moderatePatterns = [
    /\bjoin\b/i,             // Single JOIN
    /\bgroup\s+by\b/i,       // GROUP BY
    /\bhaving\b/i,           // HAVING clause
    /\border\s+by\b/i,       // ORDER BY
    /\bsubstring\b|\bconcat\b|\bcoalesce\b/i, // String functions
  ];

  if (complexPatterns.some((p) => p.test(normalizedQuery))) {
    return 'complex';
  }

  if (moderatePatterns.some((p) => p.test(normalizedQuery))) {
    return 'moderate';
  }

  return 'simple';
}

export default {
  executeQuery,
  getQueryHistory,
  clearQueryHistory,
  deleteHistoryItem,
  saveQuery,
  getSavedQueries,
  getSavedQuery,
  updateSavedQuery,
  deleteSavedQuery,
  getSchema,
  getTableSchema,
  validateQuery,
  explainQuery,
  exportQueryResults,
  cancelQuery,
  rowsToObjects,
  downloadQueryResults,
  formatExecutionTime,
  estimateQueryComplexity,
  queryKeys,
};
