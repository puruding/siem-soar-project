/**
 * Pipeline API - HTTP client for pipeline monitoring endpoints
 */

import { apiClient } from '@/api/client';
import type { ApiResponse } from '@/types/api';

// ============================================================================
// Types
// ============================================================================

export interface PipelineStatus {
  status: 'healthy' | 'degraded' | 'down';
  stages: StageStatus[];
  totalEps: number;
  errorRate: number;
  lastUpdated: string;
}

export interface StageStatus {
  name: string; // collector, parser, normalizer, enricher, router, detection
  status: 'running' | 'paused' | 'error';
  inputEps: number;
  outputEps: number;
  errorCount: number;
  lagMs: number;
  kafkaTopic: string;
  consumerGroup: string;
}

export interface StageMetrics {
  stage: string;
  throughput: number[];
  latency: number[];
  errors: number[];
  timestamps: string[];
}

export interface ThroughputData {
  totalEps: number;
  byStage: Record<string, number>;
  history: {
    timestamp: string;
    eps: number;
  }[];
}

export interface PipelineError {
  id: string;
  stage: string;
  message: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  stackTrace?: string;
}

export interface PipelineErrorsResponse {
  errors: PipelineError[];
  totalCount: number;
}

export interface StageActionResponse {
  success: boolean;
  stage: string;
  action: 'pause' | 'resume';
  timestamp: string;
  message?: string;
}

// ============================================================================
// API Functions
// ============================================================================

/**
 * Get overall pipeline status including all stages
 */
export async function getPipelineStatus(): Promise<ApiResponse<PipelineStatus>> {
  return apiClient.get<PipelineStatus>('/pipeline/status');
}

/**
 * Get all pipeline stage statuses
 */
export async function getStageStatuses(): Promise<ApiResponse<StageStatus[]>> {
  return apiClient.get<StageStatus[]>('/pipeline/stages');
}

/**
 * Get metrics for a specific stage
 * @param stageName - The stage name (collector, parser, normalizer, enricher, router, detection)
 * @param timeRange - Optional time range in minutes (default: 60)
 */
export async function getStageMetrics(
  stageName: string,
  timeRange?: number
): Promise<ApiResponse<StageMetrics>> {
  return apiClient.get<StageMetrics>(`/pipeline/stages/${stageName}/metrics`, {
    params: timeRange ? { timeRange } : undefined,
  });
}

/**
 * Pause a pipeline stage
 * @param stageName - The stage name to pause
 */
export async function pauseStage(stageName: string): Promise<ApiResponse<StageActionResponse>> {
  return apiClient.post<StageActionResponse>(`/pipeline/stages/${stageName}/pause`);
}

/**
 * Resume a paused pipeline stage
 * @param stageName - The stage name to resume
 */
export async function resumeStage(stageName: string): Promise<ApiResponse<StageActionResponse>> {
  return apiClient.post<StageActionResponse>(`/pipeline/stages/${stageName}/resume`);
}

/**
 * Get real-time throughput (events per second)
 * @param includeHistory - Whether to include historical data (default: false)
 * @param historyMinutes - How many minutes of history to include (default: 30)
 */
export async function getThroughput(
  includeHistory?: boolean,
  historyMinutes?: number
): Promise<ApiResponse<ThroughputData>> {
  return apiClient.get<ThroughputData>('/pipeline/throughput', {
    params: {
      includeHistory: includeHistory ?? false,
      historyMinutes: historyMinutes ?? 30,
    },
  });
}

/**
 * Get recent pipeline errors
 * @param limit - Maximum number of errors to return (default: 50)
 * @param severity - Filter by severity level
 * @param stage - Filter by stage name
 */
export async function getPipelineErrors(
  limit?: number,
  severity?: 'critical' | 'high' | 'medium' | 'low',
  stage?: string
): Promise<ApiResponse<PipelineErrorsResponse>> {
  return apiClient.get<PipelineErrorsResponse>('/pipeline/errors', {
    params: {
      limit: limit ?? 50,
      severity,
      stage,
    },
  });
}

// ============================================================================
// Convenience functions
// ============================================================================

/**
 * Fetch initial pipeline data for dashboard initialization
 * Returns status, throughput, and recent errors in parallel
 */
export async function fetchInitialPipelineData(): Promise<{
  status: ApiResponse<PipelineStatus>;
  throughput: ApiResponse<ThroughputData>;
  errors: ApiResponse<PipelineErrorsResponse>;
}> {
  const [status, throughput, errors] = await Promise.all([
    getPipelineStatus(),
    getThroughput(true, 60),
    getPipelineErrors(20),
  ]);

  return { status, throughput, errors };
}

/**
 * Toggle a stage's running state (pause if running, resume if paused)
 * @param stageName - The stage name
 * @param currentStatus - Current status of the stage
 */
export async function toggleStageStatus(
  stageName: string,
  currentStatus: 'running' | 'paused' | 'error'
): Promise<ApiResponse<StageActionResponse>> {
  if (currentStatus === 'running') {
    return pauseStage(stageName);
  } else if (currentStatus === 'paused') {
    return resumeStage(stageName);
  }
  // Cannot toggle a stage in error state
  return {
    success: false,
    error: {
      code: 'INVALID_STATE',
      message: 'Cannot toggle a stage in error state. Please resolve the error first.',
      timestamp: new Date().toISOString(),
    },
  };
}

// ============================================================================
// Export types for external use
// ============================================================================

export type {
  PipelineStatus as PipelineStatusType,
  StageStatus as StageStatusType,
  StageMetrics as StageMetricsType,
  ThroughputData as ThroughputDataType,
  PipelineError as PipelineErrorType,
  PipelineErrorsResponse as PipelineErrorsResponseType,
  StageActionResponse as StageActionResponseType,
};
