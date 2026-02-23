/**
 * Dashboard API - Statistics and metrics endpoints
 */

import { apiClient } from '@/api/client';
import type { TimeRangeParams } from '@/types/api';

// ============================================================================
// Types
// ============================================================================

export interface DashboardStats {
  activeAlerts: number;
  eps: number;
  openCases: number;
  detectionRate: number;
  meanTimeToDetect: number;
  meanTimeToRespond: number;
}

export interface AlertTrendData {
  timestamps: string[];
  critical: number[];
  high: number[];
  medium: number[];
  low: number[];
}

export interface TopAlert {
  id: string;
  name: string;
  severity: string;
  count: number;
  lastSeen: string;
}

export interface RecentCase {
  id: string;
  title: string;
  status: string;
  severity: string;
  assignee: string;
  createdAt: string;
  updatedAt: string;
}

export interface ThreatSummary {
  totalThreats: number;
  byCategory: { category: string; count: number }[];
  byTactic: { tactic: string; count: number }[];
  recentIOCs: { type: string; value: string; confidence: number }[];
}

export interface EPSMetric {
  timestamp: string;
  value: number;
}

export interface EPSMetricsResponse {
  metrics: EPSMetric[];
  average: number;
  peak: number;
  current: number;
}

// ============================================================================
// API Request Parameters
// ============================================================================

export interface AlertTrendParams extends TimeRangeParams {
  granularity?: 'minute' | 'hour' | 'day';
}

export interface TopAlertsParams {
  limit?: number;
  severity?: string;
}

export interface RecentCasesParams {
  limit?: number;
  status?: string;
}

export interface EPSMetricsParams extends TimeRangeParams {
  granularity?: 'minute' | 'hour';
}

// ============================================================================
// API Functions
// ============================================================================

/**
 * Get summary statistics for the dashboard
 */
export async function getDashboardStats(): Promise<DashboardStats> {
  const response = await apiClient.get<DashboardStats>('/dashboard/stats');

  if (!response.success || !response.data) {
    console.warn('Dashboard stats API not available, returning defaults');
    return {
      activeAlerts: 0,
      eps: 0,
      openCases: 0,
      detectionRate: 0,
      meanTimeToDetect: 0,
      meanTimeToRespond: 0,
    };
  }

  return response.data;
}

/**
 * Get alert trend data over time
 */
export async function getAlertTrend(
  params?: AlertTrendParams
): Promise<AlertTrendData> {
  const response = await apiClient.get<AlertTrendData>('/dashboard/alerts/trend', {
    params: {
      startTime: params?.startTime,
      endTime: params?.endTime,
      relativeTime: params?.relativeTime,
      granularity: params?.granularity,
    },
  });

  if (!response.success || !response.data) {
    console.warn('Alert trend API not available, returning defaults');
    return {
      timestamps: [],
      critical: [],
      high: [],
      medium: [],
      low: [],
    };
  }

  return response.data;
}

/**
 * Get top alerts by count
 */
export async function getTopAlerts(
  params?: TopAlertsParams
): Promise<TopAlert[]> {
  const response = await apiClient.get<TopAlert[]>('/dashboard/alerts/top', {
    params: {
      limit: params?.limit,
      severity: params?.severity,
    },
  });

  if (!response.success || !response.data) {
    console.warn('Top alerts API not available, returning empty array');
    return [];
  }

  return response.data;
}

/**
 * Get recent cases
 */
export async function getRecentCases(
  params?: RecentCasesParams
): Promise<RecentCase[]> {
  const response = await apiClient.get<RecentCase[]>('/dashboard/cases/recent', {
    params: {
      limit: params?.limit,
      status: params?.status,
    },
  });

  if (!response.success || !response.data) {
    console.warn('Recent cases API not available, returning empty array');
    return [];
  }

  return response.data;
}

/**
 * Get threat summary
 */
export async function getThreatSummary(): Promise<ThreatSummary> {
  const response = await apiClient.get<ThreatSummary>('/dashboard/threats/summary');

  if (!response.success || !response.data) {
    console.warn('Threat summary API not available, returning defaults');
    return {
      totalThreats: 0,
      byCategory: [],
      byTactic: [],
      recentIOCs: [],
    };
  }

  return response.data;
}

/**
 * Get EPS metrics over time
 */
export async function getEPSMetrics(
  params?: EPSMetricsParams
): Promise<EPSMetricsResponse> {
  const response = await apiClient.get<EPSMetricsResponse>('/dashboard/metrics/eps', {
    params: {
      startTime: params?.startTime,
      endTime: params?.endTime,
      relativeTime: params?.relativeTime,
      granularity: params?.granularity,
    },
  });

  if (!response.success || !response.data) {
    console.warn('EPS metrics API not available, returning defaults');
    return {
      metrics: [],
      average: 0,
      peak: 0,
      current: 0,
    };
  }

  return response.data;
}

// ============================================================================
// Dashboard API Object (for consistent exports)
// ============================================================================

export const dashboardApi = {
  getStats: getDashboardStats,
  getAlertTrend,
  getTopAlerts,
  getRecentCases,
  getThreatSummary,
  getEPSMetrics,
};

export default dashboardApi;
