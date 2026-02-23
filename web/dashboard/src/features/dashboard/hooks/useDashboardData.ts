import { useQuery } from '@tanstack/react-query';
import {
  getDashboardStats,
  getAlertTrend,
  getTopAlerts,
  getRecentCases,
  getThreatSummary,
  getEPSMetrics,
  type DashboardStats,
  type AlertTrendData,
  type TopAlert,
  type RecentCase,
  type ThreatSummary,
  type EPSMetricsResponse,
  type AlertTrendParams,
  type TopAlertsParams,
  type RecentCasesParams,
  type EPSMetricsParams,
} from '../api/dashboardApi';

// Re-export types for convenience
export type {
  DashboardStats,
  AlertTrendData,
  TopAlert,
  RecentCase,
  ThreatSummary,
  EPSMetricsResponse,
};

const DEFAULT_STATS: DashboardStats = {
  activeAlerts: 0,
  eps: 0,
  openCases: 0,
  detectionRate: 0,
  meanTimeToDetect: 0,
  meanTimeToRespond: 0,
};

const DEFAULT_ALERT_TREND: AlertTrendData = {
  timestamps: [],
  critical: [],
  high: [],
  medium: [],
  low: [],
};

const DEFAULT_THREAT_SUMMARY: ThreatSummary = {
  totalThreats: 0,
  byCategory: [],
  byTactic: [],
  recentIOCs: [],
};

const DEFAULT_EPS_METRICS: EPSMetricsResponse = {
  metrics: [],
  average: 0,
  peak: 0,
  current: 0,
};

/**
 * Hook for fetching dashboard summary statistics
 */
export function useDashboardData() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: getDashboardStats,
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  return {
    stats: data ?? DEFAULT_STATS,
    isLoading,
    error,
    refetch,
  };
}

/**
 * Hook for fetching alert trend data
 */
export function useAlertTrend(params?: AlertTrendParams) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-alert-trend', params],
    queryFn: () => getAlertTrend(params),
    refetchInterval: 60000, // Refresh every minute
  });

  return {
    alertTrend: data ?? DEFAULT_ALERT_TREND,
    isLoading,
    error,
    refetch,
  };
}

/**
 * Hook for fetching top alerts
 */
export function useTopAlerts(params?: TopAlertsParams) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-top-alerts', params],
    queryFn: () => getTopAlerts(params),
    refetchInterval: 60000, // Refresh every minute
  });

  return {
    topAlerts: data ?? [],
    isLoading,
    error,
    refetch,
  };
}

/**
 * Hook for fetching recent cases
 */
export function useRecentCases(params?: RecentCasesParams) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-recent-cases', params],
    queryFn: () => getRecentCases(params),
    refetchInterval: 60000, // Refresh every minute
  });

  return {
    recentCases: data ?? [],
    isLoading,
    error,
    refetch,
  };
}

/**
 * Hook for fetching threat summary
 */
export function useThreatSummary() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-threat-summary'],
    queryFn: getThreatSummary,
    refetchInterval: 120000, // Refresh every 2 minutes
  });

  return {
    threatSummary: data ?? DEFAULT_THREAT_SUMMARY,
    isLoading,
    error,
    refetch,
  };
}

/**
 * Hook for fetching EPS metrics
 */
export function useEPSMetrics(params?: EPSMetricsParams) {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['dashboard-eps-metrics', params],
    queryFn: () => getEPSMetrics(params),
    refetchInterval: 30000, // Refresh every 30 seconds
  });

  return {
    epsMetrics: data ?? DEFAULT_EPS_METRICS,
    isLoading,
    error,
    refetch,
  };
}

/**
 * Combined hook for fetching all dashboard data at once
 */
export function useAllDashboardData(options?: {
  alertTrendParams?: AlertTrendParams;
  topAlertsParams?: TopAlertsParams;
  recentCasesParams?: RecentCasesParams;
  epsMetricsParams?: EPSMetricsParams;
}) {
  const stats = useDashboardData();
  const alertTrend = useAlertTrend(options?.alertTrendParams);
  const topAlerts = useTopAlerts(options?.topAlertsParams);
  const recentCases = useRecentCases(options?.recentCasesParams);
  const threatSummary = useThreatSummary();
  const epsMetrics = useEPSMetrics(options?.epsMetricsParams);

  const isLoading =
    stats.isLoading ||
    alertTrend.isLoading ||
    topAlerts.isLoading ||
    recentCases.isLoading ||
    threatSummary.isLoading ||
    epsMetrics.isLoading;

  const error =
    stats.error ||
    alertTrend.error ||
    topAlerts.error ||
    recentCases.error ||
    threatSummary.error ||
    epsMetrics.error;

  const refetchAll = () => {
    stats.refetch();
    alertTrend.refetch();
    topAlerts.refetch();
    recentCases.refetch();
    threatSummary.refetch();
    epsMetrics.refetch();
  };

  return {
    stats: stats.stats,
    alertTrend: alertTrend.alertTrend,
    topAlerts: topAlerts.topAlerts,
    recentCases: recentCases.recentCases,
    threatSummary: threatSummary.threatSummary,
    epsMetrics: epsMetrics.epsMetrics,
    isLoading,
    error,
    refetchAll,
  };
}
