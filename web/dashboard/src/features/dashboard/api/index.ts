/**
 * Dashboard API exports
 */

export {
  // API functions
  getDashboardStats,
  getAlertTrend,
  getTopAlerts,
  getRecentCases,
  getThreatSummary,
  getEPSMetrics,
  // API object
  dashboardApi,
  // Types
  type DashboardStats,
  type AlertTrendData,
  type TopAlert,
  type RecentCase,
  type ThreatSummary,
  type EPSMetric,
  type EPSMetricsResponse,
  type AlertTrendParams,
  type TopAlertsParams,
  type RecentCasesParams,
  type EPSMetricsParams,
} from './dashboardApi';
