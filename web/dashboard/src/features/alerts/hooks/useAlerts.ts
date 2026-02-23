/**
 * useAlerts Hook - Alert management with real API integration
 */

import { useState, useEffect, useCallback } from 'react';
import { alertsApi } from '@/api/alerts';
import type { Alert, AlertFilter, AlertUpdatePayload } from '@/types/alert';
import type { PaginationParams } from '@/types/api';

interface UseAlertsOptions {
  filter?: AlertFilter;
  pagination?: PaginationParams;
  autoRefresh?: boolean;
  refreshInterval?: number; // in milliseconds
}

interface UseAlertsReturn {
  // State
  alerts: Alert[];
  loading: boolean;
  error: string | null;
  total: number;
  page: number;
  pageSize: number;

  // Actions
  fetchAlerts: () => Promise<void>;
  getAlert: (alertId: string) => Promise<Alert | null>;
  updateAlert: (alertId: string, payload: AlertUpdatePayload) => Promise<Alert | null>;
  acknowledgeAlert: (alertId: string) => Promise<Alert | null>;
  closeAlert: (alertId: string, reason?: string) => Promise<Alert | null>;
  escalateToCase: (alertId: string, caseTitle?: string) => Promise<{ caseId: string } | null>;
  bulkAcknowledge: (alertIds: string[]) => Promise<number>;
  bulkClose: (alertIds: string[], reason?: string) => Promise<number>;

  // Refresh control
  setFilter: (filter: AlertFilter) => void;
  setPagination: (pagination: Partial<PaginationParams>) => void;
  refresh: () => void;
}

export function useAlerts(options: UseAlertsOptions = {}): UseAlertsReturn {
  const {
    filter: initialFilter,
    pagination: initialPagination,
    autoRefresh = false,
    refreshInterval = 10000, // 10 seconds default
  } = options;

  // State
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [total, setTotal] = useState<number>(0);
  const [filter, setFilter] = useState<AlertFilter | undefined>(initialFilter);
  const [pagination, setPaginationState] = useState<PaginationParams>(
    initialPagination || { page: 1, pageSize: 50 }
  );

  // Fetch alerts from API
  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await alertsApi.getAlerts({
        ...pagination,
        filter,
      });

      if (response.success && response.data) {
        // Convert timestamp strings to Date objects
        const alertsWithDates = response.data.alerts.map((alert) => ({
          ...alert,
          timestamp: new Date(alert.timestamp),
          lastUpdated: new Date(alert.lastUpdated),
          events: alert.events?.map((event) => ({
            ...event,
            timestamp: new Date(event.timestamp),
          })),
        }));

        setAlerts(alertsWithDates);
        setTotal(response.data.total);
      } else {
        throw new Error(response.error?.message || 'Failed to fetch alerts');
      }
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch alerts';
      setError(errorMessage);
      setAlerts([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [filter, pagination]);

  // Get a single alert by ID
  const getAlert = useCallback(async (alertId: string): Promise<Alert | null> => {
    try {
      const response = await alertsApi.getAlert(alertId);
      if (response.success && response.data) {
        // Convert timestamp strings to Date objects
        const alert = {
          ...response.data,
          timestamp: new Date(response.data.timestamp),
          lastUpdated: new Date(response.data.lastUpdated),
          events: response.data.events?.map((event) => ({
            ...event,
            timestamp: new Date(event.timestamp),
          })),
        };
        return alert;
      }
      return null;
    } catch (err) {
      console.error(`Failed to get alert ${alertId}:`, err);
      return null;
    }
  }, []);

  // Update an alert
  const updateAlert = useCallback(
    async (alertId: string, payload: AlertUpdatePayload): Promise<Alert | null> => {
      try {
        const response = await alertsApi.updateAlert(alertId, payload);
        if (response.success && response.data) {
          const updatedAlert = {
            ...response.data,
            timestamp: new Date(response.data.timestamp),
            lastUpdated: new Date(response.data.lastUpdated),
          };

          // Update local state
          setAlerts((prev) =>
            prev.map((alert) => (alert.id === alertId ? updatedAlert : alert))
          );

          return updatedAlert;
        }
        return null;
      } catch (err) {
        console.error(`Failed to update alert ${alertId}:`, err);
        return null;
      }
    },
    []
  );

  // Acknowledge an alert
  const acknowledgeAlert = useCallback(async (alertId: string): Promise<Alert | null> => {
    try {
      const response = await alertsApi.acknowledgeAlert(alertId);
      if (response.success && response.data) {
        const acknowledgedAlert = {
          ...response.data,
          timestamp: new Date(response.data.timestamp),
          lastUpdated: new Date(response.data.lastUpdated),
        };

        // Update local state
        setAlerts((prev) =>
          prev.map((alert) => (alert.id === alertId ? acknowledgedAlert : alert))
        );

        return acknowledgedAlert;
      }
      return null;
    } catch (err) {
      console.error(`Failed to acknowledge alert ${alertId}:`, err);
      return null;
    }
  }, []);

  // Close an alert
  const closeAlert = useCallback(
    async (alertId: string, reason?: string): Promise<Alert | null> => {
      try {
        const response = await alertsApi.closeAlert(alertId, reason);
        if (response.success && response.data) {
          const closedAlert = {
            ...response.data,
            timestamp: new Date(response.data.timestamp),
            lastUpdated: new Date(response.data.lastUpdated),
          };

          // Update local state
          setAlerts((prev) =>
            prev.map((alert) => (alert.id === alertId ? closedAlert : alert))
          );

          return closedAlert;
        }
        return null;
      } catch (err) {
        console.error(`Failed to close alert ${alertId}:`, err);
        return null;
      }
    },
    []
  );

  // Escalate to case
  const escalateToCase = useCallback(
    async (alertId: string, caseTitle?: string): Promise<{ caseId: string } | null> => {
      try {
        const response = await alertsApi.createCaseFromAlert(alertId, caseTitle);
        if (response.success && response.data) {
          // Optionally refresh alerts to get updated caseId
          await fetchAlerts();
          return response.data;
        }
        return null;
      } catch (err) {
        console.error(`Failed to create case from alert ${alertId}:`, err);
        return null;
      }
    },
    [fetchAlerts]
  );

  // Bulk acknowledge
  const bulkAcknowledge = useCallback(async (alertIds: string[]): Promise<number> => {
    try {
      const response = await alertsApi.bulkAcknowledge(alertIds);
      if (response.success && response.data) {
        // Refresh alerts to get updated statuses
        await fetchAlerts();
        return response.data.acknowledged;
      }
      return 0;
    } catch (err) {
      console.error('Failed to bulk acknowledge alerts:', err);
      return 0;
    }
  }, [fetchAlerts]);

  // Bulk close
  const bulkClose = useCallback(
    async (alertIds: string[], reason?: string): Promise<number> => {
      try {
        const response = await alertsApi.bulkClose(alertIds, reason);
        if (response.success && response.data) {
          // Refresh alerts to get updated statuses
          await fetchAlerts();
          return response.data.closed;
        }
        return 0;
      } catch (err) {
        console.error('Failed to bulk close alerts:', err);
        return 0;
      }
    },
    [fetchAlerts]
  );

  // Update pagination
  const setPagination = useCallback((newPagination: Partial<PaginationParams>) => {
    setPaginationState((prev) => ({ ...prev, ...newPagination }));
  }, []);

  // Refresh (refetch with current params)
  const refresh = useCallback(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Initial fetch on mount
  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  // Auto-refresh if enabled
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      fetchAlerts();
    }, refreshInterval);

    return () => clearInterval(interval);
  }, [autoRefresh, refreshInterval, fetchAlerts]);

  return {
    // State
    alerts,
    loading,
    error,
    total,
    page: pagination.page || 1,
    pageSize: pagination.pageSize || 50,

    // Actions
    fetchAlerts,
    getAlert,
    updateAlert,
    acknowledgeAlert,
    closeAlert,
    escalateToCase,
    bulkAcknowledge,
    bulkClose,

    // Refresh control
    setFilter,
    setPagination,
    refresh,
  };
}

export type { UseAlertsOptions, UseAlertsReturn };
