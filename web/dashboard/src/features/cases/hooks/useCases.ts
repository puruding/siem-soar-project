/**
 * Cases Hook - Manages case state and API operations
 */

import { useState, useEffect, useCallback } from 'react';
import { casesApi } from '@/api/cases';
import type {
  Case,
  CaseFilter,
  CaseCreatePayload,
  CaseUpdatePayload,
} from '@/types/case';
import type { ApiResponse, PaginationParams } from '@/types/api';

interface UseCasesOptions {
  autoFetch?: boolean;
  initialFilter?: CaseFilter;
  initialPagination?: PaginationParams;
}

interface UseCasesReturn {
  // State
  cases: Case[];
  total: number;
  page: number;
  pageSize: number;
  loading: boolean;
  error: string | null;

  // Actions
  fetchCases: (params?: { filter?: CaseFilter; pagination?: PaginationParams }) => Promise<void>;
  getCase: (caseId: string) => Promise<Case | null>;
  createCase: (payload: CaseCreatePayload) => Promise<Case | null>;
  updateCase: (caseId: string, payload: CaseUpdatePayload) => Promise<Case | null>;
  closeCase: (caseId: string, resolutionSummary?: string) => Promise<Case | null>;
  assignCase: (caseId: string, assigneeId: string) => Promise<Case | null>;
  changeStatus: (caseId: string, status: Case['status'], comment?: string) => Promise<Case | null>;
  addAlert: (caseId: string, alertId: string) => Promise<Case | null>;
  removeAlert: (caseId: string, alertId: string) => Promise<Case | null>;

  // Filter/pagination
  setFilter: (filter: CaseFilter) => void;
  setPagination: (pagination: Partial<PaginationParams>) => void;
  refresh: () => Promise<void>;
}

export function useCases(options: UseCasesOptions = {}): UseCasesReturn {
  const {
    autoFetch = true,
    initialFilter = {},
    initialPagination = { page: 1, pageSize: 20 },
  } = options;

  // State
  const [cases, setCases] = useState<Case[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(initialPagination.page || 1);
  const [pageSize, setPageSize] = useState(initialPagination.pageSize || 20);
  const [filter, setFilterState] = useState<CaseFilter>(initialFilter);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Fetch cases with current filter and pagination
   */
  const fetchCases = useCallback(async (params?: {
    filter?: CaseFilter;
    pagination?: PaginationParams;
  }) => {
    setLoading(true);
    setError(null);

    try {
      const currentFilter = params?.filter ?? filter;
      const currentPagination = params?.pagination ?? { page, pageSize };

      const response = await casesApi.getCases({
        filter: currentFilter,
        page: currentPagination.page,
        pageSize: currentPagination.pageSize,
        sortBy: currentPagination.sortBy,
        sortOrder: currentPagination.sortOrder,
      });

      if (response.success && response.data) {
        setCases(response.data.cases);
        setTotal(response.data.total);
        setPage(response.data.page);
        setPageSize(response.data.pageSize);
      } else {
        throw new Error(response.error?.message || 'Failed to fetch cases');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to fetch cases:', err);
    } finally {
      setLoading(false);
    }
  }, [filter, page, pageSize]);

  /**
   * Get a single case by ID
   */
  const getCase = useCallback(async (caseId: string): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.getCase(caseId);

      if (response.success && response.data) {
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to fetch case');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to fetch case:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Create a new case
   */
  const createCase = useCallback(async (payload: CaseCreatePayload): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.createCase(payload);

      if (response.success && response.data) {
        // Add the new case to the list
        setCases(prev => [response.data!, ...prev]);
        setTotal(prev => prev + 1);
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to create case');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to create case:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Update a case
   */
  const updateCase = useCallback(async (
    caseId: string,
    payload: CaseUpdatePayload
  ): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.updateCase(caseId, payload);

      if (response.success && response.data) {
        // Update the case in the list
        setCases(prev => prev.map(c => c.id === caseId ? response.data! : c));
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to update case');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to update case:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Close a case
   */
  const closeCase = useCallback(async (
    caseId: string,
    resolutionSummary?: string
  ): Promise<Case | null> => {
    return updateCase(caseId, {
      status: 'closed',
      resolutionSummary,
    });
  }, [updateCase]);

  /**
   * Assign a case to a user
   */
  const assignCase = useCallback(async (
    caseId: string,
    assigneeId: string
  ): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.assignCase(caseId, assigneeId);

      if (response.success && response.data) {
        // Update the case in the list
        setCases(prev => prev.map(c => c.id === caseId ? response.data! : c));
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to assign case');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to assign case:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Change case status
   */
  const changeStatus = useCallback(async (
    caseId: string,
    status: Case['status'],
    comment?: string
  ): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.changeStatus(caseId, status, comment);

      if (response.success && response.data) {
        // Update the case in the list
        setCases(prev => prev.map(c => c.id === caseId ? response.data! : c));
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to change status');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to change status:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Add an alert to a case
   */
  const addAlert = useCallback(async (
    caseId: string,
    alertId: string
  ): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.addAlert(caseId, alertId);

      if (response.success && response.data) {
        // Update the case in the list
        setCases(prev => prev.map(c => c.id === caseId ? response.data! : c));
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to add alert');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to add alert:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Remove an alert from a case
   */
  const removeAlert = useCallback(async (
    caseId: string,
    alertId: string
  ): Promise<Case | null> => {
    setLoading(true);
    setError(null);

    try {
      const response = await casesApi.removeAlert(caseId, alertId);

      if (response.success && response.data) {
        // Update the case in the list
        setCases(prev => prev.map(c => c.id === caseId ? response.data! : c));
        return response.data;
      } else {
        throw new Error(response.error?.message || 'Failed to remove alert');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError(errorMessage);
      console.error('Failed to remove alert:', err);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Update filter and refetch
   */
  const setFilter = useCallback((newFilter: CaseFilter) => {
    setFilterState(newFilter);
    setPage(1); // Reset to first page
  }, []);

  /**
   * Update pagination
   */
  const setPagination = useCallback((newPagination: Partial<PaginationParams>) => {
    if (newPagination.page !== undefined) setPage(newPagination.page);
    if (newPagination.pageSize !== undefined) setPageSize(newPagination.pageSize);
  }, []);

  /**
   * Refresh current view
   */
  const refresh = useCallback(async () => {
    await fetchCases();
  }, [fetchCases]);

  // Auto-fetch on mount if enabled
  useEffect(() => {
    if (autoFetch) {
      fetchCases();
    }
  }, [autoFetch, fetchCases]);

  // Refetch when filter or pagination changes
  useEffect(() => {
    if (autoFetch) {
      fetchCases();
    }
  }, [filter, page, pageSize]);

  return {
    // State
    cases,
    total,
    page,
    pageSize,
    loading,
    error,

    // Actions
    fetchCases,
    getCase,
    createCase,
    updateCase,
    closeCase,
    assignCase,
    changeStatus,
    addAlert,
    removeAlert,

    // Filter/pagination
    setFilter,
    setPagination,
    refresh,
  };
}

// Export types
export type { UseCasesOptions, UseCasesReturn };
