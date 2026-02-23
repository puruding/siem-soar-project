import { useState, useEffect, useCallback } from 'react';
import type { EventLog, EventLogFilters } from '../types';
import { fetchEvents } from '../api/eventsApi';

export const DEMO_ASSETS = [
  { id: 'all', name: '전체 자산' },
  { id: 'firewall-01', name: 'Palo Alto Firewall (firewall-01)' },
  { id: 'web-server-01', name: 'Web Server (web-server-01)' },
  { id: 'edr-agent-01', name: 'CrowdStrike EDR (edr-agent-01)' },
  { id: 'azure-ad', name: 'Azure AD' },
];

export function useEventLogs() {
  const [events, setEvents] = useState<EventLog[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Staged filters (shown in UI)
  const [stagedFilters, setStagedFilters] = useState<EventLogFilters>({
    assetId: 'all',
    startDate: null,
    endDate: null,
  });

  // Applied filters (used for query)
  const [appliedFilters, setAppliedFilters] = useState<EventLogFilters>({
    assetId: 'all',
    startDate: null,
    endDate: null,
  });

  // Pagination
  const [page, setPage] = useState(1);
  const pageSize = 10;

  // Fetch events from API
  const loadEvents = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await fetchEvents({
        assetId: appliedFilters.assetId,
        startDate: appliedFilters.startDate,
        endDate: appliedFilters.endDate,
        page,
        pageSize,
      });

      setEvents(result.data);
      setTotalCount(result.total);
    } catch (err) {
      setError('이벤트를 불러오는데 실패했습니다.');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  }, [appliedFilters, page, pageSize]);

  // Load events when filters or page changes
  useEffect(() => {
    loadEvents();
  }, [loadEvents]);

  // Apply filters (called when search button clicked)
  const applyFilters = useCallback(() => {
    setAppliedFilters({ ...stagedFilters });
    setPage(1);
  }, [stagedFilters]);

  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));

  return {
    events,
    totalCount,
    isLoading,
    error,
    filters: stagedFilters,
    setFilters: setStagedFilters,
    applyFilters,
    page,
    setPage,
    pageSize,
    totalPages,
    refresh: loadEvents,
  };
}
