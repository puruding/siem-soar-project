/**
 * useCases Hook Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { useCases } from '../useCases';
import { casesApi } from '@/api/cases';

// Mock the casesApi
vi.mock('@/api/cases', () => ({
  casesApi: {
    getCases: vi.fn(),
    getCase: vi.fn(),
    createCase: vi.fn(),
    updateCase: vi.fn(),
    assignCase: vi.fn(),
    changeStatus: vi.fn(),
    addAlert: vi.fn(),
    removeAlert: vi.fn(),
  },
}));

describe('useCases', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should fetch cases on mount by default', async () => {
    const mockResponse = {
      success: true,
      data: {
        cases: [],
        total: 0,
        page: 1,
        pageSize: 20,
      },
    };

    vi.mocked(casesApi.getCases).mockResolvedValue(mockResponse);

    const { result } = renderHook(() => useCases());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(casesApi.getCases).toHaveBeenCalledTimes(1);
    expect(result.current.cases).toEqual([]);
    expect(result.current.total).toBe(0);
  });

  it('should not auto-fetch when autoFetch is false', () => {
    renderHook(() => useCases({ autoFetch: false }));

    expect(casesApi.getCases).not.toHaveBeenCalled();
  });

  it('should handle API errors gracefully', async () => {
    const mockError = {
      success: false,
      error: {
        code: 'API_ERROR',
        message: 'Failed to fetch cases',
        timestamp: new Date().toISOString(),
      },
    };

    vi.mocked(casesApi.getCases).mockResolvedValue(mockError);

    const { result } = renderHook(() => useCases());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.error).toBe('Failed to fetch cases');
  });

  it('should create a new case', async () => {
    const mockCase = {
      id: 'CASE-001',
      title: 'Test Case',
      description: 'Test Description',
      severity: 'high' as const,
      status: 'open' as const,
      priority: 'p1' as const,
      assignee: null,
      createdAt: new Date(),
      updatedAt: new Date(),
      alerts: [],
      alertCount: 0,
      artifacts: [],
      timeline: [],
      playbookExecutions: [],
      attachments: [],
      tags: [],
      relatedCases: [],
    };

    const mockResponse = {
      success: true,
      data: mockCase,
    };

    vi.mocked(casesApi.getCases).mockResolvedValue({
      success: true,
      data: { cases: [], total: 0, page: 1, pageSize: 20 },
    });

    vi.mocked(casesApi.createCase).mockResolvedValue(mockResponse);

    const { result } = renderHook(() => useCases());

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    const newCase = await result.current.createCase({
      title: 'Test Case',
      description: 'Test Description',
      severity: 'high',
    });

    expect(newCase).toEqual(mockCase);
    expect(casesApi.createCase).toHaveBeenCalledWith({
      title: 'Test Case',
      description: 'Test Description',
      severity: 'high',
    });
  });
});
