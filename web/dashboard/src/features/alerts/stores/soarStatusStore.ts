import { create } from 'zustand';
import type { SOARStatus } from '../hooks/useSOARStatusWebSocket';

interface SOARStatusState {
  // Map of alertId -> SOARStatus
  statuses: Map<string, SOARStatus>;
  // Active executions for an alert
  activeExecutions: Map<string, string[]>; // alertId -> executionId[]

  // Actions
  updateStatus: (alertId: string, status: SOARStatus) => void;
  clearStatus: (alertId: string) => void;
  getStatus: (alertId: string) => SOARStatus | undefined;
  getActiveExecutions: (alertId: string) => string[];
}

export const useSOARStatusStore = create<SOARStatusState>((set, get) => ({
  statuses: new Map(),
  activeExecutions: new Map(),

  updateStatus: (alertId, status) => {
    set((state) => {
      const newStatuses = new Map(state.statuses);
      newStatuses.set(alertId, status);

      const newActiveExecutions = new Map(state.activeExecutions);
      const executions = newActiveExecutions.get(alertId) || [];
      if (!executions.includes(status.executionId)) {
        newActiveExecutions.set(alertId, [...executions, status.executionId]);
      }

      return { statuses: newStatuses, activeExecutions: newActiveExecutions };
    });
  },

  clearStatus: (alertId) => {
    set((state) => {
      const newStatuses = new Map(state.statuses);
      newStatuses.delete(alertId);
      const newActiveExecutions = new Map(state.activeExecutions);
      newActiveExecutions.delete(alertId);
      return { statuses: newStatuses, activeExecutions: newActiveExecutions };
    });
  },

  getStatus: (alertId) => get().statuses.get(alertId),

  getActiveExecutions: (alertId) => get().activeExecutions.get(alertId) || [],
}));
