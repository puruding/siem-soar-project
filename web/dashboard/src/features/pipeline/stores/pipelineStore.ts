import { create } from 'zustand';
import { PipelineEvent, Classification, PipelineStats, ApprovalInfo, AuditLog } from '../types/pipeline';

interface PipelineState {
  // Connection
  isConnected: boolean;
  connectionStatus: 'connecting' | 'connected' | 'disconnected' | 'error';

  // Data
  events: PipelineEvent[];
  classifications: Map<string, Classification>;
  approvals: ApprovalInfo[];
  auditLogs: AuditLog[];
  stats: PipelineStats | null;

  // Selection
  selectedEventId: string | null;
  selectedStage: string | null;

  // Actions
  setConnectionStatus: (status: 'connecting' | 'connected' | 'disconnected' | 'error') => void;
  addEvent: (event: PipelineEvent) => void;
  updateEvent: (eventId: string, updates: Partial<PipelineEvent>) => void;
  addClassification: (classification: Classification) => void;
  addApproval: (approval: ApprovalInfo) => void;
  updateApproval: (approvalId: string, status: string) => void;
  addAuditLog: (log: AuditLog) => void;
  setStats: (stats: PipelineStats) => void;
  setSelectedEvent: (eventId: string | null) => void;
  clearEvents: () => void;
}

export const usePipelineStore = create<PipelineState>((set, get) => ({
  // Initial state
  isConnected: false,
  connectionStatus: 'disconnected',
  events: [],
  classifications: new Map(),
  approvals: [],
  auditLogs: [],
  stats: null,
  selectedEventId: null,
  selectedStage: null,

  // Actions
  setConnectionStatus: (status) =>
    set({
      connectionStatus: status,
      isConnected: status === 'connected',
    }),

  addEvent: (event) =>
    set((state) => ({
      events: [event, ...state.events].slice(0, 500), // keep latest 500
    })),

  updateEvent: (eventId, updates) =>
    set((state) => ({
      events: state.events.map((e) =>
        e.id === eventId ? { ...e, ...updates } : e
      ),
    })),

  addClassification: (classification) =>
    set((state) => {
      const next = new Map(state.classifications);
      next.set(classification.event_id, classification);
      return { classifications: next };
    }),

  addApproval: (approval) =>
    set((state) => ({
      approvals: [approval, ...state.approvals],
    })),

  updateApproval: (approvalId, status) =>
    set((state) => ({
      approvals: state.approvals.map((a) =>
        a.approval_id === approvalId
          ? { ...a, status: status as ApprovalInfo['status'] }
          : a
      ),
    })),

  addAuditLog: (log) =>
    set((state) => ({
      auditLogs: [log, ...state.auditLogs].slice(0, 1000), // keep latest 1000
    })),

  setStats: (stats) => set({ stats }),

  setSelectedEvent: (eventId) => set({ selectedEventId: eventId }),

  clearEvents: () =>
    set({
      events: [],
      classifications: new Map(),
      approvals: [],
      auditLogs: [],
      stats: null,
      selectedEventId: null,
    }),
}));
