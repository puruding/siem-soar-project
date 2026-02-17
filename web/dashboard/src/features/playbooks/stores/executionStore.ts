import { create } from 'zustand';
import type {
  ExecutionState,
  NodeExecutionResult,
  WSMessage,
  WSNodeStartPayload,
  WSNodeCompletePayload,
  WSNodeErrorPayload
} from '../types/execution.types';

interface ExecutionStore {
  // State
  execution: ExecutionState | null;
  isConnected: boolean;
  selectedNodeId: string | null;

  // Actions
  initExecution: (executionId: string) => void;
  setConnected: (connected: boolean) => void;
  handleWSMessage: (message: WSMessage) => void;
  selectNode: (nodeId: string | null) => void;
  updateNodeResult: (nodeId: string, result: Partial<NodeExecutionResult>) => void;
  setExecutionStatus: (status: ExecutionState['status']) => void;
  reset: () => void;
}

const initialExecutionState = (): ExecutionState => ({
  executionId: '',
  status: 'idle',
  nodeResults: new Map(),
  progress: 0,
});

export const useExecutionStore = create<ExecutionStore>((set, get) => ({
  execution: null,
  isConnected: false,
  selectedNodeId: null,

  initExecution: (executionId: string) => {
    set({
      execution: {
        ...initialExecutionState(),
        executionId,
        status: 'running',
        startedAt: new Date(),
      },
    });
  },

  setConnected: (connected: boolean) => set({ isConnected: connected }),

  handleWSMessage: (message: WSMessage) => {
    const { execution } = get();
    if (!execution) return;

    switch (message.type) {
      case 'node:start': {
        const payload = message.payload as WSNodeStartPayload;
        const newResults = new Map(execution.nodeResults);
        newResults.set(payload.nodeId, {
          nodeId: payload.nodeId,
          nodeName: payload.nodeName,
          status: 'running',
          startedAt: new Date(message.timestamp),
          input: payload.input,
        });
        set({
          execution: {
            ...execution,
            currentNodeId: payload.nodeId,
            nodeResults: newResults,
          },
        });
        break;
      }
      case 'node:complete': {
        const payload = message.payload as WSNodeCompletePayload;
        const newResults = new Map(execution.nodeResults);
        const existing = newResults.get(payload.nodeId);
        newResults.set(payload.nodeId, {
          ...existing,
          nodeId: payload.nodeId,
          nodeName: payload.nodeName,
          status: 'success',
          completedAt: new Date(message.timestamp),
          output: payload.output,
          duration: payload.duration,
        });

        const totalNodes = newResults.size;
        const completedNodes = Array.from(newResults.values()).filter(
          (r) => r.status === 'success' || r.status === 'error'
        ).length;

        set({
          execution: {
            ...execution,
            nodeResults: newResults,
            progress: Math.round((completedNodes / totalNodes) * 100),
          },
        });
        break;
      }
      case 'node:error': {
        const payload = message.payload as WSNodeErrorPayload;
        const newResults = new Map(execution.nodeResults);
        const existing = newResults.get(payload.nodeId);
        newResults.set(payload.nodeId, {
          ...existing,
          nodeId: payload.nodeId,
          nodeName: payload.nodeName,
          status: 'error',
          completedAt: new Date(message.timestamp),
          error: payload.error,
        });
        set({
          execution: {
            ...execution,
            nodeResults: newResults,
          },
        });
        break;
      }
      case 'execution:complete': {
        set({
          execution: {
            ...execution,
            status: 'completed',
            completedAt: new Date(message.timestamp),
            progress: 100,
          },
        });
        break;
      }
      case 'execution:pause': {
        set({
          execution: { ...execution, status: 'paused' },
        });
        break;
      }
      case 'execution:resume': {
        set({
          execution: { ...execution, status: 'running' },
        });
        break;
      }
      case 'execution:cancel': {
        set({
          execution: { ...execution, status: 'cancelled' },
        });
        break;
      }
    }
  },

  selectNode: (nodeId: string | null) => set({ selectedNodeId: nodeId }),

  updateNodeResult: (nodeId: string, result: Partial<NodeExecutionResult>) => {
    const { execution } = get();
    if (!execution) return;

    const newResults = new Map(execution.nodeResults);
    const existing = newResults.get(nodeId) || { nodeId, nodeName: '', status: 'pending' as const };
    newResults.set(nodeId, { ...existing, ...result });
    set({ execution: { ...execution, nodeResults: newResults } });
  },

  setExecutionStatus: (status: ExecutionState['status']) => {
    const { execution } = get();
    if (!execution) return;
    set({ execution: { ...execution, status } });
  },

  reset: () => set({ execution: null, selectedNodeId: null }),
}));
