import { create } from 'zustand';
import type {
  ProcessingItem,
  ProcessingMetrics,
  NodeProcessingState
} from '../types/processing.types';

interface ProcessingStore {
  // State
  activeNodeId: string | null;
  nodes: Map<string, NodeProcessingState>;

  // Actions
  initializeProcessing: (nodeId: string, nodeName: string, items: ProcessingItem[]) => void;
  updateItemStatus: (
    nodeId: string,
    itemId: string,
    status: ProcessingItem['status'],
    result?: Record<string, unknown>,
    error?: ProcessingItem['error']
  ) => void;
  updateMetrics: (nodeId: string, metrics: Partial<ProcessingMetrics>) => void;
  setActiveNode: (nodeId: string | null) => void;
  pauseProcessing: (nodeId: string) => void;
  resumeProcessing: (nodeId: string) => void;
  clearProcessing: (nodeId: string) => void;
  reset: () => void;
}

const calculateMetrics = (items: ProcessingItem[], startedAt: Date): ProcessingMetrics => {
  const now = Date.now();
  const elapsedTime = (now - startedAt.getTime()) / 1000;
  const processedItems = items.filter(
    (i) => i.status === 'success' || i.status === 'failed'
  ).length;
  const successCount = items.filter((i) => i.status === 'success').length;
  const failedCount = items.filter((i) => i.status === 'failed').length;
  const pendingCount = items.filter(
    (i) => i.status === 'pending' || i.status === 'processing'
  ).length;

  const throughput = elapsedTime > 0 ? processedItems / elapsedTime : 0;
  const completedWithDuration = items.filter((i) => i.duration !== undefined);
  const avgDuration = completedWithDuration.length > 0
    ? completedWithDuration.reduce((sum, i) => sum + (i.duration || 0), 0) / completedWithDuration.length
    : 0;
  const estimatedTimeLeft = throughput > 0 ? pendingCount / throughput : 0;

  return {
    totalItems: items.length,
    processedItems,
    successCount,
    failedCount,
    pendingCount,
    throughput: Math.round(throughput * 100) / 100,
    avgDuration: Math.round(avgDuration),
    estimatedTimeLeft: Math.round(estimatedTimeLeft),
    startedAt,
    elapsedTime: Math.round(elapsedTime),
  };
};

export const useProcessingStore = create<ProcessingStore>((set, get) => ({
  activeNodeId: null,
  nodes: new Map(),

  initializeProcessing: (nodeId: string, nodeName: string, items: ProcessingItem[]) => {
    const startedAt = new Date();
    const newNodes = new Map(get().nodes);
    newNodes.set(nodeId, {
      nodeId,
      nodeName,
      items,
      metrics: calculateMetrics(items, startedAt),
      isPaused: false,
    });
    set({ nodes: newNodes, activeNodeId: nodeId });
  },

  updateItemStatus: (nodeId, itemId, status, result, error) => {
    const { nodes } = get();
    const nodeState = nodes.get(nodeId);
    if (!nodeState) return;

    const now = new Date();
    const updatedItems = nodeState.items.map((item) =>
      item.id === itemId
        ? {
            ...item,
            status,
            result: result ?? item.result,
            error: error ?? item.error,
            completedAt: status === 'success' || status === 'failed' ? now : item.completedAt,
            duration: status === 'success' || status === 'failed'
              ? (now.getTime() - (item.startedAt?.getTime() || now.getTime()))
              : item.duration,
          }
        : item
    );

    const newNodes = new Map(nodes);
    newNodes.set(nodeId, {
      ...nodeState,
      items: updatedItems,
      metrics: calculateMetrics(updatedItems, nodeState.metrics.startedAt),
    });
    set({ nodes: newNodes });
  },

  updateMetrics: (nodeId, metrics) => {
    const { nodes } = get();
    const nodeState = nodes.get(nodeId);
    if (!nodeState) return;

    const newNodes = new Map(nodes);
    newNodes.set(nodeId, {
      ...nodeState,
      metrics: { ...nodeState.metrics, ...metrics },
    });
    set({ nodes: newNodes });
  },

  setActiveNode: (nodeId) => set({ activeNodeId: nodeId }),

  pauseProcessing: (nodeId) => {
    const { nodes } = get();
    const nodeState = nodes.get(nodeId);
    if (!nodeState) return;

    const newNodes = new Map(nodes);
    newNodes.set(nodeId, { ...nodeState, isPaused: true });
    set({ nodes: newNodes });
  },

  resumeProcessing: (nodeId) => {
    const { nodes } = get();
    const nodeState = nodes.get(nodeId);
    if (!nodeState) return;

    const newNodes = new Map(nodes);
    newNodes.set(nodeId, { ...nodeState, isPaused: false });
    set({ nodes: newNodes });
  },

  clearProcessing: (nodeId) => {
    const { nodes, activeNodeId } = get();
    const newNodes = new Map(nodes);
    newNodes.delete(nodeId);
    set({
      nodes: newNodes,
      activeNodeId: activeNodeId === nodeId ? null : activeNodeId
    });
  },

  reset: () => set({ nodes: new Map(), activeNodeId: null }),
}));
