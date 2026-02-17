import { useState, useEffect, useMemo } from 'react';
import { useProcessingStore } from '../stores/processingStore';

export interface ProcessingMetricsData {
  throughput: string;
  avgDuration: string;
  estimatedTimeLeft: string;
  progress: number;
  successRate: number;
}

export interface UseProcessingMetricsReturn {
  metrics: ProcessingMetricsData | null;
  isProcessing: boolean;
  formattedETA: string;
}

export interface UseProcessingMetricsProps {
  nodeId: string | null;
  updateInterval?: number;
}

/**
 * Hook to compute derived metrics from processingStore
 *
 * @param nodeId - The node ID to compute metrics for (null if no active processing)
 * @param updateInterval - Auto-update interval in milliseconds (default: 500ms)
 * @returns Computed metrics, processing state, and formatted ETA
 *
 * @example
 * ```tsx
 * const { metrics, isProcessing, formattedETA } = useProcessingMetrics({
 *   nodeId: activeNodeId,
 *   updateInterval: 500
 * });
 *
 * if (metrics) {
 *   console.log(`Throughput: ${metrics.throughput} items/s`);
 *   console.log(`Avg Duration: ${metrics.avgDuration}`);
 *   console.log(`ETA: ${formattedETA}`);
 * }
 * ```
 */
export function useProcessingMetrics({
  nodeId,
  updateInterval = 500
}: UseProcessingMetricsProps): UseProcessingMetricsReturn {
  const [tick, setTick] = useState(0);
  const nodes = useProcessingStore((state) => state.nodes);

  // Auto-update interval while processing
  useEffect(() => {
    if (!nodeId) return;

    const interval = setInterval(() => {
      setTick((prev) => prev + 1);
    }, updateInterval);

    return () => {
      clearInterval(interval);
    };
  }, [nodeId, updateInterval]);

  // Compute derived metrics
  const { metrics, isProcessing, formattedETA } = useMemo(() => {
    if (!nodeId) {
      return {
        metrics: null,
        isProcessing: false,
        formattedETA: ''
      };
    }

    const nodeState = nodes.get(nodeId);
    if (!nodeState) {
      return {
        metrics: null,
        isProcessing: false,
        formattedETA: ''
      };
    }

    const { metrics: rawMetrics, isPaused } = nodeState;
    const isActive = rawMetrics.pendingCount > 0 && !isPaused;

    // Format throughput
    const throughputStr = rawMetrics.throughput >= 1
      ? `${rawMetrics.throughput.toFixed(1)} items/s`
      : `${(rawMetrics.throughput * 60).toFixed(1)} items/min`;

    // Format average duration
    const avgDurationStr = rawMetrics.avgDuration >= 1000
      ? `${(rawMetrics.avgDuration / 1000).toFixed(2)}s`
      : `${rawMetrics.avgDuration}ms`;

    // Format estimated time left
    let etaStr = '';
    if (rawMetrics.estimatedTimeLeft > 0) {
      const seconds = rawMetrics.estimatedTimeLeft;
      if (seconds < 60) {
        etaStr = `${Math.ceil(seconds)}s`;
      } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = Math.ceil(seconds % 60);
        etaStr = `${minutes}m ${remainingSeconds}s`;
      } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        etaStr = `${hours}h ${minutes}m`;
      }
    }

    // Calculate progress percentage
    const progress = rawMetrics.totalItems > 0
      ? Math.round((rawMetrics.processedItems / rawMetrics.totalItems) * 100)
      : 0;

    // Calculate success rate
    const successRate = rawMetrics.processedItems > 0
      ? Math.round((rawMetrics.successCount / rawMetrics.processedItems) * 100)
      : 100;

    const processedMetrics: ProcessingMetricsData = {
      throughput: throughputStr,
      avgDuration: avgDurationStr,
      estimatedTimeLeft: etaStr,
      progress,
      successRate
    };

    return {
      metrics: processedMetrics,
      isProcessing: isActive,
      formattedETA: etaStr || 'Calculating...'
    };
  }, [nodeId, nodes, tick]);

  return {
    metrics,
    isProcessing,
    formattedETA
  };
}
