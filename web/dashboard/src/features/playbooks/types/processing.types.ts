// Individual item being processed
export interface ProcessingItem {
  id: string;
  index: number;
  nodeId: string;
  status: 'pending' | 'processing' | 'success' | 'failed' | 'retrying';
  data: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: {
    message: string;
    code?: string;
    retryCount?: number;
    maxRetries?: number;
  };
  startedAt?: Date;
  completedAt?: Date;
  duration?: number;
}

// Real-time processing metrics
export interface ProcessingMetrics {
  totalItems: number;
  processedItems: number;
  successCount: number;
  failedCount: number;
  pendingCount: number;
  throughput: number;
  avgDuration: number;
  estimatedTimeLeft: number;
  startedAt: Date;
  elapsedTime: number;
}

// Processing state for a single node
export interface NodeProcessingState {
  nodeId: string;
  nodeName: string;
  items: ProcessingItem[];
  metrics: ProcessingMetrics;
  isPaused: boolean;
}
