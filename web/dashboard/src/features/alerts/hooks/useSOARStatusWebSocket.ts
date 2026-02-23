import { useEffect, useRef, useState, useCallback } from 'react';

// WebSocket message types
export type SOARMessageType =
  | 'execution:started'
  | 'execution:progress'
  | 'execution:completed'
  | 'execution:failed'
  | 'execution:paused'
  | 'execution:resumed'
  | 'node:started'
  | 'node:completed'
  | 'node:failed'
  | 'approval:required'
  | 'approval:received'
  | 'heartbeat';

export interface ExecutionStatusMessage {
  type: SOARMessageType;
  execution_id: string;
  alert_id?: string;
  case_id?: string;
  playbook_id: string;
  playbook_name: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused' | 'waiting_approval';
  progress: number; // 0-100
  current_step?: string;
  error?: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
}

export interface NodeStatusMessage {
  type: SOARMessageType;
  execution_id: string;
  node_id: string;
  node_name: string;
  node_type: string;
  status: 'running' | 'completed' | 'failed';
  started_at?: string;
  completed_at?: string;
  duration_ms?: number;
  output?: unknown;
  error?: string;
  timestamp: string;
}

export interface SOARStatus {
  executionId: string;
  playbookId: string;
  playbookName: string;
  status: ExecutionStatusMessage['status'];
  progress: number;
  currentStep?: string;
  error?: string;
  startedAt?: string;
  completedAt?: string;
}

interface UseSOARStatusWebSocketOptions {
  alertId: string;
  enabled?: boolean;
  onStatusChange?: (status: SOARStatus) => void;
}

interface UseSOARStatusWebSocketReturn {
  status: SOARStatus | null;
  isConnected: boolean;
  error: string | null;
  connect: () => void;
  disconnect: () => void;
}

export function useSOARStatusWebSocket(
  options: UseSOARStatusWebSocketOptions
): UseSOARStatusWebSocketReturn {
  const { alertId, enabled = true, onStatusChange } = options;
  const [status, setStatus] = useState<SOARStatus | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout>();
  const reconnectAttempts = useRef(0);
  const maxReconnectAttempts = 5;

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const wsUrl = `${import.meta.env.VITE_WS_URL || 'ws://localhost:8082'}/ws/soar?topics=alert:${alertId}`;

    try {
      wsRef.current = new WebSocket(wsUrl);

      wsRef.current.onopen = () => {
        setIsConnected(true);
        setError(null);
        reconnectAttempts.current = 0;
      };

      wsRef.current.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as ExecutionStatusMessage | NodeStatusMessage;

          if (message.type === 'heartbeat') return;

          if (message.type.startsWith('execution:')) {
            const execMsg = message as ExecutionStatusMessage;
            const newStatus: SOARStatus = {
              executionId: execMsg.execution_id,
              playbookId: execMsg.playbook_id,
              playbookName: execMsg.playbook_name,
              status: execMsg.status,
              progress: execMsg.progress,
              currentStep: execMsg.current_step,
              error: execMsg.error,
              startedAt: execMsg.timestamp,
              completedAt: execMsg.status === 'completed' || execMsg.status === 'failed'
                ? execMsg.timestamp
                : undefined,
            };
            setStatus(newStatus);
            onStatusChange?.(newStatus);
          }
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      wsRef.current.onclose = () => {
        setIsConnected(false);

        // Reconnect with exponential backoff
        if (enabled && reconnectAttempts.current < maxReconnectAttempts) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 30000);
          reconnectTimeoutRef.current = setTimeout(() => {
            reconnectAttempts.current++;
            connect();
          }, delay);
        }
      };

      wsRef.current.onerror = () => {
        setError('WebSocket connection failed');
      };
    } catch (e) {
      setError('Failed to create WebSocket connection');
    }
  }, [alertId, enabled, onStatusChange]);

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setIsConnected(false);
  }, []);

  useEffect(() => {
    if (enabled && alertId) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [alertId, enabled, connect, disconnect]);

  return { status, isConnected, error, connect, disconnect };
}
