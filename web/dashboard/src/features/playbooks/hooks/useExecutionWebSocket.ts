import { useEffect, useState, useRef } from 'react';
import type { WSMessage } from '../types/execution.types';
import { mockWebSocketService } from '../services/mockWebSocketService';
import { useExecutionStore } from '../stores/executionStore';

export interface UseExecutionWebSocketReturn {
  isConnected: boolean;
  connect: () => void;
  disconnect: () => void;
  error: Error | null;
}

export interface UseExecutionWebSocketProps {
  executionId: string | null;
}

/**
 * Hook to manage WebSocket connection for execution events
 *
 * @param executionId - The execution ID to subscribe to (null to disconnect)
 * @returns WebSocket connection state and control functions
 *
 * @example
 * ```tsx
 * const { isConnected, connect, disconnect, error } = useExecutionWebSocket({
 *   executionId: execution?.executionId || null
 * });
 * ```
 */
export function useExecutionWebSocket({
  executionId
}: UseExecutionWebSocketProps): UseExecutionWebSocketReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  const { handleWSMessage, setConnected } = useExecutionStore();

  const connect = () => {
    if (!executionId) {
      setError(new Error('No execution ID provided'));
      return;
    }

    try {
      // Subscribe to WebSocket messages
      const unsubscribe = mockWebSocketService.onMessage((message: WSMessage) => {
        // Only handle messages for this execution
        if (message.executionId === executionId) {
          handleWSMessage(message);
        }
      });

      unsubscribeRef.current = unsubscribe;
      setIsConnected(true);
      setConnected(true);
      setError(null);
    } catch (err) {
      const errorObj = err instanceof Error ? err : new Error('Failed to connect');
      setError(errorObj);
      setIsConnected(false);
      setConnected(false);
    }
  };

  const disconnect = () => {
    if (unsubscribeRef.current) {
      unsubscribeRef.current();
      unsubscribeRef.current = null;
    }
    setIsConnected(false);
    setConnected(false);
    setError(null);
  };

  // Auto-connect when executionId is provided
  useEffect(() => {
    if (executionId) {
      connect();
    } else {
      disconnect();
    }

    // Cleanup on unmount
    return () => {
      disconnect();
    };
  }, [executionId]);

  return {
    isConnected,
    connect,
    disconnect,
    error
  };
}
