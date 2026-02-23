import type { Node, Edge } from '@xyflow/react';
import type {
  WSMessage,
  WSNodeStartPayload,
  WSNodeCompletePayload,
  WSNodeErrorPayload,
  WSApprovalRequiredPayload,
  WSApprovalResponsePayload,
} from '../types/execution.types';
import type { ProcessingItem } from '../types/processing.types';

type MessageHandler = (message: WSMessage) => void;
type ItemHandler = (nodeId: string, item: ProcessingItem) => void;

export interface WebSocketServiceConfig {
  url?: string;
  reconnectAttempts?: number;
  reconnectDelay?: number;
}

const defaultConfig: Required<WebSocketServiceConfig> = {
  url: 'ws://localhost:8095/ws/pipeline',
  reconnectAttempts: 5,
  reconnectDelay: 1000,
};

/**
 * WebSocket service for real-time pipeline execution updates.
 * Connects to ws://localhost:8095/ws/pipeline for pipeline execution.
 */
export class WebSocketService {
  private config: Required<WebSocketServiceConfig>;
  private handlers: Set<MessageHandler> = new Set();
  private itemHandlers: Set<ItemHandler> = new Set();
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private isIntentionallyClosed = false;
  private currentExecutionId: string | null = null;

  constructor(config?: WebSocketServiceConfig) {
    this.config = { ...defaultConfig, ...config };
  }

  private getWebSocketUrl(): string {
    // Use configured URL or build from current location
    if (this.config.url) {
      return this.config.url;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}/ws/pipeline`;
  }

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.isIntentionallyClosed = false;
    const wsUrl = this.getWebSocketUrl();

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('[WebSocket] Connected to pipeline execution service');
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const rawMessage = JSON.parse(event.data as string);

          // Handle item-level updates (custom type not in WSMessageType)
          if (rawMessage.type === 'item:update' && rawMessage.payload) {
            const payload = rawMessage.payload as { nodeId: string; item: ProcessingItem };
            this.emitItem(payload.nodeId, payload.item);
            return;
          }

          // Handle standard WSMessage types
          const message = rawMessage as WSMessage;
          this.emit(message);
        } catch (error) {
          console.error('[WebSocket] Failed to parse message:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
      };

      this.ws.onclose = () => {
        console.log('[WebSocket] Connection closed');
        if (!this.isIntentionallyClosed) {
          this.scheduleReconnect();
        }
      };
    } catch (error) {
      console.error('[WebSocket] Failed to connect:', error);
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectAttempts >= this.config.reconnectAttempts) {
      console.log('[WebSocket] Max reconnect attempts reached');
      return;
    }

    const delay = Math.min(
      this.config.reconnectDelay * Math.pow(2, this.reconnectAttempts),
      30000
    );
    this.reconnectAttempts++;

    console.log(`[WebSocket] Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
    setTimeout(() => this.connect(), delay);
  }

  onMessage(handler: MessageHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  onItemUpdate(handler: ItemHandler): () => void {
    this.itemHandlers.add(handler);
    return () => this.itemHandlers.delete(handler);
  }

  private emit(message: WSMessage): void {
    this.handlers.forEach((handler) => handler(message));
  }

  private emitItem(nodeId: string, item: ProcessingItem): void {
    this.itemHandlers.forEach((handler) => handler(nodeId, item));
  }

  private send(message: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('[WebSocket] Cannot send message - not connected');
    }
  }

  /**
   * Start execution of a playbook via WebSocket.
   * Returns a promise that resolves when execution is complete.
   */
  async startExecution(executionId: string, nodes: Node[], edges: Edge[]): Promise<void> {
    this.currentExecutionId = executionId;

    // Ensure connection is established
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      this.connect();
      // Wait for connection
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);
        const checkConnection = setInterval(() => {
          if (this.ws?.readyState === WebSocket.OPEN) {
            clearInterval(checkConnection);
            clearTimeout(timeout);
            resolve();
          }
        }, 100);
      });
    }

    // Send execution start command
    this.send({
      type: 'execution:start',
      executionId,
      nodes: nodes.map((n) => ({
        id: n.id,
        type: n.type,
        data: n.data,
      })),
      edges: edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        sourceHandle: e.sourceHandle,
        targetHandle: e.targetHandle,
      })),
      timestamp: Date.now(),
    });

    // Return promise that resolves when execution completes
    return new Promise((resolve) => {
      const unsubscribe = this.onMessage((message) => {
        if (
          message.executionId === executionId &&
          (message.type === 'execution:complete' || message.type === 'execution:cancel')
        ) {
          unsubscribe();
          this.currentExecutionId = null;
          resolve();
        }
      });
    });
  }

  pauseExecution(): void {
    if (this.currentExecutionId) {
      this.send({
        type: 'execution:pause',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
      });
    }
  }

  resumeExecution(): void {
    if (this.currentExecutionId) {
      this.send({
        type: 'execution:resume',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
      });
    }
  }

  cancelExecution(): void {
    if (this.currentExecutionId) {
      this.send({
        type: 'execution:cancel',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
      });
    }
  }

  approveNode(executionId: string, nodeId: string, comment?: string): void {
    this.send({
      type: 'approval:response',
      executionId,
      payload: {
        nodeId,
        approved: true,
        respondedBy: 'current-user', // TODO: Get from auth context
        comment,
        respondedAt: new Date().toISOString(),
      },
      timestamp: Date.now(),
    });
  }

  rejectNode(executionId: string, nodeId: string, comment?: string): void {
    this.send({
      type: 'approval:response',
      executionId,
      payload: {
        nodeId,
        approved: false,
        respondedBy: 'current-user', // TODO: Get from auth context
        comment,
        respondedAt: new Date().toISOString(),
      },
      timestamp: Date.now(),
    });
  }

  async retryItems(nodeId: string, itemIds: string[]): Promise<void> {
    if (this.currentExecutionId) {
      this.send({
        type: 'items:retry',
        executionId: this.currentExecutionId,
        payload: {
          nodeId,
          itemIds,
        },
        timestamp: Date.now(),
      });
    }
  }

  disconnect(): void {
    this.isIntentionallyClosed = true;
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.handlers.clear();
    this.itemHandlers.clear();
    this.currentExecutionId = null;
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

// Export singleton instance with default configuration
export const webSocketService = new WebSocketService();
