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

interface MockWSConfig {
  nodeExecutionDelay: number;
  itemProcessingDelay: number;
  failureRate: number;
}

type MessageHandler = (message: WSMessage) => void;
type ItemHandler = (nodeId: string, item: ProcessingItem) => void;

const defaultConfig: MockWSConfig = {
  nodeExecutionDelay: 1500,
  itemProcessingDelay: 100,
  failureRate: 0.05,
};

// Mock output data for different node types
const mockOutputs: Record<string, Record<string, unknown>> = {
  trigger: {
    alert: {
      id: 'ALERT-2026-001',
      severity: 'critical',
      source: 'EDR',
      timestamp: new Date().toISOString(),
      iocs: ['192.168.1.100', '10.0.0.50', 'malware.exe', 'c2.badactor.com'],
    },
  },
  action: {
    success: true,
    result: { processed: true, count: 5 },
    duration: 150,
  },
  integration: {
    data: { response: 'OK', items: [] },
    status: 200,
    headers: { 'content-type': 'application/json' },
  },
  decision: {
    result: true,
    branch: 'yes',
  },
  approval: {
    status: 'approved',
    approvedBy: 'admin@company.com',
    approvedAt: new Date().toISOString(),
  },
};

export class MockWebSocketService {
  private config: MockWSConfig;
  private handlers: Set<MessageHandler> = new Set();
  private itemHandlers: Set<ItemHandler> = new Set();
  private isRunning = false;
  private isPaused = false;
  private currentExecutionId: string | null = null;
  private abortController: AbortController | null = null;
  private pendingApprovals: Map<string, { resolve: (approved: boolean) => void; nodeId: string }> =
    new Map();

  constructor(config?: Partial<MockWSConfig>) {
    this.config = { ...defaultConfig, ...config };
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

  async startExecution(executionId: string, nodes: Node[], edges: Edge[]): Promise<void> {
    if (this.isRunning) return;

    this.isRunning = true;
    this.isPaused = false;
    this.currentExecutionId = executionId;
    this.abortController = new AbortController();

    this.emit({
      type: 'execution:start',
      executionId,
      timestamp: Date.now(),
      payload: { nodeCount: nodes.length },
    });

    try {
      const executionOrder = this.buildExecutionOrder(nodes, edges);

      for (const node of executionOrder) {
        if (this.abortController?.signal.aborted) break;

        while (this.isPaused) {
          await this.delay(100);
          if (this.abortController?.signal.aborted) break;
        }

        await this.executeNode(executionId, node);
      }

      if (!this.abortController?.signal.aborted) {
        this.emit({
          type: 'execution:complete',
          executionId,
          timestamp: Date.now(),
          payload: {},
        });
      }
    } finally {
      this.isRunning = false;
      this.currentExecutionId = null;
    }
  }

  private buildExecutionOrder(nodes: Node[], edges: Edge[]): Node[] {
    const visited = new Set<string>();
    const order: Node[] = [];

    // Find trigger nodes (entry points)
    const triggerNodes = nodes.filter((n) => n.type === 'trigger');
    const queue = [...triggerNodes];

    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current.id)) continue;

      visited.add(current.id);
      order.push(current);

      // Find connected nodes
      const outgoing = edges.filter((e) => e.source === current.id);
      for (const edge of outgoing) {
        const targetNode = nodes.find((n) => n.id === edge.target);
        if (targetNode && !visited.has(targetNode.id)) {
          queue.push(targetNode);
        }
      }
    }

    return order;
  }

  private async executeNode(executionId: string, node: Node): Promise<void> {
    const nodeName = (node.data as { label?: string })?.label || node.id;
    const nodeType = node.type || 'action';

    // Handle approval nodes specially - they emit their own node:start with awaiting_approval status
    if (nodeType === 'approval') {
      await this.executeApprovalNode(executionId, node, nodeName);
      return; // Don't continue to the normal completion logic
    }

    // Emit node start
    this.emit({
      type: 'node:start',
      executionId,
      timestamp: Date.now(),
      payload: {
        nodeId: node.id,
        nodeName,
        input: {},
      } as WSNodeStartPayload,
    });

    await this.delay(this.config.nodeExecutionDelay);

    // Handle loop nodes specially - emit item-level progress
    if (nodeType === 'loop') {
      await this.executeLoopNode(executionId, node, nodeName);
    }

    // Random failure based on config
    const shouldFail = Math.random() < this.config.failureRate;

    if (shouldFail) {
      this.emit({
        type: 'node:error',
        executionId,
        timestamp: Date.now(),
        payload: {
          nodeId: node.id,
          nodeName,
          error: {
            message: 'Simulated execution error',
            code: 'MOCK_ERROR',
          },
        } as WSNodeErrorPayload,
      });
    } else {
      this.emit({
        type: 'node:complete',
        executionId,
        timestamp: Date.now(),
        payload: {
          nodeId: node.id,
          nodeName,
          output: mockOutputs[nodeType] || mockOutputs.action,
          duration: this.config.nodeExecutionDelay,
        } as WSNodeCompletePayload,
      });
    }
  }

  private async executeLoopNode(executionId: string, node: Node, nodeName: string): Promise<void> {
    // Generate mock items for the loop
    const itemCount = 25;
    const items: ProcessingItem[] = Array.from({ length: itemCount }, (_, i) => ({
      id: `item-${node.id}-${i}`,
      index: i,
      nodeId: node.id,
      status: 'pending' as const,
      data: {
        ip: `192.168.1.${100 + i}`,
        port: 443 + i,
        protocol: i % 2 === 0 ? 'TCP' : 'UDP',
      },
    }));

    // Emit initial items
    items.forEach((item) => this.emitItem(node.id, item));

    // Process items
    for (const item of items) {
      if (this.abortController?.signal.aborted) break;

      while (this.isPaused) {
        await this.delay(100);
        if (this.abortController?.signal.aborted) break;
      }

      // Start processing
      this.emitItem(node.id, { ...item, status: 'processing', startedAt: new Date() });

      await this.delay(this.config.itemProcessingDelay);

      // Random failure
      const shouldFail = Math.random() < this.config.failureRate;

      if (shouldFail) {
        this.emitItem(node.id, {
          ...item,
          status: 'failed',
          completedAt: new Date(),
          error: { message: 'Item processing failed', retryCount: 0, maxRetries: 3 },
        });
      } else {
        this.emitItem(node.id, {
          ...item,
          status: 'success',
          completedAt: new Date(),
          result: { blocked: true },
        });
      }
    }
  }

  private async executeApprovalNode(
    executionId: string,
    node: Node,
    nodeName: string,
  ): Promise<void> {
    // Emit node:start with awaiting_approval status
    this.emit({
      type: 'node:start',
      executionId,
      timestamp: Date.now(),
      payload: {
        nodeId: node.id,
        nodeName,
        input: { status: 'awaiting_approval' },
      } as WSNodeStartPayload,
    });

    // Emit approval:required so the UI can prompt the user
    this.emit({
      type: 'approval:required',
      executionId,
      timestamp: Date.now(),
      payload: {
        nodeId: node.id,
        nodeName,
        executionId,
        requestedAt: new Date().toISOString(),
        description: `Manual approval required for node: ${nodeName}`,
      } as WSApprovalRequiredPayload,
    });

    // Create a Promise that resolves when approve/rejectNode is called
    const approvalKey = `${executionId}:${node.id}`;
    const approved = await new Promise<boolean>((resolve) => {
      this.pendingApprovals.set(approvalKey, { resolve, nodeId: node.id });
    });

    // Clean up the pending approval entry
    this.pendingApprovals.delete(approvalKey);

    if (approved) {
      this.emit({
        type: 'node:complete',
        executionId,
        timestamp: Date.now(),
        payload: {
          nodeId: node.id,
          nodeName,
          output: mockOutputs.approval,
          duration: this.config.nodeExecutionDelay,
        } as WSNodeCompletePayload,
      });
    } else {
      this.emit({
        type: 'node:error',
        executionId,
        timestamp: Date.now(),
        payload: {
          nodeId: node.id,
          nodeName,
          error: {
            message: 'Approval rejected by operator',
            code: 'APPROVAL_REJECTED',
          },
        } as WSNodeErrorPayload,
      });

      // Abort execution on rejection
      this.abortController?.abort();
    }
  }

  approveNode(executionId: string, nodeId: string, comment?: string): void {
    const approvalKey = `${executionId}:${nodeId}`;
    const pending = this.pendingApprovals.get(approvalKey);
    if (!pending) return;

    // Emit the response message before resolving
    this.emit({
      type: 'approval:response',
      executionId,
      timestamp: Date.now(),
      payload: {
        nodeId,
        nodeName: nodeId,
        executionId,
        approved: true,
        respondedBy: 'admin@company.com',
        comment,
        respondedAt: new Date().toISOString(),
      } as WSApprovalResponsePayload,
    });

    pending.resolve(true);
  }

  rejectNode(executionId: string, nodeId: string, comment?: string): void {
    const approvalKey = `${executionId}:${nodeId}`;
    const pending = this.pendingApprovals.get(approvalKey);
    if (!pending) return;

    // Emit the response message before resolving
    this.emit({
      type: 'approval:response',
      executionId,
      timestamp: Date.now(),
      payload: {
        nodeId,
        nodeName: nodeId,
        executionId,
        approved: false,
        comment,
        respondedAt: new Date().toISOString(),
      } as WSApprovalResponsePayload,
    });

    pending.resolve(false);
  }

  pauseExecution(): void {
    if (!this.isRunning) return;
    this.isPaused = true;
    if (this.currentExecutionId) {
      this.emit({
        type: 'execution:pause',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
        payload: {},
      });
    }
  }

  resumeExecution(): void {
    if (!this.isRunning) return;
    this.isPaused = false;
    if (this.currentExecutionId) {
      this.emit({
        type: 'execution:resume',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
        payload: {},
      });
    }
  }

  cancelExecution(): void {
    if (!this.isRunning) return;
    this.abortController?.abort();
    if (this.currentExecutionId) {
      this.emit({
        type: 'execution:cancel',
        executionId: this.currentExecutionId,
        timestamp: Date.now(),
        payload: {},
      });
    }
    this.isRunning = false;
    this.currentExecutionId = null;
  }

  async retryItems(nodeId: string, itemIds: string[]): Promise<void> {
    for (const itemId of itemIds) {
      this.emitItem(nodeId, {
        id: itemId,
        index: 0,
        nodeId,
        status: 'retrying',
        data: {},
        startedAt: new Date(),
      });

      await this.delay(this.config.itemProcessingDelay);

      // Higher success rate on retry
      const shouldFail = Math.random() < 0.1;

      if (shouldFail) {
        this.emitItem(nodeId, {
          id: itemId,
          index: 0,
          nodeId,
          status: 'failed',
          data: {},
          completedAt: new Date(),
          error: { message: 'Retry failed', retryCount: 1, maxRetries: 3 },
        });
      } else {
        this.emitItem(nodeId, {
          id: itemId,
          index: 0,
          nodeId,
          status: 'success',
          data: {},
          completedAt: new Date(),
          result: { blocked: true },
        });
      }
    }
  }

  disconnect(): void {
    this.cancelExecution();
    this.handlers.clear();
    this.itemHandlers.clear();
    this.pendingApprovals.clear();
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

export const mockWebSocketService = new MockWebSocketService();
