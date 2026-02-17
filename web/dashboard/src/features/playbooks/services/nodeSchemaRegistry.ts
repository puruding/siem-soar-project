import type { NodeOutputSchema, NodeOutputField } from '../types/template.types';
import type { Node, Edge } from '@xyflow/react';

// Default schemas for each node type
export const defaultNodeSchemas: Record<string, NodeOutputField[]> = {
  trigger: [
    {
      name: 'alert',
      type: 'object',
      description: 'Incoming alert data',
      children: [
        { name: 'id', type: 'string', description: 'Alert ID', example: 'ALERT-001' },
        { name: 'severity', type: 'string', description: 'Alert severity', example: 'critical' },
        { name: 'source', type: 'string', description: 'Alert source system', example: 'EDR' },
        { name: 'timestamp', type: 'string', description: 'Alert timestamp' },
        { name: 'iocs', type: 'array', description: 'Indicators of compromise' },
      ],
    },
  ],
  action: [
    { name: 'success', type: 'boolean', description: 'Action success status', example: true },
    { name: 'result', type: 'object', description: 'Action result data' },
    { name: 'duration', type: 'number', description: 'Execution duration (ms)', example: 150 },
  ],
  integration: [
    { name: 'data', type: 'object', description: 'Integration response data' },
    { name: 'status', type: 'number', description: 'HTTP status code', example: 200 },
    { name: 'headers', type: 'object', description: 'Response headers' },
  ],
  decision: [
    { name: 'result', type: 'boolean', description: 'Condition evaluation result' },
    { name: 'branch', type: 'string', description: 'Selected branch', example: 'yes' },
  ],
  loop: [
    { name: 'item', type: 'object', description: 'Current loop item' },
    { name: 'index', type: 'number', description: 'Current iteration index', example: 0 },
    { name: 'isFirst', type: 'boolean', description: 'First iteration flag' },
    { name: 'isLast', type: 'boolean', description: 'Last iteration flag' },
  ],
  parallel: [
    { name: 'results', type: 'array', description: 'Results from all branches' },
    { name: 'allSuccess', type: 'boolean', description: 'All branches succeeded' },
  ],
  wait: [
    { name: 'waitedMs', type: 'number', description: 'Actual wait time in ms' },
    { name: 'resumedAt', type: 'string', description: 'Resume timestamp' },
  ],
};

export class NodeSchemaRegistry {
  private schemas: Map<string, NodeOutputSchema> = new Map();

  constructor() {
    this.registerDefaults();
  }

  private registerDefaults(): void {
    // Default schemas are resolved dynamically based on node type
  }

  getNodeSchema(node: Node): NodeOutputSchema {
    const nodeType = node.type || 'action';
    const nodeName = (node.data as { label?: string })?.label || node.id;

    // Check if we have a cached schema for this specific node
    const cached = this.schemas.get(node.id);
    if (cached) return cached;

    // Generate schema from defaults
    const fields = defaultNodeSchemas[nodeType] || defaultNodeSchemas.action || [];

    return {
      nodeId: node.id,
      nodeName,
      nodeType,
      fields,
    };
  }

  getUpstreamSchemas(nodeId: string, nodes: Node[], edges: Edge[]): NodeOutputSchema[] {
    const upstreamIds = this.findUpstreamNodes(nodeId, nodes, edges);
    return upstreamIds
      .map((id) => nodes.find((n) => n.id === id))
      .filter((n): n is Node => n !== undefined)
      .map((n) => this.getNodeSchema(n));
  }

  private findUpstreamNodes(nodeId: string, nodes: Node[], edges: Edge[]): string[] {
    const visited = new Set<string>();
    const queue: string[] = [];

    // Find direct predecessors
    edges.forEach((edge) => {
      if (edge.target === nodeId && !visited.has(edge.source)) {
        queue.push(edge.source);
      }
    });

    // BFS to find all upstream nodes
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      edges.forEach((edge) => {
        if (edge.target === current && !visited.has(edge.source)) {
          queue.push(edge.source);
        }
      });
    }

    return Array.from(visited);
  }

  updateFromOutput(nodeId: string, nodeName: string, nodeType: string, output: Record<string, unknown>): void {
    const fields = this.inferSchema(output);
    this.schemas.set(nodeId, {
      nodeId,
      nodeName,
      nodeType,
      fields,
    });
  }

  private inferSchema(value: unknown, depth = 0): NodeOutputField[] {
    if (depth > 5) return []; // Prevent infinite recursion

    if (value === null || value === undefined) {
      return [];
    }

    if (Array.isArray(value)) {
      if (value.length === 0) return [];
      // Infer from first element
      const firstItem = value[0];
      if (typeof firstItem === 'object' && firstItem !== null) {
        return this.inferSchema(firstItem, depth + 1);
      }
      return [];
    }

    if (typeof value === 'object') {
      return Object.entries(value).map(([key, val]): NodeOutputField => {
        let type: NodeOutputField['type'] = 'string';
        let children: NodeOutputField[] | undefined;

        if (val === null) {
          type = 'string';
        } else if (Array.isArray(val)) {
          type = 'array';
          if (val.length > 0 && typeof val[0] === 'object') {
            children = this.inferSchema(val[0], depth + 1);
          }
        } else if (typeof val === 'object') {
          type = 'object';
          children = this.inferSchema(val, depth + 1);
        } else if (typeof val === 'number') {
          type = 'number';
        } else if (typeof val === 'boolean') {
          type = 'boolean';
        }

        return {
          name: key,
          type,
          example: type !== 'object' && type !== 'array' ? val : undefined,
          children,
        };
      });
    }

    return [];
  }

  clear(): void {
    this.schemas.clear();
  }
}

export const nodeSchemaRegistry = new NodeSchemaRegistry();
