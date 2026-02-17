import { useMemo } from 'react';
import type { Edge, Node } from '@xyflow/react';
import type { NodeOutputSchema } from '../types/template.types';
import { nodeSchemaRegistry } from '../services/nodeSchemaRegistry';

export interface UpstreamNode {
  nodeId: string;
  nodeName: string;
  schema: NodeOutputSchema;
}

export interface UseNodeOutputSchemaReturn {
  upstreamNodes: UpstreamNode[];
  updateSchema: (nodeId: string, nodeName: string, nodeType: string, output: Record<string, unknown>) => void;
}

export interface UseNodeOutputSchemaProps {
  currentNodeId: string;
  nodes: Node[];
  edges: Edge[];
}

/**
 * Hook to get output schema for upstream nodes
 *
 * @param currentNodeId - The current node ID
 * @param nodes - Array of all nodes in the flow
 * @param edges - Array of all edges in the flow
 * @returns Upstream node schemas and update function
 *
 * @example
 * ```tsx
 * const { upstreamNodes, updateSchema } = useNodeOutputSchema({
 *   currentNodeId: 'node-2',
 *   nodes: reactFlowNodes,
 *   edges: reactFlowEdges
 * });
 *
 * // Access upstream data
 * upstreamNodes.forEach(({ nodeId, nodeName, schema }) => {
 *   console.log(`${nodeName} outputs:`, schema.fields);
 * });
 *
 * // Update schema when node execution completes
 * updateSchema(nodeId, nodeName, nodeType, outputData);
 * ```
 */
export function useNodeOutputSchema({
  currentNodeId,
  nodes,
  edges
}: UseNodeOutputSchemaProps): UseNodeOutputSchemaReturn {
  // Calculate upstream nodes from edge connections
  const upstreamNodes = useMemo(() => {
    // Find all edges pointing to the current node
    const incomingEdges = edges.filter((edge) => edge.target === currentNodeId);

    // Get unique source node IDs
    const upstreamNodeIds = new Set(incomingEdges.map((edge) => edge.source));

    // Build upstream node data with schemas
    const result: UpstreamNode[] = [];

    upstreamNodeIds.forEach((nodeId) => {
      const node = nodes.find((n) => n.id === nodeId);
      if (!node) return;

      const schema = nodeSchemaRegistry.getNodeSchema(node);
      const nodeName = (node.data as { label?: string })?.label || node.id;

      result.push({
        nodeId,
        nodeName,
        schema
      });
    });

    // Sort by node name for consistent ordering
    return result.sort((a, b) => a.nodeName.localeCompare(b.nodeName));
  }, [currentNodeId, nodes, edges]);

  // Function to update schema based on actual output
  const updateSchema = (
    nodeId: string,
    nodeName: string,
    nodeType: string,
    output: Record<string, unknown>
  ) => {
    nodeSchemaRegistry.updateFromOutput(nodeId, nodeName, nodeType, output);
  };

  return {
    upstreamNodes,
    updateSchema
  };
}
