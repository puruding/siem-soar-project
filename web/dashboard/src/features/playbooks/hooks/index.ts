/**
 * Custom hooks for the n8n Playbook feature
 *
 * @module hooks
 */

export { useExecutionWebSocket } from './useExecutionWebSocket';
export { useNodeOutputSchema } from './useNodeOutputSchema';
export { useProcessingMetrics } from './useProcessingMetrics';

export type {
  UseExecutionWebSocketReturn,
  UseExecutionWebSocketProps
} from './useExecutionWebSocket';

export type {
  UpstreamNode,
  UseNodeOutputSchemaReturn,
  UseNodeOutputSchemaProps
} from './useNodeOutputSchema';

export type {
  ProcessingMetricsData,
  UseProcessingMetricsReturn,
  UseProcessingMetricsProps
} from './useProcessingMetrics';
