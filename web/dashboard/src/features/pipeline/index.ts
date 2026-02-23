/**
 * Pipeline Feature Module — Event Classification Pipeline
 *
 * Visualizes the 4-stage event processing pipeline:
 * Receive → Classify → Playbook Select → Execute
 */

export { PipelinePage } from './components/PipelinePage';

// API exports
export {
  getPipelineStatus,
  getStageStatuses,
  getStageMetrics,
  pauseStage,
  resumeStage,
  getThroughput,
  getPipelineErrors,
  fetchInitialPipelineData,
  toggleStageStatus,
} from './api/pipelineApi';

export type {
  PipelineStatus,
  StageStatus,
  StageMetrics,
  ThroughputData,
  PipelineError,
  PipelineErrorsResponse,
  StageActionResponse,
} from './api/pipelineApi';

// Hook exports
export { usePipelineWebSocket } from './hooks/usePipelineWebSocket';
export type { InitialPipelineData } from './hooks/usePipelineWebSocket';
