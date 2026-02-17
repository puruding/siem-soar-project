import { useEffect, useMemo } from 'react';
import { useShallow } from 'zustand/react/shallow';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { Progress } from '@/components/ui/progress';
import { Separator } from '@/components/ui/separator';
import { formatTimestamp, formatDuration } from '@/lib/utils';
import { useExecutionStore } from '../../stores/executionStore';
import { ExecutionControls } from './ExecutionControls';
import { NodeStatusTimeline } from './NodeStatusTimeline';
import { NodeDetailViewer } from './NodeDetailViewer';
import { StatusIndicator } from './StatusIndicator';

interface ExecutionPanelProps {
  isOpen: boolean;
  onClose: () => void;
}

export function ExecutionPanel({ isOpen, onClose }: ExecutionPanelProps) {
  const {
    execution,
    selectedNodeId,
    selectNode,
    setExecutionStatus,
    reset,
  } = useExecutionStore(
    useShallow((state) => ({
      execution: state.execution,
      selectedNodeId: state.selectedNodeId,
      selectNode: state.selectNode,
      setExecutionStatus: state.setExecutionStatus,
      reset: state.reset,
    }))
  );

  // WebSocket handlers (simulated for now - would integrate with real WebSocket service)
  const handlePause = () => {
    // TODO: Send pause message to WebSocket
    setExecutionStatus('paused');
  };

  const handleResume = () => {
    // TODO: Send resume message to WebSocket
    setExecutionStatus('running');
  };

  const handleCancel = () => {
    // TODO: Send cancel message to WebSocket
    setExecutionStatus('cancelled');
  };

  const handleReset = () => {
    reset();
    selectNode(null);
  };

  // Calculate execution duration
  const executionDuration = useMemo(() => {
    if (!execution?.startedAt) return null;
    const endTime = execution.completedAt || new Date();
    return endTime.getTime() - execution.startedAt.getTime();
  }, [execution?.startedAt, execution?.completedAt]);

  // Get selected node result
  const selectedNodeResult = useMemo(() => {
    if (!selectedNodeId || !execution?.nodeResults) return null;
    return execution.nodeResults.get(selectedNodeId) || null;
  }, [selectedNodeId, execution?.nodeResults]);

  // Auto-close when execution is reset
  useEffect(() => {
    if (!execution && isOpen) {
      onClose();
    }
  }, [execution, isOpen, onClose]);

  if (!execution) {
    return null;
  }

  const getStatusColor = () => {
    switch (execution.status) {
      case 'running':
        return 'bg-[#00A4A6]';
      case 'paused':
        return 'bg-yellow-500';
      case 'completed':
        return 'bg-[#5CC05C]';
      case 'failed':
        return 'bg-[#DC4E41]';
      case 'cancelled':
        return 'bg-gray-500';
      default:
        return 'bg-gray-400';
    }
  };

  const getStatusLabel = () => {
    switch (execution.status) {
      case 'running':
        return 'Running';
      case 'paused':
        return 'Paused';
      case 'completed':
        return 'Completed';
      case 'failed':
        return 'Failed';
      case 'cancelled':
        return 'Cancelled';
      default:
        return 'Idle';
    }
  };

  return (
    <Sheet open={isOpen} onOpenChange={onClose}>
      <SheetContent side="right" className="w-full sm:max-w-3xl p-0 flex flex-col">
        {/* Header */}
        <SheetHeader className="px-6 py-4 border-b border-[#2D3339]">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <SheetTitle className="text-lg font-semibold text-[#FFFFFF]">
                Execution Monitor
              </SheetTitle>
              <SheetDescription className="text-sm text-[#9BA7B4] mt-1">
                Execution ID: {execution.executionId}
              </SheetDescription>
            </div>
            <ExecutionControls
              executionId={execution.executionId}
              status={execution.status}
              onPause={handlePause}
              onResume={handleResume}
              onCancel={handleCancel}
              onReset={handleReset}
            />
          </div>

          {/* Progress bar */}
          <div className="mt-4 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <StatusIndicator
                  status={
                    execution.status === 'running' ? 'running' :
                    execution.status === 'completed' ? 'success' :
                    execution.status === 'failed' ? 'error' :
                    execution.status === 'cancelled' ? 'cancelled' :
                    execution.status === 'paused' ? 'queued' :
                    'pending'
                  }
                  size="sm"
                  showLabel
                />
                <span className="text-[#9BA7B4]">
                  {execution.progress}% complete
                </span>
              </div>
              <div className="flex items-center gap-3 text-[#9BA7B4]">
                {execution.startedAt && (
                  <span>Started: {formatTimestamp(execution.startedAt)}</span>
                )}
                {executionDuration !== null && (
                  <span>Duration: {formatDuration(executionDuration)}</span>
                )}
              </div>
            </div>
            <Progress
              value={execution.progress}
              indicatorColor={getStatusColor()}
              className="h-2"
            />
          </div>
        </SheetHeader>

        {/* Main content - split view */}
        <div className="flex-1 flex overflow-hidden">
          {/* Left panel - Timeline */}
          <div className="w-80 border-r border-[#2D3339] flex flex-col">
            <div className="px-4 py-3 border-b border-[#2D3339]">
              <h3 className="text-sm font-semibold text-[#FFFFFF]">Node Timeline</h3>
              <p className="text-xs text-[#9BA7B4] mt-1">
                {execution.nodeResults.size} node{execution.nodeResults.size !== 1 ? 's' : ''}
              </p>
            </div>
            <div className="flex-1 overflow-y-auto">
              <NodeStatusTimeline
                nodeResults={execution.nodeResults}
                currentNodeId={execution.currentNodeId}
                selectedNodeId={selectedNodeId ?? undefined}
                onNodeSelect={selectNode}
              />
            </div>
          </div>

          {/* Right panel - Node details */}
          <div className="flex-1 flex flex-col overflow-hidden bg-[#171D21]">
            <NodeDetailViewer nodeResult={selectedNodeResult} />
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
