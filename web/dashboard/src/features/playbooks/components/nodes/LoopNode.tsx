import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Repeat, Loader2, CheckCircle2, XCircle, Settings2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface LoopNodeData {
  label: string;
  loopType: 'forEach' | 'while' | 'times';
  sourceArray?: string;
  condition?: string;
  maxIterations?: number;
  currentIteration?: number;
  totalIterations?: number;
  status?: 'pending' | 'running' | 'completed' | 'failed';
  description?: string;
}

const LoopNode = ({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as LoopNodeData;

  const getLoopLabel = () => {
    switch (nodeData.loopType) {
      case 'forEach':
        return 'For Each';
      case 'while':
        return 'While';
      case 'times':
        return `${nodeData.maxIterations || 0} Times`;
      default:
        return 'Loop';
    }
  };

  const getStatusIcon = () => {
    switch (nodeData.status) {
      case 'running':
        return <Loader2 className="w-3.5 h-3.5 text-[#F79836] animate-spin" />;
      case 'completed':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#5CC05C]" />;
      case 'failed':
        return <XCircle className="w-3.5 h-3.5 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  const iterationProgress =
    nodeData.currentIteration && nodeData.totalIterations
      ? Math.round((nodeData.currentIteration / nodeData.totalIterations) * 100)
      : 0;

  return (
    <div
      className={cn(
        'relative min-w-[220px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#F79836] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Loop Shape - Rounded rectangle with loop icon */}
      <div
        className={cn(
          'relative px-5 py-4 rounded-2xl bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg backdrop-blur-sm',
          nodeData.status === 'running' &&
            'from-[#F79836]/30 via-[#F79836]/20 to-[#F79836]/10 border-[#F79836] animate-pulse',
          nodeData.status === 'completed' && 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60',
          nodeData.status === 'failed' && 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60',
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#F79836]/15 via-card to-card border-[#F79836]/40 hover:border-[#F79836]'
        )}
      >
        <div className="flex items-start gap-3">
          {/* Icon Container with iteration badge */}
          <div className="relative shrink-0">
            <div
              className={cn(
                'p-2.5 rounded-xl transition-all duration-300',
                'bg-gradient-to-br from-[#F79836]/30 to-[#F79836]/10',
                'border border-[#F79836]/30'
              )}
            >
              <Repeat className="w-5 h-5 text-[#F79836]" />
            </div>
            {/* Iteration Badge */}
            {nodeData.status === 'running' && nodeData.currentIteration !== undefined && (
              <div className="absolute -top-1 -right-1 min-w-[18px] h-[18px] rounded-full bg-[#F79836] text-white text-2xs font-bold flex items-center justify-center px-1">
                {nodeData.currentIteration}
              </div>
            )}
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm text-foreground truncate">
                {nodeData.label}
              </h4>
              {nodeData.status && (
                <div className="shrink-0">{getStatusIcon()}</div>
              )}
            </div>

            {nodeData.description && (
              <p className="text-2xs text-muted-foreground line-clamp-1 mb-2">
                {nodeData.description}
              </p>
            )}

            {/* Loop Type and condition/source */}
            <div className="flex flex-col gap-1">
              <span className="px-2 py-0.5 rounded-full bg-[#F79836]/20 text-2xs font-medium text-[#F79836] uppercase tracking-wide w-fit">
                {getLoopLabel()}
              </span>

              {nodeData.loopType === 'forEach' && nodeData.sourceArray && (
                <span className="text-2xs text-muted-foreground font-mono truncate">
                  in {nodeData.sourceArray}
                </span>
              )}

              {nodeData.loopType === 'while' && nodeData.condition && (
                <span className="text-2xs text-muted-foreground font-mono truncate">
                  {nodeData.condition}
                </span>
              )}
            </div>

            {/* Progress bar for running state */}
            {nodeData.status === 'running' && nodeData.totalIterations && (
              <div className="mt-2">
                <div className="h-1.5 w-full bg-[#F79836]/20 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[#F79836] rounded-full transition-all duration-300"
                    style={{ width: `${iterationProgress}%` }}
                  />
                </div>
                <div className="text-2xs text-muted-foreground mt-0.5">
                  {nodeData.currentIteration}/{nodeData.totalIterations} iterations
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Animated border for running state */}
        {nodeData.status === 'running' && (
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-[#F79836]/0 via-[#F79836]/20 to-[#F79836]/0 animate-pulse pointer-events-none" />
        )}

        {/* Settings button */}
        <button
          className={cn(
            'absolute top-2 right-2 p-1 rounded-lg',
            'bg-background/50 backdrop-blur-sm border border-border/50',
            'opacity-0 group-hover:opacity-100 transition-opacity',
            'hover:bg-background/80 hover:border-[#F79836]/50'
          )}
          onClick={(e) => {
            e.stopPropagation();
          }}
        >
          <Settings2 className="w-3 h-3 text-muted-foreground" />
        </button>
      </div>

      {/* Input Handle (Top) */}
      <Handle
        type="target"
        position={Position.Top}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#F79836] hover:!scale-125'
        )}
      />

      {/* Output Handle (Bottom) */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#F79836] hover:!scale-125'
        )}
      />

      {/* Loop-back Handle (Right side) */}
      <Handle
        type="source"
        position={Position.Right}
        id="loop"
        className={cn(
          '!w-3 !h-3 !border-2 !border-background transition-all duration-300',
          '!bg-[#F79836]/70 hover:!scale-125 hover:!bg-[#F79836]'
        )}
      />

      {/* Loop-back indicator label */}
      <div className="absolute right-[-30px] top-1/2 -translate-y-1/2 text-2xs text-[#F79836]/70 font-medium pointer-events-none">
        loop
      </div>
    </div>
  );
};

export default memo(LoopNode);
