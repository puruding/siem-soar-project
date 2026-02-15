import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { GitFork, Loader2, CheckCircle2, XCircle, Settings2, Merge } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ParallelNodeData {
  label: string;
  branches: number;
  waitForAll: boolean;
  timeout?: number;
  completedBranches?: number;
  status?: 'pending' | 'running' | 'completed' | 'failed';
  description?: string;
}

const ParallelNode = ({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as ParallelNodeData;

  const branches = Math.max(2, Math.min(nodeData.branches || 2, 5)); // Clamp between 2-5

  const getStatusIcon = () => {
    switch (nodeData.status) {
      case 'running':
        return <Loader2 className="w-3.5 h-3.5 text-[#9B59B6] animate-spin" />;
      case 'completed':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#5CC05C]" />;
      case 'failed':
        return <XCircle className="w-3.5 h-3.5 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  // Calculate handle positions for multiple outputs
  const getOutputHandlePositions = () => {
    const positions = [];
    const totalWidth = 80; // percentage width to spread handles
    const startX = (100 - totalWidth) / 2;
    const step = totalWidth / (branches - 1);

    for (let i = 0; i < branches; i++) {
      positions.push(startX + step * i);
    }
    return positions;
  };

  const outputPositions = getOutputHandlePositions();

  return (
    <div
      className={cn(
        'relative min-w-[240px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#9B59B6] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Parallel Shape - Wide rounded rectangle */}
      <div
        className={cn(
          'relative px-5 py-4 rounded-2xl bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg backdrop-blur-sm',
          nodeData.status === 'running' &&
            'from-[#9B59B6]/30 via-[#9B59B6]/20 to-[#9B59B6]/10 border-[#9B59B6] animate-pulse',
          nodeData.status === 'completed' && 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60',
          nodeData.status === 'failed' && 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60',
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#9B59B6]/15 via-card to-card border-[#9B59B6]/40 hover:border-[#9B59B6]'
        )}
      >
        <div className="flex items-start gap-3">
          {/* Icon Container */}
          <div
            className={cn(
              'shrink-0 p-2.5 rounded-xl transition-all duration-300',
              'bg-gradient-to-br from-[#9B59B6]/30 to-[#9B59B6]/10',
              'border border-[#9B59B6]/30'
            )}
          >
            <GitFork className="w-5 h-5 text-[#9B59B6]" />
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

            {/* Branch info */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="px-2 py-0.5 rounded-full bg-[#9B59B6]/20 text-2xs font-medium text-[#9B59B6] uppercase tracking-wide">
                {branches} Branches
              </span>

              {nodeData.waitForAll && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-muted/50 text-2xs font-medium text-muted-foreground">
                  <Merge className="w-3 h-3" />
                  Wait All
                </span>
              )}

              {nodeData.timeout && (
                <span className="text-2xs text-muted-foreground">
                  {nodeData.timeout}s timeout
                </span>
              )}
            </div>

            {/* Branch progress for running state */}
            {nodeData.status === 'running' && (
              <div className="mt-2 flex gap-1">
                {Array.from({ length: branches }).map((_, i) => (
                  <div
                    key={i}
                    className={cn(
                      'flex-1 h-1.5 rounded-full transition-all duration-300',
                      nodeData.completedBranches && i < nodeData.completedBranches
                        ? 'bg-[#5CC05C]'
                        : 'bg-[#9B59B6]/30'
                    )}
                  />
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Animated border for running state */}
        {nodeData.status === 'running' && (
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-[#9B59B6]/0 via-[#9B59B6]/20 to-[#9B59B6]/0 animate-pulse pointer-events-none" />
        )}

        {/* Settings button */}
        <button
          className={cn(
            'absolute top-2 right-2 p-1 rounded-lg',
            'bg-background/50 backdrop-blur-sm border border-border/50',
            'opacity-0 group-hover:opacity-100 transition-opacity',
            'hover:bg-background/80 hover:border-[#9B59B6]/50'
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
          '!bg-[#9B59B6] hover:!scale-125'
        )}
      />

      {/* Multiple Output Handles (Bottom) */}
      {outputPositions.map((leftPercent, i) => (
        <Handle
          key={`branch-${i}`}
          type="source"
          position={Position.Bottom}
          id={`branch-${i}`}
          className={cn(
            '!w-3.5 !h-3.5 !border-2 !border-background transition-all duration-300',
            '!bg-[#9B59B6] hover:!scale-125'
          )}
          style={{
            left: `${leftPercent}%`,
            bottom: '-7px',
          }}
        />
      ))}

      {/* Branch labels */}
      <div className="absolute -bottom-6 left-0 right-0 flex justify-between px-4 pointer-events-none">
        {outputPositions.map((leftPercent, i) => (
          <div
            key={`label-${i}`}
            className="text-2xs text-[#9B59B6]/70 font-medium"
            style={{
              position: 'absolute',
              left: `${leftPercent}%`,
              transform: 'translateX(-50%)',
            }}
          >
            B{i + 1}
          </div>
        ))}
      </div>

      {/* Merge indicator when waitForAll is true */}
      {nodeData.waitForAll && (
        <div className="absolute -bottom-10 left-1/2 -translate-x-1/2 flex items-center gap-1 px-2 py-0.5 rounded-full bg-[#9B59B6]/10 border border-[#9B59B6]/20 text-2xs text-[#9B59B6] pointer-events-none">
          <Merge className="w-3 h-3" />
          <span>merge</span>
        </div>
      )}
    </div>
  );
};

export default memo(ParallelNode);
