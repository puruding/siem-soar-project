import { cn } from '@/lib/utils';
import { formatDuration } from '@/lib/utils';
import { StatusIndicator } from './StatusIndicator';
import type { NodeExecutionResult } from '../../types/execution.types';

interface NodeStatusTimelineProps {
  nodeResults: Map<string, NodeExecutionResult>;
  currentNodeId?: string;
  selectedNodeId?: string;
  onNodeSelect?: (nodeId: string) => void;
}

export function NodeStatusTimeline({
  nodeResults,
  currentNodeId,
  selectedNodeId,
  onNodeSelect,
}: NodeStatusTimelineProps) {
  // Convert Map to sorted array by executionOrder (primary) or startedAt (fallback)
  const sortedNodes = Array.from(nodeResults.values()).sort((a, b) => {
    // Primary: sort by executionOrder if both have it
    if (a.executionOrder !== undefined && b.executionOrder !== undefined) {
      return a.executionOrder - b.executionOrder;
    }
    // Fallback: nodes with executionOrder come first
    if (a.executionOrder !== undefined) return -1;
    if (b.executionOrder !== undefined) return 1;
    // Last resort: sort by startedAt
    if (!a.startedAt) return 1;
    if (!b.startedAt) return -1;
    return a.startedAt.getTime() - b.startedAt.getTime();
  });

  if (sortedNodes.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
        No nodes executed yet
      </div>
    );
  }

  return (
    <div className="space-y-2 p-4">
      {sortedNodes.map((node, index) => {
        const isSelected = selectedNodeId === node.nodeId;
        const isCurrentNode = currentNodeId === node.nodeId;
        const isLastNode = index === sortedNodes.length - 1;

        return (
          <div key={node.nodeId} className="relative">
            {/* Timeline line */}
            {!isLastNode && (
              <div className="absolute left-[11px] top-8 w-0.5 h-[calc(100%+8px)] bg-[#2D3339]" />
            )}

            {/* Node item */}
            <button
              onClick={() => onNodeSelect?.(node.nodeId)}
              className={cn(
                'w-full flex items-start gap-3 p-2 rounded-lg transition-colors text-left',
                isSelected && 'bg-[#1F2527] border border-[#00A4A6]',
                !isSelected && 'hover:bg-[#1F2527]/50',
                isCurrentNode && !isSelected && 'bg-[#1F2527]/30'
              )}
            >
              {/* Status indicator */}
              <div className="relative z-10 mt-0.5">
                <StatusIndicator status={node.status} size="md" />
              </div>

              {/* Node info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={cn(
                      'text-sm font-medium truncate',
                      isSelected ? 'text-[#00A4A6]' : 'text-[#FFFFFF]'
                    )}
                  >
                    {node.nodeName}
                  </span>
                  {node.duration !== undefined && (
                    <span className="text-xs text-[#9BA7B4] shrink-0">
                      {formatDuration(node.duration)}
                    </span>
                  )}
                </div>

                {/* Additional info */}
                {isCurrentNode && node.status === 'running' && (
                  <span className="text-xs text-[#00A4A6] font-medium">
                    Running...
                  </span>
                )}
                {node.error && (
                  <span className="text-xs text-[#DC4E41] truncate block">
                    {node.error.message}
                  </span>
                )}
              </div>
            </button>
          </div>
        );
      })}
    </div>
  );
}
