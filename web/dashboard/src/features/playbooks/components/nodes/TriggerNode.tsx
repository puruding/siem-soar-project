import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Zap, Play, Clock, Webhook } from 'lucide-react';
import { cn } from '@/lib/utils';
import { StatusIndicator } from '../execution/StatusIndicator';
import type { NodeExecutionStatus } from '../../types/execution.types';

export interface TriggerNodeData {
  label: string;
  triggerType: 'alert' | 'schedule' | 'webhook' | 'manual';
  description?: string;
  status?: 'idle' | 'active' | 'disabled';
  executionStatus?: NodeExecutionStatus;
  executionDuration?: number;
}

const TriggerNode = ({ data, selected }: NodeProps) => {
  // Type assertion since NodeProps<T> doesn't properly type data
  const nodeData = data as unknown as TriggerNodeData;

  const getIcon = () => {
    switch (nodeData.triggerType) {
      case 'alert':
        return Zap;
      case 'schedule':
        return Clock;
      case 'webhook':
        return Webhook;
      case 'manual':
        return Play;
      default:
        return Zap;
    }
  };

  const Icon = getIcon();

  // Border glow effect based on execution status
  const getStatusBorderClass = () => {
    if (!nodeData.executionStatus) return '';
    switch (nodeData.executionStatus) {
      case 'running':
        return 'ring-2 ring-blue-500/50 animate-pulse';
      case 'success':
        return 'ring-2 ring-[#5CC05C]/50';
      case 'error':
        return 'ring-2 ring-[#DC4E41]/50 animate-shake';
      default:
        return '';
    }
  };

  return (
    <div
      className={cn(
        'relative min-w-[200px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#5CC05C] ring-offset-2 ring-offset-background scale-105 z-10',
        getStatusBorderClass()
      )}
    >
      {/* Hexagon shape using clip-path */}
      <div
        className={cn(
          'relative px-6 py-4 bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg',
          nodeData.status === 'active' &&
            'from-[#5CC05C]/30 via-[#5CC05C]/20 to-[#5CC05C]/10 border-[#5CC05C] animate-pulse',
          nodeData.status === 'disabled' && 'from-muted/30 to-muted/10 border-muted opacity-60',
          (!nodeData.status || nodeData.status === 'idle') &&
            'from-[#5CC05C]/20 via-[#5CC05C]/10 to-transparent border-[#5CC05C]/60 hover:border-[#5CC05C]'
        )}
        style={{
          clipPath:
            'polygon(30% 0%, 70% 0%, 100% 50%, 70% 100%, 30% 100%, 0% 50%)',
        }}
      >
        {/* Execution Status Indicator */}
        {nodeData.executionStatus && (
          <div className="absolute -top-2 -right-2 z-10">
            <StatusIndicator status={nodeData.executionStatus} size="sm" />
          </div>
        )}
        <div className="flex flex-col items-center gap-2 text-center">
          {/* Icon with pulse effect */}
          <div
            className={cn(
              'relative p-2 rounded-full transition-all duration-300',
              nodeData.status === 'active'
                ? 'bg-[#5CC05C]/30 animate-pulse'
                : 'bg-[#5CC05C]/20'
            )}
          >
            <Icon
              className={cn(
                'w-5 h-5 transition-colors',
                nodeData.status === 'active' ? 'text-[#5CC05C]' : 'text-[#5CC05C]/80'
              )}
            />
            {nodeData.status === 'active' && (
              <span className="absolute inset-0 rounded-full bg-[#5CC05C] opacity-30 animate-ping" />
            )}
          </div>

          {/* Label */}
          <div className="font-semibold text-sm text-foreground">
            {nodeData.label}
          </div>

          {/* Description */}
          {nodeData.description && (
            <div className="text-2xs text-muted-foreground line-clamp-2 max-w-[160px]">
              {nodeData.description}
            </div>
          )}

          {/* Type badge */}
          <div className="px-2 py-0.5 rounded-full bg-[#5CC05C]/20 text-2xs font-medium text-[#5CC05C] uppercase tracking-wide">
            {nodeData.triggerType}
          </div>
        </div>

        {/* Decorative glow for active state */}
        {nodeData.status === 'active' && (
          <div className="absolute inset-0 bg-[#5CC05C]/10 blur-xl -z-10 animate-pulse" />
        )}
      </div>

      {/* Output Handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#5CC05C] hover:!scale-125'
        )}
      />
    </div>
  );
};

export default memo(TriggerNode);
