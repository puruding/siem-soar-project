import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import {
  Mail,
  Shield,
  Bell,
  Database,
  Terminal,
  Loader2,
  CheckCircle2,
  XCircle,
  Settings2,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ActionNodeData {
  label: string;
  actionType: 'email' | 'slack' | 'jira' | 'block_ip' | 'isolate' | 'custom';
  status?: 'pending' | 'running' | 'completed' | 'failed';
  duration?: number;
  description?: string;
}

const ActionNode = ({ data, selected }: NodeProps) => {
  // Type assertion since NodeProps<T> doesn't properly type data
  const nodeData = data as unknown as ActionNodeData;

  const getIcon = () => {
    switch (nodeData.actionType) {
      case 'email':
        return Mail;
      case 'slack':
        return Bell;
      case 'jira':
        return Database;
      case 'block_ip':
      case 'isolate':
        return Shield;
      case 'custom':
        return Terminal;
      default:
        return Settings2;
    }
  };

  const getStatusIcon = () => {
    switch (nodeData.status) {
      case 'running':
        return <Loader2 className="w-3.5 h-3.5 text-[#00A4A6] animate-spin" />;
      case 'completed':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#5CC05C]" />;
      case 'failed':
        return <XCircle className="w-3.5 h-3.5 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  const Icon = getIcon();

  return (
    <div
      className={cn(
        'relative min-w-[220px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#00A4A6] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Rounded Rectangle */}
      <div
        className={cn(
          'relative px-5 py-4 rounded-2xl bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg backdrop-blur-sm',
          nodeData.status === 'running' &&
            'from-[#00A4A6]/30 via-[#00A4A6]/20 to-[#00A4A6]/10 border-[#00A4A6] animate-pulse',
          nodeData.status === 'completed' && 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60',
          nodeData.status === 'failed' && 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60',
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#00A4A6]/15 via-card to-card border-[#00A4A6]/40 hover:border-[#00A4A6]'
        )}
      >
        <div className="flex items-start gap-3">
          {/* Icon Container */}
          <div
            className={cn(
              'shrink-0 p-2.5 rounded-xl transition-all duration-300',
              'bg-gradient-to-br from-[#00A4A6]/30 to-[#00A4A6]/10',
              'border border-[#00A4A6]/30'
            )}
          >
            <Icon className="w-5 h-5 text-[#00A4A6]" />
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
              <p className="text-2xs text-muted-foreground line-clamp-2 mb-2">
                {nodeData.description}
              </p>
            )}

            {/* Status and duration */}
            <div className="flex items-center gap-2 flex-wrap">
              {nodeData.status && (
                <span
                  className={cn(
                    'px-2 py-0.5 rounded-full text-2xs font-medium uppercase tracking-wide',
                    nodeData.status === 'running' && 'bg-[#00A4A6]/20 text-[#00A4A6]',
                    nodeData.status === 'completed' && 'bg-[#5CC05C]/20 text-[#5CC05C]',
                    nodeData.status === 'failed' && 'bg-[#DC4E41]/20 text-[#DC4E41]',
                    nodeData.status === 'pending' && 'bg-muted text-muted-foreground'
                  )}
                >
                  {nodeData.status}
                </span>
              )}
              {nodeData.duration && (
                <span className="text-2xs text-muted-foreground">
                  {nodeData.duration}ms
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Animated border for running state */}
        {nodeData.status === 'running' && (
          <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-[#00A4A6]/0 via-[#00A4A6]/20 to-[#00A4A6]/0 animate-pulse pointer-events-none" />
        )}

        {/* Settings button */}
        <button
          className={cn(
            'absolute top-2 right-2 p-1 rounded-lg',
            'bg-background/50 backdrop-blur-sm border border-border/50',
            'opacity-0 group-hover:opacity-100 transition-opacity',
            'hover:bg-background/80 hover:border-[#00A4A6]/50'
          )}
          onClick={(e) => {
            e.stopPropagation();
          }}
        >
          <Settings2 className="w-3 h-3 text-muted-foreground" />
        </button>
      </div>

      {/* Input Handle */}
      <Handle
        type="target"
        position={Position.Top}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#00A4A6] hover:!scale-125'
        )}
      />

      {/* Output Handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#00A4A6] hover:!scale-125'
        )}
      />
    </div>
  );
};

export default memo(ActionNode);
