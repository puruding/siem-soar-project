import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Clock, Timer, Webhook, Loader2, CheckCircle2, XCircle, Settings2, Hourglass } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface WaitNodeData {
  label: string;
  waitType: 'duration' | 'until' | 'webhook';
  duration?: number; // in seconds
  untilCondition?: string;
  webhookId?: string;
  elapsed?: number; // current elapsed time in seconds
  status?: 'pending' | 'waiting' | 'completed' | 'failed';
  description?: string;
}

const WaitNode = ({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as WaitNodeData;

  const getIcon = () => {
    switch (nodeData.waitType) {
      case 'duration':
        return Timer;
      case 'until':
        return Clock;
      case 'webhook':
        return Webhook;
      default:
        return Clock;
    }
  };

  const getWaitLabel = () => {
    switch (nodeData.waitType) {
      case 'duration':
        return formatDuration(nodeData.duration || 0);
      case 'until':
        return 'Until';
      case 'webhook':
        return 'Webhook';
      default:
        return 'Wait';
    }
  };

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return `${hours}h ${mins}m`;
  };

  const getStatusIcon = () => {
    switch (nodeData.status) {
      case 'waiting':
        return <Loader2 className="w-3.5 h-3.5 text-[#3498DB] animate-spin" />;
      case 'completed':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#5CC05C]" />;
      case 'failed':
        return <XCircle className="w-3.5 h-3.5 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  const Icon = getIcon();
  const progress =
    nodeData.status === 'waiting' && nodeData.duration && nodeData.elapsed
      ? Math.min(100, (nodeData.elapsed / nodeData.duration) * 100)
      : 0;

  return (
    <div
      className={cn(
        'relative min-w-[200px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#3498DB] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Wait Shape - Rounded rectangle with clock styling */}
      <div
        className={cn(
          'relative px-5 py-4 rounded-2xl bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg backdrop-blur-sm',
          nodeData.status === 'waiting' &&
            'from-[#3498DB]/30 via-[#3498DB]/20 to-[#3498DB]/10 border-[#3498DB]',
          nodeData.status === 'completed' && 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60',
          nodeData.status === 'failed' && 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60',
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#3498DB]/15 via-card to-card border-[#3498DB]/40 hover:border-[#3498DB]'
        )}
      >
        <div className="flex items-start gap-3">
          {/* Icon Container with animated hourglass for waiting state */}
          <div className="relative shrink-0">
            <div
              className={cn(
                'p-2.5 rounded-xl transition-all duration-300',
                'bg-gradient-to-br from-[#3498DB]/30 to-[#3498DB]/10',
                'border border-[#3498DB]/30'
              )}
            >
              {nodeData.status === 'waiting' ? (
                <Hourglass className="w-5 h-5 text-[#3498DB] animate-pulse" />
              ) : (
                <Icon className="w-5 h-5 text-[#3498DB]" />
              )}
            </div>
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

            {/* Wait Type Info */}
            <div className="flex flex-col gap-1">
              <span className="px-2 py-0.5 rounded-full bg-[#3498DB]/20 text-2xs font-medium text-[#3498DB] uppercase tracking-wide w-fit">
                {getWaitLabel()}
              </span>

              {nodeData.waitType === 'until' && nodeData.untilCondition && (
                <span className="text-2xs text-muted-foreground font-mono truncate">
                  {nodeData.untilCondition}
                </span>
              )}

              {nodeData.waitType === 'webhook' && nodeData.webhookId && (
                <span className="text-2xs text-muted-foreground font-mono truncate">
                  ID: {nodeData.webhookId}
                </span>
              )}
            </div>

            {/* Progress for duration wait */}
            {nodeData.waitType === 'duration' && nodeData.status === 'waiting' && nodeData.duration && (
              <div className="mt-2">
                <div className="h-1.5 w-full bg-[#3498DB]/20 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-[#3498DB] rounded-full transition-all duration-1000"
                    style={{ width: `${progress}%` }}
                  />
                </div>
                <div className="text-2xs text-muted-foreground mt-0.5">
                  {formatDuration(nodeData.elapsed || 0)} / {formatDuration(nodeData.duration)}
                </div>
              </div>
            )}

            {/* Countdown display for waiting state */}
            {nodeData.waitType === 'duration' && nodeData.status === 'waiting' && nodeData.duration && nodeData.elapsed && (
              <div className="mt-1 text-lg font-mono font-bold text-[#3498DB]">
                {formatDuration(nodeData.duration - nodeData.elapsed)}
              </div>
            )}
          </div>
        </div>

        {/* Animated pulse effect for waiting state */}
        {nodeData.status === 'waiting' && (
          <>
            <div className="absolute inset-0 rounded-2xl bg-[#3498DB]/10 animate-ping pointer-events-none" />
            <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-[#3498DB]/0 via-[#3498DB]/10 to-[#3498DB]/0 animate-pulse pointer-events-none" />
          </>
        )}

        {/* Settings button */}
        <button
          className={cn(
            'absolute top-2 right-2 p-1 rounded-lg',
            'bg-background/50 backdrop-blur-sm border border-border/50',
            'opacity-0 group-hover:opacity-100 transition-opacity',
            'hover:bg-background/80 hover:border-[#3498DB]/50'
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
          '!bg-[#3498DB] hover:!scale-125'
        )}
      />

      {/* Output Handle (Bottom) */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#3498DB] hover:!scale-125'
        )}
      />
    </div>
  );
};

export default memo(WaitNode);
