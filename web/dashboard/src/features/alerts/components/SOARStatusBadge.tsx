import { Play, CheckCircle, XCircle, Clock, Pause } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useSOARStatusWebSocket } from '../hooks/useSOARStatusWebSocket';
import { useSOARStatusStore } from '../stores/soarStatusStore';

export interface SOARStatusBadgeProps {
  playbookName: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | 'paused' | 'waiting_approval';
  progress?: number; // 0-100
  compact?: boolean; // If true, show minimal version
  alertId?: string; // For WebSocket subscription
  enableRealtime?: boolean; // Enable real-time updates
}

const statusConfig = {
  pending: {
    icon: Clock,
    color: 'text-neon-orange border-neon-orange/50 bg-neon-orange/5',
    progressColor: 'bg-neon-orange',
    label: 'Pending',
    pulse: false,
  },
  running: {
    icon: Play,
    color: 'text-neon-blue border-neon-blue/50 bg-neon-blue/5',
    progressColor: 'bg-neon-blue',
    label: 'Running',
    pulse: true,
  },
  completed: {
    icon: CheckCircle,
    color: 'text-neon-green border-neon-green/50 bg-neon-green/5',
    progressColor: 'bg-neon-green',
    label: 'Completed',
    pulse: false,
  },
  failed: {
    icon: XCircle,
    color: 'text-red-500 border-red-500/50 bg-red-500/5',
    progressColor: 'bg-red-500',
    label: 'Failed',
    pulse: false,
  },
  cancelled: {
    icon: XCircle,
    color: 'text-gray-500 border-gray-500/50 bg-gray-500/5',
    progressColor: 'bg-gray-500',
    label: 'Cancelled',
    pulse: false,
  },
  paused: {
    icon: Pause,
    color: 'text-yellow-500 border-yellow-500/50 bg-yellow-500/5',
    progressColor: 'bg-yellow-500',
    label: 'Paused',
    pulse: false,
  },
  waiting_approval: {
    icon: Clock,
    color: 'text-purple-500 border-purple-500/50 bg-purple-500/5',
    progressColor: 'bg-purple-500',
    label: 'Awaiting Approval',
    pulse: true,
  },
} as const;

export function SOARStatusBadge({
  playbookName,
  status,
  progress = 0,
  compact = false,
  alertId,
  enableRealtime = false,
}: SOARStatusBadgeProps) {
  const updateStatus = useSOARStatusStore((state) => state.updateStatus);

  // Use WebSocket for real-time updates if enabled
  const { status: realtimeStatus, isConnected } = useSOARStatusWebSocket({
    alertId: alertId || '',
    enabled: enableRealtime && !!alertId && import.meta.env.VITE_SOAR_REALTIME_ENABLED !== 'false',
    onStatusChange: (newStatus) => {
      if (alertId) {
        updateStatus(alertId, newStatus);
      }
    },
  });

  // Use real-time status if available, otherwise fall back to props
  const displayStatus = realtimeStatus?.status || status;
  const displayProgress = realtimeStatus?.progress ?? progress;
  const displayPlaybookName = realtimeStatus?.playbookName || playbookName;

  const config = statusConfig[displayStatus];
  const Icon = config.icon;
  const showProgress = displayStatus === 'running' && displayProgress > 0;

  if (compact) {
    return (
      <div
        className={cn(
          'inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium',
          config.color
        )}
      >
        <Icon
          className={cn(
            'h-3 w-3',
            config.pulse && 'animate-pulse'
          )}
        />
        <span>{config.label}</span>
        {showProgress && (
          <span className="text-[10px] opacity-80">
            {displayProgress}%
          </span>
        )}
        {enableRealtime && isConnected && (
          <div className="h-1.5 w-1.5 rounded-full bg-neon-green animate-pulse" title="Live" />
        )}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'inline-flex flex-col gap-1.5 rounded-md border px-3 py-2 min-w-[160px]',
        config.color
      )}
    >
      {/* Header: Icon + Playbook Name */}
      <div className="flex items-center gap-2">
        <Icon
          className={cn(
            'h-4 w-4 flex-shrink-0',
            config.pulse && 'animate-pulse'
          )}
        />
        <span className="text-xs font-medium truncate flex-1">
          {displayPlaybookName}
        </span>
        {enableRealtime && isConnected && (
          <div className="h-2 w-2 rounded-full bg-neon-green animate-pulse" title="Live" />
        )}
      </div>

      {/* Progress Bar (if running) */}
      {showProgress && (
        <div className="space-y-1">
          <div className="relative h-1.5 w-full overflow-hidden rounded-full bg-background/20">
            <div
              className={cn(
                'h-full transition-all duration-300 ease-in-out',
                config.progressColor
              )}
              style={{ width: `${displayProgress}%` }}
            />
          </div>
          <div className="flex items-center justify-between text-[10px] opacity-70">
            <span>{config.label}</span>
            <span>{displayProgress}%</span>
          </div>
        </div>
      )}

      {/* Status Label (if not showing progress) */}
      {!showProgress && (
        <div className="flex items-center justify-between text-[10px] opacity-70">
          <span>{config.label}</span>
          {realtimeStatus?.currentStep && (
            <span className="truncate max-w-[100px]">{realtimeStatus.currentStep}</span>
          )}
        </div>
      )}
    </div>
  );
}
