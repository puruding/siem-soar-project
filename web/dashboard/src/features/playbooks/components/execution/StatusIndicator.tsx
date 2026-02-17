import { Loader2, CheckCircle2, XCircle, Clock, AlertTriangle, Ban } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { NodeExecutionStatus } from '../../types/execution.types';

interface StatusIndicatorProps {
  status: NodeExecutionStatus;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  className?: string;
}

const sizeClasses = {
  sm: 'w-3 h-3',
  md: 'w-4 h-4',
  lg: 'w-5 h-5',
};

const statusConfig: Record<NodeExecutionStatus, {
  icon: typeof CheckCircle2;
  color: string;
  bgColor: string;
  label: string;
  animate?: boolean;
}> = {
  pending: {
    icon: Clock,
    color: 'text-gray-400',
    bgColor: 'bg-gray-400/20',
    label: 'Pending',
  },
  queued: {
    icon: Clock,
    color: 'text-blue-400',
    bgColor: 'bg-blue-400/20',
    label: 'Queued',
    animate: true,
  },
  running: {
    icon: Loader2,
    color: 'text-blue-500',
    bgColor: 'bg-blue-500/20',
    label: 'Running',
    animate: true,
  },
  success: {
    icon: CheckCircle2,
    color: 'text-[#5CC05C]',
    bgColor: 'bg-[#5CC05C]/20',
    label: 'Success',
  },
  error: {
    icon: XCircle,
    color: 'text-[#DC4E41]',
    bgColor: 'bg-[#DC4E41]/20',
    label: 'Error',
  },
  skipped: {
    icon: AlertTriangle,
    color: 'text-yellow-500',
    bgColor: 'bg-yellow-500/20',
    label: 'Skipped',
  },
  cancelled: {
    icon: Ban,
    color: 'text-gray-500',
    bgColor: 'bg-gray-500/20',
    label: 'Cancelled',
  },
};

export function StatusIndicator({ status, size = 'md', showLabel = false, className }: StatusIndicatorProps) {
  const config = statusConfig[status];
  const Icon = config.icon;

  return (
    <div className={cn('flex items-center gap-1.5', className)}>
      <div className={cn('rounded-full p-0.5', config.bgColor)}>
        <Icon
          className={cn(
            sizeClasses[size],
            config.color,
            config.animate && status === 'running' && 'animate-spin'
          )}
        />
      </div>
      {showLabel && (
        <span className={cn('text-xs font-medium', config.color)}>
          {config.label}
        </span>
      )}
    </div>
  );
}
