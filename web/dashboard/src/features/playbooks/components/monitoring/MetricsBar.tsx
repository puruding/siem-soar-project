import { Activity, Clock, Timer } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { ProcessingMetrics } from '../../types/processing.types';

interface MetricsBarProps {
  metrics: ProcessingMetrics;
  className?: string;
}

const formatDuration = (ms: number): string => {
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  if (ms < 3600000) return `${(ms / 60000).toFixed(1)}m`;
  return `${(ms / 3600000).toFixed(1)}h`;
};

const formatTimeLeft = (seconds: number): string => {
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
};

export function MetricsBar({ metrics, className }: MetricsBarProps) {
  const progressPercentage = metrics.totalItems > 0
    ? (metrics.processedItems / metrics.totalItems) * 100
    : 0;

  return (
    <div className={cn('space-y-3', className)}>
      {/* Progress Bar */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-xs text-gray-400">
          <span>
            {metrics.processedItems} / {metrics.totalItems} items
          </span>
          <span className="font-mono">{progressPercentage.toFixed(1)}%</span>
        </div>
        <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
          <div
            className="h-full bg-blue-500 transition-all duration-300 ease-out"
            style={{ width: `${progressPercentage}%` }}
          />
        </div>
      </div>

      {/* Metrics Grid */}
      <div className="grid grid-cols-3 gap-3">
        {/* Throughput */}
        <div className="flex items-center gap-2 px-3 py-2 bg-gray-800/50 rounded-lg border border-gray-700">
          <div className="p-1.5 bg-blue-500/20 rounded">
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs text-gray-400">Throughput</div>
            <div className="font-mono text-sm font-medium text-gray-100 truncate">
              {metrics.throughput.toFixed(2)} items/s
            </div>
          </div>
        </div>

        {/* Avg Duration */}
        <div className="flex items-center gap-2 px-3 py-2 bg-gray-800/50 rounded-lg border border-gray-700">
          <div className="p-1.5 bg-purple-500/20 rounded">
            <Clock className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs text-gray-400">Avg Duration</div>
            <div className="font-mono text-sm font-medium text-gray-100 truncate">
              {formatDuration(metrics.avgDuration)}
            </div>
          </div>
        </div>

        {/* Time Left */}
        <div className="flex items-center gap-2 px-3 py-2 bg-gray-800/50 rounded-lg border border-gray-700">
          <div className="p-1.5 bg-orange-500/20 rounded">
            <Timer className="w-4 h-4 text-orange-400" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="text-xs text-gray-400">Time Left</div>
            <div className="font-mono text-sm font-medium text-gray-100 truncate">
              {metrics.estimatedTimeLeft > 0
                ? formatTimeLeft(metrics.estimatedTimeLeft)
                : 'Calculating...'}
            </div>
          </div>
        </div>
      </div>

      {/* Status Counts */}
      <div className="flex items-center gap-4 px-3 py-2 bg-gray-800/30 rounded-lg text-xs">
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-[#5CC05C] rounded-full" />
          <span className="text-gray-400">Success:</span>
          <span className="font-mono text-gray-200">{metrics.successCount}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-[#DC4E41] rounded-full" />
          <span className="text-gray-400">Failed:</span>
          <span className="font-mono text-gray-200">{metrics.failedCount}</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 bg-blue-400 rounded-full" />
          <span className="text-gray-400">Pending:</span>
          <span className="font-mono text-gray-200">{metrics.pendingCount}</span>
        </div>
      </div>
    </div>
  );
}
