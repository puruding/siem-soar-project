import { useState } from 'react';
import { AlertCircle, ChevronDown, ChevronRight, RotateCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import type { ProcessingItem } from '../../types/processing.types';

interface FailedItemsPanelProps {
  failedItems: ProcessingItem[];
  onRetryItem?: (itemId: string) => void;
  onRetryAll?: () => void;
  className?: string;
}

interface ExpandedState {
  [itemId: string]: boolean;
}

export function FailedItemsPanel({
  failedItems,
  onRetryItem,
  onRetryAll,
  className
}: FailedItemsPanelProps) {
  const [expanded, setExpanded] = useState<ExpandedState>({});

  const toggleExpanded = (itemId: string) => {
    setExpanded(prev => ({
      ...prev,
      [itemId]: !prev[itemId],
    }));
  };

  if (failedItems.length === 0) {
    return (
      <div className={cn('flex flex-col items-center justify-center py-12 text-gray-400', className)}>
        <AlertCircle className="w-12 h-12 mb-3 text-gray-600" />
        <p className="text-sm">No failed items</p>
      </div>
    );
  }

  return (
    <div className={cn('space-y-3', className)}>
      {/* Header with Retry All */}
      <div className="flex items-center justify-between px-4 py-3 bg-red-500/10 border border-red-500/20 rounded-lg">
        <div className="flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-red-400" />
          <span className="text-sm font-medium text-red-300">
            {failedItems.length} Failed Items
          </span>
        </div>
        {onRetryAll && (
          <Button
            variant="outline"
            size="sm"
            onClick={onRetryAll}
            className="gap-2 text-xs"
          >
            <RotateCw className="w-3.5 h-3.5" />
            Retry All
          </Button>
        )}
      </div>

      {/* Failed Items List */}
      <div className="space-y-2">
        {failedItems.map((item) => {
          const isExpanded = expanded[item.id] ?? false;
          const errorMessage = item.error?.message ?? 'Unknown error';
          const truncatedMessage = errorMessage.length > 80
            ? `${errorMessage.substring(0, 80)}...`
            : errorMessage;
          const retryInfo = item.error?.retryCount !== undefined && item.error?.maxRetries !== undefined
            ? `(${item.error.retryCount}/${item.error.maxRetries} retries)`
            : '';

          return (
            <div
              key={item.id}
              className="border border-gray-700 rounded-lg bg-gray-800/50 overflow-hidden"
            >
              {/* Item Header */}
              <div className="px-4 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-mono text-xs text-gray-500">
                        #{item.index + 1}
                      </span>
                      <span className="font-mono text-sm text-gray-300 truncate">
                        {item.id}
                      </span>
                      {retryInfo && (
                        <Badge variant="outline" className="text-xs">
                          {retryInfo}
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-start gap-2">
                      <button
                        onClick={() => toggleExpanded(item.id)}
                        className="flex-shrink-0 mt-0.5 text-gray-400 hover:text-gray-300 transition-colors"
                      >
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </button>
                      <p className="text-xs text-red-400 flex-1">
                        {isExpanded ? errorMessage : truncatedMessage}
                      </p>
                    </div>
                    {item.error?.code && (
                      <p className="text-xs text-gray-500 mt-1 ml-6">
                        Error Code: {item.error.code}
                      </p>
                    )}
                  </div>
                  {onRetryItem && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => onRetryItem(item.id)}
                      className="gap-2 text-xs flex-shrink-0"
                    >
                      <RotateCw className="w-3.5 h-3.5" />
                      Retry
                    </Button>
                  )}
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="px-4 py-3 bg-gray-900/50 border-t border-gray-700">
                  <div className="space-y-2 text-xs">
                    <div>
                      <span className="text-gray-500">Started:</span>{' '}
                      <span className="text-gray-300 font-mono">
                        {item.startedAt?.toLocaleString() ?? 'N/A'}
                      </span>
                    </div>
                    <div>
                      <span className="text-gray-500">Failed:</span>{' '}
                      <span className="text-gray-300 font-mono">
                        {item.completedAt?.toLocaleString() ?? 'N/A'}
                      </span>
                    </div>
                    {item.duration !== undefined && (
                      <div>
                        <span className="text-gray-500">Duration:</span>{' '}
                        <span className="text-gray-300 font-mono">
                          {item.duration < 1000
                            ? `${item.duration}ms`
                            : `${(item.duration / 1000).toFixed(2)}s`}
                        </span>
                      </div>
                    )}
                    <div className="pt-2">
                      <div className="text-gray-500 mb-1">Input Data:</div>
                      <pre className="text-xs bg-gray-950 p-2 rounded border border-gray-700 overflow-x-auto">
                        {JSON.stringify(item.data, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
