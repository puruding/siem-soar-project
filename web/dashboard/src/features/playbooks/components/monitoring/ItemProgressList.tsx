import { useMemo, useState } from 'react';
import { useVirtualizer } from '@tanstack/react-virtual';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import type { ProcessingItem } from '../../types/processing.types';

interface ItemProgressListProps {
  items: ProcessingItem[];
  containerHeight: number;
  className?: string;
}

type FilterStatus = 'all' | 'processing' | 'success' | 'failed';

const statusBadgeConfig: Record<ProcessingItem['status'], { label: string; variant: 'default' | 'secondary' | 'destructive' | 'outline' }> = {
  pending: { label: 'Pending', variant: 'outline' },
  processing: { label: 'Processing', variant: 'default' },
  success: { label: 'Success', variant: 'secondary' },
  failed: { label: 'Failed', variant: 'destructive' },
  retrying: { label: 'Retrying', variant: 'default' },
};

const formatDuration = (ms: number | undefined): string => {
  if (ms === undefined) return '-';
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(2)}s`;
  return `${(ms / 60000).toFixed(2)}m`;
};

export function ItemProgressList({ items, containerHeight, className }: ItemProgressListProps) {
  const [filter, setFilter] = useState<FilterStatus>('all');

  const filteredItems = useMemo(() => {
    if (filter === 'all') return items;
    if (filter === 'processing') {
      return items.filter(item => item.status === 'processing' || item.status === 'retrying');
    }
    return items.filter(item => item.status === filter);
  }, [items, filter]);

  const parentRef = useMemo(() => ({ current: null as HTMLDivElement | null }), []);

  const virtualizer = useVirtualizer({
    count: filteredItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 56,
    overscan: 10,
  });

  const filterCounts = useMemo(() => {
    const counts = {
      all: items.length,
      processing: 0,
      success: 0,
      failed: 0,
    };

    items.forEach(item => {
      if (item.status === 'processing' || item.status === 'retrying') {
        counts.processing++;
      } else if (item.status === 'success') {
        counts.success++;
      } else if (item.status === 'failed') {
        counts.failed++;
      }
    });

    return counts;
  }, [items]);

  return (
    <div className={cn('flex flex-col gap-3', className)}>
      {/* Filter Buttons */}
      <div className="flex items-center gap-2">
        <Button
          variant={filter === 'all' ? 'default' : 'outline'}
          size="sm"
          onClick={() => setFilter('all')}
          className="text-xs"
        >
          All ({filterCounts.all})
        </Button>
        <Button
          variant={filter === 'processing' ? 'default' : 'outline'}
          size="sm"
          onClick={() => setFilter('processing')}
          className="text-xs"
        >
          Processing ({filterCounts.processing})
        </Button>
        <Button
          variant={filter === 'success' ? 'default' : 'outline'}
          size="sm"
          onClick={() => setFilter('success')}
          className="text-xs"
        >
          Success ({filterCounts.success})
        </Button>
        <Button
          variant={filter === 'failed' ? 'default' : 'outline'}
          size="sm"
          onClick={() => setFilter('failed')}
          className="text-xs"
        >
          Failed ({filterCounts.failed})
        </Button>
      </div>

      {/* Virtualized List */}
      <div
        ref={parentRef as React.RefObject<HTMLDivElement>}
        style={{ height: containerHeight }}
        className="overflow-auto border border-gray-700 rounded-lg bg-gray-900"
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: '100%',
            position: 'relative',
          }}
        >
          {virtualizer.getVirtualItems().map((virtualItem) => {
            const item = filteredItems[virtualItem.index];
            if (!item) return null;
            const config = statusBadgeConfig[item.status];

            return (
              <div
                key={virtualItem.key}
                style={{
                  position: 'absolute',
                  top: 0,
                  left: 0,
                  width: '100%',
                  height: `${virtualItem.size}px`,
                  transform: `translateY(${virtualItem.start}px)`,
                }}
                className="px-4 py-3 border-b border-gray-800 hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <span className="font-mono text-xs text-gray-500 w-12 flex-shrink-0">
                      #{item.index + 1}
                    </span>
                    <span className="font-mono text-sm text-gray-300 truncate">
                      {item.id}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 flex-shrink-0">
                    <Badge variant={config.variant} className="text-xs">
                      {config.label}
                    </Badge>
                    <span className="font-mono text-xs text-gray-400 w-16 text-right">
                      {formatDuration(item.duration)}
                    </span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {filteredItems.length === 0 && (
        <div className="text-center py-8 text-gray-400 text-sm">
          No items matching filter
        </div>
      )}
    </div>
  );
}
