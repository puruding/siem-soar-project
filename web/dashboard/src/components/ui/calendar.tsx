import * as React from 'react';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/button';

const DAYS_OF_WEEK = ['일', '월', '화', '수', '목', '금', '토'];

function getDaysInMonth(year: number, month: number): number {
  return new Date(year, month + 1, 0).getDate();
}

function getFirstDayOfWeek(year: number, month: number): number {
  return new Date(year, month, 1).getDay();
}

function isSameDay(a: Date, b: Date): boolean {
  return (
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
  );
}

function isToday(date: Date): boolean {
  return isSameDay(date, new Date());
}

interface CalendarProps {
  mode?: 'single';
  selected?: Date;
  onSelect?: (date: Date | undefined) => void;
  className?: string;
  disabled?: (date: Date) => boolean;
}

function Calendar({
  mode = 'single',
  selected,
  onSelect,
  className,
  disabled,
}: CalendarProps) {
  const today = new Date();
  const [viewYear, setViewYear] = React.useState(
    selected ? selected.getFullYear() : today.getFullYear()
  );
  const [viewMonth, setViewMonth] = React.useState(
    selected ? selected.getMonth() : today.getMonth()
  );

  const daysInMonth = getDaysInMonth(viewYear, viewMonth);
  const firstDayOfWeek = getFirstDayOfWeek(viewYear, viewMonth);

  const prevMonth = () => {
    if (viewMonth === 0) {
      setViewMonth(11);
      setViewYear((y) => y - 1);
    } else {
      setViewMonth((m) => m - 1);
    }
  };

  const nextMonth = () => {
    if (viewMonth === 11) {
      setViewMonth(0);
      setViewYear((y) => y + 1);
    } else {
      setViewMonth((m) => m + 1);
    }
  };

  const monthLabel = `${viewYear}년 ${viewMonth + 1}월`;

  // Build grid cells: leading blanks + day cells
  const cells: (number | null)[] = [
    ...Array(firstDayOfWeek).fill(null),
    ...Array.from({ length: daysInMonth }, (_, i) => i + 1),
  ];

  // Pad to multiple of 7
  while (cells.length % 7 !== 0) {
    cells.push(null);
  }

  const handleDayClick = (day: number) => {
    const date = new Date(viewYear, viewMonth, day);
    if (disabled && disabled(date)) return;
    if (mode === 'single') {
      if (selected && isSameDay(selected, date)) {
        onSelect?.(undefined);
      } else {
        onSelect?.(date);
      }
    }
  };

  return (
    <div className={cn('p-3 select-none', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0"
          onClick={prevMonth}
          type="button"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-sm font-medium">{monthLabel}</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 w-7 p-0"
          onClick={nextMonth}
          type="button"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>

      {/* Day of week headers */}
      <div className="grid grid-cols-7 mb-1">
        {DAYS_OF_WEEK.map((d) => (
          <div
            key={d}
            className="h-8 flex items-center justify-center text-xs text-muted-foreground font-medium"
          >
            {d}
          </div>
        ))}
      </div>

      {/* Day cells */}
      <div className="grid grid-cols-7">
        {cells.map((day, idx) => {
          if (day === null) {
            return <div key={`blank-${idx}`} className="h-8" />;
          }
          const date = new Date(viewYear, viewMonth, day);
          const isSelected = selected ? isSameDay(selected, date) : false;
          const isDisabled = disabled ? disabled(date) : false;
          const _isToday = isToday(date);

          return (
            <button
              key={day}
              type="button"
              onClick={() => handleDayClick(day)}
              disabled={isDisabled}
              className={cn(
                'h-8 w-full rounded-md text-sm flex items-center justify-center transition-colors',
                'hover:bg-accent hover:text-accent-foreground',
                isSelected &&
                  'bg-primary text-primary-foreground hover:bg-primary hover:text-primary-foreground',
                _isToday && !isSelected && 'border border-primary text-primary',
                isDisabled && 'opacity-40 cursor-not-allowed pointer-events-none'
              )}
            >
              {day}
            </button>
          );
        })}
      </div>
    </div>
  );
}

Calendar.displayName = 'Calendar';

export { Calendar };
export type { CalendarProps };
