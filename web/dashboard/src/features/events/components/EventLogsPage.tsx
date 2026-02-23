import { useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover';
import { Calendar } from '@/components/ui/calendar';
import { ScrollText, Search, ChevronLeft, ChevronRight, Eye, CalendarIcon, RefreshCw, Loader2, AlertCircle } from 'lucide-react';
import { cn, truncate } from '@/lib/utils';
import type { EventLog } from '../types';
import { useEventLogs, DEMO_ASSETS } from '../hooks/useEventLogs';
import { formatEventTime } from '../api/eventsApi';

const severityVariant: Record<
  EventLog['security_severity'],
  'critical' | 'high' | 'medium' | 'low' | 'info' | 'secondary'
> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'info',
  UNKNOWN: 'secondary',
};

const severityLabel: Record<EventLog['security_severity'], string> = {
  CRITICAL: '심각',
  HIGH: '높음',
  MEDIUM: '중간',
  LOW: '낮음',
  INFORMATIONAL: '정보',
  UNKNOWN: '알 수 없음',
};

function formatDateDisplay(date: Date | null): string {
  if (!date) return '';
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

interface DateTimePickerProps {
  value: Date | null;
  onChange: (date: Date | null) => void;
  placeholder: string;
}

function DateTimePicker({ value, onChange, placeholder }: DateTimePickerProps) {
  const [open, setOpen] = useState(false);
  const [hours, setHours] = useState(value ? value.getHours().toString() : '0');
  const [minutes, setMinutes] = useState(value ? value.getMinutes().toString() : '0');
  const [seconds, setSeconds] = useState(value ? value.getSeconds().toString() : '0');

  const handleDaySelect = (day: Date | undefined) => {
    if (!day) {
      onChange(null);
      return;
    }
    const h = Math.min(23, Math.max(0, parseInt(hours) || 0));
    const m = Math.min(59, Math.max(0, parseInt(minutes) || 0));
    const s = Math.min(59, Math.max(0, parseInt(seconds) || 0));
    const newDate = new Date(day.getFullYear(), day.getMonth(), day.getDate(), h, m, s);
    onChange(newDate);
  };

  const applyTime = () => {
    if (!value) return;
    const h = Math.min(23, Math.max(0, parseInt(hours) || 0));
    const m = Math.min(59, Math.max(0, parseInt(minutes) || 0));
    const s = Math.min(59, Math.max(0, parseInt(seconds) || 0));
    const newDate = new Date(value.getFullYear(), value.getMonth(), value.getDate(), h, m, s);
    onChange(newDate);
  };

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          className={cn(
            'w-[210px] justify-start text-left font-normal font-mono text-sm',
            !value && 'text-muted-foreground'
          )}
        >
          <CalendarIcon className="mr-2 h-4 w-4 shrink-0" />
          {value ? formatDateDisplay(value) : placeholder}
        </Button>
      </PopoverTrigger>
      <PopoverContent
        className="w-auto p-0 bg-[#0F1519] border border-[#2D3339]"
        align="start"
      >
        <Calendar
          mode="single"
          selected={value ?? undefined}
          onSelect={handleDaySelect}
        />
        {/* Time inputs */}
        <div className="flex items-center gap-2 p-3 border-t border-[#2D3339]">
          <Input
            type="number"
            placeholder="시"
            min={0}
            max={23}
            value={hours}
            onChange={(e) => setHours(e.target.value)}
            onBlur={applyTime}
            className="w-16 text-center font-mono text-sm h-8"
          />
          <span className="text-muted-foreground text-sm font-bold">:</span>
          <Input
            type="number"
            placeholder="분"
            min={0}
            max={59}
            value={minutes}
            onChange={(e) => setMinutes(e.target.value)}
            onBlur={applyTime}
            className="w-16 text-center font-mono text-sm h-8"
          />
          <span className="text-muted-foreground text-sm font-bold">:</span>
          <Input
            type="number"
            placeholder="초"
            min={0}
            max={59}
            value={seconds}
            onChange={(e) => setSeconds(e.target.value)}
            onBlur={applyTime}
            className="w-16 text-center font-mono text-sm h-8"
          />
          <Button
            variant="ghost"
            size="sm"
            className="h-8 px-2 text-xs text-[#00A4A6] hover:text-[#00A4A6]/80"
            onClick={() => {
              applyTime();
              setOpen(false);
            }}
          >
            확인
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

export function EventLogsPage() {
  const {
    events,
    totalCount,
    isLoading,
    error,
    filters,
    setFilters,
    applyFilters,
    page,
    setPage,
    pageSize,
    totalPages,
    refresh,
  } = useEventLogs();

  const [selectedEvent, setSelectedEvent] = useState<EventLog | null>(null);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded bg-[#00A4A6]/10 border border-[#00A4A6]/30">
            <ScrollText className="w-5 h-5 text-[#00A4A6]" />
          </div>
          <div>
            <h1 className="text-2xl font-display font-bold tracking-tight">
              이벤트 로그
            </h1>
            <p className="text-muted-foreground text-sm">
              자산으로부터 수신된 정규화된 이벤트 로그를 조회합니다
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-sm text-muted-foreground font-mono">
            총{' '}
            <span className="text-white font-bold">{totalCount}</span>
            {' '}건
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={refresh}
            disabled={isLoading}
            className="w-8 h-8 p-0"
            title="새로고침"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RefreshCw className="w-4 h-4" />
            )}
          </Button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className="flex items-center gap-3 p-4 rounded border border-red-500/30 bg-red-500/10 text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Filters */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex flex-wrap items-end gap-3">
            {/* Asset selector */}
            <div className="flex flex-col gap-1.5 min-w-[200px]">
              <label className="text-xs text-muted-foreground uppercase tracking-wider font-mono">
                자산
              </label>
              <Select
                value={filters.assetId}
                onValueChange={(value) =>
                  setFilters((prev) => ({ ...prev, assetId: value }))
                }
              >
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="자산 선택" />
                </SelectTrigger>
                <SelectContent>
                  {DEMO_ASSETS.map((asset) => (
                    <SelectItem key={asset.id} value={asset.id}>
                      {asset.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Start datetime */}
            <div className="flex flex-col gap-1.5">
              <label className="text-xs text-muted-foreground uppercase tracking-wider font-mono">
                시작일시
              </label>
              <DateTimePicker
                value={filters.startDate}
                onChange={(date) =>
                  setFilters((prev) => ({ ...prev, startDate: date }))
                }
                placeholder="시작일시 선택"
              />
            </div>

            {/* End datetime */}
            <div className="flex flex-col gap-1.5">
              <label className="text-xs text-muted-foreground uppercase tracking-wider font-mono">
                종료일시
              </label>
              <DateTimePicker
                value={filters.endDate}
                onChange={(date) =>
                  setFilters((prev) => ({ ...prev, endDate: date }))
                }
                placeholder="종료일시 선택"
              />
            </div>

            {/* Search button */}
            <Button
              onClick={applyFilters}
              disabled={isLoading}
              className="bg-[#00A4A6] hover:bg-[#00A4A6]/80 text-white border-0"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Search className="w-4 h-4 mr-2" />
              )}
              검색
            </Button>
          </div>
        </CardHeader>

        <CardContent>
          <div className="rounded border border-[#2D3339] overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-[#171D21] border-b border-[#2D3339]">
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider w-[170px]">
                    발생시간
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider w-[160px]">
                    자산
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider w-[90px]">
                    심각도
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider w-[130px]">
                    소스 IP
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider">
                    이벤트 유형
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider">
                    원본 로그
                  </TableHead>
                  <TableHead className="text-[#9BA7B4] font-mono text-xs uppercase tracking-wider w-[60px]">
                    상세
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {isLoading ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="text-center text-muted-foreground py-16"
                    >
                      <div className="flex flex-col items-center gap-2">
                        <Loader2 className="w-8 h-8 text-[#00A4A6] animate-spin" />
                        <p>데이터를 불러오는 중...</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : events.length === 0 ? (
                  <TableRow>
                    <TableCell
                      colSpan={7}
                      className="text-center text-muted-foreground py-16"
                    >
                      <div className="flex flex-col items-center gap-2">
                        <ScrollText className="w-8 h-8 text-muted-foreground/50" />
                        <p>검색 결과가 없습니다</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((log) => (
                    <TableRow
                      key={log.id}
                      className="border-b border-[#2D3339] hover:bg-white/5 transition-colors"
                    >
                      {/* 발생시간 */}
                      <TableCell className="font-mono text-xs text-[#9BA7B4] whitespace-nowrap">
                        {formatEventTime(log.timestamp)}
                      </TableCell>

                      {/* Asset */}
                      <TableCell>
                        <div className="flex flex-col">
                          <span className="text-sm font-medium text-white">
                            {log.vendor_name}
                          </span>
                          <span className="text-xs text-muted-foreground font-mono">
                            {log.product_name}
                          </span>
                        </div>
                      </TableCell>

                      {/* Severity */}
                      <TableCell>
                        <Badge
                          variant={severityVariant[log.security_severity]}
                          className="uppercase text-[10px] font-bold"
                        >
                          {severityLabel[log.security_severity]}
                        </Badge>
                      </TableCell>

                      {/* Source IP */}
                      <TableCell className="font-mono text-sm text-[#9BA7B4]">
                        {log.principal_ip || '-'}
                      </TableCell>

                      {/* Event type */}
                      <TableCell>
                        {log.security_threat_name ? (
                          <span
                            className={cn(
                              'text-sm font-medium',
                              log.security_severity === 'CRITICAL' && 'text-[#DC4E41]',
                              log.security_severity === 'HIGH' && 'text-[#F79836]',
                              log.security_severity === 'MEDIUM' && 'text-[#FFB84D]',
                              log.security_severity === 'LOW' && 'text-[#5CC05C]',
                              (log.security_severity === 'INFORMATIONAL' ||
                                log.security_severity === 'UNKNOWN') &&
                                'text-muted-foreground'
                            )}
                          >
                            {log.security_threat_name}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground italic">
                            일반 이벤트
                          </span>
                        )}
                        {log.mitre_techniques.length > 0 && (
                          <div className="flex gap-1 mt-1 flex-wrap">
                            {log.mitre_techniques.map((t) => (
                              <span
                                key={t}
                                className="text-[10px] font-mono px-1 py-0.5 rounded bg-[#2D3339] text-[#9BA7B4] border border-[#3D4349]"
                              >
                                {t}
                              </span>
                            ))}
                          </div>
                        )}
                      </TableCell>

                      {/* Raw log (truncated) */}
                      <TableCell className="max-w-[300px]">
                        <span
                          className="text-xs font-mono text-[#9BA7B4] break-all"
                          title={log.raw_log}
                        >
                          {truncate(log.raw_log, 80)}
                        </span>
                      </TableCell>

                      {/* View button */}
                      <TableCell>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setSelectedEvent(log)}
                          className="w-8 h-8 p-0 hover:bg-[#00A4A6]/10 hover:text-[#00A4A6]"
                          title="상세 보기"
                        >
                          <Eye className="w-4 h-4" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-[#2D3339]">
              <p className="text-sm text-muted-foreground">
                <span className="font-mono text-white">
                  {(page - 1) * pageSize + 1}
                </span>
                {' '}-{' '}
                <span className="font-mono text-white">
                  {Math.min(page * pageSize, totalCount)}
                </span>
                {' '}/ 총{' '}
                <span className="font-mono text-white">{totalCount}</span>
                {' '}건
              </p>
              <div className="flex items-center gap-1">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1 || isLoading}
                  className="w-8 h-8 p-0"
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                {Array.from({ length: totalPages }, (_, i) => i + 1)
                  .filter(
                    (p) =>
                      p === 1 ||
                      p === totalPages ||
                      Math.abs(p - page) <= 1
                  )
                  .reduce<(number | string)[]>((acc, pageNum, idx, arr) => {
                    if (idx > 0 && typeof arr[idx - 1] === 'number' && (pageNum as number) - (arr[idx - 1] as number) > 1) {
                      acc.push('...');
                    }
                    acc.push(pageNum);
                    return acc;
                  }, [])
                  .map((item, idx) =>
                    typeof item === 'string' ? (
                      <span
                        key={`ellipsis-${idx}`}
                        className="text-muted-foreground text-sm px-1"
                      >
                        ...
                      </span>
                    ) : (
                      <Button
                        key={item}
                        variant={page === item ? 'default' : 'outline'}
                        size="sm"
                        onClick={() => setPage(item)}
                        disabled={isLoading}
                        className={cn(
                          'w-8 h-8 p-0',
                          page === item &&
                            'bg-[#00A4A6] hover:bg-[#00A4A6]/80 border-[#00A4A6]'
                        )}
                      >
                        {item}
                      </Button>
                    )
                  )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages || isLoading}
                  className="w-8 h-8 p-0"
                >
  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Event Detail Sheet */}
      <Sheet open={!!selectedEvent} onOpenChange={(open) => !open && setSelectedEvent(null)}>
        <SheetContent
          side="right"
          className="w-[560px] sm:max-w-[560px] bg-[#0F1519] border-l border-[#2D3339] overflow-y-auto"
        >
          <SheetHeader className="mb-6">
            <SheetTitle className="text-white text-lg font-display font-bold">
              이벤트 상세
            </SheetTitle>
          </SheetHeader>

          {selectedEvent && (
            <div className="space-y-5 text-sm">
              {/* 발생시간 */}
              <div className="flex flex-col gap-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  발생시간
                </span>
                <span className="font-mono text-white">
                  {formatEventTime(selectedEvent.timestamp)}
                </span>
              </div>

              {/* Asset */}
              <div className="flex flex-col gap-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  자산
                </span>
                <div className="flex flex-col">
                  <span className="font-medium text-white">{selectedEvent.vendor_name}</span>
                  <span className="text-xs text-muted-foreground font-mono">{selectedEvent.product_name}</span>
                </div>
              </div>

              {/* Severity */}
              <div className="flex flex-col gap-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  심각도
                </span>
                <Badge
                  variant={severityVariant[selectedEvent.security_severity]}
                  className="uppercase text-[10px] font-bold w-fit"
                >
                  {severityLabel[selectedEvent.security_severity]}
                </Badge>
              </div>

              {/* Source IP / Destination IP */}
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    소스 IP
                  </span>
                  <span className="font-mono text-white">
                    {selectedEvent.principal_ip || '-'}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    대상 IP
                  </span>
                  <span className="font-mono text-white">
                    {selectedEvent.target_ip || '-'}
                  </span>
                </div>
              </div>

              {/* Hostname / User */}
              <div className="grid grid-cols-2 gap-4">
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    호스트명
                  </span>
                  <span className="font-mono text-white">
                    {selectedEvent.principal_hostname || '-'}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                    사용자
                  </span>
                  <span className="font-mono text-white">
                    {selectedEvent.principal_user_id || '-'}
                  </span>
                </div>
              </div>

              {/* MITRE Tactics */}
              <div className="flex flex-col gap-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  MITRE 전술
                </span>
                {selectedEvent.mitre_tactics.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {selectedEvent.mitre_tactics.map((t) => (
                      <span
                        key={t}
                        className="text-xs px-2 py-0.5 rounded bg-[#1A2A3A] text-[#5BB8FF] border border-[#2D4A6A]"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-muted-foreground italic text-xs">없음</span>
                )}
              </div>

              {/* MITRE Techniques */}
              <div className="flex flex-col gap-1">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  MITRE 기법
                </span>
                {selectedEvent.mitre_techniques.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5">
                    {selectedEvent.mitre_techniques.map((t) => (
                      <span
                        key={t}
                        className="text-xs font-mono px-2 py-0.5 rounded bg-[#2D3339] text-[#9BA7B4] border border-[#3D4349]"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-muted-foreground italic text-xs">없음</span>
                )}
              </div>

              {/* Raw Log */}
              <div className="flex flex-col gap-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
                  원본 로그
                </span>
                <pre className="text-xs font-mono text-[#C8D4E0] bg-[#0A0E12] border border-[#2D3339] rounded p-3 whitespace-pre-wrap break-all leading-relaxed">
                  {selectedEvent.raw_log}
                </pre>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
