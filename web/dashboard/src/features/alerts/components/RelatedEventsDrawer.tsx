/**
 * RelatedEventsDrawer Component
 * Displays related events for a grouped alert in a slide-out drawer
 */

import { useState, useMemo } from 'react';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
  SheetFooter,
} from '@/components/ui/sheet';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  CheckSquare,
  FileText,
  Clock,
  BarChart3,
  TableIcon,
  ArrowRight,
} from 'lucide-react';
import { GroupStatistics } from './GroupStatistics';
import {
  type RelatedEvent,
  calculateGroupStatistics,
  formatEventTime,
  formatDurationBetween,
} from '../utils/groupStats';

interface GroupedAlertInfo {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  eventCount: number;
  firstEventTime: string;
  lastEventTime: string;
  groupByFields?: string[];
  groupByValues?: Record<string, string>;
}

interface RelatedEventsDrawerProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  alert: GroupedAlertInfo | null;
  events: RelatedEvent[];
  onAcknowledgeAll?: () => void;
  onCreateCase?: () => void;
}

export function RelatedEventsDrawer({
  open,
  onOpenChange,
  alert,
  events,
  onAcknowledgeAll,
  onCreateCase,
}: RelatedEventsDrawerProps) {
  const [activeTab, setActiveTab] = useState('timeline');

  const statistics = useMemo(() => {
    return calculateGroupStatistics(events);
  }, [events]);

  const duration = useMemo(() => {
    if (!alert) return '';
    return formatDurationBetween(alert.firstEventTime, alert.lastEventTime);
  }, [alert]);

  if (!alert) return null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="right"
        className="w-full sm:max-w-2xl overflow-hidden flex flex-col"
      >
        <SheetHeader className="pb-4 border-b">
          <div className="flex items-center justify-between">
            <SheetTitle className="flex items-center gap-2">
              Related Events
              <Badge variant="secondary" className="ml-2">
                {alert.eventCount}
              </Badge>
            </SheetTitle>
          </div>
          <SheetDescription>
            <div className="space-y-2">
              <p className="font-medium text-foreground">{alert.title}</p>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  Duration: {duration}
                </span>
                <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
              </div>
              {alert.groupByFields && alert.groupByValues && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {alert.groupByFields.map((field) => (
                    <Badge key={field} variant="outline" className="text-xs">
                      {field} = {alert.groupByValues?.[field] || 'N/A'}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </SheetDescription>
        </SheetHeader>

        <Tabs
          value={activeTab}
          onValueChange={setActiveTab}
          className="flex-1 flex flex-col overflow-hidden"
        >
          <TabsList className="grid w-full grid-cols-3 mt-4">
            <TabsTrigger value="timeline" className="flex items-center gap-1">
              <Clock className="w-4 h-4" />
              Timeline
            </TabsTrigger>
            <TabsTrigger value="table" className="flex items-center gap-1">
              <TableIcon className="w-4 h-4" />
              Table
            </TabsTrigger>
            <TabsTrigger value="statistics" className="flex items-center gap-1">
              <BarChart3 className="w-4 h-4" />
              Statistics
            </TabsTrigger>
          </TabsList>

          {/* Timeline View */}
          <TabsContent value="timeline" className="flex-1 overflow-hidden mt-4">
            <ScrollArea className="h-[calc(100vh-350px)]">
              <div className="space-y-2 pr-4">
                {events.map((event, index) => (
                  <div
                    key={event.id}
                    className="relative pl-6 pb-4 border-l-2 border-muted last:border-transparent"
                  >
                    {/* Timeline dot */}
                    <div
                      className={`absolute -left-[5px] top-1.5 w-2 h-2 rounded-full ${
                        event.status?.toLowerCase() === 'failure' ||
                        event.status?.toLowerCase() === 'failed'
                          ? 'bg-destructive'
                          : event.status?.toLowerCase() === 'success'
                          ? 'bg-neon-green'
                          : 'bg-primary'
                      }`}
                    />

                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 text-sm">
                          <span className="font-mono text-muted-foreground">
                            {formatEventTime(event.timestamp)}
                          </span>
                          {event.status && (
                            <Badge
                              variant={
                                event.status.toLowerCase() === 'failure' ||
                                event.status.toLowerCase() === 'failed'
                                  ? 'destructive'
                                  : event.status.toLowerCase() === 'success'
                                  ? 'success'
                                  : 'outline'
                              }
                              className="text-[10px] px-1.5 py-0"
                            >
                              {event.status}
                            </Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-sm mt-1">
                          {event.sourceIp && (
                            <span className="font-mono text-xs text-muted-foreground">
                              {event.sourceIp}
                            </span>
                          )}
                          {event.sourceIp && event.destinationIp && (
                            <ArrowRight className="w-3 h-3 text-muted-foreground" />
                          )}
                          {event.destinationIp && (
                            <span className="font-mono text-xs text-muted-foreground">
                              {event.destinationIp}
                            </span>
                          )}
                        </div>
                        {event.user && (
                          <p className="text-xs text-muted-foreground mt-1">
                            user: {event.user}
                          </p>
                        )}
                        {event.message && (
                          <p className="text-xs text-muted-foreground mt-1 truncate">
                            {event.message}
                          </p>
                        )}
                      </div>
                      <span className="text-[10px] text-muted-foreground">
                        #{events.length - index}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          </TabsContent>

          {/* Table View */}
          <TabsContent value="table" className="flex-1 overflow-hidden mt-4">
            <ScrollArea className="h-[calc(100vh-350px)]">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[80px]">Time</TableHead>
                    <TableHead>Source</TableHead>
                    <TableHead>Destination</TableHead>
                    <TableHead>User</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.map((event) => (
                    <TableRow key={event.id}>
                      <TableCell className="font-mono text-xs">
                        {formatEventTime(event.timestamp)}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {event.sourceIp || '-'}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        {event.destinationIp || '-'}
                      </TableCell>
                      <TableCell className="text-xs">{event.user || '-'}</TableCell>
                      <TableCell>
                        {event.status ? (
                          <Badge
                            variant={
                              event.status.toLowerCase() === 'failure' ||
                              event.status.toLowerCase() === 'failed'
                                ? 'destructive'
                                : event.status.toLowerCase() === 'success'
                                ? 'success'
                                : 'outline'
                            }
                            className="text-[10px]"
                          >
                            {event.status}
                          </Badge>
                        ) : (
                          '-'
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          </TabsContent>

          {/* Statistics View */}
          <TabsContent value="statistics" className="flex-1 overflow-hidden mt-4">
            <GroupStatistics statistics={statistics} />
          </TabsContent>
        </Tabs>

        <SheetFooter className="border-t pt-4 mt-4">
          <div className="flex items-center gap-2 w-full">
            <Button
              variant="outline"
              className="flex-1"
              onClick={onAcknowledgeAll}
            >
              <CheckSquare className="w-4 h-4 mr-2" />
              Acknowledge All
            </Button>
            <Button className="flex-1" onClick={onCreateCase}>
              <FileText className="w-4 h-4 mr-2" />
              Create Case
            </Button>
          </div>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  );
}
