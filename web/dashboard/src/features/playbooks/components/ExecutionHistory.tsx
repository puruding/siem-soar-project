import { useState } from 'react';
import { ScrollArea, ScrollBar } from '@/components/ui/scroll-area';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  ChevronUp,
  ChevronDown,
  CheckCircle2,
  XCircle,
  Clock,
  Loader2,
  History,
  Eye,
  Calendar,
  Timer,
  User,
  AlertTriangle,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ExecutionRun {
  id: string;
  status: 'running' | 'success' | 'failed' | 'cancelled';
  startedAt: Date;
  completedAt?: Date;
  duration?: number; // in milliseconds
  triggeredBy: string;
  nodesExecuted: number;
  totalNodes: number;
  errorMessage?: string;
  logs?: ExecutionLog[];
}

export interface ExecutionLog {
  nodeId: string;
  nodeName: string;
  status: 'success' | 'failed' | 'skipped';
  message: string;
  timestamp: Date;
  duration?: number;
}

interface ExecutionHistoryProps {
  executions: ExecutionRun[];
  onSelectExecution?: (execution: ExecutionRun) => void;
  className?: string;
}

export function ExecutionHistory({
  executions,
  onSelectExecution,
  className,
}: ExecutionHistoryProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const [selectedExecution, setSelectedExecution] = useState<ExecutionRun | null>(null);
  const [isDetailOpen, setIsDetailOpen] = useState(false);

  const formatDuration = (ms: number) => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    const mins = Math.floor(ms / 60000);
    const secs = Math.floor((ms % 60000) / 1000);
    return `${mins}m ${secs}s`;
  };

  const formatTime = (date: Date) => {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };

  const formatDate = (date: Date) => {
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' });
  };

  const getStatusIcon = (status: ExecutionRun['status']) => {
    switch (status) {
      case 'running':
        return <Loader2 className="w-4 h-4 text-blue-500 animate-spin" />;
      case 'success':
        return <CheckCircle2 className="w-4 h-4 text-[#5CC05C]" />;
      case 'failed':
        return <XCircle className="w-4 h-4 text-[#DC4E41]" />;
      case 'cancelled':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
    }
  };

  const getStatusColor = (status: ExecutionRun['status']) => {
    switch (status) {
      case 'running':
        return 'border-blue-500/50 bg-blue-500/10';
      case 'success':
        return 'border-[#5CC05C]/50 bg-[#5CC05C]/10';
      case 'failed':
        return 'border-[#DC4E41]/50 bg-[#DC4E41]/10';
      case 'cancelled':
        return 'border-yellow-500/50 bg-yellow-500/10';
    }
  };

  const handleViewDetails = (execution: ExecutionRun) => {
    setSelectedExecution(execution);
    setIsDetailOpen(true);
    onSelectExecution?.(execution);
  };

  return (
    <>
      <Collapsible
        open={isExpanded}
        onOpenChange={setIsExpanded}
        className={cn('border-t border-border/50 bg-card/30', className)}
      >
        <CollapsibleTrigger asChild>
          <Button
            variant="ghost"
            className="w-full flex items-center justify-between px-4 py-2 rounded-none hover:bg-muted/50"
          >
            <div className="flex items-center gap-2">
              <History className="w-4 h-4 text-muted-foreground" />
              <span className="text-sm font-medium">Execution History</span>
              <Badge variant="secondary" className="text-2xs">
                {executions.length}
              </Badge>
              {executions.some((e) => e.status === 'running') && (
                <Badge className="text-2xs bg-blue-500/20 text-blue-500 border-blue-500/30">
                  <Loader2 className="w-3 h-3 mr-1 animate-spin" />
                  Running
                </Badge>
              )}
            </div>
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-muted-foreground" />
            ) : (
              <ChevronUp className="w-4 h-4 text-muted-foreground" />
            )}
          </Button>
        </CollapsibleTrigger>

        <CollapsibleContent>
          <div className="px-4 pb-3">
            {executions.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                <Clock className="w-8 h-8 mx-auto mb-2 opacity-50" />
                No executions yet. Run the playbook to see history.
              </div>
            ) : (
              <ScrollArea className="w-full">
                <div className="flex gap-3 py-2">
                  {executions.map((execution) => (
                    <div
                      key={execution.id}
                      className={cn(
                        'flex-shrink-0 w-[180px] p-3 rounded-xl border-2 transition-all duration-200',
                        'hover:scale-[1.02] hover:shadow-md cursor-pointer',
                        getStatusColor(execution.status)
                      )}
                      onClick={() => handleViewDetails(execution)}
                    >
                      {/* Status and ID */}
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-1.5">
                          {getStatusIcon(execution.status)}
                          <span className="text-xs font-medium text-foreground">
                            #{execution.id.slice(-6)}
                          </span>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="w-6 h-6"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewDetails(execution);
                          }}
                        >
                          <Eye className="w-3 h-3" />
                        </Button>
                      </div>

                      {/* Time info */}
                      <div className="flex items-center gap-1 text-2xs text-muted-foreground mb-1">
                        <Calendar className="w-3 h-3" />
                        <span>{formatDate(execution.startedAt)}</span>
                        <span>{formatTime(execution.startedAt)}</span>
                      </div>

                      {/* Duration */}
                      {execution.duration !== undefined && (
                        <div className="flex items-center gap-1 text-2xs text-muted-foreground mb-2">
                          <Timer className="w-3 h-3" />
                          <span>{formatDuration(execution.duration)}</span>
                        </div>
                      )}

                      {/* Progress for running */}
                      {execution.status === 'running' && (
                        <div className="mt-2">
                          <div className="h-1.5 w-full bg-blue-500/20 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-blue-500 rounded-full transition-all duration-300"
                              style={{
                                width: `${(execution.nodesExecuted / execution.totalNodes) * 100}%`,
                              }}
                            />
                          </div>
                          <div className="text-2xs text-muted-foreground mt-1">
                            {execution.nodesExecuted}/{execution.totalNodes} nodes
                          </div>
                        </div>
                      )}

                      {/* Completion stats */}
                      {execution.status !== 'running' && (
                        <div className="flex items-center gap-2 text-2xs">
                          <span className="text-foreground font-medium">
                            {execution.nodesExecuted}/{execution.totalNodes}
                          </span>
                          <span className="text-muted-foreground">nodes</span>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
            )}
          </div>
        </CollapsibleContent>
      </Collapsible>

      {/* Execution Detail Sheet */}
      <Sheet open={isDetailOpen} onOpenChange={setIsDetailOpen}>
        <SheetContent className="w-[450px] sm:max-w-[450px]">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              {selectedExecution && getStatusIcon(selectedExecution.status)}
              Execution #{selectedExecution?.id.slice(-6)}
            </SheetTitle>
          </SheetHeader>

          {selectedExecution && (
            <div className="mt-6 space-y-6">
              {/* Status Badge */}
              <div className="flex items-center gap-2">
                <Badge
                  className={cn(
                    'capitalize',
                    selectedExecution.status === 'success' && 'bg-[#5CC05C]/20 text-[#5CC05C] border-[#5CC05C]/30',
                    selectedExecution.status === 'failed' && 'bg-[#DC4E41]/20 text-[#DC4E41] border-[#DC4E41]/30',
                    selectedExecution.status === 'running' && 'bg-blue-500/20 text-blue-500 border-blue-500/30',
                    selectedExecution.status === 'cancelled' && 'bg-yellow-500/20 text-yellow-500 border-yellow-500/30'
                  )}
                >
                  {selectedExecution.status}
                </Badge>
              </div>

              {/* Info Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1">
                  <div className="text-2xs text-muted-foreground uppercase tracking-wide">Started</div>
                  <div className="text-sm font-medium">
                    {selectedExecution.startedAt.toLocaleString()}
                  </div>
                </div>
                {selectedExecution.completedAt && (
                  <div className="space-y-1">
                    <div className="text-2xs text-muted-foreground uppercase tracking-wide">Completed</div>
                    <div className="text-sm font-medium">
                      {selectedExecution.completedAt.toLocaleString()}
                    </div>
                  </div>
                )}
                {selectedExecution.duration !== undefined && (
                  <div className="space-y-1">
                    <div className="text-2xs text-muted-foreground uppercase tracking-wide">Duration</div>
                    <div className="text-sm font-medium">
                      {formatDuration(selectedExecution.duration)}
                    </div>
                  </div>
                )}
                <div className="space-y-1">
                  <div className="text-2xs text-muted-foreground uppercase tracking-wide">Triggered By</div>
                  <div className="flex items-center gap-1 text-sm font-medium">
                    <User className="w-3 h-3" />
                    {selectedExecution.triggeredBy}
                  </div>
                </div>
              </div>

              {/* Error Message */}
              {selectedExecution.errorMessage && (
                <div className="p-3 rounded-lg bg-[#DC4E41]/10 border border-[#DC4E41]/20">
                  <div className="flex items-center gap-2 text-sm text-[#DC4E41] font-medium mb-1">
                    <XCircle className="w-4 h-4" />
                    Error
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {selectedExecution.errorMessage}
                  </p>
                </div>
              )}

              {/* Execution Logs */}
              {selectedExecution.logs && selectedExecution.logs.length > 0 && (
                <div>
                  <h4 className="text-sm font-semibold mb-3">Execution Log</h4>
                  <ScrollArea className="h-[350px] rounded-lg border border-border/50 bg-muted/20">
                    <div className="p-3 space-y-2">
                      {selectedExecution.logs.map((log, i) => (
                        <div
                          key={i}
                          className="flex items-start gap-2 p-2 rounded-lg bg-background border border-border/50"
                        >
                          <div className="shrink-0 mt-0.5">
                            {log.status === 'success' && (
                              <CheckCircle2 className="w-4 h-4 text-[#5CC05C]" />
                            )}
                            {log.status === 'failed' && (
                              <XCircle className="w-4 h-4 text-[#DC4E41]" />
                            )}
                            {log.status === 'skipped' && (
                              <AlertTriangle className="w-4 h-4 text-yellow-500" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-0.5">
                              <span className="text-xs font-medium text-foreground truncate">
                                {log.nodeName}
                              </span>
                              <span className="text-2xs text-muted-foreground shrink-0">
                                {log.timestamp.toLocaleTimeString()}
                              </span>
                              {log.duration !== undefined && (
                                <span className="text-2xs text-muted-foreground shrink-0">
                                  ({log.duration}ms)
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              {log.message}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </>
  );
}

export default ExecutionHistory;
