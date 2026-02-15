/**
 * ExecutionTimeline - Visual timeline of agent executions.
 */
import { memo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';
import {
  Activity,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Play,
  Pause,
  Bot,
  ChevronRight,
  Filter,
  Search,
  RefreshCcw,
  AlertCircle,
  Shield,
  Target,
  Zap,
} from 'lucide-react';

export type ExecutionStage =
  | 'detection'
  | 'triage'
  | 'investigation'
  | 'analysis'
  | 'response'
  | 'validation'
  | 'complete';

export type ExecutionStatus = 'in_progress' | 'completed' | 'failed' | 'awaiting_approval';

export interface ExecutionStep {
  stage: ExecutionStage;
  status: ExecutionStatus;
  agentId: string;
  agentName: string;
  startedAt: Date;
  completedAt: Date | null;
  details: string | null;
}

export interface Execution {
  id: string;
  incidentId: string;
  alertId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: ExecutionStatus;
  currentStage: ExecutionStage;
  startedAt: Date;
  completedAt: Date | null;
  steps: ExecutionStep[];
  autoInvestigation: boolean;
  autoResponse: boolean;
}

interface ExecutionTimelineProps {
  executions?: Execution[];
  limit?: number;
  compact?: boolean;
  className?: string;
}

const defaultExecutions: Execution[] = [
  {
    id: 'exec-001',
    incidentId: 'INC-2024-047',
    alertId: 'ALR-2024-001',
    severity: 'high',
    status: 'in_progress',
    currentStage: 'analysis',
    startedAt: new Date(Date.now() - 300000),
    completedAt: null,
    steps: [
      {
        stage: 'detection',
        status: 'completed',
        agentId: 'orch-001',
        agentName: 'Orchestrator',
        startedAt: new Date(Date.now() - 300000),
        completedAt: new Date(Date.now() - 295000),
        details: 'Alert received from SIEM',
      },
      {
        stage: 'triage',
        status: 'completed',
        agentId: 'ana-001',
        agentName: 'Analysis Agent',
        startedAt: new Date(Date.now() - 295000),
        completedAt: new Date(Date.now() - 280000),
        details: 'Classified as potential ransomware',
      },
      {
        stage: 'investigation',
        status: 'completed',
        agentId: 'inv-001',
        agentName: 'Investigation Agent',
        startedAt: new Date(Date.now() - 280000),
        completedAt: new Date(Date.now() - 200000),
        details: 'Collected context from 5 sources',
      },
      {
        stage: 'analysis',
        status: 'in_progress',
        agentId: 'ana-001',
        agentName: 'Analysis Agent',
        startedAt: new Date(Date.now() - 200000),
        completedAt: null,
        details: 'Analyzing threat patterns',
      },
    ],
    autoInvestigation: true,
    autoResponse: false,
  },
  {
    id: 'exec-002',
    incidentId: 'INC-2024-046',
    alertId: 'ALR-2024-002',
    severity: 'medium',
    status: 'awaiting_approval',
    currentStage: 'response',
    startedAt: new Date(Date.now() - 900000),
    completedAt: null,
    steps: [
      {
        stage: 'detection',
        status: 'completed',
        agentId: 'orch-001',
        agentName: 'Orchestrator',
        startedAt: new Date(Date.now() - 900000),
        completedAt: new Date(Date.now() - 895000),
        details: 'Alert received',
      },
      {
        stage: 'triage',
        status: 'completed',
        agentId: 'ana-001',
        agentName: 'Analysis Agent',
        startedAt: new Date(Date.now() - 895000),
        completedAt: new Date(Date.now() - 870000),
        details: 'Classified as credential theft attempt',
      },
      {
        stage: 'investigation',
        status: 'completed',
        agentId: 'inv-001',
        agentName: 'Investigation Agent',
        startedAt: new Date(Date.now() - 870000),
        completedAt: new Date(Date.now() - 750000),
        details: 'Found compromised credentials',
      },
      {
        stage: 'analysis',
        status: 'completed',
        agentId: 'ana-001',
        agentName: 'Analysis Agent',
        startedAt: new Date(Date.now() - 750000),
        completedAt: new Date(Date.now() - 700000),
        details: 'Impact: 3 accounts affected',
      },
      {
        stage: 'response',
        status: 'awaiting_approval',
        agentId: 'res-001',
        agentName: 'Response Agent',
        startedAt: new Date(Date.now() - 700000),
        completedAt: null,
        details: 'Awaiting approval for account lockout',
      },
    ],
    autoInvestigation: true,
    autoResponse: false,
  },
  {
    id: 'exec-003',
    incidentId: 'INC-2024-045',
    alertId: 'ALR-2024-003',
    severity: 'low',
    status: 'completed',
    currentStage: 'complete',
    startedAt: new Date(Date.now() - 3600000),
    completedAt: new Date(Date.now() - 3500000),
    steps: [
      {
        stage: 'detection',
        status: 'completed',
        agentId: 'orch-001',
        agentName: 'Orchestrator',
        startedAt: new Date(Date.now() - 3600000),
        completedAt: new Date(Date.now() - 3595000),
        details: 'Alert received',
      },
      {
        stage: 'triage',
        status: 'completed',
        agentId: 'ana-001',
        agentName: 'Analysis Agent',
        startedAt: new Date(Date.now() - 3595000),
        completedAt: new Date(Date.now() - 3580000),
        details: 'Classified as false positive',
      },
      {
        stage: 'complete',
        status: 'completed',
        agentId: 'orch-001',
        agentName: 'Orchestrator',
        startedAt: new Date(Date.now() - 3580000),
        completedAt: new Date(Date.now() - 3500000),
        details: 'Incident closed as false positive',
      },
    ],
    autoInvestigation: true,
    autoResponse: true,
  },
];

const stageConfig: Record<ExecutionStage, { label: string; icon: typeof Activity; color: string }> = {
  detection: { label: 'Detection', icon: AlertCircle, color: 'text-blue-500' },
  triage: { label: 'Triage', icon: Filter, color: 'text-cyan-500' },
  investigation: { label: 'Investigation', icon: Search, color: 'text-purple-500' },
  analysis: { label: 'Analysis', icon: Target, color: 'text-orange-500' },
  response: { label: 'Response', icon: Zap, color: 'text-red-500' },
  validation: { label: 'Validation', icon: Shield, color: 'text-green-500' },
  complete: { label: 'Complete', icon: CheckCircle2, color: 'text-green-500' },
};

const severityColors: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
};

function ExecutionTimelineComponent({
  executions = defaultExecutions,
  limit,
  compact = false,
  className,
}: ExecutionTimelineProps) {
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const filteredExecutions = executions
    .filter((exec) => statusFilter === 'all' || exec.status === statusFilter)
    .slice(0, limit);

  const formatDuration = (start: Date, end: Date | null): string => {
    const endTime = end || new Date();
    const diff = Math.floor((endTime.getTime() - start.getTime()) / 1000);

    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  const formatTime = (date: Date): string => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getStatusBadge = (status: ExecutionStatus) => {
    switch (status) {
      case 'in_progress':
        return (
          <Badge className="bg-blue-500/10 text-blue-500 border-0">
            <Activity className="h-3 w-3 mr-1 animate-pulse" />
            In Progress
          </Badge>
        );
      case 'completed':
        return (
          <Badge className="bg-green-500/10 text-green-500 border-0">
            <CheckCircle2 className="h-3 w-3 mr-1" />
            Completed
          </Badge>
        );
      case 'failed':
        return (
          <Badge className="bg-red-500/10 text-red-500 border-0">
            <XCircle className="h-3 w-3 mr-1" />
            Failed
          </Badge>
        );
      case 'awaiting_approval':
        return (
          <Badge className="bg-yellow-500/10 text-yellow-500 border-0">
            <Pause className="h-3 w-3 mr-1" />
            Awaiting Approval
          </Badge>
        );
    }
  };

  if (compact) {
    return (
      <div className={cn('space-y-3', className)}>
        {filteredExecutions.map((exec) => (
          <div
            key={exec.id}
            className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors cursor-pointer"
          >
            <div className={cn('w-2 h-2 rounded-full', severityColors[exec.severity])} />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-medium text-sm">{exec.incidentId}</span>
                {getStatusBadge(exec.status)}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">
                Stage: {stageConfig[exec.currentStage].label}
              </p>
            </div>
            <div className="text-xs text-muted-foreground shrink-0">
              {formatDuration(exec.startedAt, exec.completedAt)}
            </div>
            <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
          </div>
        ))}
      </div>
    );
  }

  return (
    <Card className={cn('flex flex-col h-full', className)}>
      <CardHeader className="pb-4 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Activity className="h-5 w-5" />
            Execution Timeline
          </CardTitle>
          <div className="flex items-center gap-2">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="in_progress">In Progress</SelectItem>
                <SelectItem value="completed">Completed</SelectItem>
                <SelectItem value="failed">Failed</SelectItem>
                <SelectItem value="awaiting_approval">Awaiting Approval</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={handleRefresh}>
              <RefreshCcw className={cn('h-4 w-4', isRefreshing && 'animate-spin')} />
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 min-h-0 p-0">
        <ScrollArea className="h-full px-6 pb-6">
          <div className="space-y-6">
            {filteredExecutions.map((exec) => (
              <div key={exec.id} className="border rounded-lg overflow-hidden">
                {/* Execution Header */}
                <div className="flex items-center justify-between p-4 bg-muted/30">
                  <div className="flex items-center gap-3">
                    <div className={cn('w-3 h-3 rounded-full', severityColors[exec.severity])} />
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-medium">{exec.incidentId}</span>
                        <Badge variant="outline" className="text-xs">
                          {exec.alertId}
                        </Badge>
                        {getStatusBadge(exec.status)}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        <span>Started: {formatTime(exec.startedAt)}</span>
                        <span>Duration: {formatDuration(exec.startedAt, exec.completedAt)}</span>
                        {exec.autoInvestigation && (
                          <Badge variant="outline" className="text-[10px] px-1.5">
                            Auto Investigation
                          </Badge>
                        )}
                        {exec.autoResponse && (
                          <Badge variant="outline" className="text-[10px] px-1.5">
                            Auto Response
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                  <Button variant="ghost" size="sm">
                    <ChevronRight className="h-4 w-4" />
                  </Button>
                </div>

                {/* Timeline Steps */}
                <div className="p-4">
                  <div className="relative">
                    {/* Timeline Line */}
                    <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-border" />

                    {/* Steps */}
                    <div className="space-y-4">
                      {exec.steps.map((step, idx) => {
                        const StageIcon = stageConfig[step.stage].icon;
                        return (
                          <div key={idx} className="relative flex items-start gap-4 pl-10">
                            {/* Timeline Dot */}
                            <div className={cn(
                              'absolute left-2 top-1 w-5 h-5 rounded-full border-2 flex items-center justify-center',
                              step.status === 'completed' ? 'bg-green-500/10 border-green-500' :
                              step.status === 'in_progress' ? 'bg-blue-500/10 border-blue-500' :
                              step.status === 'awaiting_approval' ? 'bg-yellow-500/10 border-yellow-500' :
                              'bg-red-500/10 border-red-500'
                            )}>
                              {step.status === 'completed' ? (
                                <CheckCircle2 className="h-3 w-3 text-green-500" />
                              ) : step.status === 'in_progress' ? (
                                <Activity className="h-3 w-3 text-blue-500 animate-pulse" />
                              ) : step.status === 'awaiting_approval' ? (
                                <Pause className="h-3 w-3 text-yellow-500" />
                              ) : (
                                <XCircle className="h-3 w-3 text-red-500" />
                              )}
                            </div>

                            {/* Step Content */}
                            <div className="flex-1 pb-2">
                              <div className="flex items-center gap-2">
                                <StageIcon className={cn('h-4 w-4', stageConfig[step.stage].color)} />
                                <span className="font-medium text-sm">
                                  {stageConfig[step.stage].label}
                                </span>
                                <Badge variant="outline" className="text-xs">
                                  <Bot className="h-3 w-3 mr-1" />
                                  {step.agentName}
                                </Badge>
                              </div>
                              {step.details && (
                                <p className="text-sm text-muted-foreground mt-1">
                                  {step.details}
                                </p>
                              )}
                              <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                                <Clock className="h-3 w-3" />
                                <span>{formatTime(step.startedAt)}</span>
                                {step.completedAt && (
                                  <>
                                    <span>-</span>
                                    <span>{formatTime(step.completedAt)}</span>
                                    <span>({formatDuration(step.startedAt, step.completedAt)})</span>
                                  </>
                                )}
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              </div>
            ))}

            {filteredExecutions.length === 0 && (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Activity className="h-12 w-12 mb-3 opacity-30" />
                <p className="text-sm">No executions found</p>
                <p className="text-xs">Executions will appear here when agents process incidents</p>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

export const ExecutionTimeline = memo(ExecutionTimelineComponent);
