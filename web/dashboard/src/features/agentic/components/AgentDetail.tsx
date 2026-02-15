/**
 * AgentDetail - Detailed view of a single agent.
 */
import { memo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { cn } from '@/lib/utils';
import {
  Bot,
  Activity,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Play,
  Pause,
  RefreshCcw,
  Settings,
  ArrowLeft,
  BarChart3,
  History,
  Cpu,
  MemoryStick,
  Zap,
  Target,
  ChevronRight,
} from 'lucide-react';
import type { Agent, AgentStatus } from './AgentList';

export interface AgentExecution {
  id: string;
  incidentId: string;
  taskType: string;
  status: 'completed' | 'failed' | 'running';
  startedAt: Date;
  completedAt: Date | null;
  duration: number | null;
  result: string | null;
}

export interface AgentMetrics {
  successRate: number;
  avgResponseTime: number;
  totalExecutions: number;
  executionsToday: number;
  cpuUsage: number;
  memoryUsage: number;
  activeConnections: number;
}

interface AgentDetailProps {
  agent: Agent;
  executions?: AgentExecution[];
  metrics?: AgentMetrics;
  onBack?: () => void;
  onStart?: () => void;
  onStop?: () => void;
  onRestart?: () => void;
  onConfigure?: () => void;
  className?: string;
}

const defaultExecutions: AgentExecution[] = [
  {
    id: 'exec-001',
    incidentId: 'INC-2024-047',
    taskType: 'investigation',
    status: 'completed',
    startedAt: new Date(Date.now() - 300000),
    completedAt: new Date(Date.now() - 270000),
    duration: 30,
    result: 'Investigation completed successfully',
  },
  {
    id: 'exec-002',
    incidentId: 'INC-2024-046',
    taskType: 'analysis',
    status: 'completed',
    startedAt: new Date(Date.now() - 900000),
    completedAt: new Date(Date.now() - 855000),
    duration: 45,
    result: 'Threat classified as ransomware',
  },
  {
    id: 'exec-003',
    incidentId: 'INC-2024-045',
    taskType: 'response',
    status: 'failed',
    startedAt: new Date(Date.now() - 1800000),
    completedAt: new Date(Date.now() - 1790000),
    duration: 10,
    result: 'Action blocked by guardrail',
  },
  {
    id: 'exec-004',
    incidentId: 'INC-2024-048',
    taskType: 'investigation',
    status: 'running',
    startedAt: new Date(Date.now() - 60000),
    completedAt: null,
    duration: null,
    result: null,
  },
];

const defaultMetrics: AgentMetrics = {
  successRate: 0.94,
  avgResponseTime: 28,
  totalExecutions: 156,
  executionsToday: 12,
  cpuUsage: 35,
  memoryUsage: 512,
  activeConnections: 3,
};

const statusConfig: Record<AgentStatus, { label: string; icon: typeof CheckCircle2; color: string; bg: string }> = {
  idle: { label: 'Idle', icon: Clock, color: 'text-gray-500', bg: 'bg-gray-500/10' },
  running: { label: 'Running', icon: Activity, color: 'text-green-500', bg: 'bg-green-500/10' },
  paused: { label: 'Paused', icon: Pause, color: 'text-yellow-500', bg: 'bg-yellow-500/10' },
  failed: { label: 'Failed', icon: XCircle, color: 'text-red-500', bg: 'bg-red-500/10' },
  initializing: { label: 'Initializing', icon: RefreshCcw, color: 'text-blue-500', bg: 'bg-blue-500/10' },
};

function AgentDetailComponent({
  agent,
  executions = defaultExecutions,
  metrics = defaultMetrics,
  onBack,
  onStart,
  onStop,
  onRestart,
  onConfigure,
  className,
}: AgentDetailProps) {
  const [activeTab, setActiveTab] = useState('overview');
  const StatusIcon = statusConfig[agent.status].icon;

  const formatDuration = (seconds: number | null): string => {
    if (seconds === null) return '-';
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  const formatTime = (date: Date): string => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="flex items-center justify-between p-6 border-b">
        <div className="flex items-center gap-4">
          {onBack && (
            <Button variant="ghost" size="sm" onClick={onBack}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <div className={cn('p-3 rounded-lg', statusConfig[agent.status].bg)}>
            <Bot className={cn('h-6 w-6', statusConfig[agent.status].color)} />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold">{agent.name}</h1>
              <Badge variant="outline">{agent.type}</Badge>
              <Badge className={cn(
                statusConfig[agent.status].bg,
                statusConfig[agent.status].color,
                'border-0'
              )}>
                <StatusIcon className="h-3 w-3 mr-1" />
                {statusConfig[agent.status].label}
              </Badge>
            </div>
            <p className="text-sm text-muted-foreground mt-1">
              ID: {agent.id}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {agent.status === 'running' ? (
            <Button variant="outline" onClick={onStop}>
              <Pause className="h-4 w-4 mr-1" />
              Stop
            </Button>
          ) : (
            <Button variant="default" onClick={onStart}>
              <Play className="h-4 w-4 mr-1" />
              Start
            </Button>
          )}
          <Button variant="outline" onClick={onRestart}>
            <RefreshCcw className="h-4 w-4 mr-1" />
            Restart
          </Button>
          <Button variant="outline" onClick={onConfigure}>
            <Settings className="h-4 w-4 mr-1" />
            Configure
          </Button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 p-6">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="h-full flex flex-col">
          <TabsList className="w-fit">
            <TabsTrigger value="overview">
              <BarChart3 className="h-4 w-4 mr-1" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="executions">
              <History className="h-4 w-4 mr-1" />
              Executions
            </TabsTrigger>
            <TabsTrigger value="resources">
              <Cpu className="h-4 w-4 mr-1" />
              Resources
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="flex-1 mt-4">
            <div className="grid grid-cols-3 gap-6">
              {/* Metrics */}
              <div className="col-span-2 space-y-6">
                <div className="grid grid-cols-4 gap-4">
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Target className="h-8 w-8 text-green-500 opacity-80" />
                        <div>
                          <p className="text-sm text-muted-foreground">Success Rate</p>
                          <p className="text-2xl font-bold">{(metrics.successRate * 100).toFixed(0)}%</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Clock className="h-8 w-8 text-blue-500 opacity-80" />
                        <div>
                          <p className="text-sm text-muted-foreground">Avg Response</p>
                          <p className="text-2xl font-bold">{metrics.avgResponseTime}s</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Zap className="h-8 w-8 text-purple-500 opacity-80" />
                        <div>
                          <p className="text-sm text-muted-foreground">Total Executions</p>
                          <p className="text-2xl font-bold">{metrics.totalExecutions}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardContent className="p-4">
                      <div className="flex items-center gap-3">
                        <Activity className="h-8 w-8 text-cyan-500 opacity-80" />
                        <div>
                          <p className="text-sm text-muted-foreground">Today</p>
                          <p className="text-2xl font-bold">{metrics.executionsToday}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* Recent Activity */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Recent Activity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {executions.slice(0, 5).map((exec) => (
                        <div
                          key={exec.id}
                          className="flex items-center gap-3 p-3 rounded-lg bg-muted/30"
                        >
                          <div className={cn(
                            'p-1.5 rounded-full',
                            exec.status === 'completed' ? 'bg-green-500/10' :
                            exec.status === 'failed' ? 'bg-red-500/10' : 'bg-blue-500/10'
                          )}>
                            {exec.status === 'completed' ? (
                              <CheckCircle2 className="h-4 w-4 text-green-500" />
                            ) : exec.status === 'failed' ? (
                              <XCircle className="h-4 w-4 text-red-500" />
                            ) : (
                              <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
                            )}
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm">{exec.incidentId}</span>
                              <Badge variant="outline" className="text-xs">
                                {exec.taskType}
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground truncate mt-0.5">
                              {exec.result || 'In progress...'}
                            </p>
                          </div>
                          <div className="text-right text-xs text-muted-foreground shrink-0">
                            <p>{formatTime(exec.startedAt)}</p>
                            <p>{formatDuration(exec.duration)}</p>
                          </div>
                          <ChevronRight className="h-4 w-4 text-muted-foreground" />
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Side Panel */}
              <div className="space-y-6">
                {/* Capabilities */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Capabilities</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-wrap gap-2">
                      {agent.capabilities.map((cap) => (
                        <Badge key={cap} variant="secondary">
                          {cap}
                        </Badge>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                {/* Current Task */}
                {agent.currentTask && (
                  <Card className="border-primary/30 bg-primary/5">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center gap-2">
                        <Activity className="h-4 w-4 text-primary animate-pulse" />
                        Current Task
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <p className="text-sm">{agent.currentTask}</p>
                    </CardContent>
                  </Card>
                )}

                {/* Resource Usage */}
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Resource Usage</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm text-muted-foreground flex items-center gap-1">
                          <Cpu className="h-3.5 w-3.5" />
                          CPU
                        </span>
                        <span className="text-sm font-medium">{metrics.cpuUsage}%</span>
                      </div>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className={cn(
                            'h-full rounded-full transition-all',
                            metrics.cpuUsage > 80 ? 'bg-red-500' :
                            metrics.cpuUsage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                          )}
                          style={{ width: `${metrics.cpuUsage}%` }}
                        />
                      </div>
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm text-muted-foreground flex items-center gap-1">
                          <MemoryStick className="h-3.5 w-3.5" />
                          Memory
                        </span>
                        <span className="text-sm font-medium">{metrics.memoryUsage} MB</span>
                      </div>
                      <div className="h-2 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-blue-500 rounded-full transition-all"
                          style={{ width: `${(metrics.memoryUsage / 1024) * 100}%` }}
                        />
                      </div>
                    </div>
                    <Separator />
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Active Connections</span>
                      <Badge variant="outline">{metrics.activeConnections}</Badge>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="executions" className="flex-1 mt-4 min-h-0">
            <Card className="h-full flex flex-col">
              <CardHeader className="pb-2 shrink-0">
                <CardTitle className="text-base">Execution History</CardTitle>
              </CardHeader>
              <CardContent className="flex-1 min-h-0 p-0">
                <ScrollArea className="h-full px-6 pb-6">
                  <div className="space-y-2">
                    {executions.map((exec) => (
                      <div
                        key={exec.id}
                        className="flex items-center gap-4 p-4 rounded-lg border hover:bg-muted/30 transition-colors"
                      >
                        <div className={cn(
                          'p-2 rounded-full shrink-0',
                          exec.status === 'completed' ? 'bg-green-500/10' :
                          exec.status === 'failed' ? 'bg-red-500/10' : 'bg-blue-500/10'
                        )}>
                          {exec.status === 'completed' ? (
                            <CheckCircle2 className="h-4 w-4 text-green-500" />
                          ) : exec.status === 'failed' ? (
                            <XCircle className="h-4 w-4 text-red-500" />
                          ) : (
                            <Activity className="h-4 w-4 text-blue-500 animate-pulse" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">{exec.incidentId}</span>
                            <Badge variant="outline" className="text-xs">{exec.taskType}</Badge>
                            <Badge variant={
                              exec.status === 'completed' ? 'default' :
                              exec.status === 'failed' ? 'destructive' : 'secondary'
                            } className="text-xs">
                              {exec.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {exec.result || 'In progress...'}
                          </p>
                        </div>
                        <div className="text-right text-sm text-muted-foreground shrink-0">
                          <p>{exec.startedAt.toLocaleString()}</p>
                          <p>Duration: {formatDuration(exec.duration)}</p>
                        </div>
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="resources" className="flex-1 mt-4">
            <Card>
              <CardContent className="p-6">
                <p className="text-muted-foreground text-center py-12">
                  Resource monitoring charts coming soon...
                </p>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

export const AgentDetail = memo(AgentDetailComponent);
