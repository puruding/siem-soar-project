/**
 * AgentDashboard - Main dashboard for autonomous SOC agents.
 */
import { memo, useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import {
  Bot,
  Activity,
  Shield,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Play,
  Pause,
  RefreshCcw,
  Settings,
  BarChart3,
  Zap,
  Brain,
  Target,
} from 'lucide-react';
import { AgentList } from './AgentList';
import { ExecutionTimeline } from './ExecutionTimeline';
import { ApprovalQueue } from './ApprovalQueue';

// Types
export interface AgentStats {
  totalAgents: number;
  activeAgents: number;
  idleAgents: number;
  failedAgents: number;
  totalIncidentsProcessed: number;
  autoInvestigationRate: number;
  autoResponseRate: number;
  avgResponseTimeSeconds: number;
}

export interface SystemHealth {
  overallStatus: 'healthy' | 'degraded' | 'unhealthy' | 'critical';
  cpuUsage: number;
  memoryUsage: number;
  activeIncidents: number;
  pendingApprovals: number;
}

interface AgentDashboardProps {
  stats?: AgentStats;
  health?: SystemHealth;
  className?: string;
}

const defaultStats: AgentStats = {
  totalAgents: 5,
  activeAgents: 3,
  idleAgents: 2,
  failedAgents: 0,
  totalIncidentsProcessed: 247,
  autoInvestigationRate: 0.72,
  autoResponseRate: 0.45,
  avgResponseTimeSeconds: 34,
};

const defaultHealth: SystemHealth = {
  overallStatus: 'healthy',
  cpuUsage: 42,
  memoryUsage: 68,
  activeIncidents: 3,
  pendingApprovals: 2,
};

function AgentDashboardComponent({
  stats = defaultStats,
  health = defaultHealth,
  className,
}: AgentDashboardProps) {
  const [activeTab, setActiveTab] = useState('overview');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-500';
      case 'degraded':
        return 'text-yellow-500';
      case 'unhealthy':
        return 'text-orange-500';
      case 'critical':
        return 'text-red-500';
      default:
        return 'text-gray-500';
    }
  };

  const getStatusBadgeVariant = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'default';
      case 'degraded':
        return 'secondary';
      case 'unhealthy':
      case 'critical':
        return 'destructive';
      default:
        return 'outline';
    }
  };

  return (
    <div className={cn('flex flex-col h-full p-6 space-y-6', className)}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Brain className="h-6 w-6 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold">Autonomous SOC</h1>
            <p className="text-sm text-muted-foreground">
              AI-powered security operations center
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant={getStatusBadgeVariant(health.overallStatus)} className="h-7 px-3">
            <Activity className={cn('h-3.5 w-3.5 mr-1', getStatusColor(health.overallStatus))} />
            System {health.overallStatus}
          </Badge>
          <Button variant="outline" size="sm" onClick={handleRefresh}>
            <RefreshCcw className={cn('h-4 w-4 mr-1', isRefreshing && 'animate-spin')} />
            Refresh
          </Button>
          <Button variant="outline" size="sm">
            <Settings className="h-4 w-4 mr-1" />
            Configure
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="bg-gradient-to-br from-blue-500/10 to-blue-600/5 border-blue-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Active Agents</p>
                <p className="text-2xl font-bold">{stats.activeAgents}/{stats.totalAgents}</p>
              </div>
              <Bot className="h-8 w-8 text-blue-500 opacity-80" />
            </div>
            <div className="mt-2 flex items-center gap-2 text-xs">
              <Badge variant="outline" className="text-green-600 border-green-600/30 bg-green-500/10">
                {stats.idleAgents} idle
              </Badge>
              {stats.failedAgents > 0 && (
                <Badge variant="outline" className="text-red-600 border-red-600/30 bg-red-500/10">
                  {stats.failedAgents} failed
                </Badge>
              )}
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-green-500/10 to-green-600/5 border-green-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Auto Investigation</p>
                <p className="text-2xl font-bold">{(stats.autoInvestigationRate * 100).toFixed(0)}%</p>
              </div>
              <Target className="h-8 w-8 text-green-500 opacity-80" />
            </div>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-green-500 rounded-full transition-all"
                style={{ width: `${stats.autoInvestigationRate * 100}%` }}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-purple-500/10 to-purple-600/5 border-purple-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Auto Response</p>
                <p className="text-2xl font-bold">{(stats.autoResponseRate * 100).toFixed(0)}%</p>
              </div>
              <Zap className="h-8 w-8 text-purple-500 opacity-80" />
            </div>
            <div className="mt-2 h-2 bg-muted rounded-full overflow-hidden">
              <div
                className="h-full bg-purple-500 rounded-full transition-all"
                style={{ width: `${stats.autoResponseRate * 100}%` }}
              />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gradient-to-br from-cyan-500/10 to-cyan-600/5 border-cyan-500/20">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Avg Response Time</p>
                <p className="text-2xl font-bold">{stats.avgResponseTimeSeconds}s</p>
              </div>
              <Clock className="h-8 w-8 text-cyan-500 opacity-80" />
            </div>
            <div className="mt-2 text-xs text-muted-foreground">
              {stats.totalIncidentsProcessed} incidents processed
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
        <TabsList className="w-fit">
          <TabsTrigger value="overview" className="gap-1.5">
            <BarChart3 className="h-4 w-4" />
            Overview
          </TabsTrigger>
          <TabsTrigger value="agents" className="gap-1.5">
            <Bot className="h-4 w-4" />
            Agents
          </TabsTrigger>
          <TabsTrigger value="timeline" className="gap-1.5">
            <Activity className="h-4 w-4" />
            Timeline
          </TabsTrigger>
          <TabsTrigger value="approvals" className="gap-1.5">
            <Shield className="h-4 w-4" />
            Approvals
            {health.pendingApprovals > 0 && (
              <Badge variant="destructive" className="ml-1 h-5 px-1.5">
                {health.pendingApprovals}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="flex-1 mt-4">
          <div className="grid grid-cols-3 gap-4 h-full">
            {/* Active Incidents */}
            <Card className="col-span-2">
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Active Incidents
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ExecutionTimeline limit={5} compact />
              </CardContent>
            </Card>

            {/* System Status */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-base flex items-center gap-2">
                  <Shield className="h-4 w-4" />
                  System Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-muted-foreground">CPU Usage</span>
                    <span className="text-sm font-medium">{health.cpuUsage}%</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all',
                        health.cpuUsage > 80 ? 'bg-red-500' :
                        health.cpuUsage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                      )}
                      style={{ width: `${health.cpuUsage}%` }}
                    />
                  </div>
                </div>
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-muted-foreground">Memory Usage</span>
                    <span className="text-sm font-medium">{health.memoryUsage}%</span>
                  </div>
                  <div className="h-2 bg-muted rounded-full overflow-hidden">
                    <div
                      className={cn(
                        'h-full rounded-full transition-all',
                        health.memoryUsage > 80 ? 'bg-red-500' :
                        health.memoryUsage > 60 ? 'bg-yellow-500' : 'bg-green-500'
                      )}
                      style={{ width: `${health.memoryUsage}%` }}
                    />
                  </div>
                </div>
                <div className="pt-2 border-t">
                  <div className="flex items-center justify-between py-2">
                    <span className="text-sm text-muted-foreground">Active Incidents</span>
                    <Badge variant="outline">{health.activeIncidents}</Badge>
                  </div>
                  <div className="flex items-center justify-between py-2">
                    <span className="text-sm text-muted-foreground">Pending Approvals</span>
                    <Badge variant={health.pendingApprovals > 0 ? 'destructive' : 'outline'}>
                      {health.pendingApprovals}
                    </Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="agents" className="flex-1 mt-4 min-h-0">
          <AgentList />
        </TabsContent>

        <TabsContent value="timeline" className="flex-1 mt-4 min-h-0">
          <ExecutionTimeline />
        </TabsContent>

        <TabsContent value="approvals" className="flex-1 mt-4 min-h-0">
          <ApprovalQueue />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export const AgentDashboard = memo(AgentDashboardComponent);
