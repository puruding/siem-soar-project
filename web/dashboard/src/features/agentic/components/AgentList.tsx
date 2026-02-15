/**
 * AgentList - List of all agents with status and controls.
 */
import { memo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';
import {
  Bot,
  Search,
  Play,
  Pause,
  RefreshCcw,
  MoreVertical,
  Activity,
  Clock,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Settings,
  Eye,
  Trash2,
} from 'lucide-react';

export type AgentStatus = 'idle' | 'running' | 'paused' | 'failed' | 'initializing';
export type AgentCapability = 'investigate' | 'analyze' | 'respond' | 'coordinate' | 'validate';

export interface Agent {
  id: string;
  name: string;
  type: string;
  status: AgentStatus;
  capabilities: AgentCapability[];
  lastActive: Date | null;
  currentTask: string | null;
  successRate: number;
  totalExecutions: number;
  avgResponseTime: number;
}

interface AgentListProps {
  agents?: Agent[];
  onStartAgent?: (id: string) => void;
  onStopAgent?: (id: string) => void;
  onRestartAgent?: (id: string) => void;
  onConfigureAgent?: (id: string) => void;
  onViewAgent?: (id: string) => void;
  className?: string;
}

const defaultAgents: Agent[] = [
  {
    id: 'inv-001',
    name: 'Investigation Agent',
    type: 'investigator',
    status: 'running',
    capabilities: ['investigate'],
    lastActive: new Date(),
    currentTask: 'Investigating alert ALR-2024-001',
    successRate: 0.94,
    totalExecutions: 156,
    avgResponseTime: 28,
  },
  {
    id: 'ana-001',
    name: 'Analysis Agent',
    type: 'analyzer',
    status: 'running',
    capabilities: ['analyze'],
    lastActive: new Date(),
    currentTask: 'Analyzing threat patterns',
    successRate: 0.91,
    totalExecutions: 142,
    avgResponseTime: 45,
  },
  {
    id: 'res-001',
    name: 'Response Agent',
    type: 'responder',
    status: 'idle',
    capabilities: ['respond'],
    lastActive: new Date(Date.now() - 300000),
    currentTask: null,
    successRate: 0.88,
    totalExecutions: 89,
    avgResponseTime: 12,
  },
  {
    id: 'orch-001',
    name: 'Orchestrator',
    type: 'coordinator',
    status: 'running',
    capabilities: ['coordinate'],
    lastActive: new Date(),
    currentTask: 'Coordinating incident INC-2024-047',
    successRate: 0.96,
    totalExecutions: 203,
    avgResponseTime: 5,
  },
  {
    id: 'val-001',
    name: 'Validation Agent',
    type: 'validator',
    status: 'paused',
    capabilities: ['validate'],
    lastActive: new Date(Date.now() - 600000),
    currentTask: null,
    successRate: 0.92,
    totalExecutions: 178,
    avgResponseTime: 8,
  },
];

const statusConfig: Record<AgentStatus, { label: string; icon: typeof CheckCircle2; color: string }> = {
  idle: { label: 'Idle', icon: Clock, color: 'text-gray-500' },
  running: { label: 'Running', icon: Activity, color: 'text-green-500' },
  paused: { label: 'Paused', icon: Pause, color: 'text-yellow-500' },
  failed: { label: 'Failed', icon: XCircle, color: 'text-red-500' },
  initializing: { label: 'Initializing', icon: RefreshCcw, color: 'text-blue-500' },
};

const capabilityLabels: Record<AgentCapability, string> = {
  investigate: 'Investigation',
  analyze: 'Analysis',
  respond: 'Response',
  coordinate: 'Coordination',
  validate: 'Validation',
};

function AgentListComponent({
  agents = defaultAgents,
  onStartAgent,
  onStopAgent,
  onRestartAgent,
  onConfigureAgent,
  onViewAgent,
  className,
}: AgentListProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('all');

  const filteredAgents = agents.filter((agent) => {
    const matchesSearch =
      agent.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      agent.type.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesStatus = statusFilter === 'all' || agent.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const formatRelativeTime = (date: Date | null): string => {
    if (!date) return 'Never';
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);

    if (seconds < 60) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <Card className={cn('flex flex-col h-full', className)}>
      <CardHeader className="pb-4 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg flex items-center gap-2">
            <Bot className="h-5 w-5" />
            Agents ({agents.length})
          </CardTitle>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm">
              <RefreshCcw className="h-4 w-4 mr-1" />
              Sync
            </Button>
          </div>
        </div>
        <div className="flex items-center gap-3 mt-4">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search agents..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8"
            />
          </div>
          <Select value={statusFilter} onValueChange={setStatusFilter}>
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="running">Running</SelectItem>
              <SelectItem value="idle">Idle</SelectItem>
              <SelectItem value="paused">Paused</SelectItem>
              <SelectItem value="failed">Failed</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </CardHeader>
      <CardContent className="flex-1 min-h-0 p-0">
        <ScrollArea className="h-full px-6 pb-6">
          <div className="space-y-3">
            {filteredAgents.map((agent) => {
              const StatusIcon = statusConfig[agent.status].icon;
              return (
                <div
                  key={agent.id}
                  className="flex items-center gap-4 p-4 rounded-lg border bg-card hover:bg-muted/30 transition-colors"
                >
                  {/* Agent Icon */}
                  <div className={cn(
                    'p-2.5 rounded-lg shrink-0',
                    agent.status === 'running' ? 'bg-green-500/10' :
                    agent.status === 'failed' ? 'bg-red-500/10' :
                    'bg-muted'
                  )}>
                    <Bot className={cn(
                      'h-5 w-5',
                      statusConfig[agent.status].color
                    )} />
                  </div>

                  {/* Agent Info */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium truncate">{agent.name}</span>
                      <Badge variant="outline" className="shrink-0 text-xs">
                        {agent.type}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <StatusIcon className={cn('h-3.5 w-3.5', statusConfig[agent.status].color)} />
                      <span className={cn('text-xs', statusConfig[agent.status].color)}>
                        {statusConfig[agent.status].label}
                      </span>
                      {agent.currentTask && (
                        <>
                          <span className="text-muted-foreground">-</span>
                          <span className="text-xs text-muted-foreground truncate">
                            {agent.currentTask}
                          </span>
                        </>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-2">
                      {agent.capabilities.map((cap) => (
                        <Badge key={cap} variant="secondary" className="text-[10px] px-1.5 py-0">
                          {capabilityLabels[cap]}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Stats */}
                  <div className="flex items-center gap-6 shrink-0 text-sm">
                    <div className="text-center">
                      <p className="text-muted-foreground text-xs">Success</p>
                      <p className={cn(
                        'font-medium',
                        agent.successRate >= 0.9 ? 'text-green-500' :
                        agent.successRate >= 0.7 ? 'text-yellow-500' : 'text-red-500'
                      )}>
                        {(agent.successRate * 100).toFixed(0)}%
                      </p>
                    </div>
                    <div className="text-center">
                      <p className="text-muted-foreground text-xs">Executions</p>
                      <p className="font-medium">{agent.totalExecutions}</p>
                    </div>
                    <div className="text-center">
                      <p className="text-muted-foreground text-xs">Avg Time</p>
                      <p className="font-medium">{agent.avgResponseTime}s</p>
                    </div>
                    <div className="text-center">
                      <p className="text-muted-foreground text-xs">Last Active</p>
                      <p className="font-medium text-xs">{formatRelativeTime(agent.lastActive)}</p>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-1 shrink-0">
                    {agent.status === 'running' ? (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onStopAgent?.(agent.id)}
                        className="h-8 w-8 p-0"
                      >
                        <Pause className="h-4 w-4" />
                      </Button>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onStartAgent?.(agent.id)}
                        className="h-8 w-8 p-0"
                      >
                        <Play className="h-4 w-4" />
                      </Button>
                    )}
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
                          <MoreVertical className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => onViewAgent?.(agent.id)}>
                          <Eye className="h-4 w-4 mr-2" />
                          View Details
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onConfigureAgent?.(agent.id)}>
                          <Settings className="h-4 w-4 mr-2" />
                          Configure
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => onRestartAgent?.(agent.id)}>
                          <RefreshCcw className="h-4 w-4 mr-2" />
                          Restart
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem className="text-destructive">
                          <Trash2 className="h-4 w-4 mr-2" />
                          Remove
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
              );
            })}

            {filteredAgents.length === 0 && (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <Bot className="h-12 w-12 mb-3 opacity-30" />
                <p className="text-sm">No agents found</p>
                <p className="text-xs">Try adjusting your filters</p>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

export const AgentList = memo(AgentListComponent);
