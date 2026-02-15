import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Switch } from '@/components/ui/switch';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Search,
  Filter,
  RefreshCw,
  Plus,
  ChevronRight,
  Clock,
  AlertTriangle,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import type { SigmaRule } from '../types';
import { ATTACK_TACTICS, STATUS_STYLES, SEVERITY_COLORS } from '../types';

interface RuleListProps {
  rules: SigmaRule[];
  selectedRule: SigmaRule | null;
  onSelectRule: (rule: SigmaRule) => void;
  onToggleEnabled: (ruleId: string) => void;
  filters: {
    search: string;
    status: string;
    severity: string;
    tactic: string;
  };
  onFiltersChange: (filters: {
    search: string;
    status: string;
    severity: string;
    tactic: string;
  }) => void;
  onCreateRule?: () => void;
}

export function RuleList({
  rules,
  selectedRule,
  onSelectRule,
  onToggleEnabled,
  filters,
  onFiltersChange,
  onCreateRule,
}: RuleListProps) {
  const severityBadgeVariant = (
    severity: SigmaRule['severity']
  ): 'critical' | 'high' | 'medium' | 'low' | 'info' => {
    if (severity === 'informational') return 'info';
    return severity;
  };

  return (
    <Card className="flex-1 flex flex-col">
      <CardHeader className="pb-4 space-y-4">
        {/* Filters */}
        <div className="flex items-center gap-4">
          <div className="relative flex-1 max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search rules..."
              value={filters.search}
              onChange={(e) =>
                onFiltersChange({ ...filters, search: e.target.value })
              }
              className="pl-10"
            />
          </div>
          <Select
            value={filters.status}
            onValueChange={(value) =>
              onFiltersChange({ ...filters, status: value })
            }
          >
            <SelectTrigger className="w-[130px]">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Status</SelectItem>
              <SelectItem value="active">Active</SelectItem>
              <SelectItem value="testing">Testing</SelectItem>
              <SelectItem value="draft">Draft</SelectItem>
              <SelectItem value="disabled">Disabled</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={filters.severity}
            onValueChange={(value) =>
              onFiltersChange({ ...filters, severity: value })
            }
          >
            <SelectTrigger className="w-[140px]">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severity</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="informational">Informational</SelectItem>
            </SelectContent>
          </Select>
          <Select
            value={filters.tactic}
            onValueChange={(value) =>
              onFiltersChange({ ...filters, tactic: value })
            }
          >
            <SelectTrigger className="w-[160px]">
              <SelectValue placeholder="Tactic" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Tactics</SelectItem>
              {ATTACK_TACTICS.map((tactic) => (
                <SelectItem key={tactic.id} value={tactic.id}>
                  {tactic.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button variant="outline" size="icon">
            <Filter className="w-4 h-4" />
          </Button>
          <div className="flex-1" />
          <Button variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          {onCreateRule && (
            <Button size="sm" onClick={onCreateRule}>
              <Plus className="w-4 h-4 mr-2" />
              New Rule
            </Button>
          )}
        </div>

        {/* Results count */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <AlertTriangle className="w-4 h-4" />
          <span>
            {rules.length} rule{rules.length !== 1 ? 's' : ''} found
          </span>
        </div>
      </CardHeader>
      <CardContent className="flex-1 min-h-0">
        <ScrollArea className="h-full">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[50px]">Enabled</TableHead>
                <TableHead>Title</TableHead>
                <TableHead className="w-[100px]">Severity</TableHead>
                <TableHead className="w-[100px]">Status</TableHead>
                <TableHead>Tactics</TableHead>
                <TableHead className="w-[100px] text-right">Triggers</TableHead>
                <TableHead className="w-[120px]">Last Triggered</TableHead>
                <TableHead className="w-[40px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow
                  key={rule.id}
                  className={cn(
                    'cursor-pointer',
                    selectedRule?.id === rule.id && 'bg-primary/5'
                  )}
                  onClick={() => onSelectRule(rule)}
                >
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <TooltipProvider>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <div>
                            <Switch
                              checked={rule.enabled}
                              onCheckedChange={() => onToggleEnabled(rule.id)}
                            />
                          </div>
                        </TooltipTrigger>
                        <TooltipContent>
                          {rule.enabled ? 'Disable rule' : 'Enable rule'}
                        </TooltipContent>
                      </Tooltip>
                    </TooltipProvider>
                  </TableCell>
                  <TableCell>
                    <div>
                      <p className="font-medium">{rule.title}</p>
                      <p className="text-xs text-muted-foreground truncate max-w-[300px]">
                        {rule.description}
                      </p>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={severityBadgeVariant(rule.severity)}
                      style={{
                        borderColor: `${SEVERITY_COLORS[rule.severity]}50`,
                        backgroundColor: `${SEVERITY_COLORS[rule.severity]}20`,
                        color: SEVERITY_COLORS[rule.severity],
                      }}
                    >
                      {rule.severity.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={cn('capitalize', STATUS_STYLES[rule.status])}
                    >
                      {rule.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {rule.attack.tactics.slice(0, 2).map((tactic) => (
                        <Badge
                          key={tactic.id}
                          variant="outline"
                          className="text-xs bg-primary/10 border-primary/30 text-primary"
                        >
                          {tactic.name}
                        </Badge>
                      ))}
                      {rule.attack.tactics.length > 2 && (
                        <Badge variant="outline" className="text-xs">
                          +{rule.attack.tactics.length - 2}
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="text-right font-mono text-sm">
                    {rule.triggerCount.toLocaleString()}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {rule.lastTriggered ? (
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatRelativeTime(rule.lastTriggered)}
                      </span>
                    ) : (
                      <span className="text-muted-foreground/50">Never</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <ChevronRight className="w-4 h-4 text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
