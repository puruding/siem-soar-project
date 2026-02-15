import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
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
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Search,
  Plus,
  Play,
  CheckCircle2,
  Clock,
  MoreVertical,
  Workflow,
  Zap,
  TrendingUp,
  Edit,
  Copy,
  Trash2,
  Pause,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  status: 'active' | 'inactive' | 'draft';
  triggers: string[];
  steps: number;
  lastRun?: Date;
  executions: number;
  successRate: number;
}

const mockPlaybooks: Playbook[] = [
  {
    id: 'PB-001',
    name: 'Malware Response',
    description:
      'Automatically isolate compromised endpoints from the network to prevent lateral movement.',
    category: 'Containment',
    status: 'active',
    triggers: ['Malware Detection', 'Ransomware Alert'],
    steps: 8,
    lastRun: new Date(Date.now() - 1000 * 60 * 30),
    executions: 156,
    successRate: 98.2,
  },
  {
    id: 'PB-002',
    name: 'Phishing Investigation',
    description:
      'Analyze reported phishing emails, extract IOCs, and check user exposure.',
    category: 'Investigation',
    status: 'active',
    triggers: ['User Report', 'Email Alert'],
    steps: 12,
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 2),
    executions: 89,
    successRate: 95.5,
  },
  {
    id: 'PB-003',
    name: 'IOC Enrichment',
    description:
      'Enrich indicators with threat intelligence from multiple sources.',
    category: 'Enrichment',
    status: 'active',
    triggers: ['New Alert', 'Manual'],
    steps: 6,
    lastRun: new Date(Date.now() - 1000 * 60 * 15),
    executions: 1245,
    successRate: 99.1,
  },
  {
    id: 'PB-004',
    name: 'Credential Reset',
    description:
      'Force password reset for compromised accounts and notify user.',
    category: 'Response',
    status: 'active',
    triggers: ['Credential Compromise'],
    steps: 5,
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 5),
    executions: 67,
    successRate: 100,
  },
  {
    id: 'PB-005',
    name: 'Lateral Movement Hunt',
    description:
      'Proactively search for signs of lateral movement in the network.',
    category: 'Hunting',
    status: 'draft',
    triggers: ['Scheduled', 'Manual'],
    steps: 15,
    executions: 0,
    successRate: 0,
  },
  {
    id: 'PB-006',
    name: 'Vulnerability Response',
    description: 'Automatically triage and assign critical vulnerabilities.',
    category: 'Response',
    status: 'inactive',
    triggers: ['Vulnerability Scan'],
    steps: 7,
    lastRun: new Date(Date.now() - 1000 * 60 * 60 * 24 * 3),
    executions: 34,
    successRate: 91.2,
  },
];

const categories = [
  'All',
  'Containment',
  'Investigation',
  'Enrichment',
  'Response',
  'Hunting',
];

const statusConfig: Record<
  string,
  { label: string; color: string; bgColor: string; borderColor: string }
> = {
  active: {
    label: 'Active',
    color: 'text-[#5CC05C]',
    bgColor: 'bg-[#5CC05C]/10',
    borderColor: 'border-[#5CC05C]/30',
  },
  inactive: {
    label: 'Inactive',
    color: 'text-muted-foreground',
    bgColor: 'bg-muted/50',
    borderColor: 'border-border',
  },
  draft: {
    label: 'Draft',
    color: 'text-[#F79836]',
    bgColor: 'bg-[#F79836]/10',
    borderColor: 'border-[#F79836]/30',
  },
};

export function PlaybookList() {
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('all');

  const filteredPlaybooks = mockPlaybooks.filter((pb) => {
    if (
      searchQuery &&
      !pb.name.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    if (categoryFilter !== 'All' && pb.category !== categoryFilter) return false;
    if (statusFilter !== 'all' && pb.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-display font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text">
            Playbooks
          </h1>
          <p className="text-muted-foreground mt-1">
            Automate security response workflows
          </p>
        </div>
        <Link to="/playbooks/new">
          <Button className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80 hover:from-[#00A4A6]/90 hover:to-[#00A4A6]/70 shadow-lg shadow-[#00A4A6]/20">
            <Plus className="w-4 h-4 mr-2" />
            New Playbook
          </Button>
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="relative overflow-hidden border-border/50 bg-gradient-to-br from-card to-card/50 backdrop-blur-sm">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <CardContent className="p-5 relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">
                  Total Playbooks
                </p>
                <p className="text-3xl font-display font-bold mt-2">24</p>
              </div>
              <div className="p-3 rounded-xl bg-primary/10 border border-primary/20">
                <Workflow className="w-6 h-6 text-primary" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden border-[#5CC05C]/30 bg-gradient-to-br from-card to-card/50 backdrop-blur-sm">
          <div className="absolute inset-0 bg-gradient-to-br from-[#5CC05C]/5 to-transparent pointer-events-none" />
          <CardContent className="p-5 relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">
                  Active
                </p>
                <p className="text-3xl font-display font-bold mt-2 text-[#5CC05C]">18</p>
              </div>
              <div className="p-3 rounded-xl bg-[#5CC05C]/10 border border-[#5CC05C]/20">
                <CheckCircle2 className="w-6 h-6 text-[#5CC05C]" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden border-[#00A4A6]/30 bg-gradient-to-br from-card to-card/50 backdrop-blur-sm">
          <div className="absolute inset-0 bg-gradient-to-br from-[#00A4A6]/5 to-transparent pointer-events-none" />
          <CardContent className="p-5 relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">
                  Runs Today
                </p>
                <p className="text-3xl font-display font-bold mt-2 text-[#00A4A6]">127</p>
              </div>
              <div className="p-3 rounded-xl bg-[#00A4A6]/10 border border-[#00A4A6]/20">
                <Zap className="w-6 h-6 text-[#00A4A6]" />
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="relative overflow-hidden border-[#5CC05C]/30 bg-gradient-to-br from-card to-card/50 backdrop-blur-sm">
          <div className="absolute inset-0 bg-gradient-to-br from-[#5CC05C]/5 to-transparent pointer-events-none" />
          <CardContent className="p-5 relative">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground uppercase tracking-wider font-semibold">
                  Success Rate
                </p>
                <p className="text-3xl font-display font-bold mt-2 text-[#5CC05C]">97.3%</p>
              </div>
              <div className="p-3 rounded-xl bg-[#5CC05C]/10 border border-[#5CC05C]/20">
                <TrendingUp className="w-6 h-6 text-[#5CC05C]" />
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
        <CardHeader className="pb-4">
          <div className="flex items-center gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search playbooks..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10 bg-background/50"
              />
            </div>
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger className="w-[180px] bg-background/50">
                <SelectValue placeholder="Category" />
              </SelectTrigger>
              <SelectContent>
                {categories.map((cat) => (
                  <SelectItem key={cat} value={cat}>
                    {cat}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[160px] bg-background/50">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="inactive">Inactive</SelectItem>
                <SelectItem value="draft">Draft</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-480px)]">
            <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
              {filteredPlaybooks.map((playbook) => {
                const statusStyle = statusConfig[playbook.status];
                if (!statusStyle) {
                  console.warn(`Unknown status: ${playbook.status}`);
                  return null;
                }
                return (
                  <Card
                    key={playbook.id}
                    className={cn(
                      'group relative overflow-hidden transition-all duration-300',
                      'hover:shadow-xl hover:scale-[1.02] hover:-translate-y-1',
                      'border-border/50 bg-gradient-to-br from-card to-card/50 backdrop-blur-sm',
                      playbook.status === 'active' && 'hover:border-[#5CC05C]/30 hover:shadow-[#5CC05C]/10',
                      playbook.status === 'draft' && 'hover:border-[#F79836]/30',
                      playbook.status === 'inactive' && 'opacity-80'
                    )}
                  >
                    {/* Status glow */}
                    <div
                      className={cn(
                        'absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-300 blur-2xl -z-10',
                        playbook.status === 'active' && 'bg-[#5CC05C]/5',
                        playbook.status === 'draft' && 'bg-[#F79836]/5'
                      )}
                    />

                    <CardContent className="p-5">
                      {/* Header */}
                      <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant="outline" className="text-xs font-medium border-primary/30 bg-primary/5">
                            {playbook.category}
                          </Badge>
                          <Badge
                            variant="outline"
                            className={cn(
                              'text-xs font-semibold',
                              statusStyle.color,
                              statusStyle.bgColor,
                              statusStyle.borderColor
                            )}
                          >
                            {statusStyle.label}
                          </Badge>
                        </div>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-8 w-8 opacity-0 group-hover:opacity-100 transition-opacity"
                            >
                              <MoreVertical className="w-4 h-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem>
                              <Edit className="w-4 h-4 mr-2" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <Copy className="w-4 h-4 mr-2" />
                              Duplicate
                            </DropdownMenuItem>
                            <DropdownMenuItem>
                              <Pause className="w-4 h-4 mr-2" />
                              {playbook.status === 'active' ? 'Pause' : 'Activate'}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem className="text-destructive">
                              <Trash2 className="w-4 h-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>

                      {/* Content */}
                      <Link to={`/playbooks/${playbook.id}`} className="block">
                        <div className="flex items-start gap-4 mb-4">
                          <div className={cn(
                            "p-3 rounded-xl shrink-0 transition-all duration-300",
                            "bg-gradient-to-br border",
                            playbook.status === 'active'
                              ? "from-[#00A4A6]/20 to-[#00A4A6]/5 border-[#00A4A6]/20 group-hover:from-[#00A4A6]/30 group-hover:to-[#00A4A6]/10"
                              : "from-muted/30 to-muted/10 border-border/30"
                          )}>
                            <Workflow className={cn(
                              "w-5 h-5 transition-colors",
                              playbook.status === 'active' ? "text-[#00A4A6]" : "text-muted-foreground"
                            )} />
                          </div>
                          <div className="flex-1 min-w-0">
                            <h3 className="font-semibold text-base mb-1 group-hover:text-primary transition-colors truncate">
                              {playbook.name}
                            </h3>
                            <p className="text-sm text-muted-foreground line-clamp-2">
                              {playbook.description}
                            </p>
                          </div>
                        </div>

                        {/* Triggers */}
                        <div className="flex flex-wrap gap-1.5 mb-4">
                          {playbook.triggers.map((trigger) => (
                            <Badge
                              key={trigger}
                              variant="outline"
                              className="text-2xs font-medium bg-background/50 border-border/50"
                            >
                              <Zap className="w-2.5 h-2.5 mr-1 text-[#5CC05C]" />
                              {trigger}
                            </Badge>
                          ))}
                        </div>

                        {/* Stats */}
                        <div className="flex items-center justify-between pt-4 border-t border-border/50">
                          <div className="flex items-center gap-4 text-xs">
                            <span className="text-muted-foreground">
                              <span className="font-semibold text-foreground">{playbook.steps}</span> steps
                            </span>
                            <span className="text-muted-foreground">
                              <span className="font-semibold text-foreground">{playbook.executions}</span> runs
                            </span>
                            {playbook.successRate > 0 && (
                              <span className="text-[#5CC05C] font-semibold">
                                {playbook.successRate}%
                              </span>
                            )}
                          </div>
                          {playbook.lastRun && (
                            <div className="flex items-center gap-1 text-2xs text-muted-foreground">
                              <Clock className="w-3 h-3" />
                              {formatRelativeTime(playbook.lastRun)}
                            </div>
                          )}
                        </div>
                      </Link>

                      {/* Actions */}
                      <div className="mt-4 pt-4 border-t border-border/50">
                        {playbook.status === 'active' ? (
                          <Button
                            variant="outline"
                            size="sm"
                            className="w-full group/btn hover:border-[#5CC05C]/50 hover:bg-[#5CC05C]/5"
                            onClick={(e) => {
                              e.preventDefault();
                            }}
                          >
                            <Play className="w-3.5 h-3.5 mr-2 group-hover/btn:text-[#5CC05C]" />
                            Run Now
                          </Button>
                        ) : playbook.status === 'draft' ? (
                          <Link to={`/playbooks/${playbook.id}`}>
                            <Button
                              variant="outline"
                              size="sm"
                              className="w-full hover:border-[#F79836]/50 hover:bg-[#F79836]/5"
                            >
                              <Edit className="w-3.5 h-3.5 mr-2" />
                              Continue Editing
                            </Button>
                          </Link>
                        ) : (
                          <Button
                            variant="outline"
                            size="sm"
                            className="w-full"
                            onClick={(e) => {
                              e.preventDefault();
                            }}
                          >
                            <Play className="w-3.5 h-3.5 mr-2" />
                            Activate
                          </Button>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
