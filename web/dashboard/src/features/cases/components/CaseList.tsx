import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Search,
  Plus,
  Filter,
  LayoutGrid,
  List,
  Clock,
  AlertTriangle,
  User,
  MoreHorizontal,
  Loader2,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import { useToast } from '@/components/ui/toaster';
import { useCases } from '../hooks/useCases';
import type { Case, CaseSeverity } from '@/types/case';

const statusStyles: Record<string, string> = {
  open: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  in_progress: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  pending: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
  reopened: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
};

// Alert interface for linking
interface AlertItem {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
}

// Initial form state for new case
interface CreateCaseForm {
  title: string;
  description: string;
  severity: CaseSeverity;
  assignee: string;
  tags: string;
  linkedAlerts: string[];
}

const initialFormState: CreateCaseForm = {
  title: '',
  description: '',
  severity: 'medium',
  assignee: '',
  tags: '',
  linkedAlerts: [],
};

// Available assignees for the dropdown
const availableAssignees = [
  { name: 'John Doe', initials: 'JD' },
  { name: 'Jane Smith', initials: 'JS' },
  { name: 'Mike Johnson', initials: 'MJ' },
  { name: 'Sarah Wilson', initials: 'SW' },
  { name: 'Alex Kim', initials: 'AK' },
];

export function CaseList() {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<'grid' | 'list'>('grid');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  // Use the cases hook
  const {
    cases,
    loading,
    error,
    createCase: createCaseApi,
    refresh,
  } = useCases();

  // Available alerts for linking
  const [availableAlerts, setAvailableAlerts] = useState<AlertItem[]>([
    { id: 'ALERT-1001', title: 'Ransomware Attack Detected', severity: 'critical', timestamp: new Date(Date.now() - 1000 * 60 * 30) },
    { id: 'ALERT-1002', title: 'C2 Communication Detected', severity: 'high', timestamp: new Date(Date.now() - 1000 * 60 * 45) },
    { id: 'ALERT-1003', title: 'Brute Force Attack Detected', severity: 'high', timestamp: new Date(Date.now() - 1000 * 60 * 60) },
    { id: 'ALERT-1004', title: 'Suspicious Login Activity', severity: 'medium', timestamp: new Date(Date.now() - 1000 * 60 * 90) },
    { id: 'ALERT-1005', title: 'Data Exfiltration Attempt', severity: 'critical', timestamp: new Date(Date.now() - 1000 * 60 * 120) },
  ]);

  // Create dialog state
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createForm, setCreateForm] = useState<CreateCaseForm>(initialFormState);

  // Handle form field changes
  const handleFormChange = (field: keyof CreateCaseForm, value: string) => {
    setCreateForm(prev => ({ ...prev, [field]: value }));
  };

  // Toggle alert selection
  const toggleAlertSelection = (alertId: string) => {
    setCreateForm(prev => ({
      ...prev,
      linkedAlerts: prev.linkedAlerts.includes(alertId)
        ? prev.linkedAlerts.filter(id => id !== alertId)
        : [...prev.linkedAlerts, alertId],
    }));
  };

  // Handle create case submission
  const handleCreateCase = async () => {
    if (!createForm.title.trim()) {
      toast({
        title: 'Validation Error',
        description: 'Case title is required.',
        variant: 'destructive',
      });
      return;
    }

    setIsCreating(true);

    try {
      // Parse tags
      const tags = createForm.tags
        .split(',')
        .map(t => t.trim().toLowerCase())
        .filter(t => t.length > 0);

      // Create case via API
      const newCase = await createCaseApi({
        title: createForm.title,
        description: createForm.description || 'No description provided.',
        severity: createForm.severity,
        assigneeId: createForm.assignee || undefined,
        alertIds: createForm.linkedAlerts.length > 0 ? createForm.linkedAlerts : undefined,
        tags: tags.length > 0 ? tags : undefined,
      });

      if (newCase) {
        // Reset form and close dialog
        setCreateForm(initialFormState);
        setIsCreateDialogOpen(false);

        toast({
          title: 'Case Created',
          description: `${newCase.id} has been created successfully.`,
          variant: 'success',
        });

        // Refresh the list
        await refresh();
      } else {
        throw new Error('Failed to create case');
      }
    } catch (error) {
      console.error('Failed to create case:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create case. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setIsCreating(false);
    }
  };

  const filteredCases = cases.filter((c) => {
    if (statusFilter !== 'all' && c.status !== statusFilter) return false;
    if (severityFilter !== 'all' && c.severity !== severityFilter) return false;
    if (
      searchQuery &&
      !c.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !c.id.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    return true;
  });

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Case Management
          </h1>
          <p className="text-muted-foreground">
            Track and manage security incidents
          </p>
        </div>
        <Button onClick={() => setIsCreateDialogOpen(true)}>
          <Plus className="w-4 h-4 mr-2" />
          New Case
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Open Cases</p>
              <p className="text-2xl font-display font-bold">12</p>
            </div>
            <div className="p-2 rounded-lg bg-neon-cyan/20">
              <AlertTriangle className="w-5 h-5 text-neon-cyan" />
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">In Progress</p>
              <p className="text-2xl font-display font-bold">8</p>
            </div>
            <div className="p-2 rounded-lg bg-neon-orange/20">
              <Clock className="w-5 h-5 text-neon-orange" />
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Critical</p>
              <p className="text-2xl font-display font-bold">3</p>
            </div>
            <div className="p-2 rounded-lg bg-threat-critical/20">
              <AlertTriangle className="w-5 h-5 text-threat-critical" />
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Avg MTTR</p>
              <p className="text-2xl font-display font-bold">2.4h</p>
            </div>
            <div className="p-2 rounded-lg bg-neon-green/20">
              <Clock className="w-5 h-5 text-neon-green" />
            </div>
          </div>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="relative w-64">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search cases..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10"
                />
              </div>
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Status</SelectItem>
                  <SelectItem value="open">Open</SelectItem>
                  <SelectItem value="in_progress">In Progress</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="resolved">Resolved</SelectItem>
                  <SelectItem value="closed">Closed</SelectItem>
                  <SelectItem value="reopened">Reopened</SelectItem>
                </SelectContent>
              </Select>
              <Select value={severityFilter} onValueChange={setSeverityFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Severity" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Severity</SelectItem>
                  <SelectItem value="critical">Critical</SelectItem>
                  <SelectItem value="high">High</SelectItem>
                  <SelectItem value="medium">Medium</SelectItem>
                  <SelectItem value="low">Low</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="icon">
                <Filter className="w-4 h-4" />
              </Button>
            </div>
            <div className="flex items-center gap-1 bg-muted rounded-lg p-1">
              <Button
                variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
                size="icon"
                className="h-8 w-8"
                onClick={() => setViewMode('grid')}
              >
                <LayoutGrid className="w-4 h-4" />
              </Button>
              <Button
                variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                size="icon"
                className="h-8 w-8"
                onClick={() => setViewMode('list')}
              >
                <List className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {error && (
            <div className="mb-4 p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
              <p className="text-sm text-destructive">Error: {error}</p>
            </div>
          )}
          <ScrollArea className="h-[calc(100vh-420px)]">
            {loading && cases.length === 0 ? (
              <div className="flex items-center justify-center h-64">
                <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
              </div>
            ) : viewMode === 'grid' ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredCases.map((caseItem) => (
                  <Link key={caseItem.id} to={`/cases/${caseItem.id}`}>
                    <Card className="p-4 h-full hover:border-primary/30 transition-all duration-200 group cursor-pointer">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Badge variant={caseItem.severity}>
                            {caseItem.severity}
                          </Badge>
                          <Badge
                            variant="outline"
                            className={cn(
                              'capitalize',
                              statusStyles[caseItem.status]
                            )}
                          >
                            {caseItem.status.replace('-', ' ')}
                          </Badge>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="opacity-0 group-hover:opacity-100 -mr-2"
                        >
                          <MoreHorizontal className="w-4 h-4" />
                        </Button>
                      </div>
                      <p className="text-xs text-muted-foreground font-mono mb-1">
                        {caseItem.id}
                      </p>
                      <h3 className="font-medium mb-2 line-clamp-2 group-hover:text-primary transition-colors">
                        {caseItem.title}
                      </h3>
                      <p className="text-sm text-muted-foreground line-clamp-2 mb-4">
                        {caseItem.description}
                      </p>
                      <div className="flex items-center justify-between mt-auto pt-4 border-t border-border">
                        <div className="flex items-center gap-2">
                          {caseItem.assignee ? (
                            <>
                              <Avatar className="w-6 h-6">
                                <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                                  {caseItem.assignee.initials}
                                </AvatarFallback>
                              </Avatar>
                              <span className="text-xs text-muted-foreground">
                                {caseItem.assignee.name}
                              </span>
                            </>
                          ) : (
                            <>
                              <User className="w-4 h-4 text-muted-foreground" />
                              <span className="text-xs text-muted-foreground">
                                Unassigned
                              </span>
                            </>
                          )}
                        </div>
                        <div className="flex items-center gap-3 text-xs text-muted-foreground">
                          <span>{caseItem.alertCount || 0} alerts</span>
                          <span>{formatRelativeTime(caseItem.updatedAt)}</span>
                        </div>
                      </div>
                    </Card>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="space-y-2">
                {filteredCases.map((caseItem) => (
                  <Link key={caseItem.id} to={`/cases/${caseItem.id}`}>
                    <div className="flex items-center gap-4 p-4 rounded-lg border border-border hover:bg-card hover:border-primary/30 transition-all duration-200 group">
                      <div className="w-20">
                        <Badge variant={caseItem.severity}>
                          {caseItem.severity}
                        </Badge>
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-muted-foreground font-mono">
                          {caseItem.id}
                        </p>
                        <p className="font-medium truncate group-hover:text-primary transition-colors">
                          {caseItem.title}
                        </p>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          'capitalize',
                          statusStyles[caseItem.status]
                        )}
                      >
                        {caseItem.status.replace('-', ' ')}
                      </Badge>
                      <div className="w-32 flex items-center gap-2">
                        {caseItem.assignee ? (
                          <>
                            <Avatar className="w-6 h-6">
                              <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                                {caseItem.assignee.initials}
                              </AvatarFallback>
                            </Avatar>
                            <span className="text-sm truncate">
                              {caseItem.assignee.name}
                            </span>
                          </>
                        ) : (
                          <span className="text-sm text-muted-foreground">
                            Unassigned
                          </span>
                        )}
                      </div>
                      <div className="w-20 text-sm font-mono text-center">
                        {caseItem.alertCount || 0}
                      </div>
                      <div className="w-24 text-sm text-muted-foreground">
                        {formatRelativeTime(caseItem.updatedAt)}
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Create Case Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Plus className="w-5 h-5 text-primary" />
              Create New Case
            </DialogTitle>
            <DialogDescription>
              Create a new security incident case for investigation and tracking.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Title */}
            <div className="space-y-2">
              <Label htmlFor="title">
                Title <span className="text-threat-critical">*</span>
              </Label>
              <Input
                id="title"
                placeholder="e.g., Ransomware Incident - Finance Department"
                value={createForm.title}
                onChange={(e) => handleFormChange('title', e.target.value)}
              />
            </div>

            {/* Description */}
            <div className="space-y-2">
              <Label htmlFor="description">Description</Label>
              <Textarea
                id="description"
                placeholder="Describe the incident in detail..."
                rows={3}
                value={createForm.description}
                onChange={(e) => handleFormChange('description', e.target.value)}
              />
            </div>

            {/* Severity and Assignee */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label>Severity</Label>
                <Select
                  value={createForm.severity}
                  onValueChange={(value) => handleFormChange('severity', value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-threat-critical" />
                        Critical
                      </span>
                    </SelectItem>
                    <SelectItem value="high">
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-threat-high" />
                        High
                      </span>
                    </SelectItem>
                    <SelectItem value="medium">
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-threat-medium" />
                        Medium
                      </span>
                    </SelectItem>
                    <SelectItem value="low">
                      <span className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-threat-low" />
                        Low
                      </span>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label>Assignee</Label>
                <Select
                  value={createForm.assignee || "unassigned"}
                  onValueChange={(value) => handleFormChange('assignee', value === "unassigned" ? "" : value)}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select assignee" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="unassigned">
                      <span className="text-muted-foreground">Unassigned</span>
                    </SelectItem>
                    {availableAssignees.map((assignee) => (
                      <SelectItem key={assignee.name} value={assignee.name}>
                        <span className="flex items-center gap-2">
                          <Avatar className="w-5 h-5">
                            <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                              {assignee.initials}
                            </AvatarFallback>
                          </Avatar>
                          {assignee.name}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Tags */}
            <div className="space-y-2">
              <Label htmlFor="tags">Tags</Label>
              <Input
                id="tags"
                placeholder="ransomware, finance, priority (comma separated)"
                value={createForm.tags}
                onChange={(e) => handleFormChange('tags', e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Separate multiple tags with commas
              </p>
            </div>

            {/* Link Alerts Section */}
            <div className="space-y-2">
              <Label className="flex items-center justify-between">
                <span>Link Alerts</span>
                {createForm.linkedAlerts.length > 0 && (
                  <Badge variant="secondary" className="ml-2">
                    {createForm.linkedAlerts.length} selected
                  </Badge>
                )}
              </Label>
              <div className="border rounded-lg max-h-[200px] overflow-y-auto">
                {availableAlerts.length === 0 ? (
                  <div className="p-4 text-center text-sm text-muted-foreground">
                    No alerts available
                  </div>
                ) : (
                  availableAlerts.map((alert) => (
                    <div
                      key={alert.id}
                      className={cn(
                        "flex items-center gap-3 p-3 border-b last:border-b-0 cursor-pointer hover:bg-muted/50 transition-colors",
                        createForm.linkedAlerts.includes(alert.id) && "bg-primary/5"
                      )}
                      onClick={() => toggleAlertSelection(alert.id)}
                    >
                      <input
                        type="checkbox"
                        checked={createForm.linkedAlerts.includes(alert.id)}
                        onChange={() => toggleAlertSelection(alert.id)}
                        className="rounded border-border"
                        onClick={(e) => e.stopPropagation()}
                      />
                      <Badge variant={alert.severity} className="shrink-0">
                        {alert.severity.toUpperCase()}
                      </Badge>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{alert.title}</p>
                        <p className="text-xs text-muted-foreground">{alert.id}</p>
                      </div>
                      <span className="text-xs text-muted-foreground shrink-0">
                        {formatRelativeTime(alert.timestamp)}
                      </span>
                    </div>
                  ))
                )}
              </div>
              <p className="text-xs text-muted-foreground">
                Select alerts to link with this case
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setCreateForm(initialFormState);
                setIsCreateDialogOpen(false);
              }}
              disabled={isCreating}
            >
              Cancel
            </Button>
            <Button onClick={handleCreateCase} disabled={isCreating}>
              {isCreating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Creating...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4 mr-2" />
                  Create Case
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
