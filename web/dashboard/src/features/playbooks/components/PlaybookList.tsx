import { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
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
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
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
  Edit2,
  Copy,
  Trash2,
  Pause,
  LayoutGrid,
  List,
  Building2,
  Code2,
  Hash,
  ToggleLeft,
  Braces,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { toast } from '@/components/ui/toaster';
import { useOrganizationVariables } from '../stores/organizationVariablesStore';
import type { PlaybookVariable, VariableType } from './VariablePanel';
import { listPlaybooksWithDefinitions, deletePlaybook as deletePlaybookApi, updatePlaybook, savePlaybook } from '../services/playbookApi';
import type { PlaybookData } from '../services/playbookApi';

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

// Note: Mock data removed - using only real data from localStorage

const categories = [
  'All',
  'Containment',
  'Investigation',
  'Enrichment',
  'Response',
  'Hunting',
  'Custom',
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

// ─────────────────────────────────────────────
// OrganizationVariablesDialog
// ─────────────────────────────────────────────

function getTypeIcon(type: VariableType) {
  switch (type) {
    case 'string':  return <Code2 className="w-3 h-3" />;
    case 'number':  return <Hash className="w-3 h-3" />;
    case 'boolean': return <ToggleLeft className="w-3 h-3" />;
    case 'array':   return <List className="w-3 h-3" />;
    case 'object':  return <Braces className="w-3 h-3" />;
  }
}

const EMPTY_VAR: Omit<PlaybookVariable, 'id'> = {
  name: '',
  type: 'string',
  scope: 'organization',
  value: '',
  description: '',
};

function OrganizationVariablesDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const { variables, addVariable, updateVariable, deleteVariable } = useOrganizationVariables();

  const [search, setSearch] = useState('');
  const [mode, setMode] = useState<'list' | 'add' | 'edit'>('list');
  const [editingVar, setEditingVar] = useState<PlaybookVariable | null>(null);
  const [formVar, setFormVar] = useState<Omit<PlaybookVariable, 'id'>>(EMPTY_VAR);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  const filtered = variables.filter(
    (v) =>
      v.name.toLowerCase().includes(search.toLowerCase()) ||
      (v.description ?? '').toLowerCase().includes(search.toLowerCase())
  );

  const openAdd = () => {
    setFormVar(EMPTY_VAR);
    setMode('add');
  };

  const openEdit = (v: PlaybookVariable) => {
    setEditingVar(v);
    setFormVar({ name: v.name, type: v.type, scope: 'organization', value: v.value, description: v.description ?? '' });
    setMode('edit');
  };

  const cancelForm = () => {
    setMode('list');
    setEditingVar(null);
  };

  const handleSave = () => {
    if (!formVar.name.trim()) return;
    if (mode === 'add') {
      addVariable(formVar);
    } else if (mode === 'edit' && editingVar) {
      updateVariable(editingVar.id, { ...formVar });
    }
    cancelForm();
  };

  const handleDelete = (id: string) => {
    deleteVariable(id);
    setConfirmDeleteId(null);
  };

  const ValueField = ({
    value,
    type,
    onChange,
  }: {
    value: unknown;
    type: VariableType;
    onChange: (v: unknown) => void;
  }) => {
    if (type === 'boolean') {
      return (
        <Select value={String(value)} onValueChange={onChange}>
          <SelectTrigger><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="true">true</SelectItem>
            <SelectItem value="false">false</SelectItem>
          </SelectContent>
        </Select>
      );
    }
    if (type === 'array' || type === 'object') {
      return (
        <Textarea
          placeholder={type === 'array' ? '["item1", "item2"]' : '{"key": "value"}'}
          value={typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
          onChange={(e) => onChange(e.target.value)}
          className="font-mono text-sm"
          rows={4}
        />
      );
    }
    return (
      <Input
        type={type === 'number' ? 'number' : 'text'}
        placeholder="Enter value..."
        value={String(value ?? '')}
        onChange={(e) => onChange(e.target.value)}
      />
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Building2 className="w-5 h-5 text-teal-500" />
            Organization Variables
          </DialogTitle>
        </DialogHeader>

        {mode === 'list' && (
          <>
            {/* Search + Add row */}
            <div className="flex items-center gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  placeholder="Search variables..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Button size="sm" onClick={openAdd}>
                <Plus className="w-4 h-4 mr-1" />
                Add
              </Button>
            </div>

            {/* Variable list */}
            <ScrollArea className="h-[360px] -mx-1 px-1">
              {filtered.length === 0 ? (
                <div className="py-12 text-center text-sm text-muted-foreground">
                  {search ? `No variables match "${search}"` : 'No organization variables defined'}
                </div>
              ) : (
                <div className="space-y-2">
                  {filtered.map((v) => (
                    <div
                      key={v.id}
                      className="p-3 rounded-lg border border-teal-500/20 bg-teal-500/5 hover:bg-teal-500/10 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="min-w-0">
                          <p className="font-mono text-sm font-semibold truncate">{v.name}</p>
                          <div className="flex items-center gap-1.5 mt-1">
                            <Badge variant="secondary" className="text-2xs capitalize">
                              {getTypeIcon(v.type)}
                              <span className="ml-1">{v.type}</span>
                            </Badge>
                            <span className="text-xs text-muted-foreground truncate">
                              {String(v.value ?? '')}
                            </span>
                          </div>
                          {v.description && (
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-1">
                              {v.description}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center gap-1 shrink-0">
                          {confirmDeleteId === v.id ? (
                            <>
                              <Button
                                size="sm"
                                variant="destructive"
                                className="h-7 text-xs px-2"
                                onClick={() => handleDelete(v.id)}
                              >
                                Confirm
                              </Button>
                              <Button
                                size="sm"
                                variant="outline"
                                className="h-7 text-xs px-2"
                                onClick={() => setConfirmDeleteId(null)}
                              >
                                Cancel
                              </Button>
                            </>
                          ) : (
                            <>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="h-7 w-7"
                                onClick={() => openEdit(v)}
                                title="Edit"
                              >
                                <Edit2 className="w-3.5 h-3.5" />
                              </Button>
                              <Button
                                size="icon"
                                variant="ghost"
                                className="h-7 w-7 hover:text-destructive"
                                onClick={() => setConfirmDeleteId(v.id)}
                                title="Delete"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </Button>
                            </>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>

            <DialogFooter className="flex items-center justify-between gap-2">
              <p className="text-xs text-muted-foreground">
                These variables are available in all playbooks
              </p>
              <Button variant="outline" onClick={() => onOpenChange(false)}>
                Close
              </Button>
            </DialogFooter>
          </>
        )}

        {(mode === 'add' || mode === 'edit') && (
          <>
            <div className="space-y-4 py-2">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  placeholder="variable_name"
                  value={formVar.name}
                  onChange={(e) => setFormVar({ ...formVar, name: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select
                    value={formVar.type}
                    onValueChange={(t: VariableType) =>
                      setFormVar({ ...formVar, type: t, value: '' })
                    }
                  >
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="string">String</SelectItem>
                      <SelectItem value="number">Number</SelectItem>
                      <SelectItem value="boolean">Boolean</SelectItem>
                      <SelectItem value="array">Array</SelectItem>
                      <SelectItem value="object">Object</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Description (optional)</Label>
                  <Input
                    placeholder="Variable description..."
                    value={String(formVar.description ?? '')}
                    onChange={(e) => setFormVar({ ...formVar, description: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Value</Label>
                <ValueField
                  value={formVar.value}
                  type={formVar.type}
                  onChange={(v) => setFormVar({ ...formVar, value: v })}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={cancelForm}>
                Cancel
              </Button>
              <Button onClick={handleSave} disabled={!formVar.name.trim()}>
                {mode === 'add' ? 'Add Variable' : 'Save Changes'}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

// ─────────────────────────────────────────────
// PlaybookList
// ─────────────────────────────────────────────

export function PlaybookList() {
  const navigate = useNavigate();
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('all');
  const [viewMode, setViewMode] = useState<'card' | 'list'>('card');
  const [savedPlaybooks, setSavedPlaybooks] = useState<Playbook[]>([]);
  const [refreshTrigger, setRefreshTrigger] = useState(0);
  const [orgVarsOpen, setOrgVarsOpen] = useState(false);

  // Load saved playbooks from API (with localStorage fallback)
  useEffect(() => {
    const loadPlaybooks = async () => {
      try {
        // First, try to load from API
        const apiPlaybooks = await listPlaybooksWithDefinitions();

        if (apiPlaybooks.length > 0) {
          const converted: Playbook[] = apiPlaybooks.map((pb: PlaybookData) => ({
            id: pb.id,
            name: pb.name || pb.display_name || 'Untitled Playbook',
            description: pb.description || 'No description',
            category: pb.category || 'Custom',
            status: (pb.enabled ? 'active' : 'draft') as 'active' | 'inactive' | 'draft',
            triggers: [pb.trigger_type || 'Manual'],
            steps: pb.definition?.nodes?.length || 0,
            lastRun: undefined,
            executions: 0,
            successRate: 0,
          }));
          setSavedPlaybooks(converted);
          return;
        }
      } catch (error) {
        console.warn('Failed to load playbooks from API, falling back to localStorage:', error);
      }

      // Fallback to localStorage
      const saved: Playbook[] = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key?.startsWith('playbook-')) {
          try {
            const data = localStorage.getItem(key);
            if (data) {
              const parsed = JSON.parse(data);
              saved.push({
                id: parsed.id,
                name: parsed.name || 'Untitled Playbook',
                description: parsed.description || 'No description',
                category: parsed.category || 'Custom',
                status: parsed.status || 'draft',
                triggers: parsed.triggers || ['Manual'],
                steps: parsed.nodes?.length || 0,
                lastRun: parsed.lastRun ? new Date(parsed.lastRun) : undefined,
                executions: parsed.executions || 0,
                successRate: parsed.successRate || 0,
              });
            }
          } catch (e) {
            console.error('Failed to parse saved playbook:', key, e);
          }
        }
      }
      setSavedPlaybooks(saved);
    };

    loadPlaybooks();

    // Listen for storage changes (for cross-tab sync within same browser)
    const handleStorageChange = () => {
      loadPlaybooks();
    };
    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, [refreshTrigger]);

  // Handler: Edit playbook
  const handleEdit = useCallback((playbookId: string) => {
    navigate(`/playbooks/${playbookId}`);
  }, [navigate]);

  // Handler: Duplicate playbook
  const handleDuplicate = useCallback(async (playbook: Playbook) => {
    const newId = `PB-${Date.now()}`;
    const key = `playbook-${playbook.id}`;
    const existingData = localStorage.getItem(key);

    let duplicatedData: Record<string, unknown>;

    if (existingData) {
      // Duplicate from saved playbook
      const data = JSON.parse(existingData);
      duplicatedData = {
        ...data,
        id: newId,
        name: `${data.name} (Copy)`,
        status: 'draft',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    } else {
      // Duplicate from playbook in state
      duplicatedData = {
        id: newId,
        name: `${playbook.name} (Copy)`,
        description: playbook.description,
        category: playbook.category,
        status: 'draft',
        triggers: playbook.triggers,
        nodes: [],
        edges: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    }

    // Save to API
    try {
      await savePlaybook({
        id: newId,
        name: duplicatedData.name as string,
        display_name: duplicatedData.name as string,
        description: duplicatedData.description as string || '',
        category: duplicatedData.category as string || 'Custom',
        status: 'DRAFT',
        trigger_type: (duplicatedData.triggers as string[])?.[0] || 'manual',
        enabled: false,
        tags: [],
        nodes: (duplicatedData.nodes as unknown[]) || [],
        edges: (duplicatedData.edges as unknown[]) || [],
        variables: (duplicatedData.variables as unknown[]) || [],
      });
      toast({
        title: 'Playbook Duplicated',
        description: 'The playbook has been duplicated successfully.',
      });
    } catch (error) {
      console.warn('Failed to save duplicate to API:', error);
    }

    // Also save to localStorage as cache
    const newKey = `playbook-${newId}`;
    localStorage.setItem(newKey, JSON.stringify(duplicatedData));

    setRefreshTrigger(prev => prev + 1);
  }, []);

  // Handler: Toggle playbook status (Activate/Pause)
  const handleToggleStatus = useCallback(async (playbook: Playbook) => {
    const key = `playbook-${playbook.id}`;
    const existingData = localStorage.getItem(key);
    const newStatus = playbook.status === 'active' ? 'inactive' : 'active';
    const isEnabled = newStatus === 'active';

    let data: Record<string, unknown>;

    if (existingData) {
      data = JSON.parse(existingData);
      data.status = newStatus;
      data.updatedAt = new Date().toISOString();
    } else {
      // Create entry for playbook
      data = {
        id: playbook.id,
        name: playbook.name,
        description: playbook.description,
        category: playbook.category,
        status: newStatus,
        triggers: playbook.triggers,
        nodes: [],
        edges: [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
    }

    // Update via API
    try {
      await updatePlaybook(playbook.id, {
        name: data.name as string,
        display_name: data.name as string,
        description: data.description as string || '',
        category: data.category as string || 'Custom',
        status: newStatus.toUpperCase(),
        trigger_type: (data.triggers as string[])?.[0] || 'manual',
        enabled: isEnabled,
        tags: [],
        nodes: (data.nodes as unknown[]) || [],
        edges: (data.edges as unknown[]) || [],
        variables: (data.variables as unknown[]) || [],
      });
      toast({
        title: isEnabled ? 'Playbook Activated' : 'Playbook Paused',
        description: `The playbook has been ${isEnabled ? 'activated' : 'paused'}.`,
      });
    } catch (error) {
      console.warn('Failed to update status via API:', error);
    }

    // Also update localStorage as cache
    localStorage.setItem(key, JSON.stringify(data));

    setRefreshTrigger(prev => prev + 1);
  }, []);

  // Handler: Delete playbook
  const handleDelete = useCallback(async (playbookId: string) => {
    if (window.confirm('Are you sure you want to delete this playbook?')) {
      try {
        // Delete from API
        await deletePlaybookApi(playbookId);
        toast({
          title: 'Playbook Deleted',
          description: 'The playbook has been deleted successfully.',
        });
      } catch (error) {
        console.warn('Failed to delete from API:', error);
      }
      // Also remove from localStorage
      const key = `playbook-${playbookId}`;
      localStorage.removeItem(key);
      setRefreshTrigger(prev => prev + 1);
    }
  }, []);

  // Handler: Test Run playbook - navigate to editor for input configuration and execution
  const handleRunPlaybook = useCallback((playbook: Playbook) => {
    toast({
      title: 'Test Run',
      description: `Opening "${playbook.name}" - configure inputs and run test`,
    });

    // Navigate to playbook editor with run mode flag
    // The editor will show the Test Run panel for input configuration
    navigate(`/playbooks/${playbook.id}?run=true`);
  }, [navigate]);

  // Use only real playbooks from localStorage
  const allPlaybooks = savedPlaybooks;

  const filteredPlaybooks = allPlaybooks.filter((pb) => {
    if (searchQuery && !pb.name.toLowerCase().includes(searchQuery.toLowerCase()))
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
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={() => setOrgVarsOpen(true)}
            className="border-teal-500/40 text-teal-500 hover:bg-teal-500/10 hover:border-teal-500/70"
          >
            <Building2 className="w-4 h-4 mr-2" />
            Organization Variables
          </Button>
          <Link to="/playbooks/new">
            <Button className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80 hover:from-[#00A4A6]/90 hover:to-[#00A4A6]/70 shadow-lg shadow-[#00A4A6]/20">
              <Plus className="w-4 h-4 mr-2" />
              New Playbook
            </Button>
          </Link>
        </div>
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
                <p className="text-3xl font-display font-bold mt-2">{allPlaybooks.length}</p>
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
                <p className="text-3xl font-display font-bold mt-2 text-[#5CC05C]">
                  {allPlaybooks.filter(p => p.status === 'active').length}
                </p>
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
            {/* View Mode Toggle */}
            <div className="flex items-center border border-border rounded-md overflow-hidden ml-auto">
              <Button
                variant={viewMode === 'card' ? 'secondary' : 'ghost'}
                size="sm"
                className="rounded-none h-9 px-3"
                onClick={() => setViewMode('card')}
              >
                <LayoutGrid className="w-4 h-4" />
              </Button>
              <Button
                variant={viewMode === 'list' ? 'secondary' : 'ghost'}
                size="sm"
                className="rounded-none h-9 px-3"
                onClick={() => setViewMode('list')}
              >
                <List className="w-4 h-4" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[calc(100vh-480px)]">
            {filteredPlaybooks.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-[400px] text-center">
                <Workflow className="w-16 h-16 text-muted-foreground/30 mb-4" />
                <h3 className="text-lg font-semibold text-muted-foreground mb-2">
                  No Playbooks Found
                </h3>
                <p className="text-sm text-muted-foreground/70 max-w-md mb-6">
                  {allPlaybooks.length === 0
                    ? 'Create your first playbook to automate security response workflows.'
                    : 'No playbooks match your current filters. Try adjusting your search criteria.'}
                </p>
                {allPlaybooks.length === 0 && (
                  <Link to="/playbooks/new">
                    <Button className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80">
                      <Plus className="w-4 h-4 mr-2" />
                      Create First Playbook
                    </Button>
                  </Link>
                )}
              </div>
            ) : viewMode === 'card' ? (
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
                              <DropdownMenuItem onClick={() => handleEdit(playbook.id)}>
                                <Edit className="w-4 h-4 mr-2" />
                                Edit
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleDuplicate(playbook)}>
                                <Copy className="w-4 h-4 mr-2" />
                                Duplicate
                              </DropdownMenuItem>
                              <DropdownMenuItem onClick={() => handleToggleStatus(playbook)}>
                                <Pause className="w-4 h-4 mr-2" />
                                {playbook.status === 'active' ? 'Pause' : 'Activate'}
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                className="text-destructive"
                                onClick={() => handleDelete(playbook.id)}
                              >
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
                                handleRunPlaybook(playbook);
                              }}
                            >
                              <Play className="w-3.5 h-3.5 mr-2 group-hover/btn:text-[#5CC05C]" />
                              Test Run
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
                              className="w-full hover:border-[#5CC05C]/50 hover:bg-[#5CC05C]/5"
                              onClick={(e) => {
                                e.preventDefault();
                                handleToggleStatus(playbook);
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
            ) : (
              <div className="space-y-2">
                {/* List Header */}
                <div className="grid grid-cols-12 gap-4 px-4 py-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider border-b border-border">
                  <div className="col-span-3">Name</div>
                  <div className="col-span-2">Category</div>
                  <div className="col-span-1">Status</div>
                  <div className="col-span-1 text-center">Steps</div>
                  <div className="col-span-1 text-center">Runs</div>
                  <div className="col-span-1 text-center">Success</div>
                  <div className="col-span-2 text-right">Last Run</div>
                  <div className="col-span-1 text-right">Actions</div>
                </div>
                {/* List Items */}
                {filteredPlaybooks.map((playbook) => {
                  const statusStyle = statusConfig[playbook.status];
                  if (!statusStyle) return null;
                  return (
                    <div
                      key={playbook.id}
                      className="grid grid-cols-12 gap-4 px-4 py-3 items-center hover:bg-muted/50 rounded-lg transition-colors group"
                    >
                      <Link
                        to={`/playbooks/${playbook.id}`}
                        className="col-span-3 flex items-center gap-3"
                      >
                        <div className={cn(
                          "p-2 rounded-lg shrink-0",
                          playbook.status === 'active'
                            ? "bg-[#00A4A6]/10"
                            : "bg-muted/30"
                        )}>
                          <Workflow className={cn(
                            "w-4 h-4",
                            playbook.status === 'active' ? "text-[#00A4A6]" : "text-muted-foreground"
                          )} />
                        </div>
                        <div className="min-w-0">
                          <p className="font-medium truncate group-hover:text-primary transition-colors">
                            {playbook.name}
                          </p>
                          <p className="text-xs text-muted-foreground truncate">
                            {playbook.description}
                          </p>
                        </div>
                      </Link>
                      <div className="col-span-2">
                        <Badge variant="outline" className="text-xs font-medium border-primary/30 bg-primary/5">
                          {playbook.category}
                        </Badge>
                      </div>
                      <div className="col-span-1">
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
                      <div className="col-span-1 text-center text-sm">
                        {playbook.steps}
                      </div>
                      <div className="col-span-1 text-center text-sm">
                        {playbook.executions}
                      </div>
                      <div className="col-span-1 text-center text-sm">
                        {playbook.successRate > 0 ? (
                          <span className="text-[#5CC05C] font-medium">{playbook.successRate}%</span>
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </div>
                      <div className="col-span-2 text-right text-xs text-muted-foreground flex items-center justify-end gap-1">
                        {playbook.lastRun ? (
                          <>
                            <Clock className="w-3 h-3" />
                            {formatRelativeTime(playbook.lastRun)}
                          </>
                        ) : (
                          <span>Never</span>
                        )}
                      </div>
                      <div className="col-span-1 flex justify-end">
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
                            <DropdownMenuItem onClick={() => handleEdit(playbook.id)}>
                              <Edit className="w-4 h-4 mr-2" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleDuplicate(playbook)}>
                              <Copy className="w-4 h-4 mr-2" />
                              Duplicate
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleToggleStatus(playbook)}>
                              <Pause className="w-4 h-4 mr-2" />
                              {playbook.status === 'active' ? 'Pause' : 'Activate'}
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => handleDelete(playbook.id)}
                            >
                              <Trash2 className="w-4 h-4 mr-2" />
                              Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </ScrollArea>
        </CardContent>
      </Card>
      <OrganizationVariablesDialog open={orgVarsOpen} onOpenChange={setOrgVarsOpen} />
    </div>
  );
}
