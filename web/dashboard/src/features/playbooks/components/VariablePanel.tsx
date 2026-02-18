import { useState } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
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
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogTrigger,
} from '@/components/ui/dialog';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import {
  Plus,
  Trash2,
  Edit2,
  Variable,
  Globe,
  Box,
  Play,
  Copy,
  Check,
  Search,
  Code2,
  Hash,
  ToggleLeft,
  List,
  Braces,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export type VariableType = 'string' | 'number' | 'boolean' | 'array' | 'object';
export type VariableScope = 'global' | 'node' | 'execution' | 'organization';

export interface PlaybookVariable {
  id: string;
  name: string;
  type: VariableType;
  scope: VariableScope;
  value: unknown;
  description?: string;
  nodeId?: string; // For node-scoped variables
}

interface VariablePanelProps {
  variables: PlaybookVariable[];
  onAddVariable: (variable: Omit<PlaybookVariable, 'id'>) => void;
  onUpdateVariable: (id: string, updates: Partial<PlaybookVariable>) => void;
  onDeleteVariable: (id: string) => void;
  selectedNodeId?: string; // Currently selected node ID for filtering node-scoped variables
  selectedNodeLabel?: string; // Label of the selected node for display
  className?: string;
}

// Variable management panel with edit/delete functionality
export function VariablePanel({
  variables,
  onAddVariable,
  onUpdateVariable,
  onDeleteVariable,
  selectedNodeId,
  selectedNodeLabel,
  className,
}: VariablePanelProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [isAddDialogOpen, setIsAddDialogOpen] = useState(false);
  const [editingVariable, setEditingVariable] = useState<PlaybookVariable | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // New variable form state
  const [newVariable, setNewVariable] = useState<Omit<PlaybookVariable, 'id'>>({
    name: '',
    type: 'string',
    scope: 'global',
    value: '',
    description: '',
  });

  const filteredVariables = variables.filter((v) =>
    v.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    v.description?.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Group variables by scope
  // Node variables are filtered by selectedNodeId
  const groupedVariables = {
    global: filteredVariables.filter((v) => v.scope === 'global'),
    execution: filteredVariables.filter((v) => v.scope === 'execution'),
    node: filteredVariables.filter((v) => v.scope === 'node' && (!selectedNodeId || v.nodeId === selectedNodeId)),
  };

  // Count all node variables (not filtered)
  const allNodeVariablesCount = filteredVariables.filter((v) => v.scope === 'node').length;

  const scopeInfo: Record<'global' | 'execution' | 'node', { title: string; description: string; icon: React.ReactNode; color: string }> = {
    global: {
      title: 'Global Variables',
      description: '이 플레이북 전체에서 사용 가능한 변수',
      icon: <Globe className="w-4 h-4" />,
      color: 'text-blue-500',
    },
    execution: {
      title: 'Execution Variables',
      description: '테스트 실행 시 입력값으로 제공되는 변수 (Test Run 패널에 표시)',
      icon: <Play className="w-4 h-4" />,
      color: 'text-[#9B59B6]',
    },
    node: {
      title: 'Node Variables',
      description: selectedNodeId
        ? `"${selectedNodeLabel || selectedNodeId}" 노드의 지역 변수`
        : '노드를 선택하면 해당 노드의 변수가 표시됩니다',
      icon: <Box className="w-4 h-4" />,
      color: 'text-[#F79836]',
    },
  };

  const getScopeIcon = (scope: VariableScope) => {
    switch (scope) {
      case 'global':
        return <Globe className="w-3 h-3" />;
      case 'node':
        return <Box className="w-3 h-3" />;
      case 'execution':
        return <Play className="w-3 h-3" />;
      default:
        return <Globe className="w-3 h-3" />;
    }
  };

  const getScopeColor = (scope: VariableScope) => {
    switch (scope) {
      case 'global':
        return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
      case 'node':
        return 'text-[#F79836] bg-[#F79836]/10 border-[#F79836]/30';
      case 'execution':
        return 'text-[#9B59B6] bg-[#9B59B6]/10 border-[#9B59B6]/30';
      default:
        return 'text-blue-500 bg-blue-500/10 border-blue-500/30';
    }
  };

  const getTypeIcon = (type: VariableType) => {
    switch (type) {
      case 'string':
        return <Code2 className="w-3 h-3" />;
      case 'number':
        return <Hash className="w-3 h-3" />;
      case 'boolean':
        return <ToggleLeft className="w-3 h-3" />;
      case 'array':
        return <List className="w-3 h-3" />;
      case 'object':
        return <Braces className="w-3 h-3" />;
    }
  };

  const formatValue = (value: unknown, type: VariableType): string => {
    if (value === null || value === undefined) return 'null';
    switch (type) {
      case 'string':
        return `"${value}"`;
      case 'number':
      case 'boolean':
        return String(value);
      case 'array':
      case 'object':
        return JSON.stringify(value, null, 2);
      default:
        return String(value);
    }
  };

  const handleCopyReference = (name: string, id: string) => {
    navigator.clipboard.writeText(`{{${name}}}`);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleAddVariable = () => {
    if (!newVariable.name.trim()) return;

    // Parse value based on type
    let parsedValue = newVariable.value;
    try {
      switch (newVariable.type) {
        case 'number':
          parsedValue = Number(newVariable.value);
          break;
        case 'boolean':
          parsedValue = newVariable.value === 'true';
          break;
        case 'array':
        case 'object':
          parsedValue = JSON.parse(newVariable.value as string);
          break;
      }
    } catch {
      // Keep as string if parsing fails
    }

    // If scope is 'node', include the selected node ID
    const variableToAdd = {
      ...newVariable,
      value: parsedValue,
      nodeId: newVariable.scope === 'node' ? selectedNodeId : undefined,
    };
    onAddVariable(variableToAdd);
    setNewVariable({
      name: '',
      type: 'string',
      scope: 'global',
      value: '',
      description: '',
    });
    setIsAddDialogOpen(false);
  };

  const handleUpdateVariable = () => {
    if (!editingVariable) return;

    let parsedValue = editingVariable.value;
    try {
      switch (editingVariable.type) {
        case 'number':
          parsedValue = Number(editingVariable.value);
          break;
        case 'boolean':
          parsedValue = editingVariable.value === 'true' || editingVariable.value === true;
          break;
        case 'array':
        case 'object':
          if (typeof editingVariable.value === 'string') {
            parsedValue = JSON.parse(editingVariable.value);
          }
          break;
      }
    } catch {
      // Keep as-is if parsing fails
    }

    onUpdateVariable(editingVariable.id, { ...editingVariable, value: parsedValue });
    setEditingVariable(null);
  };

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Variable className="w-4 h-4 text-primary" />
          <span className="text-sm font-semibold">Variables</span>
          <Badge variant="secondary" className="text-2xs">
            {variables.length}
          </Badge>
        </div>
        <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" variant="outline" className="h-7">
              <Plus className="w-3 h-3 mr-1" />
              Add
            </Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Add Variable</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  placeholder="variable_name"
                  value={newVariable.name}
                  onChange={(e) => setNewVariable({ ...newVariable, name: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select
                    value={newVariable.type}
                    onValueChange={(value: VariableType) =>
                      setNewVariable({ ...newVariable, type: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
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
                  <Label>Scope</Label>
                  <Select
                    value={newVariable.scope}
                    onValueChange={(value: VariableScope) =>
                      setNewVariable({ ...newVariable, scope: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="global">Global (플레이북 전체)</SelectItem>
                      <SelectItem value="node" disabled={!selectedNodeId}>
                        Node {selectedNodeId ? `(${selectedNodeLabel || selectedNodeId})` : '(노드 선택 필요)'}
                      </SelectItem>
                      <SelectItem value="execution">Execution (테스트 실행 입력)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Default Value</Label>
                {newVariable.type === 'boolean' ? (
                  <Select
                    value={String(newVariable.value)}
                    onValueChange={(value) => setNewVariable({ ...newVariable, value })}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="true">true</SelectItem>
                      <SelectItem value="false">false</SelectItem>
                    </SelectContent>
                  </Select>
                ) : newVariable.type === 'array' || newVariable.type === 'object' ? (
                  <Textarea
                    placeholder={newVariable.type === 'array' ? '["item1", "item2"]' : '{"key": "value"}'}
                    value={String(newVariable.value)}
                    onChange={(e) => setNewVariable({ ...newVariable, value: e.target.value })}
                    className="font-mono text-sm"
                    rows={4}
                  />
                ) : (
                  <Input
                    type={newVariable.type === 'number' ? 'number' : 'text'}
                    placeholder="Enter value..."
                    value={String(newVariable.value)}
                    onChange={(e) => setNewVariable({ ...newVariable, value: e.target.value })}
                  />
                )}
              </div>
              <div className="space-y-2">
                <Label>Description (optional)</Label>
                <Input
                  placeholder="Variable description..."
                  value={newVariable.description}
                  onChange={(e) => setNewVariable({ ...newVariable, description: e.target.value })}
                />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setIsAddDialogOpen(false)}>
                Cancel
              </Button>
              <Button onClick={handleAddVariable} disabled={!newVariable.name.trim()}>
                Add Variable
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      {/* Search */}
      <div className="relative mb-3">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
        <Input
          placeholder="Search variables..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-8 h-8 text-sm"
        />
      </div>

      {/* Variables List - Grouped by Scope */}
      <ScrollArea className="flex-1 -mx-2 px-2">
        <div className="space-y-4 pb-4">
          {filteredVariables.length === 0 ? (
            <div className="py-8 text-center text-sm text-muted-foreground">
              {searchQuery ? `No variables match "${searchQuery}"` : 'No variables defined'}
            </div>
          ) : (
            (['global', 'execution', 'node'] as const).map((scope) => {
              const scopeVars = groupedVariables[scope];
              const info = scopeInfo[scope];

              // For global/execution: skip if empty
              // For node: always show the section
              if (scope !== 'node' && scopeVars.length === 0) return null;
              // Skip node section if there are no node variables at all
              if (scope === 'node' && allNodeVariablesCount === 0) return null;

              return (
                <div key={scope} className="space-y-2">
                  {/* Scope Header */}
                  <div className={cn('flex items-center gap-2 py-2 px-1 border-b border-border/50', info.color)}>
                    {info.icon}
                    <div className="flex-1 min-w-0">
                      <h3 className="text-sm font-semibold">{info.title}</h3>
                      <p className="text-2xs text-muted-foreground">{info.description}</p>
                    </div>
                    <Badge variant="secondary" className="ml-auto text-2xs shrink-0">
                      {scope === 'node' ? `${scopeVars.length}/${allNodeVariablesCount}` : scopeVars.length}
                    </Badge>
                  </div>

                  {/* Node-specific messaging */}
                  {scope === 'node' && !selectedNodeId && (
                    <div className="py-4 text-center text-sm text-muted-foreground bg-muted/30 rounded-lg border border-dashed border-border/50">
                      <Box className="w-6 h-6 mx-auto mb-2 text-muted-foreground/50" />
                      캔버스에서 노드를 선택하세요
                    </div>
                  )}

                  {scope === 'node' && selectedNodeId && scopeVars.length === 0 && (
                    <div className="py-4 text-center text-sm text-muted-foreground bg-muted/30 rounded-lg border border-dashed border-border/50">
                      이 노드에 등록된 변수가 없습니다
                    </div>
                  )}

                  {/* Variables in this scope */}
                  {scopeVars.map((variable) => (
              <div
                key={variable.id}
                className="p-3 rounded-xl border border-border/50 bg-muted/20 hover:bg-muted/40 transition-colors"
              >
                {/* Header - Variable name and badges */}
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <span className="font-mono text-sm font-medium text-foreground">
                    {variable.name}
                  </span>
                  <Badge
                    variant="outline"
                    className={cn('text-2xs capitalize', getScopeColor(variable.scope))}
                    title={variable.scope === 'execution' ? 'This variable will appear as input in Test Run panel' : undefined}
                  >
                    {getScopeIcon(variable.scope)}
                    <span className="ml-1">{variable.scope}</span>
                  </Badge>
                  <Badge variant="secondary" className="text-2xs capitalize">
                    {getTypeIcon(variable.type)}
                    <span className="ml-1">{variable.type}</span>
                  </Badge>
                  {variable.scope === 'execution' && (
                    <span className="text-2xs text-purple-400" title="Appears in Test Run inputs">
                      → Input
                    </span>
                  )}
                </div>

                {/* Description */}
                {variable.description && (
                  <p className="text-2xs text-muted-foreground mb-2">
                    {variable.description}
                  </p>
                )}

                {/* Value preview */}
                <div className="p-2 rounded-lg bg-background/50 border border-border/30 mb-3">
                  <pre className="text-2xs font-mono text-muted-foreground overflow-x-auto whitespace-pre-wrap break-all max-h-16">
                    {formatValue(variable.value, variable.type)}
                  </pre>
                </div>

                {/* Action buttons - separate row */}
                <div className="flex items-center gap-2 pt-2 border-t border-border/30">
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-xs flex-1 border-border bg-background hover:bg-muted"
                    onClick={() => handleCopyReference(variable.name, variable.id)}
                    title="Copy reference {{variable_name}}"
                  >
                    {copiedId === variable.id ? (
                      <Check className="w-3.5 h-3.5 mr-1 text-[#5CC05C]" />
                    ) : (
                      <Copy className="w-3.5 h-3.5 mr-1" />
                    )}
                    Copy
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-xs flex-1 border-blue-500/50 bg-blue-500/10 text-blue-500 hover:bg-blue-500/20"
                    onClick={() => setEditingVariable(variable)}
                    title="Edit variable"
                  >
                    <Edit2 className="w-3.5 h-3.5 mr-1" />
                    Edit
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    className="h-7 px-2 text-xs flex-1 border-red-500/50 bg-red-500/10 text-red-500 hover:bg-red-500/20"
                    onClick={() => onDeleteVariable(variable.id)}
                    title="Delete variable"
                  >
                    <Trash2 className="w-3.5 h-3.5 mr-1" />
                    Delete
                  </Button>
                </div>
              </div>
            ))}
                </div>
              );
            })
          )}
        </div>
      </ScrollArea>

      {/* Edit Dialog */}
      <Dialog open={!!editingVariable} onOpenChange={(open) => !open && setEditingVariable(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Variable</DialogTitle>
          </DialogHeader>
          {editingVariable && (
            <div className="space-y-4 py-4">
              <div className="space-y-2">
                <Label>Name</Label>
                <Input
                  value={editingVariable.name}
                  onChange={(e) =>
                    setEditingVariable({ ...editingVariable, name: e.target.value })
                  }
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select
                    value={editingVariable.type}
                    onValueChange={(value: VariableType) =>
                      setEditingVariable({ ...editingVariable, type: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
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
                  <Label>Scope</Label>
                  <Select
                    value={editingVariable.scope}
                    onValueChange={(value: VariableScope) =>
                      setEditingVariable({ ...editingVariable, scope: value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="global">Global</SelectItem>
                      <SelectItem value="node">Node</SelectItem>
                      <SelectItem value="execution">Execution</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Value</Label>
                {editingVariable.type === 'boolean' ? (
                  <Select
                    value={String(editingVariable.value)}
                    onValueChange={(value) =>
                      setEditingVariable({ ...editingVariable, value })
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="true">true</SelectItem>
                      <SelectItem value="false">false</SelectItem>
                    </SelectContent>
                  </Select>
                ) : editingVariable.type === 'array' || editingVariable.type === 'object' ? (
                  <Textarea
                    value={
                      typeof editingVariable.value === 'string'
                        ? editingVariable.value
                        : JSON.stringify(editingVariable.value, null, 2)
                    }
                    onChange={(e) =>
                      setEditingVariable({ ...editingVariable, value: e.target.value })
                    }
                    className="font-mono text-sm"
                    rows={6}
                  />
                ) : (
                  <Input
                    type={editingVariable.type === 'number' ? 'number' : 'text'}
                    value={String(editingVariable.value)}
                    onChange={(e) =>
                      setEditingVariable({ ...editingVariable, value: e.target.value })
                    }
                  />
                )}
              </div>
              <div className="space-y-2">
                <Label>Description</Label>
                <Input
                  value={editingVariable.description || ''}
                  onChange={(e) =>
                    setEditingVariable({ ...editingVariable, description: e.target.value })
                  }
                />
              </div>
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditingVariable(null)}>
              Cancel
            </Button>
            <Button onClick={handleUpdateVariable}>Save Changes</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

export default VariablePanel;
