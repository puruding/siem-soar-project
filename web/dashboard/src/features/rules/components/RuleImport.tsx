import { useState, useCallback } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Progress } from '@/components/ui/progress';
import { Checkbox } from '@/components/ui/checkbox';
import {
  Download,
  Globe,
  Search,
  Loader2,
  CheckCircle2,
  AlertCircle,
  FileCode2,
  RefreshCw,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface ImportableRule {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  category: string;
  selected: boolean;
}

interface RuleImportProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImport: (rules: ImportableRule[]) => void;
}

// Mock repository rules
const mockRepositoryRules: ImportableRule[] = [
  {
    id: 'sigma-001',
    title: 'Mimikatz Command Line',
    severity: 'critical',
    category: 'credential_access',
    selected: false,
  },
  {
    id: 'sigma-002',
    title: 'Suspicious PowerShell Download',
    severity: 'high',
    category: 'execution',
    selected: false,
  },
  {
    id: 'sigma-003',
    title: 'Windows Event Log Cleared',
    severity: 'high',
    category: 'defense_evasion',
    selected: false,
  },
  {
    id: 'sigma-004',
    title: 'Scheduled Task Creation',
    severity: 'medium',
    category: 'persistence',
    selected: false,
  },
  {
    id: 'sigma-005',
    title: 'Remote Service Creation',
    severity: 'high',
    category: 'lateral_movement',
    selected: false,
  },
  {
    id: 'sigma-006',
    title: 'Suspicious Certutil Usage',
    severity: 'high',
    category: 'defense_evasion',
    selected: false,
  },
  {
    id: 'sigma-007',
    title: 'WMI Command Execution',
    severity: 'medium',
    category: 'execution',
    selected: false,
  },
  {
    id: 'sigma-008',
    title: 'LSASS Memory Dump',
    severity: 'critical',
    category: 'credential_access',
    selected: false,
  },
  {
    id: 'sigma-009',
    title: 'Suspicious DNS Query',
    severity: 'medium',
    category: 'command_and_control',
    selected: false,
  },
  {
    id: 'sigma-010',
    title: 'Pass the Hash Activity',
    severity: 'critical',
    category: 'lateral_movement',
    selected: false,
  },
];

export function RuleImport({ open, onOpenChange, onImport }: RuleImportProps) {
  const [repoUrl, setRepoUrl] = useState('https://github.com/SigmaHQ/sigma');
  const [isLoading, setIsLoading] = useState(false);
  const [isImporting, setIsImporting] = useState(false);
  const [importProgress, setImportProgress] = useState(0);
  const [rules, setRules] = useState<ImportableRule[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  // Fetch rules from repository
  const handleFetch = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    setRules([]);

    try {
      const response = await fetch('/api/rules/import/preview', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repository_url: repoUrl }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.data?.rules) {
          setRules(data.data.rules.map((r: ImportableRule) => ({ ...r, selected: false })));
        } else {
          // Fallback to mock data if API returns empty
          setRules(mockRepositoryRules);
        }
      } else {
        // Fallback to mock data on error
        console.warn('API unavailable, using mock rules');
        setRules(mockRepositoryRules);
      }
    } catch (error) {
      console.warn('Failed to fetch rules, using mock data:', error);
      setRules(mockRepositoryRules);
    } finally {
      setIsLoading(false);
    }
  }, [repoUrl]);

  // Toggle rule selection
  const toggleRule = useCallback((ruleId: string) => {
    setRules((prev) =>
      prev.map((rule) =>
        rule.id === ruleId ? { ...rule, selected: !rule.selected } : rule
      )
    );
  }, []);

  // Select/Deselect all
  const toggleAll = useCallback(() => {
    const allSelected = rules.every((r) => r.selected);
    setRules((prev) => prev.map((rule) => ({ ...rule, selected: !allSelected })));
  }, [rules]);

  // Filter rules by search
  const filteredRules = rules.filter(
    (rule) =>
      rule.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      rule.category.toLowerCase().includes(searchQuery.toLowerCase())
  );

  // Handle import
  const handleImport = useCallback(async () => {
    const selectedRules = rules.filter((r) => r.selected);
    if (selectedRules.length === 0) return;

    setIsImporting(true);
    setImportProgress(0);

    // Simulate import progress
    for (let i = 0; i <= selectedRules.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, 500));
      setImportProgress((i / selectedRules.length) * 100);
    }

    onImport(selectedRules);
    setIsImporting(false);
    setImportProgress(0);
    setRules([]);
    onOpenChange(false);
  }, [rules, onImport, onOpenChange]);

  const selectedCount = rules.filter((r) => r.selected).length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Download className="w-5 h-5" />
            Import Sigma Rules
          </DialogTitle>
          <DialogDescription>
            Import rules from Sigma repositories or paste rule URLs
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {/* Repository URL */}
          <div>
            <label className="text-sm font-medium mb-2 block">Repository URL</label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/SigmaHQ/sigma"
                  className="pl-10"
                />
              </div>
              <Button onClick={handleFetch} disabled={isLoading || !repoUrl}>
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <RefreshCw className="w-4 h-4" />
                )}
              </Button>
            </div>
          </div>

          {/* Error message */}
          {error && (
            <div className="p-3 rounded-lg bg-threat-critical/10 border border-threat-critical/30 flex items-center gap-2 text-sm text-threat-critical">
              <AlertCircle className="w-4 h-4" />
              {error}
            </div>
          )}

          {/* Rules list */}
          {rules.length > 0 && (
            <div className="space-y-3">
              {/* Search and selection controls */}
              <div className="flex items-center gap-3">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search rules..."
                    className="pl-10"
                  />
                </div>
                <Button variant="outline" size="sm" onClick={toggleAll}>
                  {rules.every((r) => r.selected) ? 'Deselect All' : 'Select All'}
                </Button>
              </div>

              {/* Rule selection list */}
              <ScrollArea className="h-[300px] border border-border rounded-lg">
                <div className="p-2 space-y-1">
                  {filteredRules.map((rule) => (
                    <div
                      key={rule.id}
                      className={cn(
                        'flex items-center gap-3 p-3 rounded-lg transition-colors cursor-pointer',
                        rule.selected
                          ? 'bg-primary/10 border border-primary/30'
                          : 'hover:bg-muted/30 border border-transparent'
                      )}
                      onClick={() => toggleRule(rule.id)}
                    >
                      <Checkbox
                        checked={rule.selected}
                        onCheckedChange={() => toggleRule(rule.id)}
                      />
                      <FileCode2 className="w-4 h-4 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <p className="font-medium text-sm truncate">{rule.title}</p>
                        <p className="text-xs text-muted-foreground">
                          {rule.category.replace(/_/g, ' ')}
                        </p>
                      </div>
                      <Badge
                        variant="outline"
                        className={cn(
                          'text-xs shrink-0',
                          rule.severity === 'critical' &&
                            'bg-threat-critical/20 text-threat-critical border-threat-critical/50',
                          rule.severity === 'high' &&
                            'bg-threat-high/20 text-threat-high border-threat-high/50',
                          rule.severity === 'medium' &&
                            'bg-threat-medium/20 text-threat-medium border-threat-medium/50',
                          rule.severity === 'low' &&
                            'bg-threat-low/20 text-threat-low border-threat-low/50'
                        )}
                      >
                        {rule.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              </ScrollArea>

              {/* Selection summary */}
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">
                  {selectedCount} of {rules.length} rules selected
                </span>
                {isImporting && (
                  <div className="flex items-center gap-2">
                    <Progress value={importProgress} className="w-32 h-2" />
                    <span className="text-xs text-muted-foreground">
                      {Math.round(importProgress)}%
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Loading state */}
          {isLoading && (
            <div className="py-12 text-center">
              <Loader2 className="w-8 h-8 mx-auto mb-3 animate-spin text-primary" />
              <p className="text-sm text-muted-foreground">
                Fetching rules from repository...
              </p>
            </div>
          )}

          {/* Empty state */}
          {!isLoading && rules.length === 0 && (
            <div className="py-12 text-center">
              <Download className="w-12 h-12 mx-auto mb-3 opacity-20" />
              <p className="text-muted-foreground">
                Enter a repository URL and click fetch to browse available rules
              </p>
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleImport}
            disabled={selectedCount === 0 || isImporting}
          >
            {isImporting ? (
              <>
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                Importing...
              </>
            ) : (
              <>
                <CheckCircle2 className="w-4 h-4 mr-2" />
                Import {selectedCount} Rule{selectedCount !== 1 ? 's' : ''}
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
