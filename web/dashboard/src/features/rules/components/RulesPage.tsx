import { useState, useCallback } from 'react';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from '@/components/ui/resizable';
import {
  FileCode2,
  Grid3x3,
  Download,
  Shield,
} from 'lucide-react';
import { RuleList } from './RuleList';
import { RuleEditor } from './RuleEditor';
import { RuleDetail } from './RuleDetail';
import { AttackMatrix } from './AttackMatrix';
import { RuleTestPanel } from './RuleTestPanel';
import { RuleImport } from './RuleImport';
import { RuleCreateDialog } from './RuleCreateDialog';
import { useRules, useAttackMatrix } from '../hooks/useRules';
import type { SigmaRule } from '../types';

export function RulesPage() {
  const {
    filteredRules,
    selectedRule,
    setSelectedRule,
    filters,
    setFilters,
    updateRule,
    toggleRuleEnabled,
    deleteRule,
    createRule,
    testRule,
  } = useRules();

  const {
    matrixData,
    selectedTechnique,
    setSelectedTechnique,
  } = useAttackMatrix();

  const [activeTab, setActiveTab] = useState<'list' | 'matrix'>('list');
  const [showDetailSheet, setShowDetailSheet] = useState(false);
  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // Handle rule selection
  const handleSelectRule = useCallback((rule: SigmaRule) => {
    setSelectedRule(rule);
    setShowDetailSheet(true);
  }, [setSelectedRule]);

  // Handle technique click from matrix
  const handleTechniqueClick = useCallback((techniqueId: string | null) => {
    setSelectedTechnique(techniqueId);
    if (techniqueId) {
      // Filter rules by technique
      // The useRules hook would need to be extended for this
    }
  }, [setSelectedTechnique]);

  // Handle rule save
  const handleSaveRule = useCallback((ruleId: string, updates: Partial<SigmaRule>) => {
    updateRule(ruleId, updates);
  }, [updateRule]);

  // Handle import
  const handleImport = useCallback((rules: { id: string; title: string }[]) => {
    console.log('Importing rules:', rules);
    // Would create new rules here
  }, []);

  // Handle create
  const handleCreate = useCallback((ruleData: Partial<SigmaRule>) => {
    const newRule = createRule(ruleData);
    setSelectedRule(newRule);
    setShowCreateDialog(false);
  }, [createRule, setSelectedRule]);

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between pb-4 shrink-0">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Detection Rules
          </h1>
          <p className="text-muted-foreground">
            Manage Sigma rules and MITRE ATT&CK mappings
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowImportDialog(true)}
          >
            <Download className="w-4 h-4 mr-2" />
            Import Rules
          </Button>
        </div>
      </div>

      {/* Main content area */}
      <div className="flex-1 min-h-0 flex flex-col gap-4">
        {/* ATT&CK Matrix (collapsible) */}
        <AttackMatrix
          matrixData={matrixData}
          onTechniqueClick={handleTechniqueClick}
          selectedTechnique={selectedTechnique}
        />

        {/* Rules and Editor split view */}
        <ResizablePanelGroup direction="horizontal" className="flex-1 min-h-0">
          {/* Rules List Panel */}
          <ResizablePanel defaultSize={50} minSize={30}>
            <RuleList
              rules={filteredRules}
              selectedRule={selectedRule}
              onSelectRule={handleSelectRule}
              onToggleEnabled={toggleRuleEnabled}
              filters={filters}
              onFiltersChange={setFilters}
              onCreateRule={() => setShowCreateDialog(true)}
            />
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Editor Panel */}
          <ResizablePanel defaultSize={50} minSize={30}>
            <div className="h-full flex flex-col gap-4">
              <RuleEditor
                rule={selectedRule}
                onSave={handleSaveRule}
                className="flex-1 min-h-0"
              />
              <RuleTestPanel
                rule={selectedRule}
                onTest={testRule}
              />
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {/* Rule Detail Sheet */}
      <RuleDetail
        rule={selectedRule}
        open={showDetailSheet}
        onOpenChange={setShowDetailSheet}
        onEdit={() => setShowDetailSheet(false)}
        onDelete={(ruleId) => {
          deleteRule(ruleId);
          setShowDetailSheet(false);
        }}
      />

      {/* Import Dialog */}
      <RuleImport
        open={showImportDialog}
        onOpenChange={setShowImportDialog}
        onImport={handleImport}
      />

      {/* Create Dialog */}
      <RuleCreateDialog
        open={showCreateDialog}
        onOpenChange={setShowCreateDialog}
        onCreate={handleCreate}
      />
    </div>
  );
}
