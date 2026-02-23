import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import {
  Download,
  Plus,
} from 'lucide-react';
import { RuleList } from './RuleList';
import { AttackMatrix } from './AttackMatrix';
import { RuleImport } from './RuleImport';
import { RuleCreateDialog } from './RuleCreateDialog';
import { useRules, useAttackMatrix } from '../hooks/useRules';
import type { SigmaRule } from '../types';

export function RulesPage() {
  const navigate = useNavigate();
  const {
    filteredRules,
    selectedRule,
    setSelectedRule,
    filters,
    setFilters,
    toggleRuleEnabled,
    createRule,
  } = useRules();

  const {
    matrixData,
    selectedTechnique,
    setSelectedTechnique,
  } = useAttackMatrix();

  const [showImportDialog, setShowImportDialog] = useState(false);
  const [showCreateDialog, setShowCreateDialog] = useState(false);

  // Handle technique click from matrix
  const handleTechniqueClick = useCallback((techniqueId: string | null) => {
    setSelectedTechnique(techniqueId);
  }, [setSelectedTechnique]);

  // Handle import
  const handleImport = useCallback((rules: { id: string; title: string }[]) => {
    console.log('Importing rules:', rules);
  }, []);

  // Handle create
  const handleCreate = useCallback(async (ruleData: Partial<SigmaRule>) => {
    const newRule = await createRule(ruleData);
    if (newRule) {
      navigate(`/rules/${newRule.id}`);
    }
    setShowCreateDialog(false);
  }, [createRule, navigate]);

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
          <Button
            size="sm"
            onClick={() => setShowCreateDialog(true)}
          >
            <Plus className="w-4 h-4 mr-2" />
            New Rule
          </Button>
        </div>
      </div>

      {/* Main content area */}
      <div className="flex-1 min-h-0 flex flex-col gap-4 overflow-hidden">
        {/* ATT&CK Matrix (collapsible) - fixed height */}
        <div className="shrink-0 max-h-[280px] overflow-hidden">
          <AttackMatrix
            matrixData={matrixData}
            onTechniqueClick={handleTechniqueClick}
            selectedTechnique={selectedTechnique}
          />
        </div>

        {/* Rules List - Full Width */}
        <div className="flex-1 min-h-0 overflow-hidden">
          <RuleList
            rules={filteredRules}
            onToggleEnabled={toggleRuleEnabled}
            filters={filters}
            onFiltersChange={setFilters}
            navigateToDetail={true}
          />
        </div>
      </div>

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
