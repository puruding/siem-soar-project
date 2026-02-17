import { useState, useCallback, useEffect } from 'react';
import Editor from '@monaco-editor/react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import {
  Save,
  Undo2,
  Redo2,
  Check,
  X,
  AlertCircle,
  FileCode2,
  Copy,
  Layers,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SigmaRule, AlertAggregation } from '../types';
import { SEVERITY_COLORS } from '../types';
import { RuleAggregationEditor } from './RuleAggregationEditor';
import YAML from 'yaml';

interface RuleEditorProps {
  rule: SigmaRule | null;
  onSave: (ruleId: string, updates: Partial<SigmaRule>) => void;
  className?: string;
}

interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

export function RuleEditor({ rule, onSave, className }: RuleEditorProps) {
  const [yamlContent, setYamlContent] = useState<string>('');
  const [originalContent, setOriginalContent] = useState<string>('');
  const [validation, setValidation] = useState<ValidationResult>({
    valid: true,
    errors: [],
    warnings: [],
  });
  const [hasChanges, setHasChanges] = useState(false);
  const [activeTab, setActiveTab] = useState<'detection' | 'aggregation'>('detection');
  const [alertAggregation, setAlertAggregation] = useState<AlertAggregation | undefined>(undefined);
  const [originalAggregation, setOriginalAggregation] = useState<AlertAggregation | undefined>(undefined);

  // Update content when rule changes
  useEffect(() => {
    if (rule) {
      setYamlContent(rule.rawYaml);
      setOriginalContent(rule.rawYaml);
      setAlertAggregation(rule.alertAggregation);
      setOriginalAggregation(rule.alertAggregation);
      setHasChanges(false);
      validateYaml(rule.rawYaml);
    } else {
      setYamlContent('');
      setOriginalContent('');
      setAlertAggregation(undefined);
      setOriginalAggregation(undefined);
      setHasChanges(false);
      setValidation({ valid: true, errors: [], warnings: [] });
    }
  }, [rule]);

  // Check for aggregation changes
  const hasAggregationChanges = useCallback(() => {
    if (!originalAggregation && !alertAggregation) return false;
    if (!originalAggregation || !alertAggregation) return true;
    return JSON.stringify(originalAggregation) !== JSON.stringify(alertAggregation);
  }, [originalAggregation, alertAggregation]);

  // Handle aggregation change
  const handleAggregationChange = useCallback((newAggregation: AlertAggregation | undefined) => {
    setAlertAggregation(newAggregation);
    const aggregationChanged = JSON.stringify(newAggregation) !== JSON.stringify(originalAggregation);
    const contentChanged = yamlContent !== originalContent;
    setHasChanges(contentChanged || aggregationChanged);
  }, [originalAggregation, yamlContent, originalContent]);

  // Validate YAML content
  const validateYaml = useCallback((content: string) => {
    const errors: string[] = [];
    const warnings: string[] = [];

    try {
      const parsed = YAML.parse(content);

      // Check required fields
      if (!parsed.title) {
        errors.push('Missing required field: title');
      }
      if (!parsed.logsource) {
        errors.push('Missing required field: logsource');
      }
      if (!parsed.detection) {
        errors.push('Missing required field: detection');
      }
      if (!parsed.level) {
        warnings.push('Missing recommended field: level');
      }
      if (!parsed.status) {
        warnings.push('Missing recommended field: status');
      }

      // Check detection has condition
      if (parsed.detection && !parsed.detection.condition) {
        errors.push('Detection block missing condition');
      }

      setValidation({
        valid: errors.length === 0,
        errors,
        warnings,
      });
    } catch (e) {
      setValidation({
        valid: false,
        errors: [`YAML Syntax Error: ${(e as Error).message}`],
        warnings: [],
      });
    }
  }, []);

  // Handle editor content change
  const handleEditorChange = useCallback(
    (value: string | undefined) => {
      const newContent = value || '';
      setYamlContent(newContent);
      const contentChanged = newContent !== originalContent;
      const aggregationChanged = JSON.stringify(alertAggregation) !== JSON.stringify(originalAggregation);
      setHasChanges(contentChanged || aggregationChanged);
      validateYaml(newContent);
    },
    [originalContent, validateYaml, alertAggregation, originalAggregation]
  );

  // Handle save
  const handleSave = useCallback(() => {
    if (!rule || !validation.valid) return;

    try {
      const parsed = YAML.parse(yamlContent);

      onSave(rule.id, {
        rawYaml: yamlContent,
        title: parsed.title || rule.title,
        description: parsed.description || rule.description,
        status: parsed.status || rule.status,
        severity: parsed.level || rule.severity,
        alertAggregation: alertAggregation,
      });

      setOriginalContent(yamlContent);
      setOriginalAggregation(alertAggregation);
      setHasChanges(false);
    } catch (e) {
      console.error('Failed to save rule:', e);
    }
  }, [rule, yamlContent, validation.valid, onSave, alertAggregation]);

  // Handle undo
  const handleUndo = useCallback(() => {
    setYamlContent(originalContent);
    setAlertAggregation(originalAggregation);
    setHasChanges(false);
    validateYaml(originalContent);
  }, [originalContent, originalAggregation, validateYaml]);

  // Handle copy
  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(yamlContent);
  }, [yamlContent]);

  if (!rule) {
    return (
      <Card className={cn('flex flex-col', className)}>
        <CardContent className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center">
            <FileCode2 className="w-12 h-12 mx-auto mb-4 opacity-20" />
            <p>Select a rule to edit</p>
            <p className="text-sm">or create a new rule</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className={cn('flex flex-col', className)}>
      <CardHeader className="pb-3 shrink-0">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CardTitle className="text-base">Rule Editor</CardTitle>
            <Badge
              variant="outline"
              style={{
                borderColor: `${SEVERITY_COLORS[rule.severity]}50`,
                backgroundColor: `${SEVERITY_COLORS[rule.severity]}20`,
                color: SEVERITY_COLORS[rule.severity],
              }}
            >
              {rule.severity.toUpperCase()}
            </Badge>
            {hasChanges && (
              <Badge variant="outline" className="text-neon-orange border-neon-orange/50 bg-neon-orange/10">
                Unsaved Changes
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleUndo}
              disabled={!hasChanges}
            >
              <Undo2 className="w-4 h-4 mr-2" />
              Undo
            </Button>
            <Button variant="outline" size="sm" onClick={handleCopy}>
              <Copy className="w-4 h-4 mr-2" />
              Copy
            </Button>
            <Separator orientation="vertical" className="h-6" />
            <Select defaultValue="yaml">
              <SelectTrigger className="w-[100px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="yaml">YAML</SelectItem>
              </SelectContent>
            </Select>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={!hasChanges || !validation.valid}
            >
              <Save className="w-4 h-4 mr-2" />
              Save
            </Button>
          </div>
        </div>

        {/* Validation status */}
        <div className="flex items-center gap-4 mt-3">
          {validation.valid ? (
            <div className="flex items-center gap-1.5 text-sm text-neon-green">
              <Check className="w-4 h-4" />
              <span>Valid Sigma rule</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5 text-sm text-threat-critical">
              <X className="w-4 h-4" />
              <span>Invalid syntax</span>
            </div>
          )}
          {validation.warnings.length > 0 && (
            <div className="flex items-center gap-1.5 text-sm text-threat-medium">
              <AlertCircle className="w-4 h-4" />
              <span>{validation.warnings.length} warning(s)</span>
            </div>
          )}
        </div>
      </CardHeader>
      <CardContent className="flex-1 min-h-0 flex flex-col">
        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as 'detection' | 'aggregation')}
          className="flex-1 flex flex-col min-h-0"
        >
          <TabsList className="w-fit mb-3">
            <TabsTrigger value="detection" className="text-xs gap-1.5">
              <FileCode2 className="w-3.5 h-3.5" />
              Detection Logic
            </TabsTrigger>
            <TabsTrigger value="aggregation" className="text-xs gap-1.5">
              <Layers className="w-3.5 h-3.5" />
              Aggregation
              {alertAggregation && (
                <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                  ON
                </Badge>
              )}
            </TabsTrigger>
          </TabsList>

          <TabsContent value="detection" className="flex-1 min-h-0 flex flex-col mt-0">
            <div className="flex-1 border border-border rounded-lg overflow-hidden">
              <Editor
                height="100%"
                language="yaml"
                theme="vs-dark"
                value={yamlContent}
                onChange={handleEditorChange}
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  fontFamily: "'Roboto Mono', 'JetBrains Mono', monospace",
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  wordWrap: 'on',
                  automaticLayout: true,
                  tabSize: 2,
                  insertSpaces: true,
                  renderWhitespace: 'selection',
                  cursorBlinking: 'smooth',
                  cursorSmoothCaretAnimation: 'on',
                  smoothScrolling: true,
                  padding: { top: 12, bottom: 12 },
                }}
              />
            </div>

            {/* Error/Warning display */}
            {(validation.errors.length > 0 || validation.warnings.length > 0) && (
              <div className="mt-3 space-y-2">
                {validation.errors.map((error, i) => (
                  <div
                    key={`error-${i}`}
                    className="flex items-center gap-2 p-2 rounded-lg bg-threat-critical/10 border border-threat-critical/30 text-threat-critical text-sm"
                  >
                    <X className="w-4 h-4 shrink-0" />
                    <span>{error}</span>
                  </div>
                ))}
                {validation.warnings.map((warning, i) => (
                  <div
                    key={`warning-${i}`}
                    className="flex items-center gap-2 p-2 rounded-lg bg-threat-medium/10 border border-threat-medium/30 text-threat-medium text-sm"
                  >
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    <span>{warning}</span>
                  </div>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="aggregation" className="flex-1 min-h-0 overflow-auto mt-0">
            <RuleAggregationEditor
              value={alertAggregation}
              onChange={handleAggregationChange}
            />
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
