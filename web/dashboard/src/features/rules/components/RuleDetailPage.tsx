import { useParams, useNavigate } from 'react-router-dom';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  ArrowLeft,
  ExternalLink,
  Clock,
  User,
  Tag,
  AlertTriangle,
  Code2,
  Shield,
  Calendar,
  Hash,
  BookOpen,
  Link2,
  Trash2,
  Edit3,
  Play,
  Copy,
  Download,
  ToggleLeft,
  ToggleRight,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import { useRules } from '../hooks/useRules';
import { RuleEditor } from './RuleEditor';
import { RuleTestPanel } from './RuleTestPanel';
import { SEVERITY_COLORS, STATUS_STYLES } from '../types';
import type { SigmaRule } from '../types';
import { useEffect, useState } from 'react';

export function RuleDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('overview');

  const {
    filteredRules,
    selectedRule,
    setSelectedRule,
    updateRule,
    toggleRuleEnabled,
    deleteRule,
    testRule,
  } = useRules();

  // Find and set the rule based on URL parameter
  useEffect(() => {
    if (id && filteredRules.length > 0) {
      const rule = filteredRules.find(r => r.id === id);
      if (rule) {
        setSelectedRule(rule);
      }
    }
  }, [id, filteredRules, setSelectedRule]);

  const rule = selectedRule;

  if (!rule) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-200px)]">
        <div className="text-center">
          <Shield className="w-16 h-16 mx-auto text-muted-foreground/50 mb-4" />
          <h2 className="text-xl font-semibold mb-2">Rule not found</h2>
          <p className="text-muted-foreground mb-4">The rule you're looking for doesn't exist.</p>
          <Button onClick={() => navigate('/rules')}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Rules
          </Button>
        </div>
      </div>
    );
  }

  const severityBadgeVariant = (
    severity: SigmaRule['severity']
  ): 'critical' | 'high' | 'medium' | 'low' | 'info' => {
    if (severity === 'informational') return 'info';
    return severity;
  };

  const handleDelete = () => {
    if (confirm('Are you sure you want to delete this rule?')) {
      deleteRule(rule.id);
      navigate('/rules');
    }
  };

  const handleCopyYaml = () => {
    navigator.clipboard.writeText(rule.rawYaml);
  };

  const handleSaveRule = (ruleId: string, updates: Partial<SigmaRule>) => {
    updateRule(ruleId, updates);
  };

  return (
    <div className="h-[calc(100vh-140px)] flex flex-col animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between pb-4 shrink-0">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/rules')}>
            <ArrowLeft className="w-5 h-5" />
          </Button>
          <div>
            <div className="flex items-center gap-2 mb-1">
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
              <Badge
                variant="outline"
                className={cn('capitalize', STATUS_STYLES[rule.status])}
              >
                {rule.status}
              </Badge>
              {rule.enabled ? (
                <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500/30">
                  <ToggleRight className="w-3 h-3 mr-1" />
                  Enabled
                </Badge>
              ) : (
                <Badge variant="outline" className="bg-muted text-muted-foreground">
                  <ToggleLeft className="w-3 h-3 mr-1" />
                  Disabled
                </Badge>
              )}
            </div>
            <h1 className="text-2xl font-display font-bold tracking-tight">
              {rule.title}
            </h1>
            <p className="text-muted-foreground mt-1">
              {rule.description}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => toggleRuleEnabled(rule.id)}
          >
            {rule.enabled ? (
              <>
                <ToggleLeft className="w-4 h-4 mr-2" />
                Disable
              </>
            ) : (
              <>
                <ToggleRight className="w-4 h-4 mr-2" />
                Enable
              </>
            )}
          </Button>
          <Button variant="outline" size="sm" onClick={handleCopyYaml}>
            <Copy className="w-4 h-4 mr-2" />
            Copy YAML
          </Button>
          <Button variant="destructive" size="sm" onClick={handleDelete}>
            <Trash2 className="w-4 h-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
        <TabsList className="shrink-0">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="editor">Edit Rule</TabsTrigger>
          <TabsTrigger value="test">Test</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="flex-1 overflow-auto mt-4">
          <div className="grid grid-cols-3 gap-6">
            {/* Left Column - Main Info */}
            <div className="col-span-2 space-y-6">
              {/* Metadata Card */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Hash className="w-4 h-4" />
                    Rule Information
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-muted-foreground">ID:</span>
                      <span className="font-mono bg-muted px-2 py-0.5 rounded">{rule.id}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <span className="text-muted-foreground">Version:</span>
                      <span className="font-mono">v{rule.version}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <User className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">Author:</span>
                      <span>{rule.author}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <Calendar className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">Created:</span>
                      <span>{formatRelativeTime(rule.createdAt)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <Clock className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">Updated:</span>
                      <span>{formatRelativeTime(rule.updatedAt)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">Triggers:</span>
                      <span className="font-mono">{rule.triggerCount.toLocaleString()}</span>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Log Sources */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Code2 className="w-4 h-4" />
                    Log Sources
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-3">
                    {rule.logsources.category && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="text-muted-foreground">Category:</span>
                        <Badge variant="outline">{rule.logsources.category}</Badge>
                      </div>
                    )}
                    {rule.logsources.product && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="text-muted-foreground">Product:</span>
                        <Badge variant="outline">{rule.logsources.product}</Badge>
                      </div>
                    )}
                    {rule.logsources.service && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="text-muted-foreground">Service:</span>
                        <Badge variant="outline">{rule.logsources.service}</Badge>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Detection Logic */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Code2 className="w-4 h-4" />
                    Detection Logic (YAML)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="p-4 rounded-lg bg-muted/30 border border-border">
                    <pre className="text-sm font-mono text-muted-foreground whitespace-pre-wrap overflow-x-auto max-h-[400px]">
                      {rule.rawYaml}
                    </pre>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Right Column - ATT&CK, Tags, References */}
            <div className="space-y-6">
              {/* ATT&CK Mapping */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    MITRE ATT&CK
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                      Tactics
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {rule.attack.tactics.map((tactic) => (
                        <Badge
                          key={tactic.id}
                          variant="outline"
                          className="bg-primary/10 border-primary/30 text-primary"
                        >
                          {tactic.id}: {tactic.name}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <Separator />
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                      Techniques
                    </p>
                    <div className="flex flex-wrap gap-2">
                      {rule.attack.techniques.map((technique) => (
                        <a
                          key={technique.id}
                          href={`https://attack.mitre.org/techniques/${technique.id}${
                            technique.subtechnique ? `/${technique.subtechnique}` : ''
                          }/`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Badge
                            variant="outline"
                            className="bg-neon-cyan/10 border-neon-cyan/30 text-neon-cyan hover:bg-neon-cyan/20 transition-colors"
                          >
                            {technique.id}
                            {technique.subtechnique && `.${technique.subtechnique}`}
                            <ExternalLink className="w-3 h-3 ml-1" />
                          </Badge>
                        </a>
                      ))}
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Tags */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Tag className="w-4 h-4" />
                    Tags
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {rule.tags.map((tag) => (
                      <Badge key={tag} variant="outline" className="text-xs">
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* References */}
              {rule.references.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base flex items-center gap-2">
                      <BookOpen className="w-4 h-4" />
                      References
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {rule.references.map((ref, index) => (
                        <a
                          key={index}
                          href={ref}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
                        >
                          <Link2 className="w-4 h-4 shrink-0" />
                          <span className="truncate">{ref}</span>
                          <ExternalLink className="w-3 h-3 shrink-0" />
                        </a>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="editor" className="flex-1 mt-4">
          <RuleEditor
            rule={rule}
            onSave={handleSaveRule}
            className="h-full"
          />
        </TabsContent>

        <TabsContent value="test" className="flex-1 mt-4">
          <RuleTestPanel
            rule={rule}
            onTest={testRule}
          />
        </TabsContent>

        <TabsContent value="history" className="flex-1 mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Rule Change History</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">
                Change history tracking coming soon...
              </p>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
