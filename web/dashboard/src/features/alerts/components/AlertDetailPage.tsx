import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  ArrowLeft,
  ExternalLink,
  Play,
  CheckCircle,
  XCircle,
  FolderPlus,
  Clock,
  Target,
  Server,
  FileText,
  Bot,
  Sparkles,
  Loader2,
  AlertTriangle,
  Shield,
  Activity,
  Hash,
  User,
  Globe,
} from 'lucide-react';
import { formatTimestamp, cn } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { Message } from '@/features/copilot/components/MessageBubble';
import { useToast } from '@/components/ui/toaster';
import { useUEBAStore, ANOMALY_TYPES, UEBA_TO_MITRE } from '@/features/ueba';

interface AlertData {
  id: string;
  alert_id: string;
  event_id: string;
  tenant_id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  source: string;
  source_type: string;
  target: string;
  timestamp: string;
  updated_at: string;
  fields: Record<string, any>;
  matched_fields: Record<string, any>;
  raw_log: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
}

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: string;
  enabled: boolean;
}

interface RelatedAlert {
  id: string;
  title: string;
  severity: string;
  status: string;
  timestamp: string;
}

// MITRE ATT&CK Tactics data with descriptions
const MITRE_TACTICS_DATA: Record<string, { name: string; description: string }> = {
  TA0001: { name: 'Initial Access', description: 'The adversary is trying to get into your network.' },
  TA0002: { name: 'Execution', description: 'The adversary is trying to run malicious code.' },
  TA0003: { name: 'Persistence', description: 'The adversary is trying to maintain their foothold.' },
  TA0004: { name: 'Privilege Escalation', description: 'The adversary is trying to gain higher-level permissions.' },
  TA0005: { name: 'Defense Evasion', description: 'The adversary is trying to avoid being detected.' },
  TA0006: { name: 'Credential Access', description: 'The adversary is trying to steal account names and passwords.' },
  TA0007: { name: 'Discovery', description: 'The adversary is trying to figure out your environment.' },
  TA0008: { name: 'Lateral Movement', description: 'The adversary is trying to move through your environment.' },
  TA0009: { name: 'Collection', description: 'The adversary is trying to gather data of interest.' },
  TA0010: { name: 'Exfiltration', description: 'The adversary is trying to steal data.' },
  TA0011: { name: 'Command and Control', description: 'The adversary is trying to communicate with compromised systems.' },
  TA0040: { name: 'Impact', description: 'The adversary is trying to manipulate, interrupt, or destroy systems and data.' },
};

// Keep legacy mapping for backwards compatibility
const MITRE_TACTICS: Record<string, string> = Object.fromEntries(
  Object.entries(MITRE_TACTICS_DATA).map(([id, data]) => [id, data.name])
);

// MITRE ATT&CK Techniques data
const MITRE_TECHNIQUES: Record<string, { name: string; tactic: string; description: string; detection: string }> = {
  T1078: { name: 'Valid Accounts', tactic: 'TA0001', description: 'Adversaries may obtain and abuse credentials of existing accounts to gain Initial Access, Persistence, Privilege Escalation, or Defense Evasion.', detection: 'Monitor authentication logs for unusual login patterns, impossible travel, or access from unexpected locations.' },
  T1071: { name: 'Application Layer Protocol', tactic: 'TA0011', description: 'Adversaries may communicate using application layer protocols to avoid detection by blending in with existing traffic.', detection: 'Analyze network traffic for anomalous protocol usage, unusual payload sizes, or suspicious destinations.' },
  T1573: { name: 'Encrypted Channel', tactic: 'TA0011', description: 'Adversaries may employ encryption to conceal command and control traffic.', detection: 'Monitor for encrypted traffic to unusual destinations or with abnormal TLS certificate characteristics.' },
  T1110: { name: 'Brute Force', tactic: 'TA0006', description: 'Adversaries may use brute force techniques to gain access to accounts when passwords are unknown.', detection: 'Monitor for multiple failed authentication attempts, account lockouts, or rapid login attempts from single sources.' },
  T1003: { name: 'OS Credential Dumping', tactic: 'TA0006', description: 'Adversaries may attempt to dump credentials to obtain account login information.', detection: 'Monitor for processes accessing LSASS, SAM database access, or use of credential dumping tools.' },
  T1486: { name: 'Data Encrypted for Impact', tactic: 'TA0040', description: 'Adversaries may encrypt data on target systems to interrupt availability.', detection: 'Monitor for unusual file encryption activity, ransomware indicators, or mass file modifications.' },
  T1490: { name: 'Inhibit System Recovery', tactic: 'TA0040', description: 'Adversaries may delete or remove built-in operating system recovery data and features.', detection: 'Monitor for deletion of shadow copies, backup catalog modifications, or recovery partition changes.' },
  T1059: { name: 'Command and Scripting Interpreter', tactic: 'TA0002', description: 'Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.', detection: 'Monitor for suspicious command-line activity, encoded commands, or unusual script execution.' },
  T1055: { name: 'Process Injection', tactic: 'TA0005', description: 'Adversaries may inject code into processes to evade defenses and elevate privileges.', detection: 'Monitor for API calls associated with process injection, unusual memory allocations, or code injection patterns.' },
  T1027: { name: 'Obfuscated Files or Information', tactic: 'TA0005', description: 'Adversaries may attempt to make files or information difficult to discover or analyze.', detection: 'Detect encoded or encrypted payloads, packed executables, or unusual file entropy levels.' },
};

// Selected MITRE item for popup
interface MITREItemDetail {
  id: string;
  type: 'tactic' | 'technique';
  name: string;
  description: string;
  detection?: string;
  tactic?: string;
}

const statusStyles: Record<string, string> = {
  new: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  acknowledged: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

export function AlertDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { toast } = useToast();

  const [alert, setAlert] = useState<AlertData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<string | null>(null);
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isPlaybookDialogOpen, setIsPlaybookDialogOpen] = useState(false);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [executionStatus, setExecutionStatus] = useState<string | null>(null);
  const [relatedAlerts, setRelatedAlerts] = useState<RelatedAlert[]>([]);

  // MITRE ATT&CK popup state
  const [selectedMITRE, setSelectedMITRE] = useState<MITREItemDetail | null>(null);
  const [isMITREDialogOpen, setIsMITREDialogOpen] = useState(false);

  // Handle MITRE technique click
  const handleTechniqueClick = (techniqueId: string) => {
    const technique = MITRE_TECHNIQUES[techniqueId];
    if (technique) {
      setSelectedMITRE({
        id: techniqueId,
        type: 'technique',
        name: technique.name,
        description: technique.description,
        detection: technique.detection,
        tactic: technique.tactic,
      });
    } else {
      setSelectedMITRE({
        id: techniqueId,
        type: 'technique',
        name: techniqueId,
        description: 'Technique details not available locally. Click "View in MITRE" for full information.',
        detection: 'See MITRE ATT&CK framework for detection guidance.',
      });
    }
    setIsMITREDialogOpen(true);
  };

  // Handle MITRE tactic click
  const handleTacticClick = (tacticId: string) => {
    const tactic = MITRE_TACTICS_DATA[tacticId];
    if (tactic) {
      setSelectedMITRE({
        id: tacticId,
        type: 'tactic',
        name: tactic.name,
        description: tactic.description,
      });
    } else {
      setSelectedMITRE({
        id: tacticId,
        type: 'tactic',
        name: tacticId,
        description: 'Tactic details not available locally. Click "View in MITRE" for full information.',
      });
    }
    setIsMITREDialogOpen(true);
  };

  // Get UEBA alerts from store
  const uebaAlerts = useUEBAStore((state) => state.alerts);

  // Fetch alert data
  useEffect(() => {
    const fetchAlert = async () => {
      if (!id) return;

      setLoading(true);
      setError(null);

      // Check if this is a UEBA alert (ID starts with "UEBA-")
      if (id.startsWith('UEBA-')) {
        // Find alert in UEBA store
        const uebaAlert = uebaAlerts.find((a) => a.id === id);
        if (uebaAlert) {
          // Convert UEBA alert to AlertData format
          const tacticId = UEBA_TO_MITRE[uebaAlert.anomalyType];
          const convertedAlert: AlertData = {
            id: uebaAlert.id,
            alert_id: uebaAlert.id,
            event_id: `evt-${uebaAlert.id}`,
            tenant_id: 'default',
            rule_id: `rule-ueba-${uebaAlert.anomalyType}`,
            rule_name: `UEBA - ${ANOMALY_TYPES[uebaAlert.anomalyType] || uebaAlert.anomalyType}`,
            title: uebaAlert.title,
            description: uebaAlert.explanation,
            severity: uebaAlert.severity,
            status: uebaAlert.status,
            source: 'UEBA',
            source_type: 'ML/UEBA',
            target: uebaAlert.entityId,
            timestamp: uebaAlert.detectedAt,
            updated_at: uebaAlert.detectedAt,
            fields: {
              entityId: uebaAlert.entityId,
              entityType: uebaAlert.entityType,
              anomalyType: uebaAlert.anomalyType,
              anomalyScore: uebaAlert.score,
              anomalyTypeName: ANOMALY_TYPES[uebaAlert.anomalyType] || uebaAlert.anomalyType,
            },
            matched_fields: {
              entity: uebaAlert.entityId,
              type: uebaAlert.entityType,
              score: `${(uebaAlert.score * 100).toFixed(0)}%`,
            },
            raw_log: JSON.stringify({
              source: 'UEBA',
              entity_id: uebaAlert.entityId,
              entity_type: uebaAlert.entityType,
              anomaly_type: uebaAlert.anomalyType,
              anomaly_score: uebaAlert.score,
              explanation: uebaAlert.explanation,
              detected_at: uebaAlert.detectedAt,
            }, null, 2),
            mitre_tactics: tacticId ? [tacticId] : [],
            mitre_techniques: [],
          };
          setAlert(convertedAlert);
          setLoading(false);
          return;
        } else {
          setError('UEBA Alert not found');
          setLoading(false);
          return;
        }
      }

      // For non-UEBA alerts, try API
      try {
        const response = await fetch(`/api/v1/alerts/${id}`);
        if (!response.ok) {
          throw new Error(`Alert not found (${response.status})`);
        }
        const data = await response.json();
        if (data.success && data.alert) {
          setAlert(data.alert);
        } else {
          throw new Error('Invalid response format');
        }
      } catch (err) {
        console.error('Failed to fetch alert:', err);
        setError(err instanceof Error ? err.message : 'Failed to fetch alert');
      } finally {
        setLoading(false);
      }
    };

    fetchAlert();
  }, [id, uebaAlerts]);

  // Fetch related alerts
  useEffect(() => {
    const fetchRelatedAlerts = async () => {
      if (!id) return;

      try {
        const response = await fetch(`/api/v1/alerts/${id}/related`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data?.alerts) {
            setRelatedAlerts(data.data.alerts);
          }
        }
      } catch (error) {
        console.warn('Failed to fetch related alerts:', error);
      }
    };

    fetchRelatedAlerts();
  }, [id]);

  const handleAcknowledge = async () => {
    if (!alert) return;
    setIsLoading('acknowledge');
    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'acknowledged' }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.alert) {
          setAlert(data.alert);
          toast({
            title: 'Alert Acknowledged',
            description: `Alert ${alert.id} has been acknowledged.`,
          });
        }
      }
    } catch (error) {
      console.error('Failed to acknowledge:', error);
      toast({
        title: 'Error',
        description: 'Failed to acknowledge alert.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  const handleClose = async () => {
    if (!alert) return;
    setIsLoading('close');
    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: 'closed' }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.alert) {
          setAlert(data.alert);
          toast({
            title: 'Alert Closed',
            description: `Alert ${alert.id} has been closed.`,
          });
        }
      }
    } catch (error) {
      console.error('Failed to close:', error);
      toast({
        title: 'Error',
        description: 'Failed to close alert.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  const handleCreateCase = async () => {
    if (!alert) return;
    setIsLoading('case');
    try {
      const response = await fetch('/api/v1/cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: `Case: ${alert.title}`,
          description: `Alert ${alert.id}: ${alert.description || alert.rule_name}`,
          priority: alert.severity,
          alert_ids: [alert.id],
        }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success && data.case) {
          toast({
            title: 'Case Created',
            description: `Case ${data.case.id} has been created.`,
          });
          // Navigate to case
          navigate(`/cases/${data.case.id}`);
        }
      }
    } catch (error) {
      console.error('Failed to create case:', error);
      toast({
        title: 'Error',
        description: 'Failed to create case.',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  const handleRunPlaybook = async () => {
    try {
      const response = await fetch('/api/v1/playbooks');
      const data = await response.json();
      setPlaybooks(data.playbooks || []);
      setIsPlaybookDialogOpen(true);
      setExecutionStatus(null);
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
      toast({
        title: 'Error',
        description: 'Failed to fetch playbooks.',
        variant: 'destructive',
      });
    }
  };

  const executePlaybook = async (playbook: Playbook) => {
    if (!alert) return;
    setExecutionStatus('running');
    try {
      const response = await fetch(`/api/v1/playbooks/run/${playbook.id}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ alert_id: alert.id }),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setExecutionStatus('completed');
          toast({
            title: 'Playbook Executed',
            description: `${playbook.name} completed successfully.`,
          });
        }
      } else {
        setExecutionStatus('failed');
      }
    } catch (error) {
      setExecutionStatus('failed');
      console.error('Failed to execute playbook:', error);
    }
  };

  // Copilot configuration - mockMode enabled for demo without backend
  const copilotConfig: CopilotConfig = {
    apiEndpoint: '/api',
    wsEndpoint: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
    language: 'auto',
    streamingEnabled: false,
    mockMode: true,
  };

  const getInitialMessages = (): Message[] => {
    if (!alert) return [];
    return [
      {
        id: 'system-welcome',
        role: 'assistant',
        content: [
          {
            type: 'text',
            content:
              `I'm analyzing alert **${alert.id}**: "${alert.title}"\n\n` +
              `**Severity:** ${alert.severity.toUpperCase()}\n` +
              `**Status:** ${alert.status}\n` +
              `**Source:** ${alert.source}\n` +
              `**Rule:** ${alert.rule_name}\n` +
              (alert.mitre_techniques?.length
                ? `**MITRE ATT&CK:** ${alert.mitre_techniques.join(', ')}\n`
                : '') +
              `\nHow can I help you investigate this alert?`,
          },
        ],
        timestamp: new Date(),
      },
    ];
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-[calc(100vh-200px)]">
        <Loader2 className="w-8 h-8 animate-spin text-primary" />
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="flex flex-col items-center justify-center h-[calc(100vh-200px)] space-y-4">
        <AlertTriangle className="w-16 h-16 text-threat-high" />
        <h2 className="text-xl font-semibold">Alert Not Found</h2>
        <p className="text-muted-foreground">{error || 'The requested alert could not be found.'}</p>
        <Button onClick={() => navigate('/alerts')}>
          <ArrowLeft className="w-4 h-4 mr-2" />
          Back to Alerts
        </Button>
      </div>
    );
  }

  const tacticName = alert.mitre_tactics?.[0]
    ? MITRE_TACTICS[alert.mitre_tactics[0]] || alert.mitre_tactics[0]
    : undefined;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="icon" onClick={() => navigate('/alerts')}>
            <ArrowLeft className="w-5 h-5" />
          </Button>
          <div>
            <p className="text-sm text-muted-foreground font-mono">{alert.id}</p>
            <h1 className="text-2xl font-display font-bold tracking-tight">{alert.title}</h1>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
          <Badge variant="outline" className={cn('capitalize', statusStyles[alert.status])}>
            {alert.status}
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="col-span-2 space-y-6">
          {/* Overview Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Alert Overview
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Description */}
              <div>
                <h4 className="text-sm font-medium mb-2">Description</h4>
                <p className="text-sm text-muted-foreground">
                  {alert.description || `Alert triggered by rule: ${alert.rule_name}`}
                </p>
              </div>

              <Separator />

              {/* Details Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Clock className="w-4 h-4" />
                    <span className="text-xs">Detected</span>
                  </div>
                  <p className="text-sm font-mono">{formatTimestamp(new Date(alert.timestamp))}</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Server className="w-4 h-4" />
                    <span className="text-xs">Source</span>
                  </div>
                  <p className="text-sm">{alert.source}</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Activity className="w-4 h-4" />
                    <span className="text-xs">Source Type</span>
                  </div>
                  <p className="text-sm">{alert.source_type}</p>
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <Hash className="w-4 h-4" />
                    <span className="text-xs">Rule ID</span>
                  </div>
                  <p className="text-sm font-mono">{alert.rule_id}</p>
                </div>
              </div>

              {/* MITRE ATT&CK */}
              {(alert.mitre_tactics?.length > 0 || alert.mitre_techniques?.length > 0) && (
                <>
                  <Separator />
                  <div>
                    <div className="flex items-center justify-between mb-3">
                      <h4 className="text-sm font-medium flex items-center gap-2">
                        <FileText className="w-4 h-4" />
                        MITRE ATT&CK Mapping
                      </h4>
                      <a
                        href="https://attack.mitre.org/"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-muted-foreground hover:text-primary transition-colors"
                      >
                        View Framework →
                      </a>
                    </div>
                    <div className="space-y-3">
                      {/* Tactics */}
                      {alert.mitre_tactics?.length > 0 && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-2">Tactics</p>
                          <div className="flex flex-wrap gap-2">
                            {alert.mitre_tactics.map((tactic) => {
                              const tacticData = MITRE_TACTICS_DATA[tactic];
                              return (
                                <button
                                  key={tactic}
                                  onClick={() => handleTacticClick(tactic)}
                                  className="inline-flex items-center px-2 py-1 rounded-md bg-neon-pink/10 text-neon-pink border border-neon-pink/30 text-xs font-mono hover:bg-neon-pink/20 transition-colors cursor-pointer"
                                  title={tacticData?.name || tactic}
                                >
                                  {tactic}
                                  {tacticData && (
                                    <span className="ml-1 text-neon-pink/70">({tacticData.name})</span>
                                  )}
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      )}
                      {/* Techniques */}
                      {alert.mitre_techniques?.length > 0 && (
                        <div>
                          <p className="text-xs text-muted-foreground mb-2">Techniques</p>
                          <div className="flex flex-wrap gap-2">
                            {alert.mitre_techniques.map((technique) => {
                              const techData = MITRE_TECHNIQUES[technique];
                              return (
                                <button
                                  key={technique}
                                  onClick={() => handleTechniqueClick(technique)}
                                  className="inline-flex items-center px-2 py-1 rounded-md bg-primary/10 text-primary border border-primary/30 text-xs font-mono hover:bg-primary/20 transition-colors cursor-pointer"
                                  title={techData?.name || technique}
                                >
                                  {technique}
                                  {techData && (
                                    <span className="ml-1 text-primary/70">({techData.name})</span>
                                  )}
                                </button>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Fields Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5" />
                Event Details
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium mb-2">Extracted Fields</h4>
                  {alert.fields && Object.keys(alert.fields).length > 0 ? (
                    <div className="bg-muted/30 rounded-lg p-4 font-mono text-sm">
                      <pre className="whitespace-pre-wrap overflow-x-auto">
                        {JSON.stringify(alert.fields, null, 2)}
                      </pre>
                    </div>
                  ) : (
                    <div className="bg-muted/30 rounded-lg p-4 text-sm text-muted-foreground flex items-center gap-2">
                      <Activity className="w-4 h-4" />
                      <span>No extracted fields available for this alert</span>
                    </div>
                  )}
                </div>

                {alert.matched_fields && Object.keys(alert.matched_fields).length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Matched Fields</h4>
                    <div className="bg-threat-high/10 rounded-lg p-4 font-mono text-sm border border-threat-high/30">
                      <pre className="whitespace-pre-wrap overflow-x-auto">
                        {JSON.stringify(alert.matched_fields, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                {alert.raw_log && alert.raw_log.trim() !== '' && (
                  <div>
                    <h4 className="text-sm font-medium mb-2">Raw Log</h4>
                    <div className="bg-muted/30 rounded-lg p-4 font-mono text-xs">
                      <pre className="whitespace-pre-wrap overflow-x-auto break-all">
                        {alert.raw_log}
                      </pre>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-start"
                  onClick={handleAcknowledge}
                  disabled={isLoading === 'acknowledge' || alert.status === 'acknowledged' || alert.status === 'closed'}
                >
                  {isLoading === 'acknowledge' ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <CheckCircle className="w-4 h-4 mr-2 text-neon-green" />
                  )}
                  Acknowledge
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-start"
                  onClick={handleClose}
                  disabled={isLoading === 'close' || alert.status === 'closed'}
                >
                  {isLoading === 'close' ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <XCircle className="w-4 h-4 mr-2 text-threat-critical" />
                  )}
                  Close
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-start"
                  onClick={handleCreateCase}
                  disabled={isLoading === 'case'}
                >
                  {isLoading === 'case' ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <FolderPlus className="w-4 h-4 mr-2 text-primary" />
                  )}
                  Create Case
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="justify-start"
                  onClick={handleRunPlaybook}
                >
                  <Play className="w-4 h-4 mr-2 text-neon-orange" />
                  Run Playbook
                </Button>
              </div>

              <Separator />

              <Button
                className="w-full bg-gradient-to-r from-[#7B61FF] to-[#00A4A6] hover:from-[#8B71FF] hover:to-[#10B4B6] text-white"
                size="sm"
                onClick={() => setIsAIAssistantOpen(true)}
              >
                <Bot className="w-4 h-4 mr-2" />
                <span>AI Assistant</span>
                <Sparkles className="w-3 h-3 ml-2 animate-pulse" />
              </Button>
            </CardContent>
          </Card>

          {/* Related Alerts */}
          {relatedAlerts.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Related Alerts</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {relatedAlerts.map((related) => (
                    <div
                      key={related.id}
                      className="flex items-center justify-between p-2 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer"
                      onClick={() => navigate(`/alerts/${related.id}`)}
                    >
                      <div className="min-w-0">
                        <p className="text-xs text-muted-foreground font-mono truncate">
                          {related.id}
                        </p>
                        <p className="text-sm truncate">{related.title}</p>
                      </div>
                      <Badge variant={related.severity as any} className="text-2xs shrink-0 ml-2">
                        {related.severity}
                      </Badge>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      {/* AI Assistant Dialog */}
      <Dialog open={isAIAssistantOpen} onOpenChange={setIsAIAssistantOpen}>
        <DialogContent className="max-w-2xl h-[80vh] p-0 gap-0 flex flex-col">
          <DialogHeader className="px-6 py-4 border-b border-border shrink-0">
            <DialogTitle className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-[#7B61FF]" />
              AI Assistant - {alert.id}
              <Sparkles className="w-4 h-4 text-[#00A4A6] animate-pulse" />
            </DialogTitle>
          </DialogHeader>
          <div className="flex-1 overflow-hidden min-h-0">
            <CopilotChat
              config={copilotConfig}
              initialMessages={getInitialMessages()}
              contextData={{
                alertId: alert.id,
                alertTitle: alert.title,
                severity: alert.severity,
                status: alert.status,
                source: alert.source,
                fields: alert.fields,
                mitreTactics: alert.mitre_tactics,
                mitreTechniques: alert.mitre_techniques,
              }}
              className="h-full border-0 rounded-none"
            />
          </div>
        </DialogContent>
      </Dialog>

      {/* Playbook Selection Dialog */}
      <Dialog open={isPlaybookDialogOpen} onOpenChange={setIsPlaybookDialogOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Play className="w-5 h-5 text-neon-orange" />
              Select Playbook to Run
            </DialogTitle>
          </DialogHeader>
          <ScrollArea className="max-h-[400px]">
            <div className="space-y-2 pr-4">
              {playbooks.map((pb) => (
                <div
                  key={pb.id}
                  className={cn(
                    'p-3 border rounded-lg cursor-pointer transition-colors',
                    'hover:bg-muted/50 hover:border-primary/50',
                    !pb.enabled && 'opacity-50 cursor-not-allowed'
                  )}
                  onClick={() => pb.enabled && executePlaybook(pb)}
                >
                  <div className="flex justify-between items-start">
                    <span className="font-medium">{pb.name}</span>
                    <Badge variant="outline" className="text-2xs">
                      {pb.category}
                    </Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mt-1">{pb.description}</p>
                </div>
              ))}
            </div>
          </ScrollArea>
          {executionStatus && (
            <div
              className={cn(
                'mt-4 p-3 rounded-lg',
                executionStatus === 'running' && 'bg-neon-blue/10 border border-neon-blue/30',
                executionStatus === 'completed' && 'bg-neon-green/10 border border-neon-green/30',
                executionStatus === 'failed' && 'bg-threat-critical/10 border border-threat-critical/30'
              )}
            >
              <div className="flex items-center gap-2">
                {executionStatus === 'running' && (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin text-neon-blue" />
                    <span className="text-sm">Playbook executing...</span>
                  </>
                )}
                {executionStatus === 'completed' && (
                  <>
                    <CheckCircle className="w-4 h-4 text-neon-green" />
                    <span className="text-sm">Playbook completed successfully</span>
                  </>
                )}
                {executionStatus === 'failed' && (
                  <>
                    <XCircle className="w-4 h-4 text-threat-critical" />
                    <span className="text-sm">Playbook execution failed</span>
                  </>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {/* MITRE ATT&CK Detail Dialog */}
      <Dialog open={isMITREDialogOpen} onOpenChange={setIsMITREDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <FileText className="w-5 h-5 text-neon-pink" />
              {selectedMITRE?.type === 'tactic' ? 'Tactic Details' : 'Technique Details'}
            </DialogTitle>
          </DialogHeader>
          {selectedMITRE && (
            <div className="space-y-4">
              {/* ID and Name */}
              <div className="flex items-center gap-3">
                <Badge
                  variant="outline"
                  className={cn(
                    "font-mono text-sm px-3 py-1",
                    selectedMITRE.type === 'tactic'
                      ? "bg-neon-pink/10 text-neon-pink border-neon-pink/30"
                      : "bg-primary/10 text-primary border-primary/30"
                  )}
                >
                  {selectedMITRE.id}
                </Badge>
                <span className="font-semibold text-lg">{selectedMITRE.name}</span>
              </div>

              {/* Tactic category for techniques */}
              {selectedMITRE.type === 'technique' && selectedMITRE.tactic && (
                <div className="flex items-center gap-2 text-sm">
                  <span className="text-muted-foreground">Tactic:</span>
                  <Badge variant="outline" className="bg-neon-pink/10 text-neon-pink border-neon-pink/30 text-xs">
                    {MITRE_TACTICS_DATA[selectedMITRE.tactic]?.name || selectedMITRE.tactic}
                  </Badge>
                </div>
              )}

              {/* Description */}
              <div>
                <h4 className="text-sm font-medium mb-2 text-muted-foreground">Description</h4>
                <p className="text-sm leading-relaxed">{selectedMITRE.description}</p>
              </div>

              {/* Detection Methods (for techniques only) */}
              {selectedMITRE.type === 'technique' && selectedMITRE.detection && (
                <div>
                  <h4 className="text-sm font-medium mb-2 text-muted-foreground flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Detection Methods
                  </h4>
                  <div className="bg-muted/30 rounded-lg p-3 border border-border">
                    <p className="text-sm leading-relaxed">{selectedMITRE.detection}</p>
                  </div>
                </div>
              )}

              {/* View in MITRE Link */}
              <div className="pt-2 border-t border-border">
                <a
                  href={
                    selectedMITRE.type === 'tactic'
                      ? `https://attack.mitre.org/tactics/${selectedMITRE.id}/`
                      : `https://attack.mitre.org/techniques/${selectedMITRE.id}/`
                  }
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 text-sm text-primary hover:underline"
                >
                  <Globe className="w-4 h-4" />
                  View in MITRE ATT&CK Framework
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
