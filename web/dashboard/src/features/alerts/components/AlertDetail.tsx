import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  X,
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
  AlertCircle,
  CheckCircle2,
  Shield,
  Globe,
  MessageCircle,
  Send,
  User,
  Terminal,
} from 'lucide-react';
import { Input } from '@/components/ui/input';
import { formatTimestamp, cn } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { Message } from '@/features/copilot/components/MessageBubble';
import { toast } from '@/components/ui/toaster';
import { alertsApi } from '@/api/alerts';
import { playbooksApi } from '@/api/playbooks';

interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  source: string;
  target: string;
  timestamp: Date;
  tactic?: string;
  technique?: string;
  mitre_tactics?: string[];
  mitre_techniques?: string[];
}

// IOC (Indicator of Compromise) interface for TI matching
interface IOCMatch {
  id: string;
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  confidence: number;
  source: string;
  lastSeen?: string;
}

// TI (Threat Intelligence) matching result
interface TIMatchResult {
  totalSources: number;
  matchedSources: number;
  iocs: IOCMatch[];
}

// Alert comment interface
interface AlertComment {
  id: string;
  alert_id: string;
  author: string;
  content: string;
  created_at: string;
}

// Simple playbook interface for the playbook selection dialog
// This matches the Gateway API response format
interface SimplePlaybook {
  id: string;
  name: string;
  description: string;
  category: string;
  trigger_type?: string;
  enabled?: boolean;
}

interface AlertDetailProps {
  alert: Alert;
  onClose: () => void;
  onStatusChange?: (alertId: string, newStatus: string) => void;
  onAlertSelect?: (alertId: string) => void;
}

const statusStyles: Record<string, string> = {
  new: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  acknowledged: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

const categoryStyles: Record<string, string> = {
  enrichment: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  containment: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  notification: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  remediation: 'bg-neon-pink/20 text-neon-pink border-neon-pink/50',
};

// MITRE ATT&CK Tactics data
const MITRE_TACTICS: Record<string, { name: string; description: string }> = {
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

export function AlertDetail({ alert, onClose, onStatusChange, onAlertSelect }: AlertDetailProps) {
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isLoading, setIsLoading] = useState<string | null>(null);
  const [isPlaybookDialogOpen, setIsPlaybookDialogOpen] = useState(false);
  const [playbooks, setPlaybooks] = useState<SimplePlaybook[]>([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState<string | null>(null);
  const [executionStatus, setExecutionStatus] = useState<string | null>(null);
  const [currentStatus, setCurrentStatus] = useState(alert.status);

  // Update current status when alert changes
  useEffect(() => {
    setCurrentStatus(alert.status);
  }, [alert.status]);

  // TI (Threat Intelligence) matching state
  const [tiMatch, setTIMatch] = useState<TIMatchResult | null>(null);
  const [tiLoading, setTILoading] = useState(false);

  // Comments state
  const [comments, setComments] = useState<AlertComment[]>([]);
  const [commentsLoading, setCommentsLoading] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [submittingComment, setSubmittingComment] = useState(false);

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
      // Fallback for unknown techniques
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
    const tactic = MITRE_TACTICS[tacticId];
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

  // Fetch comments for the alert
  useEffect(() => {
    const fetchComments = async () => {
      setCommentsLoading(true);
      try {
        const response = await fetch(`/api/v1/alerts/${alert.id}/comments`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data?.comments) {
            setComments(data.data.comments);
          }
        }
      } catch (error) {
        console.warn('Failed to fetch comments:', error);
      } finally {
        setCommentsLoading(false);
      }
    };
    fetchComments();
  }, [alert.id]);

  // Handle adding a new comment
  const handleAddComment = async () => {
    if (!newComment.trim()) return;

    setSubmittingComment(true);
    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/comments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          author: 'SOC Analyst',
          content: newComment.trim(),
        }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.data?.comment) {
          setComments(prev => [...prev, data.data.comment]);
          setNewComment('');
          toast({
            title: 'Comment Added',
            description: 'Your comment has been added successfully.',
            variant: 'success',
          });
        }
      } else {
        throw new Error('Failed to add comment');
      }
    } catch (error) {
      console.error('Failed to add comment:', error);
      toast({
        title: 'Error',
        description: 'Failed to add comment. Please try again.',
        variant: 'destructive',
      });
    } finally {
      setSubmittingComment(false);
    }
  };

  // Fetch or generate TI matching data based on alert
  useEffect(() => {
    const fetchTIData = async () => {
      setTILoading(true);
      try {
        // Try to fetch from TI API
        const response = await fetch(`/api/v1/ti/match?alert_id=${alert.id}`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data) {
            setTIMatch(data.data);
            setTILoading(false);
            return;
          }
        }
      } catch {
        // API not available, generate mock data based on alert content
      }

      // Generate contextual TI data based on alert
      const mockIOCs: IOCMatch[] = [];

      // Extract potential IOCs from alert target
      if (alert.target) {
        // Check if target looks like an IP address
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (ipRegex.test(alert.target)) {
          mockIOCs.push({
            id: 'ioc-1',
            indicator: alert.target,
            type: 'ip',
            confidence: 85,
            source: 'VirusTotal',
            lastSeen: new Date().toISOString(),
          });
          mockIOCs.push({
            id: 'ioc-2',
            indicator: alert.target,
            type: 'ip',
            confidence: 78,
            source: 'AbuseIPDB',
            lastSeen: new Date(Date.now() - 86400000).toISOString(),
          });
        }
        // Check if target looks like a domain
        else if (alert.target.includes('.') && !alert.target.includes('@')) {
          mockIOCs.push({
            id: 'ioc-1',
            indicator: alert.target,
            type: 'domain',
            confidence: 92,
            source: 'AlienVault OTX',
            lastSeen: new Date().toISOString(),
          });
        }
      }

      // Add hash IOC for malware-related alerts
      if (alert.title.toLowerCase().includes('malware') ||
          alert.title.toLowerCase().includes('ransomware')) {
        mockIOCs.push({
          id: 'ioc-hash',
          indicator: 'a1b2c3d4e5f6789012345678901234567890abcd',
          type: 'hash',
          confidence: 95,
          source: 'VirusTotal',
          lastSeen: new Date().toISOString(),
        });
      }

      // Default IOCs if none generated
      if (mockIOCs.length === 0) {
        mockIOCs.push({
          id: 'ioc-default-1',
          indicator: '192.168.1.100',
          type: 'ip',
          confidence: 85,
          source: 'VirusTotal',
          lastSeen: new Date().toISOString(),
        });
        mockIOCs.push({
          id: 'ioc-default-2',
          indicator: '192.168.1.100',
          type: 'ip',
          confidence: 72,
          source: 'AbuseIPDB',
          lastSeen: new Date(Date.now() - 172800000).toISOString(),
        });
      }

      setTIMatch({
        totalSources: 5,
        matchedSources: mockIOCs.length > 0 ? Math.min(mockIOCs.length, 3) : 2,
        iocs: mockIOCs,
      });
      setTILoading(false);
    };

    fetchTIData();
  }, [alert.id, alert.target, alert.title]);

  // Copilot configuration - mockMode enabled for demo without backend
  const copilotConfig: CopilotConfig = {
    apiEndpoint: '/api',
    wsEndpoint: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
    language: 'auto',
    streamingEnabled: false,
    mockMode: true,
  };

  // Create initial message with alert context
  const getInitialMessages = (): Message[] => {
    // Build MITRE ATT&CK info string
    let mitreInfo = '';
    if (alert.mitre_tactics?.length || alert.mitre_techniques?.length) {
      const tactics = alert.mitre_tactics?.join(', ') || alert.tactic || 'N/A';
      const techniques = alert.mitre_techniques?.join(', ') || alert.technique || 'N/A';
      mitreInfo = `**MITRE ATT&CK:**\n  - Tactics: ${tactics}\n  - Techniques: ${techniques}\n`;
    } else if (alert.technique) {
      mitreInfo = `**MITRE ATT&CK:** ${alert.technique} (${alert.tactic})\n`;
    }

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
              `**Status:** ${currentStatus}\n` +
              `**Source:** ${alert.source}\n` +
              `**Target:** ${alert.target}\n` +
              mitreInfo +
              `\nHow can I help you investigate this alert? I can:\n` +
              `- Analyze the threat and provide context\n` +
              `- Suggest investigation steps\n` +
              `- Recommend playbooks to run\n` +
              `- Find similar historical alerts`,
          },
        ],
        timestamp: new Date(),
      },
    ];
  };

  // Alert context data for AI
  const alertContext = {
    alertId: alert.id,
    alertTitle: alert.title,
    alertDescription: alert.description,
    severity: alert.severity,
    status: currentStatus,
    source: alert.source,
    target: alert.target,
    timestamp: alert.timestamp.toISOString(),
    tactic: alert.tactic,
    technique: alert.technique,
    mitre_tactics: alert.mitre_tactics,
    mitre_techniques: alert.mitre_techniques,
  };

  // Related alerts - fetch from API with fallback
  const [relatedAlerts, setRelatedAlerts] = useState<Array<{id: string; title: string; severity: string}>>([
    { id: 'ALT-2024-003', title: 'Related network activity', severity: 'high' },
    { id: 'ALT-2024-007', title: 'Similar pattern detected', severity: 'medium' },
  ]);

  // Timeline with dynamic entries
  const [timeline, setTimeline] = useState([
    {
      time: alert.timestamp,
      event: 'Alert created',
      type: 'created',
    },
    {
      time: new Date(alert.timestamp.getTime() + 60000),
      event: 'AI triage: High priority',
      type: 'ai',
    },
    {
      time: new Date(alert.timestamp.getTime() + 120000),
      event: 'Enrichment complete',
      type: 'enriched',
    },
  ]);

  useEffect(() => {
    const fetchRelatedAlerts = async () => {
      try {
        const response = await fetch(`/api/v1/alerts/${alert.id}/related`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data?.alerts) {
            setRelatedAlerts(data.data.alerts);
          }
        }
      } catch (error) {
        console.warn('Failed to fetch related alerts, using defaults:', error);
      }
    };
    fetchRelatedAlerts();
  }, [alert.id]);

  // Add timeline entry helper
  const addTimelineEntry = (event: string, type: string) => {
    setTimeline(prev => [
      ...prev,
      {
        time: new Date(),
        event,
        type,
      },
    ]);
  };

  // Handle Acknowledge action
  const handleAcknowledge = async () => {
    if (currentStatus === 'acknowledged') return;

    setIsLoading('acknowledge');
    try {
      const response = await alertsApi.acknowledgeAlert(alert.id);

      if (response.success) {
        setCurrentStatus('acknowledged');
        onStatusChange?.(alert.id, 'acknowledged');
        addTimelineEntry('Alert acknowledged', 'action');
        toast({
          title: 'Alert Acknowledged',
          description: `Alert ${alert.id} has been acknowledged`,
          variant: 'success',
        });
      } else {
        throw new Error(response.error?.message || 'Failed to acknowledge alert');
      }
    } catch (error) {
      console.error('Failed to acknowledge:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to acknowledge alert',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  // Handle Close action
  const handleClose = async () => {
    if (currentStatus === 'closed') return;

    setIsLoading('close');
    try {
      const response = await alertsApi.closeAlert(alert.id);

      if (response.success) {
        setCurrentStatus('closed');
        onStatusChange?.(alert.id, 'closed');
        addTimelineEntry('Alert closed', 'action');
        toast({
          title: 'Alert Closed',
          description: `Alert ${alert.id} has been closed`,
          variant: 'success',
        });
      } else {
        throw new Error(response.error?.message || 'Failed to close alert');
      }
    } catch (error) {
      console.error('Failed to close:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to close alert',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  // Handle Create Case action
  const handleCreateCase = async () => {
    setIsLoading('case');
    try {
      const response = await alertsApi.createCaseFromAlert(alert.id, `Case: ${alert.title}`);

      if (response.success && response.data) {
        addTimelineEntry(`Case ${response.data.caseId} created`, 'case');
        toast({
          title: 'Case Created',
          description: `Case ${response.data.caseId} has been created from this alert`,
          variant: 'success',
        });
      } else {
        throw new Error(response.error?.message || 'Failed to create case');
      }
    } catch (error) {
      console.error('Failed to create case:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to create case',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
    }
  };

  // Handle Run Playbook action
  const handleRunPlaybook = async () => {
    setIsLoading('playbook');
    setExecutionStatus(null);
    setSelectedPlaybook(null);

    try {
      const response = await playbooksApi.getPlaybooks();
      if (response.success && response.data?.playbooks) {
        // Map to SimplePlaybook format for the dialog
        const simplePlaybooks: SimplePlaybook[] = response.data.playbooks.map(pb => ({
          id: pb.id,
          name: pb.name,
          description: pb.description,
          category: pb.category,
        }));
        setPlaybooks(simplePlaybooks);
      } else {
        throw new Error(response.error?.message || 'Failed to load playbooks');
      }
    } catch (error) {
      console.error('Failed to fetch playbooks:', error);
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to load playbooks',
        variant: 'destructive',
      });
    } finally {
      setIsLoading(null);
      setIsPlaybookDialogOpen(true);
    }
  };

  // Execute selected playbook
  const executePlaybook = async (playbook: SimplePlaybook) => {
    setSelectedPlaybook(playbook.id);
    setExecutionStatus('running');

    try {
      // Use alertsApi.runPlaybook for alert-triggered playbook execution
      const response = await alertsApi.runPlaybook(alert.id, playbook.id);

      if (response.success && response.data?.executionId) {
        const executionId = response.data.executionId;
        let attempts = 0;
        const maxAttempts = 10;

        const pollStatus = async () => {
          attempts++;
          try {
            const statusResponse = await playbooksApi.getExecution(executionId);
            if (statusResponse.success && statusResponse.data) {
              const execution = statusResponse.data;
              if (execution.status === 'completed') {
                setExecutionStatus('completed');
                addTimelineEntry(`Playbook "${playbook.name}" completed`, 'playbook');
                toast({
                  title: 'Playbook Completed',
                  description: `${playbook.name} executed successfully`,
                  variant: 'success',
                });
                return;
              } else if (execution.status === 'failed') {
                setExecutionStatus('failed');
                toast({
                  title: 'Playbook Failed',
                  description: 'Playbook execution failed',
                  variant: 'destructive',
                });
                return;
              }
            }

            if (attempts < maxAttempts) {
              setTimeout(pollStatus, 1000);
            } else {
              setExecutionStatus('completed');
              addTimelineEntry(`Playbook "${playbook.name}" completed`, 'playbook');
            }
          } catch {
            if (attempts < maxAttempts) {
              setTimeout(pollStatus, 1000);
            }
          }
        };

        setTimeout(pollStatus, 1000);
      } else {
        throw new Error(response.error?.message || 'Failed to execute playbook');
      }
    } catch (error) {
      console.error('Failed to execute playbook:', error);
      setExecutionStatus('failed');
      toast({
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to execute playbook',
        variant: 'destructive',
      });
    }
  };

  // Handle View Full Details
  const handleViewFullDetails = () => {
    window.open(`/alerts/${alert.id}`, '_blank');
  };

  // Handle related alert click
  const handleRelatedAlertClick = (relatedId: string) => {
    if (onAlertSelect) {
      onAlertSelect(relatedId);
    }
  };

  return (
    <Card className="w-[480px] shrink-0 flex flex-col h-[calc(100vh-180px)] sticky top-6 bg-[#1F2527]" style={{ overflow: 'hidden' }}>
      <CardHeader className="flex flex-row items-center justify-between pb-2 shrink-0 px-6">
        <div className="flex-1 min-w-0 pr-2">
          <p className="text-xs text-muted-foreground font-mono">{alert.id}</p>
          <CardTitle className="text-base mt-1 truncate">{alert.title}</CardTitle>
        </div>
        <Button variant="ghost" size="icon" className="shrink-0" onClick={onClose}>
          <X className="w-4 h-4" />
        </Button>
      </CardHeader>

      <div className="flex-1 overflow-y-auto overflow-x-hidden px-6">
        <CardContent className="space-y-6 bg-[#1F2527] p-0">
          {/* Status and severity */}
          <div className="flex items-center gap-3">
            <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
            <Badge
              variant="outline"
              className={cn('capitalize', statusStyles[currentStatus])}
            >
              {currentStatus}
            </Badge>
          </div>

          {/* Description */}
          <div className="overflow-hidden">
            <h4 className="text-sm font-medium mb-2">Description</h4>
            <p className="text-sm text-muted-foreground break-words">{alert.description}</p>
          </div>

          <Separator />

          {/* Details grid */}
          <div className="grid grid-cols-2 gap-4 overflow-hidden">
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Clock className="w-4 h-4 shrink-0" />
                <span className="text-xs">Detected</span>
              </div>
              <p className="text-sm font-mono truncate">
                {formatTimestamp(alert.timestamp)}
              </p>
            </div>
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Server className="w-4 h-4 shrink-0" />
                <span className="text-xs">Source</span>
              </div>
              <p className="text-sm truncate">{alert.source}</p>
            </div>
            <div className="space-y-1 min-w-0">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Target className="w-4 h-4 shrink-0" />
                <span className="text-xs">Target</span>
              </div>
              <p className="text-sm font-mono truncate" title={alert.target}>{alert.target}</p>
            </div>
          </div>

          {/* MITRE ATT&CK Mapping Section */}
          {((alert.mitre_tactics && alert.mitre_tactics.length > 0) ||
            (alert.mitre_techniques && alert.mitre_techniques.length > 0) ||
            alert.technique) && (
            <>
              <Separator />
              <div className="overflow-hidden">
                <div className="flex items-center justify-between mb-3 gap-2">
                  <h4 className="text-sm font-medium flex items-center gap-2 shrink-0">
                    <FileText className="w-4 h-4 text-neon-pink shrink-0" />
                    <span>MITRE ATT&CK</span>
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
                  {((alert.mitre_tactics && alert.mitre_tactics.length > 0) || alert.tactic) && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Tactics</p>
                      <div className="flex flex-wrap gap-2">
                        {alert.mitre_tactics && alert.mitre_tactics.length > 0 ? (
                          alert.mitre_tactics.map((tactic, idx) => {
                            const tacticData = MITRE_TACTICS[tactic];
                            return (
                              <button
                                key={idx}
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
                          })
                        ) : alert.tactic ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-md bg-neon-pink/10 text-neon-pink border border-neon-pink/30 text-xs font-mono">
                            {alert.tactic}
                          </span>
                        ) : null}
                      </div>
                    </div>
                  )}

                  {/* Techniques */}
                  {((alert.mitre_techniques && alert.mitre_techniques.length > 0) || alert.technique) && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Techniques</p>
                      <div className="flex flex-wrap gap-2">
                        {alert.mitre_techniques && alert.mitre_techniques.length > 0 ? (
                          alert.mitre_techniques.map((technique, idx) => {
                            const techData = MITRE_TECHNIQUES[technique];
                            return (
                              <button
                                key={idx}
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
                          })
                        ) : alert.technique ? (
                          <span className="inline-flex items-center px-2 py-1 rounded-md bg-primary/10 text-primary border border-primary/30 text-xs font-mono">
                            {alert.technique}
                          </span>
                        ) : null}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          <Separator />

          {/* TI (Threat Intelligence) Matching Section */}
          <div className="overflow-hidden">
            <div className="flex items-center justify-between mb-3 gap-2">
              <h4 className="text-sm font-medium flex items-center gap-2 shrink-0">
                <Shield className="w-4 h-4 text-neon-cyan shrink-0" />
                <span>Threat Intelligence</span>
              </h4>
              {tiLoading ? (
                <Loader2 className="w-4 h-4 animate-spin text-muted-foreground shrink-0" />
              ) : tiMatch && (
                <Badge variant="outline" className="bg-neon-cyan/10 text-neon-cyan border-neon-cyan/50 shrink-0 text-xs">
                  {tiMatch.matchedSources} matched
                </Badge>
              )}
            </div>

            {tiLoading ? (
              <div className="flex items-center justify-center py-4">
                <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                <span className="ml-2 text-sm text-muted-foreground">Checking threat intel...</span>
              </div>
            ) : tiMatch && tiMatch.iocs.length > 0 ? (
              <div className="border border-border rounded-lg overflow-hidden">
                <Table className="table-fixed w-full">
                  <TableHeader>
                    <TableRow className="bg-muted/30">
                      <TableHead className="text-xs py-2 w-[45%]">IOC</TableHead>
                      <TableHead className="text-xs py-2 w-[15%]">Type</TableHead>
                      <TableHead className="text-xs py-2 w-[20%]">Score</TableHead>
                      <TableHead className="text-xs py-2 w-[20%]">Source</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tiMatch.iocs.map((ioc) => (
                      <TableRow key={ioc.id} className="hover:bg-muted/20">
                        <TableCell className="py-2">
                          <div className="flex items-center gap-1">
                            <Globe className="w-3 h-3 text-muted-foreground shrink-0" />
                            <span className="font-mono text-xs truncate" title={ioc.indicator}>
                              {ioc.indicator}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="py-2">
                          <Badge variant="outline" className="text-2xs uppercase px-1">
                            {ioc.type}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-2">
                          <span className={cn(
                            "text-xs font-medium",
                            ioc.confidence >= 80 ? "text-threat-critical" :
                            ioc.confidence >= 60 ? "text-neon-orange" :
                            "text-neon-green"
                          )}>
                            {ioc.confidence}%
                          </span>
                        </TableCell>
                        <TableCell className="py-2">
                          <span className="text-xs text-muted-foreground truncate block">{ioc.source}</span>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <div className="text-center py-4 text-sm text-muted-foreground">
                No threat intelligence matches found
              </div>
            )}
          </div>

          <Separator />

          {/* Quick actions */}
          <div className="overflow-hidden">
            <h4 className="text-sm font-medium mb-3">Quick Actions</h4>
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant="outline"
                size="sm"
                className="justify-start overflow-hidden"
                onClick={handleAcknowledge}
                disabled={isLoading === 'acknowledge' || currentStatus === 'acknowledged' || currentStatus === 'closed'}
              >
                {isLoading === 'acknowledge' ? (
                  <Loader2 className="w-4 h-4 mr-2 shrink-0 animate-spin" />
                ) : currentStatus === 'acknowledged' ? (
                  <CheckCircle2 className="w-4 h-4 mr-2 shrink-0 text-neon-green" />
                ) : (
                  <CheckCircle className="w-4 h-4 mr-2 shrink-0 text-neon-green" />
                )}
                <span className="truncate">{currentStatus === 'acknowledged' ? 'Acknowledged' : 'Acknowledge'}</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="justify-start overflow-hidden"
                onClick={handleClose}
                disabled={isLoading === 'close' || currentStatus === 'closed'}
              >
                {isLoading === 'close' ? (
                  <Loader2 className="w-4 h-4 mr-2 shrink-0 animate-spin" />
                ) : currentStatus === 'closed' ? (
                  <CheckCircle2 className="w-4 h-4 mr-2 shrink-0 text-muted-foreground" />
                ) : (
                  <XCircle className="w-4 h-4 mr-2 shrink-0 text-threat-critical" />
                )}
                <span className="truncate">{currentStatus === 'closed' ? 'Closed' : 'Close'}</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="justify-start overflow-hidden"
                onClick={handleCreateCase}
                disabled={isLoading === 'case'}
              >
                {isLoading === 'case' ? (
                  <Loader2 className="w-4 h-4 mr-2 shrink-0 animate-spin" />
                ) : (
                  <FolderPlus className="w-4 h-4 mr-2 shrink-0 text-primary" />
                )}
                <span className="truncate">Create Case</span>
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="justify-start overflow-hidden"
                onClick={handleRunPlaybook}
                disabled={isLoading === 'playbook'}
              >
                {isLoading === 'playbook' ? (
                  <Loader2 className="w-4 h-4 mr-2 shrink-0 animate-spin" />
                ) : (
                  <Play className="w-4 h-4 mr-2 shrink-0 text-neon-orange" />
                )}
                <span className="truncate">Playbook</span>
              </Button>
            </div>

            {/* AI Assistant Section */}
            <div className="mt-4 pt-4 border-t border-border overflow-hidden">
              <Button
                className="w-full bg-gradient-to-r from-[#7B61FF] to-[#00A4A6] hover:from-[#8B71FF] hover:to-[#10B4B6] text-white overflow-hidden"
                size="sm"
                onClick={() => setIsAIAssistantOpen(true)}
              >
                <Bot className="w-4 h-4 mr-2 shrink-0" />
                <span className="truncate">AI Assistant</span>
                <Sparkles className="w-3 h-3 ml-2 shrink-0 animate-pulse" />
              </Button>
              <p className="text-2xs text-muted-foreground text-center mt-2 px-2">
                AI-powered analysis
              </p>
            </div>
          </div>

          <Separator />

          {/* Timeline */}
          <div>
            <h4 className="text-sm font-medium mb-3">Activity Timeline</h4>
            <div className="space-y-3">
              {timeline.map((event, i) => (
                <div key={i} className="flex gap-3 relative">
                  {i !== timeline.length - 1 && (
                    <div className="absolute left-1.5 top-4 bottom-0 w-px bg-border" />
                  )}
                  <div
                    className={cn(
                      'w-3 h-3 rounded-full mt-1 shrink-0',
                      event.type === 'created' && 'bg-primary',
                      event.type === 'ai' && 'bg-neon-pink',
                      event.type === 'enriched' && 'bg-neon-green',
                      event.type === 'action' && 'bg-neon-blue',
                      event.type === 'case' && 'bg-neon-cyan',
                      event.type === 'playbook' && 'bg-neon-orange'
                    )}
                  />
                  <div className="flex-1 pb-3">
                    <p className="text-sm text-foreground">{event.event}</p>
                    <p className="text-xs text-muted-foreground/80">
                      {formatTimestamp(event.time)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Related alerts */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-medium">Related Alerts</h4>
              {relatedAlerts.length > 0 && (
                <Badge variant="outline" className="text-2xs">
                  {relatedAlerts.length} found
                </Badge>
              )}
            </div>
            <div className="space-y-2">
              {relatedAlerts.length === 0 ? (
                <p className="text-sm text-muted-foreground">No related alerts found</p>
              ) : (
                relatedAlerts.map((related) => (
                  <div
                    key={related.id}
                    className="flex items-center justify-between p-2 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                    onClick={() => handleRelatedAlertClick(related.id)}
                  >
                    <div>
                      <p className="text-xs text-muted-foreground font-mono">
                        {related.id}
                      </p>
                      <p className="text-sm">{related.title}</p>
                    </div>
                    <Badge
                      variant={related.severity as 'high' | 'medium'}
                      className="text-2xs"
                    >
                      {related.severity}
                    </Badge>
                  </div>
                ))
              )}
            </div>
            {/* View in Query Console button */}
            <Button
              variant="outline"
              size="sm"
              className="w-full mt-3"
              onClick={() => {
                // Build query based on alert-specific data
                const conditions: string[] = [`alert_id = '${alert.id}'`];

                // Add target condition if available
                if (alert.target && alert.target !== 'N/A') {
                  conditions.push(`(source_ip = '${alert.target}' OR dest_ip = '${alert.target}' OR user = '${alert.target}')`);
                }

                // Add MITRE technique condition if available
                if (alert.technique) {
                  conditions.push(`mitre_technique = '${alert.technique}'`);
                }

                // Build time range around alert timestamp
                const alertTime = new Date(alert.timestamp);
                const startTime = new Date(alertTime.getTime() - 30 * 60 * 1000).toISOString(); // 30 min before
                const endTime = new Date(alertTime.getTime() + 30 * 60 * 1000).toISOString(); // 30 min after

                const query = `SELECT timestamp, source_ip, dest_ip, user, action, message
FROM events
WHERE (${conditions.join(' OR ')})
  AND timestamp BETWEEN '${startTime}' AND '${endTime}'
ORDER BY timestamp DESC
LIMIT 100`;

                // Navigate to query console with pre-filled query
                const encodedQuery = encodeURIComponent(query);
                window.location.href = `/query?q=${encodedQuery}&alert_id=${alert.id}`;
              }}
            >
              <Terminal className="w-4 h-4 mr-2" />
              View in Query Console
            </Button>
          </div>

          <Separator />

          {/* Comments Section */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <MessageCircle className="w-4 h-4 text-neon-blue" />
                Comments
              </h4>
              <Badge variant="outline" className="text-2xs">
                {comments.length}
              </Badge>
            </div>

            {/* Comment input */}
            <div className="flex gap-2 mb-3">
              <Input
                placeholder="Add a comment..."
                value={newComment}
                onChange={(e) => setNewComment(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleAddComment();
                  }
                }}
                disabled={submittingComment}
                className="text-sm"
              />
              <Button
                size="sm"
                onClick={handleAddComment}
                disabled={!newComment.trim() || submittingComment}
              >
                {submittingComment ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Send className="w-4 h-4" />
                )}
              </Button>
            </div>

            {/* Comments list */}
            <div className="space-y-3 max-h-[200px] overflow-y-auto">
              {commentsLoading ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                  <span className="ml-2 text-xs text-muted-foreground">Loading comments...</span>
                </div>
              ) : comments.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No comments yet. Be the first to comment.
                </p>
              ) : (
                comments.map((comment) => (
                  <div
                    key={comment.id}
                    className="p-3 rounded-lg bg-muted/30 border border-border/50"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <User className="w-3 h-3 text-muted-foreground" />
                      <span className="text-xs font-medium">{comment.author}</span>
                      <span className="text-2xs text-muted-foreground">
                        {formatTimestamp(new Date(comment.created_at))}
                      </span>
                    </div>
                    <p className="text-sm text-foreground">{comment.content}</p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* View full details */}
          <Button
            className="w-full"
            variant="outline"
            onClick={handleViewFullDetails}
          >
            <ExternalLink className="w-4 h-4 mr-2" />
            View Full Details
          </Button>
        </CardContent>
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
              contextData={alertContext}
              className="h-full border-0 rounded-none"
              onError={(error) => console.error('Copilot error:', error)}
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
          <div className="space-y-2 max-h-[400px] overflow-y-auto pr-2">
            {playbooks.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8">
                <AlertCircle className="w-8 h-8 text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground">No playbooks available</p>
              </div>
            ) : (
              playbooks.map((pb) => (
                <div
                  key={pb.id}
                  className={cn(
                    "p-3 border rounded-lg cursor-pointer transition-all",
                    selectedPlaybook === pb.id
                      ? "border-primary bg-primary/5"
                      : "hover:bg-muted/50 hover:border-muted-foreground/30"
                  )}
                  onClick={() => executePlaybook(pb)}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-medium text-sm">{pb.name}</span>
                    <Badge
                      variant="outline"
                      className={cn("text-2xs capitalize", categoryStyles[pb.category])}
                    >
                      {pb.category}
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{pb.description}</p>

                  {selectedPlaybook === pb.id && executionStatus && (
                    <div className="mt-2 pt-2 border-t border-border">
                      <div className="flex items-center gap-2 text-xs">
                        {executionStatus === 'running' && (
                          <>
                            <Loader2 className="w-3 h-3 animate-spin text-neon-orange" />
                            <span className="text-neon-orange">Executing...</span>
                          </>
                        )}
                        {executionStatus === 'completed' && (
                          <>
                            <CheckCircle2 className="w-3 h-3 text-neon-green" />
                            <span className="text-neon-green">Completed successfully</span>
                          </>
                        )}
                        {executionStatus === 'failed' && (
                          <>
                            <XCircle className="w-3 h-3 text-threat-critical" />
                            <span className="text-threat-critical">Execution failed</span>
                          </>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {executionStatus === 'completed' && (
            <div className="flex justify-end pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setIsPlaybookDialogOpen(false);
                  setSelectedPlaybook(null);
                  setExecutionStatus(null);
                }}
              >
                Close
              </Button>
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
                    {MITRE_TACTICS[selectedMITRE.tactic]?.name || selectedMITRE.tactic}
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
    </Card>
  );
}
