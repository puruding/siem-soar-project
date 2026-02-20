import { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Input } from '@/components/ui/input';
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
  User as UserIcon,
  Globe,
  Scale,
  Timer,
  Filter,
  Layers,
  CheckCircle2,
  MessageCircle,
  Send,
  BarChart3,
  TableIcon,
  ArrowRight,
  TrendingUp,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Brain,
} from 'lucide-react';
import { formatTimestamp, cn } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { Message } from '@/features/copilot/components/MessageBubble';
import { useToast } from '@/components/ui/toaster';
import { useUEBAStore, ANOMALY_TYPES, UEBA_TO_MITRE } from '@/features/ueba';
import { GroupStatistics } from './GroupStatistics';
import {
  calculateGroupStatistics,
  formatEventTime,
  formatDurationBetween,
  formatFullTimestamp,
} from '../utils/groupStats';

interface MLModelInfo {
  model_id: string;
  model_name: string;
  model_version: string;
  model_type: string;
  model_description: string;
  training_data: string;
  last_trained: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  features_used: string[];
  confidence_boost: number;
}

interface RiskFactor {
  factor: string;
  weight: number;
  triggered: boolean;
}

interface MLAnalysis {
  anomaly_score: number | null;
  threat_category: string;
  risk_factors: RiskFactor[];
  similar_incidents: number;
  false_positive_likelihood: number;
}

interface DetectionReason {
  rule_description: string;
  rule_conditions: Record<string, any>;
  rule_threshold: number;
  rule_window_minutes: number;
  rule_aggregate_by: string[];
  rule_tags: string[];
  matched_count: number;
  classification_method: string;
  classification_confidence: number;
  ml_model?: MLModelInfo | null;
  ml_analysis?: MLAnalysis | null;
}

interface IOCMatch {
  id: string;
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
  confidence: number;
  source: string;
  lastSeen?: string;
}

interface RelatedEvent {
  id: string;
  timestamp: string;
  sourceIp?: string;
  destinationIp?: string;
  user?: string;
  action?: string;
  status?: string;
  message?: string;
}

interface ContributingFeature {
  feature: string;
  importance: number;
  value: number;
  baseline: number;
}

interface EventMLAnalysis {
  anomaly_score: number;
  is_anomalous: boolean;
  contributing_features: ContributingFeature[];
  threat_indicators: string[];
}

interface MatchedEvent {
  id: string;
  timestamp: string;
  event_type: string;
  source_ip?: string;
  dest_ip?: string;
  dest_port?: number;
  protocol?: string;
  bytes_sent?: number;
  bytes_received?: number;
  user?: string;
  action?: string;
  raw_log?: string;
  ml_analysis?: EventMLAnalysis | null;
}

interface MatchedEventsResponse {
  success: boolean;
  events: MatchedEvent[];
  total: number;
  ml_model?: MLModelInfo | null;
  analysis_summary?: {
    total_anomalous: number;
    avg_anomaly_score: number;
    top_features: string[];
  } | null;
}

interface AlertComment {
  id: string;
  alert_id: string;
  author: string;
  content: string;
  created_at: string;
}

interface TimelineEntry {
  time: Date;
  event: string;
  type: 'created' | 'ai' | 'enriched' | 'action' | 'case' | 'playbook';
}

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
  detection_reason?: DetectionReason;
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

interface AIRecommendation {
  priority: number;
  action: string;
  description: string;
  category: string;
}

interface AIInterpretation {
  summary: string;
  key_findings: string[];
  risk_assessment: string;
}

interface AIAnalysisResponse {
  success: boolean;
  alert_id: string;
  timestamp: string;
  alert_info: {
    id: string;
    title: string;
    severity: string;
    status: string;
    source: string;
    rule_name: string;
    rule_id: string;
    mitre_tactics: string[];
    mitre_techniques: string[];
    matched_count: number;
    source_ip?: string;
    target?: string;
    user?: string;
  };
  ml_classification: {
    method: string;
    confidence: number;
    model?: MLModelInfo | null;
  };
  ml_analysis: {
    anomaly_score: number;
    threat_category?: string;
    similar_incidents: number;
    false_positive_likelihood: number;
    risk_factors: RiskFactor[];
  };
  events_analysis: {
    total_events: number;
    anomalous_events: number;
    avg_anomaly_score: number;
    top_features: string[];
    threat_indicators: string[];
  };
  risk_level: string;
  risk_color: string;
  interpretation: AIInterpretation;
  recommendations: AIRecommendation[];
}

interface GroupedAlertInfo {
  isGrouped: boolean;
  eventCount: number;
  firstEventTime?: string;
  lastEventTime?: string;
  duration?: string;
  groupByFields?: string[];
  groupByValues?: Record<string, string>;
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

// Helper function to calculate duration between two timestamps
function calculateDuration(start: string, end: string): string {
  const startDate = new Date(start);
  const endDate = new Date(end);
  const diffMs = endDate.getTime() - startDate.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMins / 60);

  if (diffHours > 0) {
    return `${diffHours}h ${diffMins % 60}m`;
  }
  return `${diffMins}m`;
}

// Generate mock grouped alert data
function generateMockGroupedAlert(groupId: string): AlertData {
  const mockAlerts: Record<string, Partial<AlertData>> = {
    'GROUP-001': {
      id: 'GROUP-001',
      title: 'Multiple Failed Login Attempts',
      description: 'Grouped alerts for repeated authentication failures from same source',
      severity: 'high',
      status: 'new',
      source: 'IAM',
      source_type: 'Authentication',
      target: '192.168.1.100',
      timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(),
      mitre_tactics: ['TA0006'],
      mitre_techniques: ['T1110'],
      fields: { source_ip: '192.168.1.100', event_count: 47 },
      rule_id: 'RULE-AUTH-001',
      rule_name: 'Failed Login Detection',
      detection_reason: {
        rule_description: 'Detects multiple failed authentication attempts from same source',
        rule_conditions: { failed_auth_threshold: 5, time_window: '5m' },
        rule_threshold: 5,
        rule_window_minutes: 5,
        rule_aggregate_by: ['source.ip', 'rule.id'],
        rule_tags: ['authentication', 'brute-force'],
        matched_count: 47,
        classification_method: 'rule-based',
        classification_confidence: 0.95,
      },
    },
    'GROUP-002': {
      id: 'GROUP-002',
      title: 'Suspicious Network Scanning',
      description: 'Port scanning activity detected from internal host',
      severity: 'medium',
      status: 'new',
      source: 'NDR',
      source_type: 'Network',
      target: '10.0.0.0/24',
      timestamp: new Date(Date.now() - 15 * 60 * 1000).toISOString(),
      mitre_tactics: ['TA0007'],
      mitre_techniques: ['T1046'],
      fields: { source_ip: '192.168.1.55', event_count: 128 },
      rule_id: 'RULE-SCAN-001',
      rule_name: 'Port Scan Detection',
      detection_reason: {
        rule_description: 'Detects port scanning behavior',
        rule_conditions: { unique_ports_threshold: 10, time_window: '60m' },
        rule_threshold: 10,
        rule_window_minutes: 60,
        rule_aggregate_by: ['source.ip', 'target.network'],
        rule_tags: ['reconnaissance', 'scanning'],
        matched_count: 128,
        classification_method: 'rule-based',
        classification_confidence: 0.88,
      },
    },
    'GROUP-003': {
      id: 'GROUP-003',
      title: 'Malware Communication Pattern',
      description: 'Multiple C2 beacon attempts to same destination',
      severity: 'critical',
      status: 'new',
      source: 'EDR',
      source_type: 'Endpoint',
      target: '185.123.45.67',
      timestamp: new Date(Date.now() - 3 * 60 * 1000).toISOString(),
      mitre_tactics: ['TA0011'],
      mitre_techniques: ['T1071', 'T1573'],
      fields: { dest_ip: '185.123.45.67', process_name: 'svchost.exe', event_count: 23 },
      rule_id: 'RULE-C2-001',
      rule_name: 'C2 Beacon Detection',
      detection_reason: {
        rule_description: 'Detects command and control beacon patterns',
        rule_conditions: { beacon_interval_consistent: true, suspicious_destination: true },
        rule_threshold: 3,
        rule_window_minutes: 45,
        rule_aggregate_by: ['dest.ip', 'process.name'],
        rule_tags: ['c2', 'malware', 'exfiltration'],
        matched_count: 23,
        classification_method: 'ml-assisted',
        classification_confidence: 0.92,
      },
    },
    'GROUP-004': {
      id: 'GROUP-004',
      title: 'Data Exfiltration Attempt',
      description: 'Large data transfers to external destinations',
      severity: 'critical',
      status: 'investigating',
      source: 'DLP',
      source_type: 'Data Loss Prevention',
      target: 'external-storage.com',
      timestamp: new Date(Date.now() - 8 * 60 * 1000).toISOString(),
      mitre_tactics: ['TA0010'],
      mitre_techniques: ['T1048', 'T1567'],
      fields: { user: 'john.doe', dest_domain: 'external-storage.com', event_count: 15 },
      rule_id: 'RULE-DLP-001',
      rule_name: 'Data Exfiltration Detection',
      detection_reason: {
        rule_description: 'Detects unusual data transfer volumes',
        rule_conditions: { data_volume_mb: 500, external_destination: true },
        rule_threshold: 100,
        rule_window_minutes: 120,
        rule_aggregate_by: ['user.name', 'dest.domain'],
        rule_tags: ['exfiltration', 'dlp', 'data-loss'],
        matched_count: 15,
        classification_method: 'rule-based',
        classification_confidence: 0.90,
      },
    },
  };

  const mockData = mockAlerts[groupId] || mockAlerts['GROUP-001'];
  if (!mockData) {
    throw new Error(`Mock data not found for group ID: ${groupId}`);
  }
  return {
    ...mockData,
    id: groupId,
    alert_id: groupId,
    event_id: `evt-${groupId}`,
    tenant_id: '11111111-1111-1111-1111-111111111111',
    created_at: mockData.timestamp!,
    updated_at: mockData.timestamp!,
    raw_log: JSON.stringify(mockData, null, 2),
  } as AlertData;
}

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
  const [groupedInfo, setGroupedInfo] = useState<GroupedAlertInfo | null>(null);

  // MITRE ATT&CK popup state
  const [selectedMITRE, setSelectedMITRE] = useState<MITREItemDetail | null>(null);
  const [isMITREDialogOpen, setIsMITREDialogOpen] = useState(false);

  // Threat Intelligence state
  const [tiMatch, setTIMatch] = useState<{iocs: IOCMatch[], matchedSources: number} | null>(null);
  const [tiLoading, setTILoading] = useState(false);

  // Related Events state
  const [relatedEvents, setRelatedEvents] = useState<RelatedEvent[]>([]);
  const [eventsTab, setEventsTab] = useState('timeline');
  const [eventsLoading, setEventsLoading] = useState(false);

  // Comments state
  const [comments, setComments] = useState<AlertComment[]>([]);
  const [commentsLoading, setCommentsLoading] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [submittingComment, setSubmittingComment] = useState(false);

  // Timeline state
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);

  // Matched Events state
  const [matchedEvents, setMatchedEvents] = useState<MatchedEvent[]>([]);
  const [matchedEventsExpanded, setMatchedEventsExpanded] = useState(false);
  const [matchedEventsMLModel, setMatchedEventsMLModel] = useState<MLModelInfo | null>(null);
  const [matchedEventsAnalysis, setMatchedEventsAnalysis] = useState<{
    total_anomalous: number;
    avg_anomaly_score: number;
    top_features: string[];
  } | null>(null);

  // AI Analysis state
  const [aiAnalysis, setAiAnalysis] = useState<AIAnalysisResponse | null>(null);
  const [aiAnalysisLoading, setAiAnalysisLoading] = useState(false);
  const [aiAnalysisError, setAiAnalysisError] = useState<string | null>(null);

  // Calculate statistics from related events using useMemo
  const eventStatistics = useMemo(() => {
    return calculateGroupStatistics(relatedEvents as any);
  }, [relatedEvents]);

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

      // Check if this is a GROUP- alert (mock grouped alert)
      if (id.startsWith('GROUP-')) {
        const mockGroupedAlert = generateMockGroupedAlert(id);
        setAlert(mockGroupedAlert);
        setLoading(false);
        return;
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

  // Detect grouped alerts and populate groupedInfo
  useEffect(() => {
    if (!alert) return;

    // Check if this is a grouped alert
    const isGrouped = alert.id.startsWith('GROUP-') || (alert.fields?.event_count && alert.fields.event_count > 1);

    if (isGrouped) {
      // For GROUP- alerts, generate info
      if (alert.id.startsWith('GROUP-')) {
        const eventCount = alert.fields?.event_count || 47;
        const firstEventTime = new Date(Date.now() - 30 * 60 * 1000).toISOString();
        const lastEventTime = new Date(Date.now() - 2 * 60 * 1000).toISOString();

        setGroupedInfo({
          isGrouped: true,
          eventCount,
          firstEventTime,
          lastEventTime,
          duration: calculateDuration(firstEventTime, lastEventTime),
          groupByFields: alert.detection_reason?.rule_aggregate_by || ['source.ip', 'rule.id'],
          groupByValues: {
            'source.ip': alert.fields?.source_ip || alert.target || '192.168.1.100',
            'rule.id': alert.rule_id || 'RULE-001',
            'target.network': alert.fields?.target_network || alert.target,
            'dest.ip': alert.fields?.dest_ip || alert.target,
            'process.name': alert.fields?.process_name || 'N/A',
            'user.name': alert.fields?.user || alert.fields?.user_name || 'N/A',
            'dest.domain': alert.fields?.dest_domain || alert.target,
          },
        });
      } else {
        // Real alert with multiple events
        const eventCount = alert.fields?.event_count || 1;
        const firstEventTime = new Date(new Date(alert.timestamp).getTime() - 10 * 60 * 1000).toISOString();
        const lastEventTime = alert.timestamp;

        setGroupedInfo({
          isGrouped: true,
          eventCount,
          firstEventTime,
          lastEventTime,
          duration: calculateDuration(firstEventTime, lastEventTime),
          groupByFields: alert.detection_reason?.rule_aggregate_by || ['principal_ip'],
          groupByValues: {
            'principal_ip': alert.fields?.source_ip || alert.fields?.principal_ip || '',
          },
        });
      }
    } else {
      setGroupedInfo(null);
    }
  }, [alert]);

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

  // Fetch Threat Intelligence data from TI service
  useEffect(() => {
    const fetchTIData = async () => {
      if (!alert) return;
      setTILoading(true);

      try {
        // Extract IOCs from alert
        const iocs: string[] = [];

        // Add target if it looks like an IOC
        if (alert.target) {
          iocs.push(alert.target);
        }

        // Extract IPs from fields
        if (alert.fields?.source_ip) {
          iocs.push(alert.fields.source_ip);
        }
        if (alert.fields?.destination_ip) {
          iocs.push(alert.fields.destination_ip);
        }
        if (alert.fields?.src_ip) {
          iocs.push(alert.fields.src_ip);
        }
        if (alert.fields?.dst_ip) {
          iocs.push(alert.fields.dst_ip);
        }

        // Try to fetch from TI service match endpoint
        const response = await fetch(`/api/v1/ti/match?alert_id=${alert.id}`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data) {
            // Map the API response to our IOCMatch format
            const matchedIOCs: IOCMatch[] = (data.data.iocs || []).map((ioc: any) => ({
              id: ioc.id || `ioc-${Math.random().toString(36).substr(2, 9)}`,
              indicator: ioc.indicator,
              type: ioc.type as 'ip' | 'domain' | 'hash' | 'url' | 'email',
              confidence: ioc.confidence || 0,
              source: ioc.source || 'Unknown',
              lastSeen: new Date().toISOString(),
            }));

            // If we got results from API, also do individual lookups for extracted IOCs
            if (iocs.length > 0 && matchedIOCs.length === 0) {
              // Try individual IP lookups
              for (const indicator of iocs.slice(0, 3)) { // Limit to 3 lookups
                const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
                if (ipRegex.test(indicator)) {
                  try {
                    const ipResp = await fetch(`/api/v1/ti/lookup/ip/${indicator}`);
                    if (ipResp.ok) {
                      const ipData = await ipResp.json();
                      if (ipData.success && ipData.results) {
                        ipData.results.forEach((result: any, idx: number) => {
                          matchedIOCs.push({
                            id: `ioc-${indicator}-${idx}`,
                            indicator: indicator,
                            type: 'ip',
                            confidence: result.confidence || ipData.aggregated_score || 0,
                            source: result.source || 'Unknown',
                            lastSeen: result.last_seen || new Date().toISOString(),
                          });
                        });
                      }
                    }
                  } catch {
                    // Individual lookup failed, continue
                  }
                }
              }
            }

            setTIMatch({
              iocs: matchedIOCs,
              matchedSources: data.data.total_sources || matchedIOCs.length,
            });
            setTILoading(false);
            return;
          }
        }
      } catch (error) {
        console.warn('TI lookup failed:', error);
      }

      // Fallback: Generate contextual TI data based on alert if API fails
      const mockIOCs: IOCMatch[] = [];

      // Extract potential IOCs from alert target
      if (alert.target) {
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
        } else if (alert.target.includes('.') && !alert.target.includes('@')) {
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
        iocs: mockIOCs,
        matchedSources: mockIOCs.length > 0 ? Math.min(mockIOCs.length, 3) : 2,
      });
      setTILoading(false);
    };

    fetchTIData();
  }, [alert?.id]);

  // Fetch related events
  useEffect(() => {
    const fetchRelatedEvents = async () => {
      if (!alert) return;
      setEventsLoading(true);

      try {
        const response = await fetch(`/api/v1/alerts/${alert.id}/events`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data?.events) {
            setRelatedEvents(data.data.events);
            setEventsLoading(false);
            return;
          }
        }
      } catch {
        // API not available, generate mock data
      }

      // Generate mock related events
      const mockEvents: RelatedEvent[] = [];
      const baseTime = new Date(alert.timestamp);
      const eventTypes = ['authentication', 'network', 'process', 'file'];
      const statuses = ['success', 'failure', 'blocked'];
      const users = ['admin', 'jsmith', 'system', alert.target];

      // Use groupedInfo event count if available, otherwise default to 15
      const eventCount = groupedInfo?.eventCount || alert.detection_reason?.matched_count || 15;
      const maxEvents = Math.min(eventCount, 20); // Cap at 20 for performance

      for (let i = 0; i < maxEvents; i++) {
        const timestamp = new Date(baseTime.getTime() - i * 60000).toISOString();
        mockEvents.push({
          id: `evt-${i}`,
          timestamp,
          sourceIp: `192.168.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`,
          destinationIp: `10.0.${Math.floor(Math.random() * 10)}.${Math.floor(Math.random() * 255)}`,
          user: users[Math.floor(Math.random() * users.length)],
          action: eventTypes[Math.floor(Math.random() * eventTypes.length)],
          status: statuses[Math.floor(Math.random() * statuses.length)],
          message: `${eventTypes[Math.floor(Math.random() * eventTypes.length)]} event detected`,
        });
      }

      setRelatedEvents(mockEvents);
      setEventsLoading(false);
    };

    fetchRelatedEvents();
  }, [alert]);

  // Fetch comments
  useEffect(() => {
    const fetchComments = async () => {
      if (!alert) return;
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
  }, [alert]);

  // Initialize timeline
  useEffect(() => {
    if (!alert) return;

    const alertTime = new Date(alert.timestamp);
    setTimeline([
      {
        time: alertTime,
        event: 'Alert created',
        type: 'created',
      },
      {
        time: new Date(alertTime.getTime() + 60000),
        event: 'AI triage: High priority',
        type: 'ai',
      },
      {
        time: new Date(alertTime.getTime() + 120000),
        event: 'Enrichment complete',
        type: 'enriched',
      },
    ]);
  }, [alert]);

  // Fetch matched events for detection reason
  useEffect(() => {
    const fetchMatchedEvents = async () => {
      if (!alert?.id) return;
      try {
        const response = await fetch(`/api/v1/alerts/${alert.id}/matched-events`);
        if (response.ok) {
          const data: MatchedEventsResponse = await response.json();
          setMatchedEvents(data.events || []);
          setMatchedEventsMLModel(data.ml_model || null);
          setMatchedEventsAnalysis(data.analysis_summary || null);
        }
      } catch (error) {
        console.error('Failed to fetch matched events:', error);
        // Generate mock matched events based on alert data
        const mockEvents: MatchedEvent[] = Array.from({ length: alert.detection_reason?.matched_count || 3 }, (_, i) => ({
          id: `evt-${i + 1}`,
          timestamp: new Date(Date.now() - (i * 60000)).toISOString(),
          event_type: 'NETWORK_CONNECTION',
          source_ip: alert.fields?.source_ip || '192.168.1.100',
          dest_ip: '10.0.0.50',
          user: alert.fields?.user || 'system',
          action: 'BLOCK',
          raw_log: `[${new Date().toISOString()}] BLOCK connection from ${alert.fields?.source_ip || '192.168.1.100'} to 10.0.0.50:443`
        }));
        setMatchedEvents(mockEvents);
        setMatchedEventsMLModel(null);
        setMatchedEventsAnalysis(null);
      }
    };
    fetchMatchedEvents();
  }, [alert?.id, alert?.detection_reason?.matched_count, alert?.fields]);

  // Add timeline entry helper
  const addTimelineEntry = (event: string, type: TimelineEntry['type']) => {
    setTimeline(prev => [
      ...prev,
      {
        time: new Date(),
        event,
        type,
      },
    ]);
  };

  // Handle adding a new comment
  const handleAddComment = async () => {
    if (!newComment.trim() || !alert) return;

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
          addTimelineEntry('Comment added', 'action');
          toast({
            title: 'Comment Added',
            description: 'Your comment has been added successfully.',
          });
        }
      } else {
        // Mock success for demo
        const mockComment: AlertComment = {
          id: `comment-${Date.now()}`,
          alert_id: alert.id,
          author: 'SOC Analyst',
          content: newComment.trim(),
          created_at: new Date().toISOString(),
        };
        setComments(prev => [...prev, mockComment]);
        setNewComment('');
        addTimelineEntry('Comment added', 'action');
        toast({
          title: 'Comment Added',
          description: 'Your comment has been added successfully.',
        });
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
          addTimelineEntry('Alert acknowledged', 'action');
          toast({
            title: 'Alert Acknowledged',
            description: `Alert ${alert.id} has been acknowledged.`,
          });
        }
      } else {
        // Mock success for demo
        setAlert({ ...alert, status: 'acknowledged' });
        addTimelineEntry('Alert acknowledged', 'action');
        toast({
          title: 'Alert Acknowledged',
          description: `Alert ${alert.id} has been acknowledged.`,
        });
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
          addTimelineEntry('Alert closed', 'action');
          toast({
            title: 'Alert Closed',
            description: `Alert ${alert.id} has been closed.`,
          });
        }
      } else {
        // Mock success for demo
        setAlert({ ...alert, status: 'closed' });
        addTimelineEntry('Alert closed', 'action');
        toast({
          title: 'Alert Closed',
          description: `Alert ${alert.id} has been closed.`,
        });
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
          addTimelineEntry(`Case ${data.case.id} created`, 'case');
          toast({
            title: 'Case Created',
            description: `Case ${data.case.id} has been created.`,
          });
          // Navigate to case
          navigate(`/cases/${data.case.id}`);
        }
      } else {
        // Mock success for demo
        const mockCaseId = `CASE-${Date.now().toString(36).toUpperCase()}`;
        addTimelineEntry(`Case ${mockCaseId} created`, 'case');
        toast({
          title: 'Case Created',
          description: `Case ${mockCaseId} has been created.`,
        });
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
          addTimelineEntry(`Playbook "${playbook.name}" completed`, 'playbook');
          toast({
            title: 'Playbook Executed',
            description: `${playbook.name} completed successfully.`,
          });
        }
      } else {
        // Mock success for demo
        setTimeout(() => {
          setExecutionStatus('completed');
          addTimelineEntry(`Playbook "${playbook.name}" completed`, 'playbook');
          toast({
            title: 'Playbook Executed',
            description: `${playbook.name} completed successfully.`,
          });
        }, 2000);
      }
    } catch (error) {
      setExecutionStatus('failed');
      console.error('Failed to execute playbook:', error);
    }
  };

  // Fetch AI Analysis from API
  const fetchAIAnalysis = async () => {
    if (!alert?.id) return;

    setAiAnalysisLoading(true);
    setAiAnalysisError(null);

    try {
      const response = await fetch(`/api/v1/alerts/${alert.id}/ai-analysis`);
      if (!response.ok) {
        throw new Error(`Failed to fetch AI analysis: ${response.status}`);
      }
      const data: AIAnalysisResponse = await response.json();
      if (data.success) {
        setAiAnalysis(data);
      } else {
        throw new Error('Invalid AI analysis response');
      }
    } catch (error) {
      console.error('Failed to fetch AI analysis:', error);
      setAiAnalysisError(error instanceof Error ? error.message : 'Failed to fetch AI analysis');
    } finally {
      setAiAnalysisLoading(false);
    }
  };

  // Handle AI Assistant button click
  const handleOpenAIAssistant = async () => {
    setIsAIAssistantOpen(true);
    // Fetch fresh AI analysis when dialog opens
    if (!aiAnalysis || aiAnalysis.alert_id !== alert?.id) {
      await fetchAIAnalysis();
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

    // If AI analysis is loading, show loading message with spinning animation
    if (aiAnalysisLoading) {
      return [
        {
          id: 'loading',
          role: 'assistant',
          content: [{ type: 'text', content: '🔄 AI 분석을 수행 중입니다...\n\n⏳ LLM 모델에서 Alert 정보를 분석하고 있습니다. 잠시만 기다려 주세요.' }],
          timestamp: new Date(),
          isStreaming: true,
        },
      ];
    }

    // If AI analysis failed, show error and fallback
    if (aiAnalysisError) {
      return [
        {
          id: 'error',
          role: 'assistant',
          content: [{ type: 'text', content: `⚠️ AI 분석 조회 실패: ${aiAnalysisError}\n\n기본 Alert 정보를 표시합니다.` }],
          timestamp: new Date(),
        },
      ];
    }

    // If AI analysis is available, use it
    if (aiAnalysis) {
      const { alert_info, ml_classification, ml_analysis, events_analysis, risk_level, interpretation, recommendations } = aiAnalysis;

      // Build ML Model section
      let mlModelSection = '';
      if (ml_classification.model) {
        const m = ml_classification.model;
        mlModelSection = `### 사용된 ML 모델\n`;
        mlModelSection += `- **모델명:** ${m.model_name} v${m.model_version}\n`;
        mlModelSection += `- **유형:** ${m.model_type}\n`;
        mlModelSection += `- **정확도:** ${(m.accuracy * 100).toFixed(0)}% | **정밀도:** ${(m.precision * 100).toFixed(0)}% | **재현율:** ${(m.recall * 100).toFixed(0)}%\n`;
        mlModelSection += `- **학습 데이터:** ${m.training_data}\n\n`;
      }

      // Build risk factors section
      let riskFactorsSection = '';
      const triggeredFactors = ml_analysis.risk_factors?.filter(rf => rf.triggered) || [];
      if (triggeredFactors.length > 0) {
        riskFactorsSection = `### ⚠️ 발동된 위험 요소\n`;
        triggeredFactors.forEach(rf => {
          riskFactorsSection += `- **${rf.factor}** (가중치: ${(rf.weight * 100).toFixed(0)}%)\n`;
        });
        riskFactorsSection += '\n';
      }

      // Build threat indicators section
      let threatIndicatorsSection = '';
      if (events_analysis.threat_indicators.length > 0) {
        threatIndicatorsSection = `### 🚨 탐지된 위협 지표\n`;
        events_analysis.threat_indicators.forEach(ind => {
          const readableName = ind.replace(/_/g, ' ').replace(/\b\w/g, (c: string) => c.toUpperCase());
          threatIndicatorsSection += `- ${readableName}\n`;
        });
        threatIndicatorsSection += '\n';
      }

      // Build recommendations section
      let recommendationsSection = `---\n## ✅ 대응 권고사항\n\n`;
      const riskEmoji = risk_level === 'CRITICAL' ? '🔴' : risk_level === 'HIGH' ? '🟠' : risk_level === 'MEDIUM' ? '🟡' : '🟢';
      recommendationsSection += `### ${riskEmoji} ${risk_level === 'CRITICAL' ? '긴급 대응 필요' : risk_level === 'HIGH' ? '우선 조사 필요' : risk_level === 'MEDIUM' ? '조사 권장' : '모니터링 권장'}\n\n`;

      recommendations.forEach((rec, idx) => {
        recommendationsSection += `**${idx + 1}. ${rec.action}**\n`;
        recommendationsSection += `   ${rec.description}\n\n`;
      });

      // Build the complete message
      const fullAnalysis =
        `# 🔍 Alert AI 분석 리포트\n\n` +
        `> 📅 분석 시간: ${new Date(aiAnalysis.timestamp).toLocaleString()}\n\n` +
        `---\n## 📋 Alert 기본 정보\n\n` +
        `| 항목 | 값 |\n|------|-----|\n` +
        `| **Alert ID** | \`${alert_info.id}\` |\n` +
        `| **제목** | ${alert_info.title} |\n` +
        `| **심각도** | ${alert_info.severity.toUpperCase()} |\n` +
        `| **상태** | ${alert_info.status} |\n` +
        `| **소스** | ${alert_info.source} |\n` +
        `| **탐지 규칙** | ${alert_info.rule_name} (${alert_info.rule_id}) |\n` +
        (alert_info.mitre_techniques?.length ? `| **MITRE ATT&CK** | ${alert_info.mitre_techniques.join(', ')} |\n` : '') +
        `| **소스 IP** | ${alert_info.source_ip || 'N/A'} |\n` +
        `| **대상** | ${alert_info.target || 'N/A'} |\n` +
        `| **사용자** | ${alert_info.user || 'N/A'} |\n` +
        `| **매칭 이벤트** | ${alert_info.matched_count}건 |\n\n` +
        `---\n## 🤖 ML 분석 결과\n\n` +
        `**분류 방법:** ${ml_classification.method === 'ML_ASSISTED' ? '🧠 ML 보조 분석' : '📋 규칙 기반'}\n` +
        `**신뢰도:** ${(ml_classification.confidence * 100).toFixed(0)}%\n\n` +
        mlModelSection +
        `### ML 분석 상세\n` +
        `| 지표 | 값 | 의미 |\n|------|-----|------|\n` +
        `| **이상 점수** | ${(ml_analysis.anomaly_score * 100).toFixed(0)}% | ${ml_analysis.anomaly_score > 0.8 ? '🔴 매우 높음' : ml_analysis.anomaly_score > 0.6 ? '🟠 높음' : ml_analysis.anomaly_score > 0.4 ? '🟡 중간' : '🟢 낮음'} |\n` +
        `| **위협 카테고리** | ${ml_analysis.threat_category || 'N/A'} | 분류된 위협 유형 |\n` +
        `| **유사 인시던트** | ${ml_analysis.similar_incidents}건 | 과거 유사 사례 |\n` +
        `| **오탐 가능성** | ${(ml_analysis.false_positive_likelihood * 100).toFixed(0)}% | ${ml_analysis.false_positive_likelihood < 0.15 ? '✅ 낮음 (신뢰 가능)' : ml_analysis.false_positive_likelihood < 0.3 ? '⚠️ 중간' : '❌ 높음 (검증 필요)'} |\n\n` +
        riskFactorsSection +
        `### 📊 매칭 이벤트 분석\n` +
        `- **전체 이벤트:** ${events_analysis.total_events}건\n` +
        `- **이상 이벤트:** ${events_analysis.anomalous_events}건\n` +
        `- **평균 이상 점수:** ${(events_analysis.avg_anomaly_score * 100).toFixed(0)}%\n` +
        `- **주요 기여 피처:** ${events_analysis.top_features.join(', ')}\n\n` +
        threatIndicatorsSection +
        `---\n## 💡 종합 해석\n\n` +
        `> ${interpretation.summary}\n\n` +
        `**주요 발견 사항:**\n` +
        interpretation.key_findings.map(f => `- ${f}`).join('\n') + '\n\n' +
        `**위험 평가:** ${interpretation.risk_assessment}\n\n` +
        recommendationsSection +
        `\n---\n추가 질문이 있으시면 말씀해 주세요!`;

      return [
        {
          id: 'ai-analysis',
          role: 'assistant',
          content: [{ type: 'text', content: fullAnalysis }],
          timestamp: new Date(),
        },
      ];
    }

    // Fallback: Build from local data if no AI analysis
    const dr = alert.detection_reason;
    const mlModel = dr?.ml_model;
    const mlAnalysisLocal = dr?.ml_analysis;

    let mlSection = '';
    if (dr) {
      mlSection = `\n---\n## 🤖 ML 분석 결과\n\n`;
      mlSection += `**분류 방법:** ${dr.classification_method === 'ML_ASSISTED' ? 'ML 보조 분석' : '규칙 기반'}\n`;
      mlSection += `**신뢰도:** ${(dr.classification_confidence * 100).toFixed(0)}%\n\n`;

      if (mlModel) {
        mlSection += `### 사용된 ML 모델\n`;
        mlSection += `- **모델명:** ${mlModel.model_name} v${mlModel.model_version}\n`;
        mlSection += `- **유형:** ${mlModel.model_type}\n`;
        mlSection += `- **정확도:** ${(mlModel.accuracy * 100).toFixed(0)}% | **정밀도:** ${(mlModel.precision * 100).toFixed(0)}% | **재현율:** ${(mlModel.recall * 100).toFixed(0)}%\n\n`;
      }

      if (mlAnalysisLocal) {
        mlSection += `### ML 분석 상세\n`;
        mlSection += `- **이상 점수 (Anomaly Score):** ${mlAnalysisLocal.anomaly_score !== null ? `${(mlAnalysisLocal.anomaly_score * 100).toFixed(0)}%` : 'N/A'}\n`;
        mlSection += `- **위협 카테고리:** ${mlAnalysisLocal.threat_category}\n`;
        mlSection += `- **유사 인시던트:** ${mlAnalysisLocal.similar_incidents}건\n`;
        mlSection += `- **오탐 가능성:** ${(mlAnalysisLocal.false_positive_likelihood * 100).toFixed(0)}%\n\n`;

        // Risk factors
        const triggeredFactors = mlAnalysisLocal.risk_factors?.filter(rf => rf.triggered) || [];
        if (triggeredFactors.length > 0) {
          mlSection += `### ⚠️ 발동된 위험 요소\n`;
          triggeredFactors.forEach(rf => {
            mlSection += `- **${rf.factor}** (가중치: ${(rf.weight * 100).toFixed(0)}%)\n`;
          });
          mlSection += '\n';
        }
      }
    }

    // Build matched events analysis section
    let eventsSection = '';
    if (matchedEventsAnalysis) {
      eventsSection = `### 📊 매칭 이벤트 분석 요약\n`;
      eventsSection += `- **이상 이벤트 수:** ${matchedEventsAnalysis.total_anomalous}건\n`;
      eventsSection += `- **평균 이상 점수:** ${(matchedEventsAnalysis.avg_anomaly_score * 100).toFixed(0)}%\n`;
      eventsSection += `- **주요 기여 피처:** ${matchedEventsAnalysis.top_features.join(', ')}\n\n`;
    }

    // Build threat indicators from events
    let indicatorsSection = '';
    const allIndicators = new Set<string>();
    matchedEvents.forEach(evt => {
      evt.ml_analysis?.threat_indicators?.forEach(ind => allIndicators.add(ind));
    });
    if (allIndicators.size > 0) {
      indicatorsSection = `### 🚨 탐지된 위협 지표\n`;
      Array.from(allIndicators).forEach(ind => {
        const readableName = ind.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
        indicatorsSection += `- ${readableName}\n`;
      });
      indicatorsSection += '\n';
    }

    // Build recommendations
    let recommendations = `---\n## ✅ 대응 권고사항\n\n`;

    const severity = alert.severity.toLowerCase();
    const anomalyScore = mlAnalysisLocal?.anomaly_score || 0;
    const fpLikelihood = mlAnalysisLocal?.false_positive_likelihood || 0.5;

    if (severity === 'critical' || anomalyScore > 0.8) {
      recommendations += `### 🔴 긴급 대응 필요\n`;
      recommendations += `1. **즉시 격리 검토:** 소스 호스트(${alert.fields?.source_ip || alert.target})를 네트워크에서 격리\n`;
      recommendations += `2. **EDR 조사:** 해당 시점의 프로세스 및 파일 활동 확인\n`;
      recommendations += `3. **계정 검토:** 관련 사용자(${alert.fields?.user || 'N/A'}) 계정 활동 확인\n`;
      recommendations += `4. **IOC 추출:** 관련 IP, 도메인, 해시값 수집 및 차단\n`;
    } else if (severity === 'high' || anomalyScore > 0.6) {
      recommendations += `### 🟠 우선 조사 필요\n`;
      recommendations += `1. **상세 로그 분석:** 해당 시간대 전후 로그 확인\n`;
      recommendations += `2. **연관 이벤트 조사:** 동일 소스/대상의 다른 Alert 확인\n`;
      recommendations += `3. **자산 중요도 확인:** 영향받는 시스템의 비즈니스 중요도 평가\n`;
    } else {
      recommendations += `### 🟡 모니터링 권장\n`;
      recommendations += `1. **추이 관찰:** 유사 패턴 반복 여부 모니터링\n`;
      recommendations += `2. **기준선 검토:** 정상 행동 기준선 업데이트 검토\n`;
    }

    if (fpLikelihood < 0.15) {
      recommendations += `\n> 💡 **참고:** 오탐 가능성이 ${(fpLikelihood * 100).toFixed(0)}%로 낮아 실제 위협일 가능성이 높습니다.\n`;
    } else if (fpLikelihood > 0.3) {
      recommendations += `\n> ⚠️ **주의:** 오탐 가능성이 ${(fpLikelihood * 100).toFixed(0)}%로 다소 높습니다. 추가 검증을 권장합니다.\n`;
    }

    // Build the complete message
    const fullAnalysis =
      `# 🔍 Alert 자동 분석 리포트\n\n` +
      `**Alert ID:** ${alert.id}\n` +
      `**제목:** ${alert.title}\n` +
      `**심각도:** ${alert.severity.toUpperCase()}\n` +
      `**상태:** ${alert.status}\n` +
      `**소스:** ${alert.source}\n` +
      `**탐지 규칙:** ${alert.rule_name}\n` +
      (alert.mitre_techniques?.length ? `**MITRE ATT&CK:** ${alert.mitre_techniques.join(', ')}\n` : '') +
      `**매칭 이벤트:** ${dr?.matched_count || 0}건\n` +
      mlSection +
      eventsSection +
      indicatorsSection +
      recommendations +
      `\n---\n추가 질문이 있으시면 말씀해 주세요!`;

    return [
      {
        id: 'system-analysis',
        role: 'assistant',
        content: [
          {
            type: 'text',
            content: fullAnalysis,
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

          {/* Group Information Card - Only for Grouped Alerts */}
          {groupedInfo?.isGrouped && (
            <Card className="border-neon-cyan/30 bg-neon-cyan/5">
              <CardHeader className="pb-3">
                <CardTitle className="text-lg flex items-center gap-2">
                  <Layers className="w-5 h-5 text-neon-cyan" />
                  Group Information
                  <Badge className="bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50 ml-2">
                    {groupedInfo.eventCount} events
                  </Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Duration */}
                {groupedInfo.firstEventTime && groupedInfo.lastEventTime && (
                  <div className="flex items-center gap-4 p-3 bg-muted/30 rounded-lg">
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">Duration:</span>
                    </div>
                    <span className="font-mono text-neon-cyan">
                      {groupedInfo.duration || calculateDuration(groupedInfo.firstEventTime, groupedInfo.lastEventTime)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      ({new Date(groupedInfo.firstEventTime).toLocaleTimeString()} - {new Date(groupedInfo.lastEventTime).toLocaleTimeString()})
                    </span>
                  </div>
                )}

                {/* Group By Fields */}
                {groupedInfo.groupByFields && groupedInfo.groupByFields.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                      <Filter className="w-4 h-4 text-muted-foreground" />
                      Grouped By
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {groupedInfo.groupByFields.map((field) => (
                        <Badge
                          key={field}
                          variant="outline"
                          className="bg-neon-cyan/10 border-neon-cyan/30 px-3 py-1"
                        >
                          <span className="text-muted-foreground mr-1">{field}:</span>
                          <span className="text-neon-cyan font-mono">
                            {groupedInfo.groupByValues?.[field] || 'N/A'}
                          </span>
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {/* Event Statistics Summary */}
                <div className="grid grid-cols-3 gap-4 pt-2">
                  <div className="text-center p-3 bg-muted/20 rounded-lg">
                    <div className="text-2xl font-bold text-neon-cyan">{groupedInfo.eventCount}</div>
                    <div className="text-xs text-muted-foreground">Total Events</div>
                  </div>
                  <div className="text-center p-3 bg-muted/20 rounded-lg">
                    <div className="text-2xl font-bold text-neon-orange">
                      {groupedInfo.groupByFields?.length || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">Group Fields</div>
                  </div>
                  <div className="text-center p-3 bg-muted/20 rounded-lg">
                    <div className="text-2xl font-bold text-neon-green">
                      {groupedInfo.duration || '-'}
                    </div>
                    <div className="text-xs text-muted-foreground">Duration</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Detection Reason Card */}
          {alert.detection_reason && (
            <Card className="border-neon-cyan/30 bg-neon-cyan/5">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Scale className="w-5 h-5 text-neon-cyan" />
                  Detection Reason
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Rule Information */}
                <div>
                  <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                    <Target className="w-4 h-4" />
                    Rule Information
                  </h4>
                  <div className="space-y-2">
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground min-w-[80px]">Rule ID:</span>
                      <span className="text-sm font-mono text-neon-cyan">{alert.rule_id}</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground min-w-[80px]">Rule Name:</span>
                      <span className="text-sm font-medium">{alert.rule_name}</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground min-w-[80px]">Description:</span>
                      <span className="text-sm">{alert.detection_reason.rule_description}</span>
                    </div>
                    <div className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground min-w-[80px]">Severity:</span>
                      <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
                    </div>
                    {alert.detection_reason.rule_tags.length > 0 && (
                      <div className="flex items-start gap-2">
                        <span className="text-xs text-muted-foreground min-w-[80px]">Tags:</span>
                        <div className="flex flex-wrap gap-1">
                          {alert.detection_reason.rule_tags.map((tag) => (
                            <Badge key={tag} variant="outline" className="text-xs">
                              {tag}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <Separator />

                {/* Detection Conditions */}
                <div>
                  <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                    <Filter className="w-4 h-4" />
                    Detection Conditions
                  </h4>
                  <div className="bg-muted/30 rounded-lg overflow-hidden border border-border">
                    <div className="grid grid-cols-2 gap-px bg-border">
                      {Object.entries(alert.detection_reason.rule_conditions).map(([field, values]) => (
                        <div key={field} className="bg-background p-3">
                          <div className="text-xs text-muted-foreground mb-1 font-mono">{field}</div>
                          <div className="flex flex-wrap gap-1">
                            {Array.isArray(values) ? (
                              values.map((value, idx) => (
                                <span key={idx} className="text-sm font-medium text-neon-cyan">
                                  {String(value)}
                                  {idx < values.length - 1 && <span className="text-muted-foreground">,</span>}
                                </span>
                              ))
                            ) : (
                              <span className="text-sm font-medium text-neon-cyan">{String(values)}</span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Threshold & Window */}
                <div>
                  <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                    <Timer className="w-4 h-4" />
                    Threshold & Time Window
                  </h4>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="bg-muted/30 rounded-lg p-3 border border-border">
                      <div className="text-xs text-muted-foreground mb-1">Threshold</div>
                      <div className="text-lg font-bold text-neon-orange">
                        {alert.detection_reason.rule_threshold} events
                      </div>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-3 border border-border">
                      <div className="text-xs text-muted-foreground mb-1">Time Window</div>
                      <div className="text-lg font-bold text-neon-blue">
                        {alert.detection_reason.rule_window_minutes} min
                      </div>
                    </div>
                    <div className="bg-muted/30 rounded-lg p-3 border border-border">
                      <div className="text-xs text-muted-foreground mb-1">Aggregate By</div>
                      <div className="text-sm font-mono mt-1">
                        {alert.detection_reason.rule_aggregate_by.length > 0
                          ? alert.detection_reason.rule_aggregate_by.join(', ')
                          : 'None'}
                      </div>
                    </div>
                  </div>
                </div>

                <Separator />

                {/* Classification Details */}
                <div>
                  <h4 className="text-sm font-medium mb-3 flex items-center gap-2">
                    <Layers className="w-4 h-4" />
                    Classification Details
                  </h4>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm text-muted-foreground">Method</span>
                      <Badge variant="outline" className={cn(
                        alert.detection_reason.classification_method === 'ML_ASSISTED'
                          ? "bg-neon-purple/10 text-neon-purple border-neon-purple/30"
                          : "bg-primary/10 text-primary border-primary/30"
                      )}>
                        {alert.detection_reason.classification_method === 'ML_ASSISTED' && (
                          <Brain className="w-3 h-3 mr-1" />
                        )}
                        {alert.detection_reason.classification_method.toLowerCase().replace('_', '-')}
                      </Badge>
                    </div>
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm text-muted-foreground">Confidence</span>
                        <span className="text-sm font-bold text-neon-green">
                          {(alert.detection_reason.classification_confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                      <div className="w-full bg-muted/30 rounded-full h-2 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-neon-green to-neon-cyan rounded-full transition-all"
                          style={{
                            width: `${alert.detection_reason.classification_confidence * 100}%`,
                          }}
                        />
                      </div>
                    </div>

                    {/* ML Model Quick Info */}
                    {alert.detection_reason.ml_model && (
                      <div className="p-2 bg-neon-purple/10 border border-neon-purple/20 rounded-lg">
                        <div className="flex items-center gap-2 mb-2">
                          <Brain className="w-3 h-3 text-neon-purple" />
                          <span className="text-xs font-medium text-neon-purple">ML Model</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div>
                            <span className="text-muted-foreground">Name: </span>
                            <span>{alert.detection_reason.ml_model.model_name}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Version: </span>
                            <span className="font-mono">{alert.detection_reason.ml_model.model_version}</span>
                          </div>
                          <div className="col-span-2">
                            <span className="text-muted-foreground">Type: </span>
                            <span className="text-neon-cyan">{alert.detection_reason.ml_model.model_type}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* ML Analysis */}
                    {alert.detection_reason.ml_analysis && (
                      <div className="p-2 bg-neon-cyan/10 border border-neon-cyan/20 rounded-lg space-y-2">
                        <div className="flex items-center gap-2">
                          <Activity className="w-3 h-3 text-neon-cyan" />
                          <span className="text-xs font-medium text-neon-cyan">ML Analysis</span>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          {alert.detection_reason.ml_analysis.anomaly_score !== null && (
                            <div>
                              <span className="text-muted-foreground">Anomaly Score: </span>
                              <span className={cn(
                                "font-bold",
                                alert.detection_reason.ml_analysis.anomaly_score > 0.8 ? "text-threat-critical" :
                                alert.detection_reason.ml_analysis.anomaly_score > 0.6 ? "text-neon-orange" :
                                "text-neon-green"
                              )}>
                                {(alert.detection_reason.ml_analysis.anomaly_score * 100).toFixed(0)}%
                              </span>
                            </div>
                          )}
                          <div>
                            <span className="text-muted-foreground">Category: </span>
                            <Badge variant="outline" className="text-xs">{alert.detection_reason.ml_analysis.threat_category}</Badge>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Similar Incidents: </span>
                            <span>{alert.detection_reason.ml_analysis.similar_incidents}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">FP Likelihood: </span>
                            <span className={cn(
                              alert.detection_reason.ml_analysis.false_positive_likelihood < 0.1 ? "text-neon-green" :
                              alert.detection_reason.ml_analysis.false_positive_likelihood < 0.2 ? "text-neon-orange" :
                              "text-threat-high"
                            )}>
                              {(alert.detection_reason.ml_analysis.false_positive_likelihood * 100).toFixed(0)}%
                            </span>
                          </div>
                        </div>
                        {/* Risk Factors */}
                        {alert.detection_reason.ml_analysis.risk_factors && (
                          <div className="pt-2 border-t border-neon-cyan/20">
                            <div className="text-xs text-muted-foreground mb-1">Risk Factors:</div>
                            <div className="space-y-1">
                              {alert.detection_reason.ml_analysis.risk_factors.map((rf) => (
                                <div key={rf.factor} className="flex items-center justify-between text-xs">
                                  <div className="flex items-center gap-1">
                                    {rf.triggered ? (
                                      <CheckCircle className="w-3 h-3 text-threat-high" />
                                    ) : (
                                      <XCircle className="w-3 h-3 text-muted-foreground/50" />
                                    )}
                                    <span className={rf.triggered ? "text-foreground" : "text-muted-foreground/50"}>
                                      {rf.factor}
                                    </span>
                                  </div>
                                  <span className={cn(
                                    "font-mono",
                                    rf.triggered ? "text-neon-orange" : "text-muted-foreground/50"
                                  )}>
                                    {(rf.weight * 100).toFixed(0)}%
                                  </span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                <Separator />

                {/* Matched Events - Expandable */}
                <div className="border border-neon-orange/30 rounded-lg overflow-hidden">
                  <button
                    onClick={() => setMatchedEventsExpanded(!matchedEventsExpanded)}
                    className="w-full flex items-center justify-between p-3 bg-neon-orange/10 hover:bg-neon-orange/20 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-neon-orange" />
                      <span className="font-medium">Matched Events</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge className="bg-neon-orange/20 text-neon-orange border-neon-orange/50">
                        {alert.detection_reason?.matched_count || matchedEvents.length}
                      </Badge>
                      {matchedEventsExpanded ? (
                        <ChevronUp className="w-4 h-4 text-muted-foreground" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-muted-foreground" />
                      )}
                    </div>
                  </button>

                  {matchedEventsExpanded && (
                    <div className="p-3 space-y-3 max-h-[500px] overflow-y-auto">
                      {/* ML Model Information */}
                      {matchedEventsMLModel && (
                        <div className="p-3 bg-neon-purple/10 border border-neon-purple/30 rounded-lg space-y-3">
                          <div className="flex items-center gap-2">
                            <Brain className="w-4 h-4 text-neon-purple" />
                            <span className="text-sm font-semibold text-neon-purple">ML Model Used</span>
                          </div>
                          <div className="grid grid-cols-2 gap-3 text-sm">
                            <div>
                              <span className="text-muted-foreground">Model: </span>
                              <span className="font-medium">{matchedEventsMLModel.model_name}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Version: </span>
                              <span className="font-mono">{matchedEventsMLModel.model_version}</span>
                            </div>
                            <div className="col-span-2">
                              <span className="text-muted-foreground">Type: </span>
                              <span className="text-neon-cyan">{matchedEventsMLModel.model_type}</span>
                            </div>
                            <div className="col-span-2 text-xs text-muted-foreground">
                              {matchedEventsMLModel.model_description}
                            </div>
                          </div>
                          <div className="grid grid-cols-4 gap-2 pt-2 border-t border-neon-purple/20">
                            <div className="text-center">
                              <div className="text-xs text-muted-foreground">Accuracy</div>
                              <div className="text-sm font-bold text-neon-green">{(matchedEventsMLModel.accuracy * 100).toFixed(0)}%</div>
                            </div>
                            <div className="text-center">
                              <div className="text-xs text-muted-foreground">Precision</div>
                              <div className="text-sm font-bold text-neon-cyan">{(matchedEventsMLModel.precision * 100).toFixed(0)}%</div>
                            </div>
                            <div className="text-center">
                              <div className="text-xs text-muted-foreground">Recall</div>
                              <div className="text-sm font-bold text-neon-orange">{(matchedEventsMLModel.recall * 100).toFixed(0)}%</div>
                            </div>
                            <div className="text-center">
                              <div className="text-xs text-muted-foreground">F1 Score</div>
                              <div className="text-sm font-bold text-neon-purple">{(matchedEventsMLModel.f1_score * 100).toFixed(0)}%</div>
                            </div>
                          </div>
                          <div className="pt-2 border-t border-neon-purple/20">
                            <div className="text-xs text-muted-foreground mb-1">Features Used:</div>
                            <div className="flex flex-wrap gap-1">
                              {matchedEventsMLModel.features_used.slice(0, 6).map((feature) => (
                                <Badge key={feature} variant="outline" className="text-xs bg-neon-purple/10 text-neon-purple border-neon-purple/30">
                                  {feature}
                                </Badge>
                              ))}
                              {matchedEventsMLModel.features_used.length > 6 && (
                                <Badge variant="outline" className="text-xs">
                                  +{matchedEventsMLModel.features_used.length - 6} more
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Analysis Summary */}
                      {matchedEventsAnalysis && (
                        <div className="p-3 bg-neon-cyan/10 border border-neon-cyan/30 rounded-lg">
                          <div className="flex items-center gap-2 mb-2">
                            <BarChart3 className="w-4 h-4 text-neon-cyan" />
                            <span className="text-sm font-semibold text-neon-cyan">Analysis Summary</span>
                          </div>
                          <div className="grid grid-cols-3 gap-3 text-sm">
                            <div className="text-center p-2 bg-muted/30 rounded">
                              <div className="text-lg font-bold text-threat-high">{matchedEventsAnalysis.total_anomalous}</div>
                              <div className="text-xs text-muted-foreground">Anomalous Events</div>
                            </div>
                            <div className="text-center p-2 bg-muted/30 rounded">
                              <div className="text-lg font-bold text-neon-orange">{(matchedEventsAnalysis.avg_anomaly_score * 100).toFixed(0)}%</div>
                              <div className="text-xs text-muted-foreground">Avg Anomaly Score</div>
                            </div>
                            <div className="text-center p-2 bg-muted/30 rounded">
                              <div className="text-xs text-muted-foreground mb-1">Top Features</div>
                              <div className="flex flex-wrap gap-1 justify-center">
                                {matchedEventsAnalysis.top_features.slice(0, 2).map((f) => (
                                  <Badge key={f} variant="outline" className="text-xs">{f}</Badge>
                                ))}
                              </div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Events List */}
                      {matchedEvents.length === 0 ? (
                        <p className="text-sm text-muted-foreground text-center py-4">
                          No event details available
                        </p>
                      ) : (
                        matchedEvents.map((event, index) => (
                          <div
                            key={event.id}
                            className="p-3 bg-muted/30 rounded-lg border border-border/50 space-y-2"
                          >
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="text-xs font-mono text-muted-foreground">
                                  #{index + 1} - {event.id}
                                </span>
                                {event.ml_analysis?.is_anomalous && (
                                  <Badge className="text-xs bg-threat-high/20 text-threat-high border-threat-high/50">
                                    Anomalous
                                  </Badge>
                                )}
                              </div>
                              <div className="flex items-center gap-2">
                                {event.ml_analysis && (
                                  <Badge variant="outline" className={cn(
                                    "text-xs",
                                    event.ml_analysis.anomaly_score > 0.8 ? "text-threat-critical border-threat-critical/50" :
                                    event.ml_analysis.anomaly_score > 0.6 ? "text-neon-orange border-neon-orange/50" :
                                    "text-neon-green border-neon-green/50"
                                  )}>
                                    Score: {(event.ml_analysis.anomaly_score * 100).toFixed(0)}%
                                  </Badge>
                                )}
                                <span className="text-xs text-muted-foreground">
                                  {new Date(event.timestamp).toLocaleString()}
                                </span>
                              </div>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-sm">
                              <div>
                                <span className="text-muted-foreground">Type: </span>
                                <Badge variant="outline" className="text-xs">
                                  {event.event_type}
                                </Badge>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Action: </span>
                                <Badge
                                  variant="outline"
                                  className={cn(
                                    "text-xs",
                                    event.action === 'BLOCK' && "text-threat-critical border-threat-critical/50",
                                    event.action === 'ALLOW' && "text-neon-green border-neon-green/50"
                                  )}
                                >
                                  {event.action}
                                </Badge>
                              </div>
                              {event.source_ip && (
                                <div>
                                  <span className="text-muted-foreground">Source: </span>
                                  <span className="font-mono text-neon-cyan">{event.source_ip}</span>
                                </div>
                              )}
                              {event.dest_ip && (
                                <div>
                                  <span className="text-muted-foreground">Dest: </span>
                                  <span className="font-mono text-neon-cyan">{event.dest_ip}:{event.dest_port || ''}</span>
                                </div>
                              )}
                              {event.bytes_sent !== undefined && (
                                <div>
                                  <span className="text-muted-foreground">Sent: </span>
                                  <span>{(event.bytes_sent / 1024).toFixed(1)} KB</span>
                                </div>
                              )}
                              {event.bytes_received !== undefined && (
                                <div>
                                  <span className="text-muted-foreground">Recv: </span>
                                  <span>{(event.bytes_received / 1024).toFixed(1)} KB</span>
                                </div>
                              )}
                              {event.user && (
                                <div>
                                  <span className="text-muted-foreground">User: </span>
                                  <span>{event.user}</span>
                                </div>
                              )}
                              {event.protocol && (
                                <div>
                                  <span className="text-muted-foreground">Protocol: </span>
                                  <span>{event.protocol}</span>
                                </div>
                              )}
                            </div>

                            {/* ML Analysis per Event */}
                            {event.ml_analysis && (
                              <div className="mt-2 p-2 bg-neon-purple/5 border border-neon-purple/20 rounded space-y-2">
                                <div className="flex items-center gap-2">
                                  <Brain className="w-3 h-3 text-neon-purple" />
                                  <span className="text-xs font-semibold text-neon-purple">ML Analysis</span>
                                </div>
                                {event.ml_analysis.contributing_features && event.ml_analysis.contributing_features.length > 0 && (
                                  <div className="space-y-1">
                                    <div className="text-xs text-muted-foreground">Contributing Features:</div>
                                    <div className="grid grid-cols-2 gap-1">
                                      {event.ml_analysis.contributing_features.slice(0, 4).map((cf) => (
                                        <div key={cf.feature} className="flex items-center justify-between text-xs p-1 bg-muted/30 rounded">
                                          <span className="text-muted-foreground">{cf.feature}</span>
                                          <div className="flex items-center gap-1">
                                            <span className={cn(
                                              cf.value > cf.baseline * 1.5 ? "text-threat-high" : "text-foreground"
                                            )}>
                                              {typeof cf.value === 'number' && cf.value < 1
                                                ? cf.value.toFixed(2)
                                                : Math.round(cf.value)}
                                            </span>
                                            <span className="text-muted-foreground/50">
                                              (base: {typeof cf.baseline === 'number' && cf.baseline < 1
                                                ? cf.baseline.toFixed(2)
                                                : Math.round(cf.baseline)})
                                            </span>
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                                {event.ml_analysis.threat_indicators && event.ml_analysis.threat_indicators.length > 0 && (
                                  <div className="flex flex-wrap gap-1">
                                    {event.ml_analysis.threat_indicators.map((indicator) => (
                                      <Badge key={indicator} className="text-xs bg-threat-high/20 text-threat-high border-threat-high/30">
                                        {indicator.replace(/_/g, ' ')}
                                      </Badge>
                                    ))}
                                  </div>
                                )}
                              </div>
                            )}

                            {event.raw_log && (
                              <div className="mt-2 p-2 bg-black/30 rounded text-xs font-mono text-muted-foreground overflow-x-auto">
                                {event.raw_log}
                              </div>
                            )}
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Threat Intelligence Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-neon-cyan" />
                  Threat Intelligence
                </CardTitle>
                {tiLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                ) : tiMatch && (
                  <Badge variant="outline" className="bg-neon-cyan/10 text-neon-cyan border-neon-cyan/50 text-xs">
                    {tiMatch.matchedSources} sources matched
                  </Badge>
                )}
              </div>
            </CardHeader>
            <CardContent>
              {tiLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                  <span className="ml-2 text-sm text-muted-foreground">Checking threat intel...</span>
                </div>
              ) : tiMatch && tiMatch.iocs.length > 0 ? (
                <div className="border border-border rounded-lg overflow-hidden">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/30">
                        <TableHead className="text-xs py-2">IOC</TableHead>
                        <TableHead className="text-xs py-2 w-[80px]">Type</TableHead>
                        <TableHead className="text-xs py-2 w-[80px]">Score</TableHead>
                        <TableHead className="text-xs py-2 w-[100px]">Source</TableHead>
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
                <div className="text-center py-6 text-sm text-muted-foreground">
                  <AlertCircle className="w-8 h-8 mx-auto mb-2 text-muted-foreground/50" />
                  No threat intelligence matches found
                </div>
              )}
            </CardContent>
          </Card>

          {/* Related Events Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Activity className="w-5 h-5 text-neon-blue" />
                  Related Events
                </CardTitle>
                <Badge variant="outline" className="text-xs">
                  {relatedEvents.length} events
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {eventsLoading ? (
                <div className="flex items-center justify-center py-6">
                  <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
                  <span className="ml-2 text-sm text-muted-foreground">Loading events...</span>
                </div>
              ) : relatedEvents.length > 0 ? (
                <Tabs value={eventsTab} onValueChange={setEventsTab}>
                  <TabsList className="grid w-full grid-cols-3 mb-4">
                    <TabsTrigger value="timeline" className="flex items-center gap-1">
                      <Clock className="w-4 h-4" />
                      Timeline
                    </TabsTrigger>
                    <TabsTrigger value="table" className="flex items-center gap-1">
                      <TableIcon className="w-4 h-4" />
                      Table
                    </TabsTrigger>
                    <TabsTrigger value="statistics" className="flex items-center gap-1">
                      <BarChart3 className="w-4 h-4" />
                      Statistics
                    </TabsTrigger>
                  </TabsList>

                  {/* Timeline View */}
                  <TabsContent value="timeline" className="mt-0">
                    <ScrollArea className="h-[300px]">
                      <div className="space-y-2 pr-4">
                        {relatedEvents.map((event, index) => (
                          <div
                            key={event.id}
                            className="relative pl-6 pb-3 border-l-2 border-muted last:border-transparent"
                          >
                            <div
                              className={cn(
                                'absolute -left-[5px] top-1.5 w-2 h-2 rounded-full',
                                event.status?.toLowerCase() === 'failure' ||
                                event.status?.toLowerCase() === 'failed'
                                  ? 'bg-threat-critical'
                                  : event.status?.toLowerCase() === 'success'
                                  ? 'bg-neon-green'
                                  : 'bg-primary'
                              )}
                            />
                            <div className="flex items-start justify-between gap-4">
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 text-sm">
                                  <span className="font-mono text-muted-foreground">
                                    {formatEventTime(event.timestamp)}
                                  </span>
                                  {event.status && (
                                    <Badge
                                      variant={
                                        event.status.toLowerCase() === 'failure' ||
                                        event.status.toLowerCase() === 'failed'
                                          ? 'destructive'
                                          : event.status.toLowerCase() === 'success'
                                          ? 'success'
                                          : 'outline'
                                      }
                                      className="text-[10px] px-1.5 py-0"
                                    >
                                      {event.status}
                                    </Badge>
                                  )}
                                </div>
                                <div className="flex items-center gap-2 text-sm mt-1">
                                  {event.sourceIp && (
                                    <span className="font-mono text-xs text-muted-foreground">
                                      {event.sourceIp}
                                    </span>
                                  )}
                                  {event.sourceIp && event.destinationIp && (
                                    <ArrowRight className="w-3 h-3 text-muted-foreground" />
                                  )}
                                  {event.destinationIp && (
                                    <span className="font-mono text-xs text-muted-foreground">
                                      {event.destinationIp}
                                    </span>
                                  )}
                                </div>
                                {event.user && (
                                  <p className="text-xs text-muted-foreground mt-1">
                                    user: {event.user}
                                  </p>
                                )}
                                {event.message && (
                                  <p className="text-xs text-muted-foreground mt-1 truncate">
                                    {event.message}
                                  </p>
                                )}
                              </div>
                              <span className="text-[10px] text-muted-foreground">
                                #{relatedEvents.length - index}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </ScrollArea>
                  </TabsContent>

                  {/* Table View */}
                  <TabsContent value="table" className="mt-0">
                    <ScrollArea className="h-[300px]">
                      <Table>
                        <TableHeader>
                          <TableRow>
                            <TableHead className="w-[100px]">Time</TableHead>
                            <TableHead>Source</TableHead>
                            <TableHead>Destination</TableHead>
                            <TableHead>User</TableHead>
                            <TableHead>Status</TableHead>
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {relatedEvents.map((event) => (
                            <TableRow key={event.id}>
                              <TableCell className="font-mono text-xs">
                                {formatEventTime(event.timestamp)}
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {event.sourceIp || '-'}
                              </TableCell>
                              <TableCell className="font-mono text-xs">
                                {event.destinationIp || '-'}
                              </TableCell>
                              <TableCell className="text-xs">{event.user || '-'}</TableCell>
                              <TableCell>
                                {event.status ? (
                                  <Badge
                                    variant={
                                      event.status.toLowerCase() === 'failure' ||
                                      event.status.toLowerCase() === 'failed'
                                        ? 'destructive'
                                        : event.status.toLowerCase() === 'success'
                                        ? 'success'
                                        : 'outline'
                                    }
                                    className="text-[10px]"
                                  >
                                    {event.status}
                                  </Badge>
                                ) : (
                                  '-'
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </ScrollArea>
                  </TabsContent>

                  {/* Statistics View */}
                  <TabsContent value="statistics" className="mt-0">
                    <GroupStatistics statistics={eventStatistics} className="h-[300px]" />
                  </TabsContent>
                </Tabs>
              ) : (
                <div className="text-center py-6 text-sm text-muted-foreground">
                  <Activity className="w-8 h-8 mx-auto mb-2 text-muted-foreground/50" />
                  No related events found
                </div>
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
                onClick={handleOpenAIAssistant}
                disabled={aiAnalysisLoading}
              >
                {aiAnalysisLoading ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : (
                  <Bot className="w-4 h-4 mr-2" />
                )}
                <span>{aiAnalysisLoading ? 'AI 분석 중...' : 'AI Assistant'}</span>
                {!aiAnalysisLoading && <Sparkles className="w-3 h-3 ml-2 animate-pulse" />}
              </Button>
            </CardContent>
          </Card>

          {/* Activity Timeline Card */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Clock className="w-5 h-5 text-neon-pink" />
                Activity Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[200px]">
                <div className="space-y-3 pr-2">
                  {timeline.map((entry, i) => (
                    <div key={i} className="flex gap-3 relative">
                      {i !== timeline.length - 1 && (
                        <div className="absolute left-1.5 top-4 bottom-0 w-px bg-border" />
                      )}
                      <div
                        className={cn(
                          'w-3 h-3 rounded-full mt-1 shrink-0',
                          entry.type === 'created' && 'bg-primary',
                          entry.type === 'ai' && 'bg-neon-pink',
                          entry.type === 'enriched' && 'bg-neon-green',
                          entry.type === 'action' && 'bg-neon-blue',
                          entry.type === 'case' && 'bg-neon-cyan',
                          entry.type === 'playbook' && 'bg-neon-orange'
                        )}
                      />
                      <div className="flex-1 pb-2">
                        <p className="text-sm text-foreground">{entry.event}</p>
                        <p className="text-xs text-muted-foreground/80">
                          {formatTimestamp(entry.time)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Comments Card */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <MessageCircle className="w-5 h-5 text-neon-blue" />
                  Comments
                </CardTitle>
                <Badge variant="outline" className="text-xs">
                  {comments.length}
                </Badge>
              </div>
            </CardHeader>
            <CardContent>
              {/* Comment input */}
              <div className="flex gap-2 mb-4">
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
              <ScrollArea className="h-[180px]">
                <div className="space-y-3 pr-2">
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
                          <UserIcon className="w-3 h-3 text-muted-foreground" />
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
              </ScrollArea>
            </CardContent>
          </Card>

          {/* Related Alerts */}
          {relatedAlerts.length > 0 && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>Related Alerts</CardTitle>
                  <Badge variant="outline" className="text-xs">
                    {relatedAlerts.length} found
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {relatedAlerts.map((related) => (
                    <div
                      key={related.id}
                      className="flex items-center justify-between p-2 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
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
              key={`copilot-${alert.id}-${aiAnalysisLoading ? 'loading' : aiAnalysis ? 'loaded' : 'init'}`}
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
