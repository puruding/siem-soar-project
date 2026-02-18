import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  addEdge,
  Node,
  Edge,
  Connection,
  BackgroundVariant,
  MarkerType,
  Panel,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Progress } from '@/components/ui/progress';
import {
  ArrowLeft,
  Save,
  Play,
  Zap,
  Clock,
  Webhook,
  Mail,
  Bell,
  Shield,
  Database,
  Terminal,
  GitBranch,
  Ticket,
  Cloud,
  Plug,
  Maximize2,
  Minimize2,
  Undo2,
  Redo2,
  ZoomIn,
  ZoomOut,
  Grid3x3,
  CheckCircle2,
  XCircle,
  Info,
  StopCircle,
  RotateCcw,
  Variable,
  Rocket,
  Activity,
  BarChart3,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { toast } from '@/components/ui/toaster';

import {
  TriggerNode,
  ActionNode,
  DecisionNode,
  IntegrationNode,
  LoopNode,
  ParallelNode,
  WaitNode,
  ApprovalGateNode,
  TriggerNodeData,
  ActionNodeData,
  DecisionNodeData,
  IntegrationNodeData,
  LoopNodeData,
  ParallelNodeData,
  WaitNodeData,
  ApprovalGateNodeData,
} from './nodes';
import { LabeledEdge } from './edges';
import { NodePalette } from './NodePalette';
import { ExecutionHistory, ExecutionRun, ExecutionLog, ApprovalInfo } from './ExecutionHistory';
import { VariablePanel, PlaybookVariable } from './VariablePanel';
import { useOrganizationVariables } from '../stores/organizationVariablesStore';
import { ExecutionPanel } from './execution';
import { DynamicInputForm, validateAllFields } from './DynamicInputForm';
import { TRIGGER_INPUT_SCHEMAS, getDefaultInputValues, getPlaybookInputSchema } from '../constants/triggerInputSchemas';
import type { PlaybookInputField, InputValues, TriggerType, InputFieldType } from '../types/inputSchema';
import { ProcessingMonitor } from './monitoring/ProcessingMonitor';
import { TemplateEditor } from './editor';
import { useExecutionWebSocket, useNodeOutputSchema, useProcessingMetrics } from '../hooks';
import { useExecutionStore } from '../stores/executionStore';
import { useProcessingStore } from '../stores/processingStore';
import { mockWebSocketService } from '../services/mockWebSocketService';
import {
  deployPlaybook,
  convertNodesToSteps,
  savePlaybook,
  updatePlaybook,
  getPlaybookWithDefinition,
  type PlaybookDeployRequest,
  type PlaybookSaveRequest,
} from '../services/playbookApi';

// Convert execution-scoped variables to input fields
function variableToInputField(variable: PlaybookVariable, order: number): PlaybookInputField {
  // Map variable type to input field type
  const typeMap: Record<string, InputFieldType> = {
    string: 'text',
    number: 'number',
    boolean: 'boolean',
    array: 'json',
    object: 'json',
  };

  return {
    id: `var-${variable.id}`,
    name: variable.name,
    label: variable.name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    type: typeMap[variable.type] || 'text',
    required: false,
    defaultValue: variable.value,
    description: variable.description,
    placeholder: variable.description || `Enter ${variable.name}...`,
    group: 'Custom Variables',
    order: 100 + order,
  };
}

// Node type configuration
const nodeTypes = {
  trigger: TriggerNode,
  action: ActionNode,
  decision: DecisionNode,
  integration: IntegrationNode,
  loop: LoopNode,
  parallel: ParallelNode,
  wait: WaitNode,
  approval: ApprovalGateNode,
} as any;

const edgeTypes = {
  labeled: LabeledEdge,
} as any;

// Execution history - starts empty, populated by actual Test Runs
// Note: Mock data removed - only real executions are shown now
const initialExecutions: ExecutionRun[] = [];


// Sample variables
const sampleVariables: PlaybookVariable[] = [
  {
    id: 'var-1',
    name: 'severity_threshold',
    type: 'string',
    scope: 'global',
    value: 'high',
    description: 'Minimum severity to trigger response',
  },
  {
    id: 'var-2',
    name: 'max_retries',
    type: 'number',
    scope: 'global',
    value: 3,
    description: 'Maximum retry attempts for actions',
  },
  {
    id: 'var-3',
    name: 'alert_recipients',
    type: 'array',
    scope: 'global',
    value: ['soc@example.com', 'security@example.com'],
    description: 'Email recipients for alerts',
  },
  {
    id: 'var-4',
    name: 'firewall_zone',
    type: 'string',
    scope: 'execution',
    value: '',
    description: 'Target firewall zone for blocking rules',
  },
  {
    id: 'var-5',
    name: 'block_duration_hours',
    type: 'number',
    scope: 'execution',
    value: 24,
    description: 'How long to maintain the block (hours)',
  },
];

// Playbook flow definitions - each playbook has unique nodes and edges
const playbookFlows: Record<string, { nodes: Node[]; edges: Edge[] }> = {
  // PB-001: Malware Response
  'PB-001': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'Malware Alert', triggerType: 'alert', description: 'High severity malware detection', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'action',
        position: { x: 380, y: 280 },
        data: { label: 'Enrich IOCs', actionType: 'custom', description: 'Query threat intelligence' } as any,
      },
      {
        id: '3',
        type: 'decision',
        position: { x: 355, y: 500 },
        data: { label: 'Severity Check', condition: 'severity >= critical', outcomes: { yes: 'Critical', no: 'Standard' } } as any,
      },
      {
        id: '4',
        type: 'action',
        position: { x: 150, y: 750 },
        data: { label: 'Isolate Endpoint', actionType: 'isolate', description: 'Network isolation' } as any,
      },
      {
        id: '5',
        type: 'integration',
        position: { x: 560, y: 750 },
        data: { label: 'Create Ticket', integrationType: 'ticketing', connectionStatus: 'connected' } as any,
      },
      {
        id: '6',
        type: 'action',
        position: { x: 160, y: 1000 },
        data: { label: 'Notify SOC', actionType: 'slack', description: '#security-alerts' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, data: { animated: true }, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#F79836' }, style: { stroke: '#F79836' } },
      { id: 'e3-4', source: '3', sourceHandle: 'yes', target: '4', type: 'labeled', data: { label: 'Yes', condition: 'yes', animated: true }, markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e3-5', source: '3', sourceHandle: 'no', target: '5', type: 'labeled', data: { label: 'No', condition: 'no' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#DC4E41' }, style: { stroke: '#DC4E41' } },
      { id: 'e4-6', source: '4', target: '6', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
    ],
  },
  // PB-002: Phishing Investigation
  'PB-002': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'User Report', triggerType: 'manual', description: 'Phishing email reported', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'action',
        position: { x: 380, y: 200 },
        data: { label: 'Extract Email Headers', actionType: 'custom', description: 'Parse email metadata' } as any,
      },
      {
        id: '3',
        type: 'action',
        position: { x: 380, y: 350 },
        data: { label: 'Extract URLs & Attachments', actionType: 'custom', description: 'Extract IOCs from email' } as any,
      },
      {
        id: '4',
        type: 'parallel',
        position: { x: 350, y: 500 },
        data: { label: 'Parallel Analysis', branches: ['URL Check', 'Attachment Sandbox', 'Sender Reputation'] } as any,
      },
      {
        id: '5',
        type: 'integration',
        position: { x: 150, y: 700 },
        data: { label: 'VirusTotal Scan', integrationType: 'threat-intel', connectionStatus: 'connected' } as any,
      },
      {
        id: '6',
        type: 'integration',
        position: { x: 380, y: 700 },
        data: { label: 'Sandbox Analysis', integrationType: 'sandbox', connectionStatus: 'connected' } as any,
      },
      {
        id: '7',
        type: 'integration',
        position: { x: 610, y: 700 },
        data: { label: 'Check Sender', integrationType: 'email', connectionStatus: 'connected' } as any,
      },
      {
        id: '8',
        type: 'decision',
        position: { x: 355, y: 900 },
        data: { label: 'Is Malicious?', condition: 'threat_score > 70', outcomes: { yes: 'Block', no: 'Monitor' } } as any,
      },
      {
        id: '9',
        type: 'action',
        position: { x: 150, y: 1100 },
        data: { label: 'Block Sender', actionType: 'email', description: 'Add to blocklist' } as any,
      },
      {
        id: '10',
        type: 'action',
        position: { x: 380, y: 1100 },
        data: { label: 'Find Affected Users', actionType: 'custom', description: 'Search mailboxes' } as any,
      },
      {
        id: '11',
        type: 'action',
        position: { x: 610, y: 1100 },
        data: { label: 'Log to SIEM', actionType: 'custom', description: 'Record incident' } as any,
      },
      {
        id: '12',
        type: 'action',
        position: { x: 380, y: 1300 },
        data: { label: 'Notify Security Team', actionType: 'slack', description: '#phishing-alerts' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e3-4', source: '3', target: '4', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e4-5', source: '4', target: '5', type: 'labeled', data: { label: 'Branch 1' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#9333EA' }, style: { stroke: '#9333EA' } },
      { id: 'e4-6', source: '4', target: '6', type: 'labeled', data: { label: 'Branch 2' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#9333EA' }, style: { stroke: '#9333EA' } },
      { id: 'e4-7', source: '4', target: '7', type: 'labeled', data: { label: 'Branch 3' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#9333EA' }, style: { stroke: '#9333EA' } },
      { id: 'e5-8', source: '5', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e6-8', source: '6', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e7-8', source: '7', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e8-9', source: '8', sourceHandle: 'yes', target: '9', type: 'labeled', data: { label: 'Yes' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e8-10', source: '8', sourceHandle: 'yes', target: '10', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e8-11', source: '8', sourceHandle: 'no', target: '11', type: 'labeled', data: { label: 'No' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#DC4E41' }, style: { stroke: '#DC4E41' } },
      { id: 'e9-12', source: '9', target: '12', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e10-12', source: '10', target: '12', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
    ],
  },
  // PB-003: IOC Enrichment
  'PB-003': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'New Alert', triggerType: 'alert', description: 'Alert with IOCs received', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'action',
        position: { x: 380, y: 200 },
        data: { label: 'Extract IOCs', actionType: 'custom', description: 'Parse IPs, domains, hashes' } as any,
      },
      {
        id: '3',
        type: 'loop',
        position: { x: 355, y: 380 },
        data: { label: 'For Each IOC', iterator: 'ioc', collection: 'extracted_iocs', maxIterations: 100 } as any,
      },
      {
        id: '4',
        type: 'integration',
        position: { x: 150, y: 580 },
        data: { label: 'VirusTotal', integrationType: 'threat-intel', connectionStatus: 'connected' } as any,
      },
      {
        id: '5',
        type: 'integration',
        position: { x: 380, y: 580 },
        data: { label: 'AbuseIPDB', integrationType: 'threat-intel', connectionStatus: 'connected' } as any,
      },
      {
        id: '6',
        type: 'integration',
        position: { x: 610, y: 580 },
        data: { label: 'Shodan', integrationType: 'osint', connectionStatus: 'connected' } as any,
      },
      {
        id: '7',
        type: 'action',
        position: { x: 380, y: 780 },
        data: { label: 'Aggregate Results', actionType: 'custom', description: 'Combine TI data' } as any,
      },
      {
        id: '8',
        type: 'action',
        position: { x: 380, y: 950 },
        data: { label: 'Update Alert', actionType: 'custom', description: 'Add enrichment data' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e3-4', source: '3', target: '4', type: 'labeled', data: { label: 'Loop' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#14B8A6' }, style: { stroke: '#14B8A6' } },
      { id: 'e3-5', source: '3', target: '5', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#14B8A6' }, style: { stroke: '#14B8A6' } },
      { id: 'e3-6', source: '3', target: '6', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#14B8A6' }, style: { stroke: '#14B8A6' } },
      { id: 'e4-7', source: '4', target: '7', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e5-7', source: '5', target: '7', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e6-7', source: '6', target: '7', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e7-8', source: '7', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
    ],
  },
  // PB-004: Credential Reset
  'PB-004': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'Credential Compromise', triggerType: 'alert', description: 'Compromised credentials detected', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'integration',
        position: { x: 380, y: 220 },
        data: { label: 'Get User Info', integrationType: 'directory', connectionStatus: 'connected' } as any,
      },
      {
        id: '3',
        type: 'action',
        position: { x: 380, y: 400 },
        data: { label: 'Force Password Reset', actionType: 'custom', description: 'Reset via AD' } as any,
      },
      {
        id: '4',
        type: 'action',
        position: { x: 380, y: 580 },
        data: { label: 'Revoke Sessions', actionType: 'custom', description: 'Invalidate all tokens' } as any,
      },
      {
        id: '5',
        type: 'action',
        position: { x: 380, y: 760 },
        data: { label: 'Notify User', actionType: 'email', description: 'Send reset instructions' } as any,
      },
      {
        id: '6',
        type: 'integration',
        position: { x: 380, y: 940 },
        data: { label: 'Log Incident', integrationType: 'ticketing', connectionStatus: 'connected' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e3-4', source: '3', target: '4', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e4-5', source: '4', target: '5', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e5-6', source: '5', target: '6', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
    ],
  },
  // PB-005: Lateral Movement Hunt
  'PB-005': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'Scheduled Hunt', triggerType: 'schedule', description: 'Daily at 06:00 UTC', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'action',
        position: { x: 380, y: 200 },
        data: { label: 'Query Login Events', actionType: 'custom', description: 'SIEM query for auth logs' } as any,
      },
      {
        id: '3',
        type: 'action',
        position: { x: 380, y: 350 },
        data: { label: 'Query Process Creation', actionType: 'custom', description: 'EDR process events' } as any,
      },
      {
        id: '4',
        type: 'action',
        position: { x: 380, y: 500 },
        data: { label: 'Analyze Network Flow', actionType: 'custom', description: 'Check lateral connections' } as any,
      },
      {
        id: '5',
        type: 'decision',
        position: { x: 355, y: 680 },
        data: { label: 'Suspicious Activity?', condition: 'anomaly_score > threshold', outcomes: { yes: 'Alert', no: 'Log' } } as any,
      },
      {
        id: '6',
        type: 'action',
        position: { x: 150, y: 880 },
        data: { label: 'Create Hunt Alert', actionType: 'custom', description: 'High priority alert' } as any,
      },
      {
        id: '7',
        type: 'action',
        position: { x: 380, y: 880 },
        data: { label: 'Notify Threat Hunters', actionType: 'slack', description: '#threat-hunting' } as any,
      },
      {
        id: '8',
        type: 'action',
        position: { x: 610, y: 880 },
        data: { label: 'Log Results', actionType: 'custom', description: 'Store hunt results' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e3-4', source: '3', target: '4', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e4-5', source: '4', target: '5', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#F79836' }, style: { stroke: '#F79836' } },
      { id: 'e5-6', source: '5', sourceHandle: 'yes', target: '6', type: 'labeled', data: { label: 'Yes' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e5-7', source: '5', sourceHandle: 'yes', target: '7', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e5-8', source: '5', sourceHandle: 'no', target: '8', type: 'labeled', data: { label: 'No' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#DC4E41' }, style: { stroke: '#DC4E41' } },
    ],
  },
  // PB-006: Vulnerability Response
  'PB-006': {
    nodes: [
      {
        id: '1',
        type: 'trigger',
        position: { x: 400, y: 50 },
        data: { label: 'Vulnerability Scan', triggerType: 'webhook', description: 'New scan results received', status: 'active' } as any,
      },
      {
        id: '2',
        type: 'action',
        position: { x: 380, y: 200 },
        data: { label: 'Parse Scan Results', actionType: 'custom', description: 'Extract vulnerabilities' } as any,
      },
      {
        id: '3',
        type: 'decision',
        position: { x: 355, y: 380 },
        data: { label: 'CVSS >= 9.0?', condition: 'cvss >= 9.0', outcomes: { yes: 'Critical', no: 'Check High' } } as any,
      },
      {
        id: '4',
        type: 'action',
        position: { x: 100, y: 580 },
        data: { label: 'Create Critical Ticket', actionType: 'custom', description: 'P1 - Immediate action' } as any,
      },
      {
        id: '5',
        type: 'decision',
        position: { x: 500, y: 580 },
        data: { label: 'CVSS >= 7.0?', condition: 'cvss >= 7.0', outcomes: { yes: 'High', no: 'Normal' } } as any,
      },
      {
        id: '6',
        type: 'action',
        position: { x: 350, y: 780 },
        data: { label: 'Create High Ticket', actionType: 'custom', description: 'P2 - Within 24h' } as any,
      },
      {
        id: '7',
        type: 'action',
        position: { x: 650, y: 780 },
        data: { label: 'Create Normal Ticket', actionType: 'custom', description: 'P3 - Standard SLA' } as any,
      },
      {
        id: '8',
        type: 'action',
        position: { x: 380, y: 980 },
        data: { label: 'Update Asset DB', actionType: 'custom', description: 'Record vulnerability' } as any,
      },
    ],
    edges: [
      { id: 'e1-2', source: '1', target: '2', type: 'labeled', animated: true, markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e2-3', source: '2', target: '3', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#F79836' }, style: { stroke: '#F79836' } },
      { id: 'e3-4', source: '3', sourceHandle: 'yes', target: '4', type: 'labeled', data: { label: 'Critical' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#DC4E41' }, style: { stroke: '#DC4E41' } },
      { id: 'e3-5', source: '3', sourceHandle: 'no', target: '5', type: 'labeled', data: { label: 'No' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#F79836' }, style: { stroke: '#F79836' } },
      { id: 'e5-6', source: '5', sourceHandle: 'yes', target: '6', type: 'labeled', data: { label: 'High' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#F79836' }, style: { stroke: '#F79836' } },
      { id: 'e5-7', source: '5', sourceHandle: 'no', target: '7', type: 'labeled', data: { label: 'Normal' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#5CC05C' }, style: { stroke: '#5CC05C' } },
      { id: 'e4-8', source: '4', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e6-8', source: '6', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
      { id: 'e7-8', source: '7', target: '8', type: 'labeled', markerEnd: { type: MarkerType.ArrowClosed, color: '#00A4A6' }, style: { stroke: '#00A4A6' } },
    ],
  },
};

// Helper function to get playbook flow by ID
function getPlaybookFlow(id: string | undefined): { nodes: Node[]; edges: Edge[]; name?: string; description?: string; status?: string; category?: string; variables?: PlaybookVariable[] } {
  if (!id || id === 'new') {
    return { nodes: [], edges: [] };
  }

  // First check localStorage for saved playbooks
  const savedData = localStorage.getItem(`playbook-${id}`);
  if (savedData) {
    try {
      const parsed = JSON.parse(savedData);
      return {
        nodes: (parsed.nodes || []).map((n: any) => ({
          ...n,
          position: n.position || { x: 0, y: 0 },
        })),
        edges: parsed.edges || [],
        name: parsed.name,
        description: parsed.description,
        status: parsed.status,
        category: parsed.category,
        variables: parsed.variables, // Load saved variables
      };
    } catch (e) {
      console.error('Failed to parse saved playbook:', e);
    }
  }

  // Fall back to predefined flows
  const flow = playbookFlows[id];
  if (flow) {
    return flow;
  }

  // Return empty for unknown IDs instead of defaulting to PB-001
  return { nodes: [], edges: [] };
}

export function PlaybookEditor() {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const isNew = !id || id === 'new';
  const shouldAutoRun = searchParams.get('run') === 'true';

  // Organization variables from store
  const { variables: organizationVariables } = useOrganizationVariables();

  // Helper to safely get string values from node data
  const getNodeDataString = (data: any, key: string, defaultValue = ''): string => {
    return (data[key] as string) || defaultValue;
  };

  const playbookFlow = getPlaybookFlow(id);
  const [nodes, setNodes, onNodesChange] = useNodesState(playbookFlow.nodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(playbookFlow.edges);
  const [selectedNode, setSelectedNode] = useState<Node | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Playbook metadata state
  const [playbookName, setPlaybookName] = useState(
    playbookFlow.name || (isNew ? 'New Playbook' : 'Untitled Playbook')
  );
  const [playbookDescription, setPlaybookDescription] = useState(
    playbookFlow.description || (isNew ? 'Create a new automation workflow' : '')
  );
  const [playbookStatus, setPlaybookStatus] = useState<'draft' | 'active' | 'inactive'>(
    (playbookFlow.status as 'draft' | 'active' | 'inactive') || 'draft'
  );
  const [playbookCategory, setPlaybookCategory] = useState(
    playbookFlow.category || 'Custom'
  );

  // Reload playbook data when id changes - API first, then localStorage fallback
  useEffect(() => {
    const loadPlaybook = async () => {
      // For new playbooks, use empty state
      if (isNew) {
        setNodes([]);
        setEdges([]);
        setPlaybookName('New Playbook');
        setPlaybookDescription('Create a new automation workflow');
        setPlaybookStatus('draft');
        setPlaybookCategory('Custom');
        setVariables([]);
        return;
      }

      // Try to load from API first
      try {
        const apiData = await getPlaybookWithDefinition(id!);
        if (apiData && apiData.definition) {
          const def = apiData.definition;
          // Parse nodes and edges from definition
          const loadedNodes = (def.nodes as Node[]) || [];
          const loadedEdges = (def.edges as Edge[]) || [];
          const loadedVars = (def.variables as PlaybookVariable[]) || [];

          setNodes(loadedNodes);
          setEdges(loadedEdges);
          setPlaybookName(apiData.name || apiData.display_name || 'Untitled Playbook');
          setPlaybookDescription(apiData.description || '');
          setPlaybookStatus((apiData.enabled ? 'active' : 'draft') as 'draft' | 'active' | 'inactive');
          setPlaybookCategory(apiData.category || 'Custom');
          setVariables(loadedVars);

          // Clear localStorage entry since we got fresh data from API
          localStorage.removeItem(`playbook-${id}`);
          return;
        }
      } catch (apiError) {
        console.warn('API load failed, trying localStorage:', apiError);
      }

      // Fall back to localStorage/predefined flows
      const flow = getPlaybookFlow(id);
      setNodes(flow.nodes);
      setEdges(flow.edges);
      setPlaybookName(flow.name || 'Untitled Playbook');
      setPlaybookDescription(flow.description || '');
      setPlaybookStatus((flow.status as 'draft' | 'active' | 'inactive') || 'draft');
      setPlaybookCategory(flow.category || 'Custom');
      if (flow.variables) {
        setVariables(flow.variables);
      }
    };

    loadPlaybook();
  }, [id, isNew, setNodes, setEdges]);

  // Sync selectedNode with nodes when nodes are updated
  useEffect(() => {
    if (selectedNode) {
      const updatedNode = nodes.find((n) => n.id === selectedNode.id);
      if (updatedNode && JSON.stringify(updatedNode.data) !== JSON.stringify(selectedNode.data)) {
        setSelectedNode(updatedNode);
      }
    }
  }, [nodes, selectedNode]);
  const [propertiesTab, setPropertiesTab] = useState<'node' | 'variables'>('node');

  // Variables state - load from saved playbook or use defaults for new playbooks
  const [variables, setVariables] = useState<PlaybookVariable[]>(
    playbookFlow.variables || (isNew ? [] : sampleVariables)
  );

  // Get trigger type from trigger node
  const triggerType = useMemo((): TriggerType => {
    const triggerNode = nodes.find(n => n.type === 'trigger');
    if (triggerNode) {
      const triggerData = triggerNode.data as any;
      if (triggerData?.triggerType) {
        return triggerData.triggerType as TriggerType;
      }
    }
    return 'manual'; // Default to manual if no trigger found
  }, [nodes]);

  // Get input schema based on trigger type + execution-scoped variables
  const inputSchema = useMemo((): PlaybookInputField[] => {
    // Base schema from trigger type
    const baseSchema = getPlaybookInputSchema(triggerType);

    // Add execution-scoped playbook variables as input fields
    const executionVars = variables
      .filter(v => v.scope === 'execution')
      .map((v, i) => variableToInputField(v, i));

    // Also include organization variables in test run inputs (they appear as pre-filled context)
    const orgExecutionVars = organizationVariables
      .map((v, i) => ({
        ...variableToInputField(v, 200 + i),
        group: 'Organization Variables',
        label: v.name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
      }));

    // Merge: base schema first, then custom variables, then org variables
    return [...baseSchema, ...executionVars, ...orgExecutionVars];
  }, [triggerType, variables]);

  // Dynamic test run inputs based on schema
  const [testRunInputs, setTestRunInputs] = useState<InputValues>(() =>
    getDefaultInputValues(TRIGGER_INPUT_SCHEMAS['alert'])
  );

  // Update inputs when schema changes (trigger type or variables)
  useEffect(() => {
    const defaults = getDefaultInputValues(inputSchema);

    // Also apply current values from execution-scoped variables
    variables
      .filter(v => v.scope === 'execution')
      .forEach(v => {
        if (v.value !== undefined && v.value !== null && v.value !== '') {
          defaults[v.name] = v.value;
        }
      });

    setTestRunInputs(defaults);
  }, [inputSchema, variables]);

  // Execution history state - starts empty, populated by Test Run
  const [executionHistory, setExecutionHistory] = useState<ExecutionRun[]>(initialExecutions);

  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const [reactFlowInstance, setReactFlowInstance] = useState<any>(null);

  // Test Run state
  interface TestRunLog {
    nodeId: string;
    message: string;
    status: 'info' | 'success' | 'error';
    timestamp: Date;
  }

  interface TestRunState {
    isRunning: boolean;
    currentNodeId: string | null;
    logs: TestRunLog[];
    progress: number;
    results: { success: number; failed: number; skipped: number };
  }

  const [testRunState, setTestRunState] = useState<TestRunState>({
    isRunning: false,
    currentNodeId: null,
    logs: [],
    progress: 0,
    results: { success: 0, failed: 0, skipped: 0 },
  });
  const [isTestRunPanelOpen, setIsTestRunPanelOpen] = useState(false);

  // Auto-open Test Run panel when navigated with ?run=true
  useEffect(() => {
    if (shouldAutoRun && !isNew && nodes.length > 0) {
      setIsTestRunPanelOpen(true);
    }
  }, [shouldAutoRun, isNew, nodes.length]);

  // Execution view state
  const [isExecutionPanelOpen, setIsExecutionPanelOpen] = useState(false);
  const [isProcessingMonitorOpen, setIsProcessingMonitorOpen] = useState(false);

  // Custom hooks for n8n-style features
  const executionStore = useExecutionStore();
  const { isConnected, connect: connectWs, disconnect: disconnectWs } = useExecutionWebSocket({
    executionId: executionStore.execution?.executionId || null
  });
  const { upstreamNodes } = useNodeOutputSchema({
    currentNodeId: selectedNode?.id || '',
    nodes,
    edges
  });

  // Connect handler
  const onConnect = useCallback(
    (params: Connection) => {
      // Determine edge color based on source node type
      let edgeColor = '#64748b';
      let animated = false;

      const sourceNode = nodes.find((n) => n.id === params.source);
      if (sourceNode?.type === 'trigger') {
        edgeColor = '#5CC05C';
        animated = true;
      } else if (sourceNode?.type === 'action') {
        edgeColor = '#00A4A6';
      } else if (sourceNode?.type === 'decision') {
        edgeColor = params.sourceHandle === 'yes' ? '#5CC05C' : '#DC4E41';
      } else if (sourceNode?.type === 'integration') {
        edgeColor = '#7B61FF';
      } else if (sourceNode?.type === 'loop') {
        edgeColor = params.sourceHandle === 'loop' ? '#F79836' : '#F79836';
        animated = params.sourceHandle === 'loop';
      } else if (sourceNode?.type === 'parallel') {
        edgeColor = '#9B59B6';
      } else if (sourceNode?.type === 'wait') {
        edgeColor = '#3498DB';
      }

      const newEdge: Edge = {
        ...params,
        id: `e${params.source}-${params.target}`,
        type: 'labeled',
        animated,
        data: { animated },
        markerEnd: { type: MarkerType.ArrowClosed, color: edgeColor },
        style: { stroke: edgeColor },
      };

      setEdges((eds) => addEdge(newEdge, eds));
    },
    [setEdges, nodes]
  );

  // Add node from palette
  const onDragOver = useCallback((event: React.DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }, []);

  const onDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault();

      const type = event.dataTransfer.getData('application/reactflow-type');
      const label = event.dataTransfer.getData('application/reactflow-label');
      const nodeData = event.dataTransfer.getData('application/reactflow-data');

      if (!type || !reactFlowInstance) return;

      const position = reactFlowInstance.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });

      const newNode: Node = {
        id: `${type}-${Date.now()}`,
        type,
        position,
        data: { label, ...JSON.parse(nodeData) },
      };

      setNodes((nds) => [...nds, newNode]);
    },
    [reactFlowInstance, setNodes]
  );

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // Auto layout
  const autoLayout = useCallback(() => {
    // Simple vertical layout
    const layoutedNodes = nodes.map((node, index) => ({
      ...node,
      position: { x: 400, y: index * 200 + 50 },
    }));
    setNodes(layoutedNodes);
    toast({
      title: 'Layout Applied',
      description: 'Nodes have been auto-arranged.',
    });
  }, [nodes, setNodes]);

  // Save state
  const [isSaving, setIsSaving] = useState(false);
  const [isDeploying, setIsDeploying] = useState(false);

  // Save playbook handler - saves to API with localStorage fallback
  const handleSave = useCallback(async () => {
    setIsSaving(true);
    try {
      // Generate a proper ID for new playbooks
      const playbookId = id && id !== 'new' ? id : `PB-${Date.now()}`;
      const isNewPlaybook = !id || id === 'new';

      // Prepare nodes and edges data
      const nodesData = nodes.map(n => ({
        id: n.id,
        type: n.type,
        position: n.position,
        data: n.data,
      }));

      const edgesData = edges.map(e => ({
        id: e.id,
        source: e.source,
        target: e.target,
        sourceHandle: e.sourceHandle,
        targetHandle: e.targetHandle,
        type: e.type,
        data: e.data,
      }));

      // Determine trigger type from trigger node
      const triggerNode = nodes.find(n => n.type === 'trigger');
      const triggerTypeValue = (triggerNode?.data as Record<string, unknown>)?.triggerType as string || 'manual';

      // Prepare API request
      const request: PlaybookSaveRequest = {
        id: playbookId,
        name: playbookName,
        display_name: playbookName,
        description: playbookDescription,
        category: playbookCategory,
        status: playbookStatus,
        trigger_type: triggerTypeValue,
        enabled: playbookStatus === 'active',
        tags: [],
        nodes: nodesData,
        edges: edgesData,
        variables: variables,
      };

      let savedToApi = false;

      // Try to save to API
      try {
        if (isNewPlaybook) {
          const response = await savePlaybook(request);
          // Update URL if new playbook was created with a new ID
          if (response.id && response.id !== playbookId) {
            window.history.replaceState(null, '', `/playbooks/${response.id}`);
          }
        } else {
          await updatePlaybook(playbookId, request);
        }
        savedToApi = true;
      } catch (apiError) {
        console.warn('API save failed, using localStorage fallback:', apiError);
      }

      // Also save to localStorage as cache/fallback
      const playbookData = {
        id: playbookId,
        name: playbookName,
        description: playbookDescription,
        category: playbookCategory,
        status: playbookStatus,
        triggers: ['Manual'],
        nodes: nodesData,
        edges: edgesData,
        variables,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      localStorage.setItem(`playbook-${playbookId}`, JSON.stringify(playbookData));

      toast({
        title: 'Playbook Saved',
        description: savedToApi
          ? `Successfully saved "${playbookName}" to database.`
          : `Saved "${playbookName}" locally. API not available.`,
        variant: savedToApi ? 'success' : 'default',
      });
    } catch (error) {
      console.error('Failed to save playbook:', error);
      toast({
        title: 'Save Failed',
        description: 'An error occurred while saving the playbook.',
        variant: 'destructive',
      });
    } finally {
      setIsSaving(false);
    }
  }, [id, playbookName, playbookDescription, playbookCategory, playbookStatus, nodes, edges, variables]);

  // Deploy playbook handler - calls SOAR backend API
  const handleDeploy = useCallback(async () => {
    if (nodes.length === 0) {
      toast({
        title: 'Cannot Deploy',
        description: 'Add at least one node before deploying.',
        variant: 'destructive',
      });
      return;
    }

    // Validate: must have trigger node
    const hasTrigger = nodes.some(n => n.type === 'trigger');
    if (!hasTrigger) {
      toast({
        title: 'Cannot Deploy',
        description: 'Playbook must have at least one trigger node.',
        variant: 'destructive',
      });
      return;
    }

    setIsDeploying(true);
    try {
      // Find trigger node to get trigger configuration
      const triggerNode = nodes.find(n => n.type === 'trigger');
      const triggerData = triggerNode?.data as Record<string, unknown> | undefined;

      // Build deploy request from frontend state
      const deployRequest: PlaybookDeployRequest = {
        id: id || `pb-${Date.now()}`,
        name: playbookName.toLowerCase().replace(/\s+/g, '_'),
        display_name: playbookName,
        description: playbookDescription,
        category: playbookCategory.toLowerCase(),
        enabled: true,
        version: 1,
        trigger: {
          type: (triggerData?.triggerType as string) || 'manual',
          conditions: triggerData?.conditions as PlaybookDeployRequest['trigger']['conditions'],
        },
        steps: convertNodesToSteps(nodes, edges),
        variables: variables.map(v => ({
          name: v.name,
          type: v.type,
          value: v.value,
        })),
      };

      // Call backend API
      const response = await deployPlaybook(deployRequest);

      // Update local state to active
      setPlaybookStatus('active');

      // Save to localStorage as well for offline access
      const playbookData = {
        id: response.id || deployRequest.id,
        name: playbookName,
        description: playbookDescription,
        status: 'active',
        category: playbookCategory,
        nodes,
        edges,
        variables,
        version: response.version || 1,
        deployedAt: new Date().toISOString(),
        workflowId: response.workflow_id,
      };
      localStorage.setItem(`playbook-${playbookData.id}`, JSON.stringify(playbookData));

      // Create execution record for deployment
      const newExecution: ExecutionRun = {
        id: `deploy-${Date.now()}`,
        status: 'success',
        startedAt: new Date(),
        completedAt: new Date(),
        duration: 0,
        triggeredBy: 'deployment',
        nodesExecuted: nodes.length,
        totalNodes: nodes.length,
      };
      setExecutionHistory(prev => [newExecution, ...prev]);

      toast({
        title: 'Playbook Deployed',
        description: `Successfully deployed to SOAR backend! ID: ${response.id || deployRequest.id}`,
        variant: 'success',
      });

    } catch (error) {
      console.error('Failed to deploy playbook:', error);

      // Fallback: save locally if backend is unavailable
      const playbookData = {
        id: id || `pb-${Date.now()}`,
        name: playbookName,
        description: playbookDescription,
        status: 'active',
        category: playbookCategory,
        nodes,
        edges,
        variables,
        deployedAt: new Date().toISOString(),
      };
      localStorage.setItem(`playbook-${playbookData.id}`, JSON.stringify(playbookData));

      toast({
        title: 'Deployed Locally',
        description: 'Backend unavailable. Playbook saved locally and will sync when backend is online.',
      });
    } finally {
      setIsDeploying(false);
    }
  }, [id, nodes, edges, playbookName, playbookDescription, playbookCategory, variables]);

  // Test Run simulation - executes playbook with current input values
  const startTestRun = useCallback(async () => {
    if (nodes.length === 0) {
      toast({
        title: 'No Nodes',
        description: 'Add nodes to the playbook before running a test.',
        variant: 'destructive',
      });
      return;
    }

    // Log input parameters being used for this execution
    console.log('Starting test run with inputs:', testRunInputs);
    setTestRunState({
      isRunning: true,
      currentNodeId: null,
      logs: [],
      progress: 0,
      results: { success: 0, failed: 0, skipped: 0 },
    });

    // Initialize execution store and WebSocket for demo purposes
    const executionId = `exec-${Date.now()}-${Math.random().toString(36).substring(7)}`;
    executionStore.initExecution(executionId);

    // Create new execution record in history
    const newExecution: ExecutionRun = {
      id: executionId,
      status: 'running',
      startedAt: new Date(),
      triggeredBy: 'manual',
      nodesExecuted: 0,
      totalNodes: nodes.length,
    };
    setExecutionHistory((prev) => [newExecution, ...prev]);

    // IMPORTANT: Register the message handler BEFORE starting execution
    // to ensure all events are captured in correct order
    const unsubscribe = mockWebSocketService.onMessage((message) => {
      if (message.executionId === executionId) {
        executionStore.handleWSMessage(message);

        // Handle approval required message
        if (message.type === 'approval:required') {
          const payload = message.payload as { nodeId: string; nodeName: string };
          setExecutionHistory((prev) =>
            prev.map((exec) => {
              if (exec.id === executionId) {
                return {
                  ...exec,
                  status: 'pending_approval' as const,
                  approval: {
                    required: true,
                    status: 'pending' as const,
                    requestedAt: new Date(),
                    currentStep: payload.nodeName,
                    nodeId: payload.nodeId,
                  },
                };
              }
              return exec;
            })
          );
        }
      }
    });

    // Start mock WebSocket execution in background (for ExecutionPanel demo)
    mockWebSocketService.startExecution(executionId, nodes, edges).finally(() => {
      // Cleanup handler when execution completes
      unsubscribe();

      // Update execution history with final status
      setExecutionHistory((prev) =>
        prev.map((exec) => {
          if (exec.id === executionId && exec.status === 'running') {
            return {
              ...exec,
              status: 'success' as const,
              completedAt: new Date(),
              duration: Date.now() - exec.startedAt.getTime(),
              nodesExecuted: nodes.length,
            };
          }
          return exec;
        })
      );
    });

    // Execute playbook with proper conditional branching
    const triggerNodes = nodes.filter((n) => n.type === 'trigger');
    if (triggerNodes.length === 0) {
      setTestRunState((prev) => ({
        ...prev,
        isRunning: false,
        logs: [
          {
            nodeId: 'system',
            message: 'No trigger nodes found',
            status: 'error',
            timestamp: new Date(),
          },
        ],
      }));
      return;
    }

    // Track execution state
    const visited = new Set<string>();
    const skippedNodes = new Set<string>();
    let successCount = 0;
    let failedCount = 0;
    let skippedCount = 0;

    // Get next nodes based on current node and decision results
    const getNextNodes = (currentId: string, decisionResult?: boolean): Node[] => {
      const outgoingEdges = edges.filter((e) => e.source === currentId);

      // For decision nodes, filter by the correct branch
      const currentNode = nodes.find(n => n.id === currentId);
      if (currentNode?.type === 'decision' && decisionResult !== undefined) {
        const branchHandle = decisionResult ? 'yes' : 'no';
        const filteredEdges = outgoingEdges.filter(e => e.sourceHandle === branchHandle);
        return filteredEdges
          .map(e => nodes.find(n => n.id === e.target))
          .filter((n): n is Node => n !== undefined);
      }

      return outgoingEdges
        .map(e => nodes.find(n => n.id === e.target))
        .filter((n): n is Node => n !== undefined);
    };

    // Mark nodes on skipped branch
    const markSkippedBranch = (currentId: string, skippedHandle: string) => {
      const skippedEdges = edges.filter(e => e.source === currentId && e.sourceHandle === skippedHandle);
      const bfsQueue = skippedEdges.map(e => e.target);

      while (bfsQueue.length > 0) {
        const nodeId = bfsQueue.shift()!;
        if (skippedNodes.has(nodeId) || visited.has(nodeId)) continue;
        skippedNodes.add(nodeId);

        // Find children of skipped node
        const childEdges = edges.filter(e => e.source === nodeId);
        childEdges.forEach(e => bfsQueue.push(e.target));
      }
    };

    // Execute a single node
    const executeNode = async (node: Node): Promise<{ success: boolean; decisionResult?: boolean }> => {
      // Set node to running/evaluating state
      setNodes((nds) =>
        nds.map((n) =>
          n.id === node.id
            ? {
                ...n,
                data: {
                  ...n.data,
                  status: n.type === 'trigger' ? 'active'
                       : n.type === 'decision' ? 'evaluating'
                       : 'running',
                } as any,
              }
            : n
        )
      );

      setTestRunState((prev) => ({
        ...prev,
        currentNodeId: node.id,
        logs: [
          ...prev.logs,
          {
            nodeId: node.id,
            message: `Executing: ${(node.data as any).label || node.id}`,
            status: 'info',
            timestamp: new Date(),
          },
        ],
      }));

      // Simulate execution delay
      await new Promise((resolve) => setTimeout(resolve, 1200));

      if (node.type === 'decision') {
        // Evaluate condition (random for demo, would use real logic in production)
        const conditionResult = Math.random() > 0.5;

        setNodes((nds) =>
          nds.map((n) =>
            n.id === node.id
              ? {
                  ...n,
                  data: {
                    ...n.data,
                    status: 'evaluated',
                    conditionResult,
                  } as any,
                }
              : n
          )
        );

        setTestRunState((prev) => ({
          ...prev,
          logs: [
            ...prev.logs,
            {
              nodeId: node.id,
              message: `Condition "${(node.data as any).condition || 'default'}" evaluated: ${conditionResult ? 'YES (true)' : 'NO (false)'}`,
              status: 'success',
              timestamp: new Date(),
            },
          ],
        }));

        return { success: true, decisionResult: conditionResult };
      } else {
        // Regular node execution (90% success rate for demo)
        const isSuccess = Math.random() > 0.1;

        setNodes((nds) =>
          nds.map((n) =>
            n.id === node.id
              ? {
                  ...n,
                  data: {
                    ...n.data,
                    status: isSuccess ? 'completed' : 'failed',
                    duration: Math.floor(Math.random() * 500) + 100,
                  } as any,
                }
              : n
          )
        );

        setTestRunState((prev) => ({
          ...prev,
          logs: [
            ...prev.logs,
            {
              nodeId: node.id,
              message: isSuccess ? 'Completed successfully' : 'Execution failed',
              status: isSuccess ? 'success' : 'error',
              timestamp: new Date(),
            },
          ],
        }));

        return { success: isSuccess };
      }
    };

    // BFS execution with proper branching
    const queue: Node[] = [...triggerNodes];
    let totalProcessed = 0;
    const estimatedTotal = nodes.length;

    while (queue.length > 0) {
      const current = queue.shift()!;

      if (visited.has(current.id)) continue;
      if (skippedNodes.has(current.id)) {
        // Mark as skipped in UI
        setNodes((nds) =>
          nds.map((n) =>
            n.id === current.id
              ? { ...n, data: { ...n.data, status: 'skipped' } as any }
              : n
          )
        );
        setTestRunState((prev) => ({
          ...prev,
          logs: [
            ...prev.logs,
            {
              nodeId: current.id,
              message: `Skipped (branch not taken)`,
              status: 'info',
              timestamp: new Date(),
            },
          ],
        }));
        skippedCount++;
        continue;
      }

      visited.add(current.id);
      totalProcessed++;

      // Update progress
      setTestRunState((prev) => ({
        ...prev,
        progress: Math.min((totalProcessed / estimatedTotal) * 100, 95),
      }));

      // Execute the node
      const result = await executeNode(current);

      if (result.success) {
        successCount++;
      } else {
        failedCount++;
      }

      // Get next nodes to execute
      if (current.type === 'decision' && result.decisionResult !== undefined) {
        // For decision nodes, mark the skipped branch
        const skippedHandle = result.decisionResult ? 'no' : 'yes';
        markSkippedBranch(current.id, skippedHandle);

        // Only queue nodes from the taken branch
        const nextNodes = getNextNodes(current.id, result.decisionResult);
        nextNodes.forEach(n => {
          if (!visited.has(n.id) && !skippedNodes.has(n.id)) {
            queue.push(n);
          }
        });
      } else {
        // For other nodes, queue all children
        const nextNodes = getNextNodes(current.id);
        nextNodes.forEach(n => {
          if (!visited.has(n.id)) {
            queue.push(n);
          }
        });
      }

      // Update results
      setTestRunState((prev) => ({
        ...prev,
        results: {
          success: successCount,
          failed: failedCount,
          skipped: skippedCount,
        },
      }));
    }

    // Mark any remaining unvisited nodes as skipped
    nodes.forEach(node => {
      if (!visited.has(node.id) && !skippedNodes.has(node.id) && node.type !== 'trigger') {
        setNodes((nds) =>
          nds.map((n) =>
            n.id === node.id
              ? { ...n, data: { ...n.data, status: 'skipped' } as any }
              : n
          )
        );
      }
    });

    setTestRunState((prev) => ({
      ...prev,
      isRunning: false,
      currentNodeId: null,
      progress: 100,
      results: {
        success: successCount,
        failed: failedCount,
        skipped: skippedCount,
      },
    }));
  }, [nodes, edges, setNodes, testRunInputs]);

  const stopTestRun = useCallback(() => {
    setTestRunState((prev) => ({
      ...prev,
      isRunning: false,
      currentNodeId: null,
    }));

    // Reset node statuses
    setNodes((nds) =>
      nds.map((n) => ({
        ...n,
        data: {
          ...n.data,
          status: undefined,
          conditionResult: undefined,
          duration: undefined,
        } as any,
      }))
    );
  }, [setNodes]);

  const resetTestRun = useCallback(() => {
    setTestRunState({
      isRunning: false,
      currentNodeId: null,
      logs: [],
      progress: 0,
      results: { success: 0, failed: 0, skipped: 0 },
    });

    // Reset node statuses
    setNodes((nds) =>
      nds.map((n) => ({
        ...n,
        data: {
          ...n.data,
          status: undefined,
          conditionResult: undefined,
          duration: undefined,
        } as any,
      }))
    );
  }, [setNodes]);

  // Update node data helper
  const updateNodeData = useCallback(
    (nodeId: string, newData: Partial<any>) => {
      setNodes((nds) =>
        nds.map((n) =>
          n.id === nodeId ? { ...n, data: { ...n.data, ...newData } } : n
        )
      );
    },
    [setNodes]
  );

  // Variable handlers
  const handleAddVariable = useCallback((variable: Omit<PlaybookVariable, 'id'>) => {
    const newVariable: PlaybookVariable = {
      ...variable,
      id: `var-${Date.now()}`,
    };
    setVariables((prev) => [...prev, newVariable]);
  }, []);

  const handleUpdateVariable = useCallback((id: string, updates: Partial<PlaybookVariable>) => {
    setVariables((prev) =>
      prev.map((v) => (v.id === id ? { ...v, ...updates } : v))
    );
  }, []);

  const handleDeleteVariable = useCallback((id: string) => {
    setVariables((prev) => prev.filter((v) => v.id !== id));
  }, []);

  // Handle execution selection for highlighting nodes
  const handleSelectExecution = useCallback((execution: ExecutionRun) => {
    // Could highlight nodes based on execution logs
    console.log('Selected execution:', execution.id);
  }, []);

  // Handle approval workflow
  const handleApproveExecution = useCallback((executionId: string, comment?: string) => {
    setExecutionHistory((prev) =>
      prev.map((exec) => {
        if (exec.id === executionId && exec.status === 'pending_approval') {
          return {
            ...exec,
            status: 'running' as const,
            approval: exec.approval
              ? {
                  ...exec.approval,
                  status: 'approved' as const,
                  respondedAt: new Date(),
                  respondedBy: 'admin',
                  comment,
                }
              : undefined,
          };
        }
        return exec;
      })
    );

    // Resume the execution via WebSocket
    const execution = executionHistory.find((e) => e.id === executionId);
    if (execution?.approval?.nodeId) {
      mockWebSocketService.approveNode(executionId, execution.approval.nodeId, comment);
    }

    toast({
      title: 'Execution Approved',
      description: `Approved by admin at ${new Date().toLocaleTimeString()}. Workflow will continue.`,
      variant: 'success',
    });
  }, [executionHistory]);

  const handleRejectExecution = useCallback((executionId: string, comment?: string) => {
    setExecutionHistory((prev) =>
      prev.map((exec) => {
        if (exec.id === executionId && exec.status === 'pending_approval') {
          return {
            ...exec,
            status: 'cancelled' as const,
            completedAt: new Date(),
            duration: Date.now() - exec.startedAt.getTime(),
            approval: exec.approval
              ? {
                  ...exec.approval,
                  status: 'rejected' as const,
                  respondedAt: new Date(),
                  respondedBy: 'admin',
                  comment,
                }
              : undefined,
          };
        }
        return exec;
      })
    );

    // Reject the execution via WebSocket
    const execution = executionHistory.find((e) => e.id === executionId);
    if (execution?.approval?.nodeId) {
      mockWebSocketService.rejectNode(executionId, execution.approval.nodeId, comment);
    }

    toast({
      title: 'Execution Rejected',
      description: 'Workflow has been cancelled due to rejection.',
      variant: 'destructive',
    });
  }, [executionHistory]);

  return (
    <div
      className={cn(
        'flex flex-col animate-fade-in',
        isFullscreen ? 'fixed inset-0 z-50 bg-background' : 'h-[calc(100vh-140px)]'
      )}
    >
      {/* Header */}
      <div className="flex items-center justify-between pb-4 px-4 shrink-0 border-b border-border/50 bg-background/95 backdrop-blur-sm">
        <div className="flex items-center gap-4">
          <Link to="/playbooks">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="w-5 h-5" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <Input
                value={playbookName}
                onChange={(e) => setPlaybookName(e.target.value)}
                className="text-lg font-display font-bold border-none p-0 h-auto focus-visible:ring-0 max-w-[300px]"
                placeholder="Enter playbook name..."
              />
              <Badge
                variant="outline"
                className={cn(
                  playbookStatus === 'active' && 'text-[#5CC05C] border-[#5CC05C]/50',
                  playbookStatus === 'draft' && 'text-[#F79836] border-[#F79836]/50',
                  playbookStatus === 'inactive' && 'text-muted-foreground border-border'
                )}
              >
                {playbookStatus.charAt(0).toUpperCase() + playbookStatus.slice(1)}
              </Badge>
            </div>
            <Input
              value={playbookDescription}
              onChange={(e) => setPlaybookDescription(e.target.value)}
              className="text-sm text-muted-foreground border-none p-0 h-auto focus-visible:ring-0 max-w-[400px]"
              placeholder="Enter description..."
            />
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="icon"
            onClick={() => {
              toast({
                title: 'Undo',
                description: 'Undo action triggered (Ctrl+Z)',
              });
            }}
            title="Undo (Ctrl+Z)"
          >
            <Undo2 className="w-4 h-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            onClick={() => {
              toast({
                title: 'Redo',
                description: 'Redo action triggered (Ctrl+Y)',
              });
            }}
            title="Redo (Ctrl+Y)"
          >
            <Redo2 className="w-4 h-4" />
          </Button>
          <Button variant="outline" size="icon" onClick={autoLayout}>
            <Grid3x3 className="w-4 h-4" />
          </Button>
          <Separator orientation="vertical" className="h-6" />
          <Button
            variant="outline"
            onClick={() => setIsTestRunPanelOpen(true)}
            disabled={testRunState.isRunning}
          >
            <Play className="w-4 h-4 mr-2" />
            Test Run
          </Button>
          <Button
            variant="outline"
            onClick={() => setIsExecutionPanelOpen(true)}
          >
            <Activity className="w-4 h-4 mr-2" />
            Execution View
          </Button>
          <Button
            variant="outline"
            onClick={() => setIsProcessingMonitorOpen(true)}
          >
            <BarChart3 className="w-4 h-4 mr-2" />
            Monitor
          </Button>
          <Button variant="outline" onClick={handleSave} disabled={isSaving}>
            {isSaving ? (
              <RotateCcw className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Save className="w-4 h-4 mr-2" />
            )}
            {isSaving ? 'Saving...' : 'Save'}
          </Button>
          <Button onClick={handleDeploy} disabled={isDeploying}>
            {isDeploying ? (
              <RotateCcw className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Rocket className="w-4 h-4 mr-2" />
            )}
            {isDeploying ? 'Deploying...' : 'Deploy'}
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsFullscreen(!isFullscreen)}
          >
            {isFullscreen ? (
              <Minimize2 className="w-4 h-4" />
            ) : (
              <Maximize2 className="w-4 h-4" />
            )}
          </Button>
        </div>
      </div>

      <div className="flex gap-4 flex-1 min-h-0 p-4">
        {/* Node Palette */}
        <Card className="w-72 shrink-0 border-border/50 bg-card/50 backdrop-blur-sm">
          <CardHeader className="pb-3">
            <CardTitle className="text-base flex items-center gap-2">
              <Zap className="w-4 h-4 text-primary" />
              Components
            </CardTitle>
          </CardHeader>
          <CardContent className="h-[calc(100vh-320px)]">
            <NodePalette />
          </CardContent>
        </Card>

        {/* Canvas Area (includes canvas + execution history) */}
        <div className="flex-1 flex flex-col min-h-0 gap-0">
          {/* Canvas */}
          <div
            ref={reactFlowWrapper}
            className="flex-1 rounded-xl border-2 border-border/50 bg-muted/20 overflow-hidden relative"
          >
            <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            onInit={setReactFlowInstance}
            onDrop={onDrop}
            onDragOver={onDragOver}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            snapToGrid
            snapGrid={[20, 20]}
            connectionLineStyle={{
              stroke: '#00A4A6',
              strokeWidth: 2,
            }}
            defaultEdgeOptions={{
              type: 'labeled',
              style: { strokeWidth: 2 },
            }}
          >
            <Background
              variant={BackgroundVariant.Dots}
              gap={20}
              size={1}
              color="hsl(var(--muted-foreground) / 0.2)"
            />
            <Controls
              className="bg-card/90 backdrop-blur-sm border border-border/50 rounded-lg shadow-lg"
              showInteractive={false}
            />
            <MiniMap
              className="bg-card/90 backdrop-blur-sm border border-border/50 rounded-lg shadow-lg"
              nodeColor={(node) => {
                switch (node.type) {
                  case 'trigger':
                    return '#5CC05C';
                  case 'action':
                    return '#00A4A6';
                  case 'decision':
                    return '#F79836';
                  case 'integration':
                    return '#7B61FF';
                  case 'loop':
                    return '#F79836';
                  case 'parallel':
                    return '#9B59B6';
                  case 'wait':
                    return '#3498DB';
                  default:
                    return '#64748b';
                }
              }}
              maskColor="hsl(var(--background) / 0.8)"
            />
            <Panel position="top-left" className="bg-card/90 backdrop-blur-sm border border-border/50 rounded-lg px-3 py-2 shadow-lg">
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <span className="font-semibold text-foreground">
                  {nodes.length}
                </span>
                nodes
                <Separator orientation="vertical" className="h-4 mx-1" />
                <span className="font-semibold text-foreground">
                  {edges.length}
                </span>
                connections
              </div>
            </Panel>
          </ReactFlow>
          </div>

          {/* Execution History - inside canvas area */}
          <ExecutionHistory
            executions={executionHistory}
            onSelectExecution={handleSelectExecution}
            onApprove={handleApproveExecution}
            onReject={handleRejectExecution}
            className="shrink-0 rounded-b-xl"
          />
        </div>

        {/* Properties Panel */}
        <Card className="w-80 shrink-0 border-border/50 bg-card/50 backdrop-blur-sm">
          <CardHeader className="pb-3">
            <Tabs value={propertiesTab} onValueChange={(v) => setPropertiesTab(v as 'node' | 'variables')}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="node" className="text-xs">
                  <Zap className="w-3 h-3 mr-1" />
                  Node
                </TabsTrigger>
                <TabsTrigger value="variables" className="text-xs">
                  <Variable className="w-3 h-3 mr-1" />
                  Variables
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </CardHeader>
          <CardContent className="h-[calc(100vh-360px)]">
            {propertiesTab === 'variables' ? (
              <VariablePanel
                variables={variables}
                onAddVariable={handleAddVariable}
                onUpdateVariable={handleUpdateVariable}
                onDeleteVariable={handleDeleteVariable}
                selectedNodeId={selectedNode?.id}
                selectedNodeLabel={selectedNode?.data?.label as string | undefined}
              />
            ) : selectedNode ? (
              <ScrollArea className="h-full">
                <div className="space-y-4">
                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wide">
                      Node Type
                    </label>
                    <Badge variant="outline" className="mt-1 capitalize">
                      {selectedNode.type}
                    </Badge>
                  </div>

                  <div>
                    <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                      Label
                    </label>
                    <Input
                      value={selectedNode.data.label as string}
                      onChange={(e) =>
                        updateNodeData(selectedNode.id, { label: e.target.value })
                      }
                    />
                  </div>

                  {/* TriggerNode settings */}
                  {selectedNode.type === 'trigger' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Status
                        </label>
                        <Select
                          value={(selectedNode.data.status as string) || 'idle'}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, { status: value })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="idle">Idle</SelectItem>
                            <SelectItem value="active">Active</SelectItem>
                            <SelectItem value="disabled">Disabled</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Trigger Type
                        </label>
                        <Select
                          value={(selectedNode.data.triggerType as string) || ''}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, {
                              triggerType: value,
                            })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="alert">Alert</SelectItem>
                            <SelectItem value="schedule">Schedule</SelectItem>
                            <SelectItem value="webhook">Webhook</SelectItem>
                            <SelectItem value="manual">Manual</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {selectedNode.data.triggerType === 'alert' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Alert Source
                            </label>
                            <Input
                              value={(selectedNode.data.alertSource as string) || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  alertSource: e.target.value,
                                })
                              }
                              placeholder="SIEM, EDR, Firewall"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Alert Type
                            </label>
                            <Input
                              value={(selectedNode.data as any).alertType || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  alertType: e.target.value,
                                })
                              }
                              placeholder="Malware, Intrusion"
                            />
                          </div>
                        </>
                      )}

                      {selectedNode.data.triggerType === 'schedule' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Cron Expression
                            </label>
                            <Input
                              value={(selectedNode.data as any).cronExpression || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  cronExpression: e.target.value,
                                })
                              }
                              placeholder="0 0 * * *"
                              className="font-mono text-sm"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Timezone
                            </label>
                            <Select
                              value={(selectedNode.data as any).timezone || 'UTC'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  timezone: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="UTC">UTC</SelectItem>
                                <SelectItem value="Asia/Seoul">
                                  Asia/Seoul
                                </SelectItem>
                                <SelectItem value="America/New_York">
                                  America/New_York
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </>
                      )}

                      {selectedNode.data.triggerType === 'webhook' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Webhook URL (readonly)
                            </label>
                            <Input
                              value={
                                ((selectedNode.data as any).webhookUrl as string) ||
                                `https://api.soar.example.com/webhook/${selectedNode.id}`
                              }
                              readOnly
                              className="font-mono text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Auth Method
                            </label>
                            <Select
                              value={(selectedNode.data as any).authMethod || 'none'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  authMethod: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="none">None</SelectItem>
                                <SelectItem value="api_key">API Key</SelectItem>
                                <SelectItem value="bearer_token">
                                  Bearer Token
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </>
                      )}

                      {selectedNode.data.triggerType === 'manual' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Required Inputs
                          </label>
                          <Textarea
                            value={(selectedNode.data as any).requiredInputs || ''}
                            onChange={(e) =>
                              updateNodeData(selectedNode.id, {
                                requiredInputs: e.target.value,
                              })
                            }
                            placeholder="field1, field2, field3"
                            rows={2}
                          />
                        </div>
                      )}
                    </>
                  )}

                  {/* ActionNode settings */}
                  {selectedNode.type === 'action' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Action Type
                        </label>
                        <Select
                          value={(selectedNode.data as any).actionType}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, {
                              actionType: value,
                            })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="email">Email</SelectItem>
                            <SelectItem value="slack">Slack</SelectItem>
                            <SelectItem value="jira">Jira</SelectItem>
                            <SelectItem value="block_ip">Block IP</SelectItem>
                            <SelectItem value="isolate">Isolate</SelectItem>
                            <SelectItem value="custom">Custom</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {selectedNode.data.actionType === 'email' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Recipients (comma-separated)
                            </label>
                            <Input
                              value={(selectedNode.data as any).recipients || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  recipients: e.target.value,
                                })
                              }
                              placeholder="user1@example.com, user2@example.com"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Subject Template
                            </label>
                            <Input
                              value={(selectedNode.data as any).subject || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  subject: e.target.value,
                                })
                              }
                              placeholder="Alert: {{severity}} - {{title}}"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Body Template
                            </label>
                            <Textarea
                              value={(selectedNode.data as any).body || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  body: e.target.value,
                                })
                              }
                              placeholder="Alert details..."
                              rows={3}
                            />
                          </div>
                        </>
                      )}

                      {selectedNode.data.actionType === 'slack' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Channel
                            </label>
                            <Input
                              value={(selectedNode.data as any).channel || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  channel: e.target.value,
                                })
                              }
                              placeholder="#security-alerts"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Message Template
                            </label>
                            <Textarea
                              value={(selectedNode.data as any).messageTemplate || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  messageTemplate: e.target.value,
                                })
                              }
                              placeholder="{{severity}} alert detected..."
                              rows={3}
                            />
                          </div>
                        </>
                      )}

                      {selectedNode.data.actionType === 'jira' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Project Key
                            </label>
                            <Input
                              value={(selectedNode.data as any).project || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  project: e.target.value,
                                })
                              }
                              placeholder="SEC"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Issue Type
                            </label>
                            <Select
                              value={(selectedNode.data as any).issueType || 'Incident'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  issueType: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="Bug">Bug</SelectItem>
                                <SelectItem value="Task">Task</SelectItem>
                                <SelectItem value="Story">Story</SelectItem>
                                <SelectItem value="Incident">Incident</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Priority
                            </label>
                            <Select
                              value={(selectedNode.data as any).priority || 'High'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  priority: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="Highest">Highest</SelectItem>
                                <SelectItem value="High">High</SelectItem>
                                <SelectItem value="Medium">Medium</SelectItem>
                                <SelectItem value="Low">Low</SelectItem>
                                <SelectItem value="Lowest">Lowest</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Assignee
                            </label>
                            <Input
                              value={(selectedNode.data as any).assignee || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  assignee: e.target.value,
                                })
                              }
                              placeholder="john.doe"
                            />
                          </div>
                        </>
                      )}

                      {selectedNode.data.actionType === 'block_ip' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Firewall Integration
                            </label>
                            <Select
                              value={
                                ((selectedNode.data as any).firewallIntegration as string) || 'default'
                              }
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  firewallIntegration: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="default">
                                  Default Firewall
                                </SelectItem>
                                <SelectItem value="palo_alto">
                                  Palo Alto
                                </SelectItem>
                                <SelectItem value="checkpoint">
                                  Check Point
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Block Duration (minutes)
                            </label>
                            <Input
                              type="number"
                              value={(selectedNode.data as any).duration || '60'}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  duration: e.target.value,
                                })
                              }
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              IP Field Name
                            </label>
                            <Input
                              value={(selectedNode.data as any).ipField || 'src_ip'}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  ipField: e.target.value,
                                })
                              }
                            />
                          </div>
                        </>
                      )}

                      {selectedNode.data.actionType === 'isolate' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              EDR Integration
                            </label>
                            <Select
                              value={(selectedNode.data as any).edrIntegration || 'default'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  edrIntegration: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="default">Default EDR</SelectItem>
                                <SelectItem value="crowdstrike">
                                  CrowdStrike
                                </SelectItem>
                                <SelectItem value="sentinelone">
                                  SentinelOne
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Isolation Level
                            </label>
                            <Select
                              value={(selectedNode.data as any).isolationLevel || 'full'}
                              onValueChange={(value) =>
                                updateNodeData(selectedNode.id, {
                                  isolationLevel: value,
                                })
                              }
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="full">Full</SelectItem>
                                <SelectItem value="network_only">
                                  Network Only
                                </SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </>
                      )}

                      {selectedNode.data.actionType === 'custom' && (
                        <>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Script Path
                            </label>
                            <Input
                              value={(selectedNode.data as any).scriptPath || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  scriptPath: e.target.value,
                                })
                              }
                              placeholder="/opt/scripts/custom_action.py"
                              className="font-mono text-sm"
                            />
                          </div>
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Parameters (JSON)
                            </label>
                            <Textarea
                              value={(selectedNode.data as any).parameters || ''}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  parameters: e.target.value,
                                })
                              }
                              placeholder='{"key": "value"}'
                              className="font-mono text-sm"
                              rows={3}
                            />
                          </div>
                          {/* Template Editor for JSON Flow Data */}
                          {upstreamNodes.length > 0 && (
                            <div>
                              <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                                Data Template
                              </label>
                              <TemplateEditor
                                value={(selectedNode.data as any).dataTemplate || ''}
                                onChange={(value) =>
                                  updateNodeData(selectedNode.id, { dataTemplate: value })
                                }
                                upstreamNodes={upstreamNodes.map(n => ({
                                  nodeId: n.nodeId,
                                  nodeName: n.nodeName,
                                }))}
                                placeholder="Use {{ $node.xxx.json.yyy }} to reference upstream data"
                              />
                            </div>
                          )}
                          <div>
                            <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                              Timeout (seconds)
                            </label>
                            <Input
                              type="number"
                              value={(selectedNode.data as any).timeout || '30'}
                              onChange={(e) =>
                                updateNodeData(selectedNode.id, {
                                  timeout: e.target.value,
                                })
                              }
                            />
                          </div>
                        </>
                      )}
                    </>
                  )}

                  {/* DecisionNode settings */}
                  {selectedNode.type === 'decision' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Condition
                        </label>
                        <Input
                          value={(selectedNode.data.condition as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              condition: e.target.value,
                            })
                          }
                          placeholder="severity >= critical"
                          className="font-mono text-sm"
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Yes Label
                        </label>
                        <Input
                          value={((selectedNode.data.outcomes as any)?.yes as string) || 'Yes'}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              outcomes: {
                                ...((selectedNode.data.outcomes as any) || { yes: 'Yes', no: 'No' }),
                                yes: e.target.value,
                              },
                            })
                          }
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          No Label
                        </label>
                        <Input
                          value={((selectedNode.data.outcomes as any)?.no as string) || 'No'}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              outcomes: {
                                ...((selectedNode.data.outcomes as any) || { yes: 'Yes', no: 'No' }),
                                no: e.target.value,
                              },
                            })
                          }
                        />
                      </div>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Evaluation Mode
                        </label>
                        <Select
                          value={(selectedNode.data as any).evaluationMode || 'any'}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, {
                              evaluationMode: value,
                            })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="any">Any (OR)</SelectItem>
                            <SelectItem value="all">All (AND)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </>
                  )}

                  {/* IntegrationNode settings */}
                  {selectedNode.type === 'integration' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Integration Type
                        </label>
                        <Select
                          value={(selectedNode.data as any).integrationType}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, {
                              integrationType: value,
                            })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="siem">SIEM</SelectItem>
                            <SelectItem value="edr">EDR</SelectItem>
                            <SelectItem value="firewall">Firewall</SelectItem>
                            <SelectItem value="ticketing">Ticketing</SelectItem>
                            <SelectItem value="custom">Custom</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Connection Status
                        </label>
                        <Input
                          value={(selectedNode.data as any).connectionStatus || 'connected'}
                          readOnly
                          className="text-sm"
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          API URL
                        </label>
                        <Input
                          value={(selectedNode.data as any).apiUrl || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              apiUrl: e.target.value,
                            })
                          }
                          placeholder="https://api.integration.com/v1"
                          className="font-mono text-sm"
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          API Key
                        </label>
                        <Input
                          type="password"
                          value={(selectedNode.data as any).apiKey || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              apiKey: e.target.value,
                            })
                          }
                          placeholder="••••••••"
                          className="font-mono text-sm"
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Query Template
                        </label>
                        <Textarea
                          value={(selectedNode.data as any).queryTemplate || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              queryTemplate: e.target.value,
                            })
                          }
                          placeholder="Query or action template..."
                          className="font-mono text-sm"
                          rows={3}
                        />
                      </div>
                    </>
                  )}

                  {/* LoopNode settings */}
                  {selectedNode.type === 'loop' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Loop Type
                        </label>
                        <Select
                          value={(selectedNode.data as any).loopType || 'forEach'}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, { loopType: value })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="forEach">For Each</SelectItem>
                            <SelectItem value="while">While</SelectItem>
                            <SelectItem value="times">Times</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {(selectedNode.data as any).loopType === 'forEach' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Source Array
                          </label>
                          <Input
                            value={(selectedNode.data as any).sourceArray || ''}
                            onChange={(e) =>
                              updateNodeData(selectedNode.id, {
                                sourceArray: e.target.value,
                              })
                            }
                            placeholder="{{items}}"
                            className="font-mono text-sm"
                          />
                        </div>
                      )}

                      {(selectedNode.data as any).loopType === 'while' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Condition
                          </label>
                          <Input
                            value={(selectedNode.data as any).condition || ''}
                            onChange={(e) =>
                              updateNodeData(selectedNode.id, {
                                condition: e.target.value,
                              })
                            }
                            placeholder="count < 10"
                            className="font-mono text-sm"
                          />
                        </div>
                      )}

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Max Iterations
                        </label>
                        <Input
                          type="number"
                          value={(selectedNode.data as any).maxIterations || 10}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              maxIterations: parseInt(e.target.value) || 10,
                            })
                          }
                          min={1}
                          max={1000}
                        />
                      </div>
                    </>
                  )}

                  {/* ParallelNode settings */}
                  {selectedNode.type === 'parallel' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Number of Branches
                        </label>
                        <Input
                          type="number"
                          value={(selectedNode.data as any).branches || 2}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              branches: Math.max(2, Math.min(5, parseInt(e.target.value) || 2)),
                            })
                          }
                          min={2}
                          max={5}
                        />
                      </div>

                      <div className="flex items-center justify-between">
                        <label className="text-xs text-muted-foreground uppercase tracking-wide">
                          Wait for All
                        </label>
                        <Select
                          value={(selectedNode.data as any).waitForAll ? 'true' : 'false'}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, {
                              waitForAll: value === 'true',
                            })
                          }
                        >
                          <SelectTrigger className="w-24">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="true">Yes</SelectItem>
                            <SelectItem value="false">No</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Timeout (seconds)
                        </label>
                        <Input
                          type="number"
                          value={(selectedNode.data as any).timeout || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              timeout: parseInt(e.target.value) || undefined,
                            })
                          }
                          placeholder="No timeout"
                          min={1}
                        />
                      </div>
                    </>
                  )}

                  {/* WaitNode settings */}
                  {selectedNode.type === 'wait' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data.description as string) || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Wait Type
                        </label>
                        <Select
                          value={(selectedNode.data as any).waitType || 'duration'}
                          onValueChange={(value) =>
                            updateNodeData(selectedNode.id, { waitType: value })
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="duration">Duration</SelectItem>
                            <SelectItem value="until">Until Condition</SelectItem>
                            <SelectItem value="webhook">Webhook</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>

                      {(selectedNode.data as any).waitType === 'duration' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Duration (seconds)
                          </label>
                          <Input
                            type="number"
                            value={(selectedNode.data as any).duration || 60}
                            onChange={(e) =>
                              updateNodeData(selectedNode.id, {
                                duration: parseInt(e.target.value) || 60,
                              })
                            }
                            min={1}
                          />
                        </div>
                      )}

                      {(selectedNode.data as any).waitType === 'until' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Until Condition
                          </label>
                          <Input
                            value={(selectedNode.data as any).untilCondition || ''}
                            onChange={(e) =>
                              updateNodeData(selectedNode.id, {
                                untilCondition: e.target.value,
                              })
                            }
                            placeholder="{{status}} === 'completed'"
                            className="font-mono text-sm"
                          />
                        </div>
                      )}

                      {(selectedNode.data as any).waitType === 'webhook' && (
                        <div>
                          <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                            Webhook ID
                          </label>
                          <Input
                            value={(selectedNode.data as any).webhookId || selectedNode.id}
                            readOnly
                            className="font-mono text-sm"
                          />
                        </div>
                      )}
                    </>
                  )}

                  {/* ApprovalGate Node settings */}
                  {selectedNode.type === 'approval' && (
                    <>
                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Description
                        </label>
                        <Textarea
                          value={(selectedNode.data as any).description || ''}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              description: e.target.value,
                            })
                          }
                          rows={2}
                          placeholder="Approval required for critical actions"
                        />
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Approver Roles
                        </label>
                        <Input
                          value={((selectedNode.data as any).approverRoles || []).join(', ')}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              approverRoles: e.target.value.split(',').map((s: string) => s.trim()).filter(Boolean),
                            })
                          }
                          placeholder="SOC Manager, Security Lead"
                        />
                        <p className="text-2xs text-muted-foreground mt-1">
                          Comma-separated list of roles
                        </p>
                      </div>

                      <div>
                        <label className="text-xs text-muted-foreground uppercase tracking-wide mb-1 block">
                          Timeout (seconds)
                        </label>
                        <Input
                          type="number"
                          value={(selectedNode.data as any).timeout || 3600}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              timeout: parseInt(e.target.value, 10) || 3600,
                            })
                          }
                          min={60}
                          step={60}
                        />
                        <p className="text-2xs text-muted-foreground mt-1">
                          Time before automatic action (min: 60s)
                        </p>
                      </div>

                      <div className="flex items-center justify-between">
                        <label className="text-xs text-muted-foreground uppercase tracking-wide">
                          Auto-Reject on Timeout
                        </label>
                        <input
                          type="checkbox"
                          checked={(selectedNode.data as any).autoReject || false}
                          onChange={(e) =>
                            updateNodeData(selectedNode.id, {
                              autoReject: e.target.checked,
                            })
                          }
                          className="w-4 h-4 rounded border-border"
                        />
                      </div>
                    </>
                  )}

                  <div className="pt-4">
                    <Button
                      variant="destructive"
                      className="w-full"
                      onClick={() => {
                        setNodes((nds) => nds.filter((n) => n.id !== selectedNode.id));
                        setEdges((eds) =>
                          eds.filter(
                            (e) =>
                              e.source !== selectedNode.id &&
                              e.target !== selectedNode.id
                          )
                        );
                        setSelectedNode(null);
                      }}
                    >
                      Delete Node
                    </Button>
                  </div>
                </div>
              </ScrollArea>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-center text-muted-foreground">
                <Zap className="w-8 h-8 mb-2 opacity-50" />
                <p className="text-sm">Select a node to edit its properties</p>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Test Run Panel */}
      <Sheet open={isTestRunPanelOpen} onOpenChange={setIsTestRunPanelOpen}>
        <SheetContent className="w-[500px] sm:max-w-[500px]">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Play className="w-5 h-5" />
              Playbook Execution
            </SheetTitle>
          </SheetHeader>

          <div className="mt-6 space-y-6">
            {/* Input Parameters - Always visible at top when not running */}
            {!testRunState.isRunning && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-semibold flex items-center gap-2">
                    <Variable className="w-4 h-4" />
                    Input Parameters
                  </h4>
                  <Badge variant="outline" className="text-xs">
                    {triggerType}
                  </Badge>
                </div>
                <div className="p-3 rounded-lg border border-border/50 bg-muted/20 max-h-[300px] overflow-y-auto">
                  <DynamicInputForm
                    fields={inputSchema}
                    values={testRunInputs}
                    onChange={setTestRunInputs}
                    disabled={testRunState.isRunning}
                    compact={true}
                  />
                </div>
              </div>
            )}

            {/* Actions - Right after input parameters */}
            <div className="flex gap-2">
              {testRunState.isRunning ? (
                <Button
                  onClick={stopTestRun}
                  variant="destructive"
                  className="flex-1"
                >
                  <StopCircle className="w-4 h-4 mr-2" />
                  Stop
                </Button>
              ) : (
                <>
                  <Button
                    onClick={() => {
                      const validation = validateAllFields(inputSchema, testRunInputs);
                      if (!validation.valid) {
                        toast({
                          title: 'Validation Error',
                          description: 'Please fill in all required fields correctly.',
                          variant: 'destructive',
                        });
                        return;
                      }
                      startTestRun();
                    }}
                    className="flex-1"
                    disabled={nodes.length === 0}
                  >
                    <Play className="w-4 h-4 mr-2" />
                    Run Playbook
                  </Button>
                  <Button
                    onClick={resetTestRun}
                    variant="outline"
                    disabled={testRunState.logs.length === 0}
                  >
                    <RotateCcw className="w-4 h-4 mr-2" />
                    Reset
                  </Button>
                </>
              )}
            </div>

            {/* Separator */}
            <Separator />

            {/* Progress - Shows execution status */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Execution Progress</span>
                <span className="text-sm text-muted-foreground">
                  {Math.round(testRunState.progress)}%
                </span>
              </div>
              <Progress value={testRunState.progress} className="h-2" />
            </div>

            {/* Results Summary */}
            <div className="flex gap-3">
              <Badge
                variant="outline"
                className="flex items-center gap-1 px-3 py-1 text-green-600 border-green-600/50"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span className="font-semibold">
                  {testRunState.results.success}
                </span>
                <span className="text-xs">Success</span>
              </Badge>
              <Badge
                variant="outline"
                className="flex items-center gap-1 px-3 py-1 text-red-600 border-red-600/50"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span className="font-semibold">
                  {testRunState.results.failed}
                </span>
                <span className="text-xs">Failed</span>
              </Badge>
            </div>

            {/* Current Node */}
            {testRunState.isRunning && testRunState.currentNodeId && (
              <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <div className="flex items-center gap-2 text-sm">
                  <Info className="w-4 h-4 text-blue-500" />
                  <span className="text-muted-foreground">Executing:</span>
                  <span className="font-medium">
                    {
                      (nodes.find((n) => n.id === testRunState.currentNodeId)
                        ?.data as any)?.label || testRunState.currentNodeId
                    }
                  </span>
                </div>
              </div>
            )}

            {/* Status Message */}
            {!testRunState.isRunning && testRunState.progress === 100 && (
              <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                <div className="flex items-center gap-2 text-sm text-green-600">
                  <CheckCircle2 className="w-4 h-4" />
                  <span className="font-medium">Execution completed successfully</span>
                </div>
              </div>
            )}

            {/* Execution Logs */}
            <div>
              <h4 className="text-sm font-semibold mb-3">Execution Log</h4>
              <ScrollArea className="h-[250px] rounded-lg border border-border/50 bg-muted/20">
                <div className="p-3 space-y-2">
                  {testRunState.logs.length === 0 ? (
                    <div className="text-center py-8 text-muted-foreground text-sm">
                      No logs yet. Run the playbook to see execution details.
                    </div>
                  ) : (
                    testRunState.logs.map((log, i) => (
                      <div
                        key={i}
                        className="flex items-start gap-2 p-2 rounded-lg bg-background border border-border/50"
                      >
                        <div className="shrink-0 mt-0.5">
                          {log.status === 'success' && (
                            <CheckCircle2 className="w-4 h-4 text-green-500" />
                          )}
                          {log.status === 'error' && (
                            <XCircle className="w-4 h-4 text-red-500" />
                          )}
                          {log.status === 'info' && (
                            <Info className="w-4 h-4 text-blue-500" />
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-0.5">
                            <span className="text-xs font-medium text-foreground truncate">
                              {
                                (nodes.find((n) => n.id === log.nodeId)?.data as any)
                                  ?.label || log.nodeId
                              }
                            </span>
                            <span className="text-2xs text-muted-foreground shrink-0">
                              {log.timestamp.toLocaleTimeString()}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {log.message}
                          </p>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </ScrollArea>
            </div>
          </div>
        </SheetContent>
      </Sheet>

      {/* Execution Panel */}
      <ExecutionPanel
        isOpen={isExecutionPanelOpen}
        onClose={() => setIsExecutionPanelOpen(false)}
      />

      {/* Processing Monitor */}
      <ProcessingMonitor
        isOpen={isProcessingMonitorOpen}
        onClose={() => setIsProcessingMonitorOpen(false)}
      />
    </div>
  );
}
