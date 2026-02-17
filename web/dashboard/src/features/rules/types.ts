export interface AttackTactic {
  id: string; // e.g., 'TA0001'
  name: string; // e.g., 'Initial Access'
}

export interface AttackTechnique {
  id: string; // e.g., 'T1566'
  name: string; // e.g., 'Phishing'
  subtechnique?: string;
}

// Alert Aggregation (Grouping) configuration
export interface AlertAggregation {
  group_by: string[];      // UDM field paths for grouping
  window: string;          // Time window: "15m", "30m", "1h", "6h", "24h"
  action: 'merge' | 'group' | 'drop';
  max_count: number;       // Maximum alerts before action
}

// Predefined UDM fields for group_by selection
export interface UdmGroupByField {
  value: string;
  label: string;
  category: 'Principal' | 'Target' | 'File' | 'Network' | 'Process' | 'Other';
}

export const UDM_GROUP_BY_FIELDS: UdmGroupByField[] = [
  // Principal (Source)
  { value: 'principal.ip', label: 'Source IP', category: 'Principal' },
  { value: 'principal.hostname', label: 'Source Hostname', category: 'Principal' },
  { value: 'principal.user.user_name', label: 'Username', category: 'Principal' },
  { value: 'principal.user.email_addresses', label: 'User Email', category: 'Principal' },
  { value: 'principal.asset.asset_id', label: 'Source Asset ID', category: 'Principal' },
  // Target
  { value: 'target.ip', label: 'Target IP', category: 'Target' },
  { value: 'target.hostname', label: 'Target Hostname', category: 'Target' },
  { value: 'target.port', label: 'Target Port', category: 'Target' },
  { value: 'target.user.user_name', label: 'Target User', category: 'Target' },
  { value: 'target.asset.asset_id', label: 'Target Asset ID', category: 'Target' },
  // File
  { value: 'target.file.sha256', label: 'File Hash (SHA256)', category: 'File' },
  { value: 'target.file.md5', label: 'File Hash (MD5)', category: 'File' },
  { value: 'target.file.full_path', label: 'File Path', category: 'File' },
  { value: 'target.file.file_name', label: 'File Name', category: 'File' },
  // Network
  { value: 'network.dns.questions[0].name', label: 'DNS Query', category: 'Network' },
  { value: 'target.url', label: 'URL', category: 'Network' },
  { value: 'network.http.user_agent', label: 'User Agent', category: 'Network' },
  { value: 'network.application_protocol', label: 'Protocol', category: 'Network' },
  // Process
  { value: 'target.process.command_line', label: 'Command Line', category: 'Process' },
  { value: 'target.process.file.full_path', label: 'Process Path', category: 'Process' },
  { value: 'principal.process.file.full_path', label: 'Parent Process', category: 'Process' },
];

// Time window options
export const AGGREGATION_WINDOWS = [
  { value: '15m', label: '15 minutes' },
  { value: '30m', label: '30 minutes' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
] as const;

// Aggregation action options
export const AGGREGATION_ACTIONS = [
  { value: 'merge', label: 'Merge', description: 'Combine into single alert with count' },
  { value: 'group', label: 'Group', description: 'Group alerts but keep all visible' },
  { value: 'drop', label: 'Drop', description: 'Drop duplicate alerts after max_count' },
] as const;

export interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status: 'draft' | 'testing' | 'active' | 'disabled';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  author: string;
  references: string[];
  tags: string[];
  logsources: {
    category?: string;
    product?: string;
    service?: string;
  };
  rawYaml: string;
  attack: {
    tactics: AttackTactic[];
    techniques: AttackTechnique[];
  };
  enabled: boolean;
  lastTriggered?: Date;
  triggerCount: number;
  version: number;
  createdAt: Date;
  updatedAt: Date;
  // Alert aggregation settings (optional)
  alertAggregation?: AlertAggregation;
}

export interface RuleTestResult {
  success: boolean;
  matchedEvents: number;
  totalEvents: number;
  matches: { eventIndex: number; matchedConditions: string[] }[];
  executionTime: number;
  error?: string;
}

// MITRE ATT&CK Matrix Tactics
export const ATTACK_TACTICS: AttackTactic[] = [
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' },
];

// Severity colors mapping
export const SEVERITY_COLORS: Record<SigmaRule['severity'], string> = {
  critical: '#DC4E41',
  high: '#F79836',
  medium: '#FFB84D',
  low: '#5CC05C',
  informational: '#6B7280',
};

// Status styles mapping
export const STATUS_STYLES: Record<SigmaRule['status'], string> = {
  draft: 'bg-muted/50 text-muted-foreground border-border',
  testing: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  active: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  disabled: 'bg-muted text-muted-foreground border-border',
};
