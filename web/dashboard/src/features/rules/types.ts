export interface AttackTactic {
  id: string; // e.g., 'TA0001'
  name: string; // e.g., 'Initial Access'
}

export interface AttackTechnique {
  id: string; // e.g., 'T1566'
  name: string; // e.g., 'Phishing'
  subtechnique?: string;
}

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
