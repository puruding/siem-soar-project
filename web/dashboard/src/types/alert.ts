/**
 * Alert type definitions for the SOC Dashboard
 */

export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus =
  | 'new'
  | 'acknowledged'
  | 'investigating'
  | 'resolved'
  | 'closed'
  | 'false_positive';

export interface AlertSource {
  type: 'siem' | 'edr' | 'ndr' | 'ids' | 'waf' | 'firewall' | 'custom';
  name: string;
  ip?: string;
  hostname?: string;
}

export interface AlertTarget {
  type: 'host' | 'user' | 'network' | 'application' | 'service';
  identifier: string;
  ip?: string;
  hostname?: string;
  username?: string;
}

export interface MitreAttack {
  tactic: string;
  tacticId: string;
  technique: string;
  techniqueId: string;
  subtechnique?: string;
  subtechniqueId?: string;
}

export interface AlertEnrichment {
  geoip?: {
    country: string;
    city?: string;
    latitude?: number;
    longitude?: number;
    asn?: string;
    asnOrg?: string;
  };
  threatIntel?: {
    isMalicious: boolean;
    score: number;
    sources: string[];
    tags: string[];
  };
  asset?: {
    assetId: string;
    assetType: string;
    criticality: 'critical' | 'high' | 'medium' | 'low';
    owner?: string;
    department?: string;
  };
  user?: {
    userId: string;
    username: string;
    department?: string;
    manager?: string;
    riskScore?: number;
  };
}

export interface AITriage {
  classification: string;
  confidence: number;
  priority: number;
  suggestedPlaybooks: string[];
  similarAlerts: string[];
  summary?: string;
  reasoning?: string;
}

export interface AlertEvent {
  id: string;
  timestamp: Date;
  eventType: string;
  rawLog: string;
  parsedFields: Record<string, unknown>;
  sourceLogType?: string;
}

export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: AlertSeverity;
  status: AlertStatus;
  source: AlertSource;
  target: AlertTarget;
  timestamp: Date;
  lastUpdated: Date;
  detectionRule?: string;
  mitre?: MitreAttack;
  enrichment?: AlertEnrichment;
  aiTriage?: AITriage;
  events?: AlertEvent[];
  tags: string[];
  assignee?: string;
  caseId?: string;
  notes?: string[];
}

export interface AlertFilter {
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  timeRange?: {
    start: Date;
    end: Date;
  };
  search?: string;
  tags?: string[];
  assignee?: string;
  source?: string[];
  hasCase?: boolean;
}

export interface AlertStats {
  total: number;
  bySeverity: Record<AlertSeverity, number>;
  byStatus: Record<AlertStatus, number>;
  bySource: Record<string, number>;
  trend: {
    timestamp: Date;
    count: number;
  }[];
}

export interface AlertAction {
  type: 'acknowledge' | 'close' | 'escalate' | 'create_case' | 'run_playbook' | 'assign' | 'add_note';
  alertId: string;
  payload?: Record<string, unknown>;
}

export interface AlertUpdatePayload {
  status?: AlertStatus;
  assignee?: string;
  tags?: string[];
  notes?: string;
  caseId?: string;
}
