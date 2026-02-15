/**
 * Case type definitions for incident management
 */

export type CaseSeverity = 'critical' | 'high' | 'medium' | 'low';

export type CaseStatus =
  | 'open'
  | 'in_progress'
  | 'pending'
  | 'resolved'
  | 'closed'
  | 'reopened';

export type CasePriority = 'p1' | 'p2' | 'p3' | 'p4';

export interface CaseAssignee {
  id: string;
  name: string;
  email: string;
  initials: string;
  avatar?: string;
  role: 'analyst' | 'senior_analyst' | 'manager' | 'incident_responder';
}

export interface CaseTimeline {
  id: string;
  timestamp: Date;
  type: 'created' | 'updated' | 'comment' | 'status_change' | 'assignment' | 'alert_added' | 'playbook_executed' | 'escalated';
  actor: string;
  description: string;
  metadata?: Record<string, unknown>;
}

export interface CaseArtifact {
  id: string;
  type: 'ip' | 'domain' | 'hash' | 'url' | 'email' | 'file' | 'user' | 'host' | 'other';
  value: string;
  description?: string;
  isMalicious?: boolean;
  source: string;
  addedAt: Date;
  addedBy: string;
  tags?: string[];
  enrichment?: Record<string, unknown>;
}

export interface CasePlaybookExecution {
  id: string;
  playbookId: string;
  playbookName: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  startedAt: Date;
  completedAt?: Date;
  initiatedBy: string;
  result?: Record<string, unknown>;
  error?: string;
}

export interface CaseAttachment {
  id: string;
  filename: string;
  mimeType: string;
  size: number;
  uploadedAt: Date;
  uploadedBy: string;
  description?: string;
  url: string;
}

export interface Case {
  id: string;
  title: string;
  description: string;
  severity: CaseSeverity;
  status: CaseStatus;
  priority: CasePriority;
  assignee: CaseAssignee | null;
  createdAt: Date;
  updatedAt: Date;
  closedAt?: Date;
  alerts: string[];
  alertCount: number;
  artifacts: CaseArtifact[];
  timeline: CaseTimeline[];
  playbookExecutions: CasePlaybookExecution[];
  attachments: CaseAttachment[];
  tags: string[];
  relatedCases: string[];
  ttd?: number; // Time to detect (minutes)
  ttr?: number; // Time to respond (minutes)
  resolutionSummary?: string;
  rootCause?: string;
  lessonsLearned?: string;
  customFields?: Record<string, unknown>;
}

export interface CaseFilter {
  severity?: CaseSeverity[];
  status?: CaseStatus[];
  priority?: CasePriority[];
  assignee?: string;
  timeRange?: {
    start: Date;
    end: Date;
  };
  search?: string;
  tags?: string[];
  hasAlerts?: boolean;
}

export interface CaseStats {
  total: number;
  open: number;
  inProgress: number;
  resolved: number;
  bySeverity: Record<CaseSeverity, number>;
  byStatus: Record<CaseStatus, number>;
  averageTTD: number;
  averageTTR: number;
  trend: {
    timestamp: Date;
    opened: number;
    closed: number;
  }[];
}

export interface CaseCreatePayload {
  title: string;
  description: string;
  severity: CaseSeverity;
  priority?: CasePriority;
  assigneeId?: string;
  alertIds?: string[];
  tags?: string[];
}

export interface CaseUpdatePayload {
  title?: string;
  description?: string;
  severity?: CaseSeverity;
  status?: CaseStatus;
  priority?: CasePriority;
  assigneeId?: string;
  tags?: string[];
  resolutionSummary?: string;
  rootCause?: string;
  lessonsLearned?: string;
}
