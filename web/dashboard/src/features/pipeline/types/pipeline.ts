export interface PipelineEvent {
  id: string;
  tenant_id: string;
  raw_log: string;
  source: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  stage: 'event_receive' | 'classification' | 'playbook_select' | 'flow_execution';
  classification?: Classification;
  playbook_match?: PlaybookMatch;
  execution?: ExecutionStatus;
  created_at: string;
}

export interface Classification {
  id: string;
  event_id: string;
  label: string;
  confidence: number;
  method: 'SIGMA' | 'TI_IOC' | 'HYBRID' | 'RULE_BASED';
  matched_rules: string[];
  matched_iocs: string[];
  mitre_tactics: string[];
  mitre_techniques: string[];
  processing_time_ms: number;
}

export interface PlaybookMatch {
  playbook_id: string;
  playbook_name: string;
  match_score: number;
  trigger_tags: string[];
  step_count: number;
}

export interface ExecutionStatus {
  execution_id: string;
  status: 'PENDING' | 'RUNNING' | 'WAITING_APPROVAL' | 'COMPLETED' | 'FAILED';
  current_step: number;
  total_steps: number;
  approval_info?: ApprovalInfo;
}

export interface ApprovalInfo {
  approval_id: string;
  step_name: string;
  required_role: string;
  approver?: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
}

export interface AuditLog {
  id: string;
  event_type: string;
  actor_type: 'AI' | 'SYSTEM' | 'SOAR' | 'USER';
  actor_id: string;
  message: string;
  created_at: string;
}

export interface PipelineStats {
  total_events: number;
  processed_events: number;
  auto_classified: number;
  automation_rate: number;
  avg_processing_ms: number;
}
