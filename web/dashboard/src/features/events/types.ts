export interface EventLog {
  id: string;
  tenant_id: string;
  timestamp: Date;
  vendor_name: string;
  product_name: string;
  principal_ip: string;
  target_ip: string;
  principal_hostname: string;
  principal_user_id: string;
  security_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'UNKNOWN';
  security_threat_name: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  raw_log: string;
}

export interface EventLogFilters {
  assetId: string;
  startDate: Date | null;
  endDate: Date | null;
}
