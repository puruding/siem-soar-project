import { create } from 'zustand';

// ============================================================================
// Types
// ============================================================================

export interface UEBAAlert {
  id: string;
  entityId: string;
  entityType: 'user' | 'host' | 'ip';
  anomalyType: string;
  score: number; // 0.0 ~ 1.0
  severity: 'low' | 'medium' | 'high' | 'critical';
  detectedAt: string;
  explanation: string;
  // Alert 통합용 필드
  title: string;
  source: 'UEBA' | 'ML-Triage';
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved';
}

export interface EntityRisk {
  entityId: string;
  entityType: 'user' | 'host' | 'ip';
  riskScore: number;
  anomalyCount: number;
  lastDetectedAt: string;
  criticalCount: number;
}

// StandardAlert interface for AlertList compatibility
export interface StandardAlert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'closed';
  source: string;
  target: string;
  timestamp: Date;
  tactic?: string;
  technique?: string;
  // UEBA specific data
  uebaData?: {
    anomalyType: string;
    score: number;
    entityType: 'user' | 'host' | 'ip';
  };
}

// ============================================================================
// Constants
// ============================================================================

export const ANOMALY_TYPES: Record<string, string> = {
  unusual_time: '비정상 시간대',
  unusual_location: '비정상 위치',
  unusual_volume: '비정상 볼륨',
  credential_anomaly: '인증 이상',
  lateral_movement: '측면 이동',
  privilege_escalation: '권한 상승',
  data_exfiltration: '데이터 유출',
  account_compromise: '계정 침해',
  insider_threat: '내부자 위협',
  sequence_anomaly: '시퀀스 이상',
};

// MITRE mapping (UEBA type -> MITRE Tactic)
export const UEBA_TO_MITRE: Record<string, string> = {
  lateral_movement: 'TA0008',
  privilege_escalation: 'TA0004',
  data_exfiltration: 'TA0010',
  credential_anomaly: 'TA0006',
  unusual_time: 'TA0001',
  account_compromise: 'TA0006',
  insider_threat: 'TA0009',
  sequence_anomaly: 'TA0002',
};

// MITRE tactic names
const MITRE_TACTICS: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
};

// ============================================================================
// Store Interface
// ============================================================================

interface UEBAStore {
  alerts: UEBAAlert[];
  entityRisks: EntityRisk[];
  loading: boolean;
  error: string | null;
  lastUpdated: Date | null;

  fetchAlerts: () => Promise<void>;
  fetchEntityRisks: () => Promise<void>;
  getAlertsAsStandardFormat: () => StandardAlert[];
}

// ============================================================================
// Store Implementation
// ============================================================================

export const useUEBAStore = create<UEBAStore>((set, get) => ({
  alerts: [],
  entityRisks: [],
  loading: false,
  error: null,
  lastUpdated: null,

  fetchAlerts: async () => {
    set({ loading: true, error: null });
    try {
      const response = await fetch('/api/v1/ueba/alerts');
      if (response.ok) {
        const data = await response.json();
        set({
          alerts: data.alerts || [],
          lastUpdated: new Date(),
          loading: false,
        });
      } else {
        // API endpoint not implemented yet - gracefully handle
        console.debug(`UEBA alerts API not available (${response.status})`);
        set({
          alerts: [],
          lastUpdated: new Date(),
          loading: false,
          error: null, // Don't set error for unimplemented endpoints
        });
      }
    } catch (err) {
      // Network error or API not running - log debug info only
      console.debug('UEBA alerts API unavailable:', err instanceof Error ? err.message : 'Unknown error');
      set({
        alerts: [],
        lastUpdated: new Date(),
        loading: false,
        error: null, // Don't expose errors to UI for optional features
      });
    }
  },

  fetchEntityRisks: async () => {
    try {
      const response = await fetch('/api/v1/ueba/entity-risks');
      if (response.ok) {
        const data = await response.json();
        set({ entityRisks: data.entityRisks || [] });
      } else {
        // API endpoint not implemented yet - gracefully handle
        console.debug(`UEBA entity risks API not available (${response.status})`);
        set({ entityRisks: [] });
      }
    } catch (err) {
      // Network error or API not running - log debug info only
      console.debug('UEBA entity risks API unavailable:', err instanceof Error ? err.message : 'Unknown error');
      set({ entityRisks: [] });
    }
  },

  getAlertsAsStandardFormat: () => {
    const { alerts } = get();
    return alerts.map((alert) => {
      const tacticId = UEBA_TO_MITRE[alert.anomalyType];
      return {
        id: alert.id,
        title: alert.title || `${ANOMALY_TYPES[alert.anomalyType] || alert.anomalyType} - ${alert.entityId}`,
        description: alert.explanation,
        severity: alert.severity,
        status: alert.status,
        source: 'UEBA',
        target: alert.entityId,
        timestamp: new Date(alert.detectedAt),
        tactic: tacticId ? MITRE_TACTICS[tacticId] : undefined,
        technique: undefined, // UEBA doesn't map to specific techniques
        uebaData: {
          anomalyType: alert.anomalyType,
          score: alert.score,
          entityType: alert.entityType,
        },
      };
    });
  },
}));

// Initialize on module load
useUEBAStore.getState().fetchAlerts();
useUEBAStore.getState().fetchEntityRisks();
