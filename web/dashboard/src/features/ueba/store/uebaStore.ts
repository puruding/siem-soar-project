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
// Mock Data
// ============================================================================

function generateMockUEBAAlerts(): UEBAAlert[] {
  return [
    // ========== 트래픽 급증 탐지 시나리오 ==========
    {
      id: 'UEBA-T001',
      entityId: 'WEB-SERVER-01',
      entityType: 'host',
      anomalyType: 'unusual_volume',
      score: 0.95,
      severity: 'critical',
      detectedAt: new Date(Date.now() - 1000 * 30).toISOString(), // 30초 전
      explanation: '평소 대비 1,500% 트래픽 급증 감지. 기준선: 2,000 req/min → 현재: 32,000 req/min. DDoS 공격 또는 봇 트래픽 의심',
      title: 'Critical Traffic Spike - 1500% Increase',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-T002',
      entityId: '10.20.30.100',
      entityType: 'ip',
      anomalyType: 'unusual_volume',
      score: 0.91,
      severity: 'critical',
      detectedAt: new Date(Date.now() - 1000 * 45).toISOString(), // 45초 전
      explanation: '단일 IP에서 비정상 요청량 탐지. 1분간 8,500건 요청 (평균: 50건). 자동화된 스캐닝 또는 봇 활동 의심',
      title: 'Abnormal Request Volume from Single IP',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-T003',
      entityId: 'API-GATEWAY-PROD',
      entityType: 'host',
      anomalyType: 'unusual_volume',
      score: 0.88,
      severity: 'high',
      detectedAt: new Date(Date.now() - 1000 * 60).toISOString(), // 1분 전
      explanation: 'API 게이트웨이 트래픽 급증. /api/v1/login 엔드포인트 500% 증가. Credential Stuffing 공격 가능성',
      title: 'API Traffic Surge - Login Endpoint',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-T004',
      entityId: 'DB-CLUSTER-01',
      entityType: 'host',
      anomalyType: 'unusual_volume',
      score: 0.86,
      severity: 'high',
      detectedAt: new Date(Date.now() - 1000 * 90).toISOString(), // 1.5분 전
      explanation: '데이터베이스 쿼리량 급증. 평균 대비 800% 증가. SELECT 쿼리 집중 (데이터 스크래핑 의심)',
      title: 'Database Query Volume Spike',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-T005',
      entityId: '203.45.67.89',
      entityType: 'ip',
      anomalyType: 'unusual_volume',
      score: 0.82,
      severity: 'high',
      detectedAt: new Date(Date.now() - 1000 * 120).toISOString(), // 2분 전
      explanation: '외부 IP에서 대역폭 급증. Outbound 트래픽 12GB/min (평균: 500MB/min). 데이터 유출 경로 확인 필요',
      title: 'Outbound Bandwidth Spike',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-T006',
      entityId: 'CDN-EDGE-KR-01',
      entityType: 'host',
      anomalyType: 'unusual_volume',
      score: 0.75,
      severity: 'medium',
      detectedAt: new Date(Date.now() - 1000 * 180).toISOString(), // 3분 전
      explanation: 'CDN 엣지 서버 트래픽 300% 증가. 특정 리전(한국) 집중. 정상적인 이벤트 트래픽 또는 공격 확인 필요',
      title: 'CDN Edge Traffic Increase',
      source: 'UEBA',
      status: 'new',
    },
    // ========== 기존 UEBA 탐지 ==========
    {
      id: 'UEBA-001',
      entityId: 'john.doe@company.com',
      entityType: 'user',
      anomalyType: 'unusual_time',
      score: 0.92,
      severity: 'critical',
      detectedAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      explanation: '평소 근무 시간 외 비정상적인 로그인 활동 감지',
      title: 'Unusual Login Time Detected',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-002',
      entityId: '192.168.10.45',
      entityType: 'ip',
      anomalyType: 'lateral_movement',
      score: 0.88,
      severity: 'high',
      detectedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      explanation: '내부 네트워크 스캔 및 측면 이동 패턴',
      title: 'Lateral Movement Pattern Detected',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-003',
      entityId: 'WORKSTATION-42',
      entityType: 'host',
      anomalyType: 'data_exfiltration',
      score: 0.85,
      severity: 'critical',
      detectedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      explanation: '대용량 데이터 외부 전송 시도',
      title: 'Data Exfiltration Attempt',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-004',
      entityId: 'admin@company.com',
      entityType: 'user',
      anomalyType: 'privilege_escalation',
      score: 0.78,
      severity: 'high',
      detectedAt: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      explanation: '비정상적인 관리자 권한 사용 패턴',
      title: 'Privilege Escalation Anomaly',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-005',
      entityId: '10.0.5.123',
      entityType: 'ip',
      anomalyType: 'unusual_volume',
      score: 0.65,
      severity: 'medium',
      detectedAt: new Date(Date.now() - 1000 * 60 * 32).toISOString(),
      explanation: '평균 대비 3배 이상의 네트워크 트래픽',
      title: 'Unusual Network Volume',
      source: 'UEBA',
      status: 'new',
    },
    {
      id: 'UEBA-006',
      entityId: 'jane.smith@company.com',
      entityType: 'user',
      anomalyType: 'credential_anomaly',
      score: 0.72,
      severity: 'medium',
      detectedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      explanation: '동일 계정으로 여러 지역에서 동시 접속',
      title: 'Credential Anomaly Detected',
      source: 'UEBA',
      status: 'new',
    },
  ];
}

function generateMockEntityRisks(): EntityRisk[] {
  return [
    // 트래픽 급증 관련 고위험 엔티티
    {
      entityId: 'WEB-SERVER-01',
      entityType: 'host',
      riskScore: 0.95,
      anomalyCount: 15,
      lastDetectedAt: new Date(Date.now() - 1000 * 30).toISOString(),
      criticalCount: 5,
    },
    {
      entityId: '10.20.30.100',
      entityType: 'ip',
      riskScore: 0.91,
      anomalyCount: 8,
      lastDetectedAt: new Date(Date.now() - 1000 * 45).toISOString(),
      criticalCount: 3,
    },
    {
      entityId: 'API-GATEWAY-PROD',
      entityType: 'host',
      riskScore: 0.88,
      anomalyCount: 6,
      lastDetectedAt: new Date(Date.now() - 1000 * 60).toISOString(),
      criticalCount: 2,
    },
    // 기존 고위험 엔티티
    {
      entityId: 'john.doe@company.com',
      entityType: 'user',
      riskScore: 0.92,
      anomalyCount: 8,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      criticalCount: 3,
    },
    {
      entityId: '192.168.10.45',
      entityType: 'ip',
      riskScore: 0.88,
      anomalyCount: 12,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      criticalCount: 2,
    },
    {
      entityId: 'WORKSTATION-42',
      entityType: 'host',
      riskScore: 0.85,
      anomalyCount: 6,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
      criticalCount: 2,
    },
    {
      entityId: 'admin@company.com',
      entityType: 'user',
      riskScore: 0.78,
      anomalyCount: 5,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      criticalCount: 1,
    },
    {
      entityId: '10.0.5.123',
      entityType: 'ip',
      riskScore: 0.65,
      anomalyCount: 4,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 32).toISOString(),
      criticalCount: 0,
    },
    {
      entityId: 'jane.smith@company.com',
      entityType: 'user',
      riskScore: 0.62,
      anomalyCount: 3,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      criticalCount: 0,
    },
    {
      entityId: 'SERVER-DB-01',
      entityType: 'host',
      riskScore: 0.58,
      anomalyCount: 3,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
      criticalCount: 0,
    },
    {
      entityId: '172.16.8.90',
      entityType: 'ip',
      riskScore: 0.55,
      anomalyCount: 2,
      lastDetectedAt: new Date(Date.now() - 1000 * 60 * 75).toISOString(),
      criticalCount: 0,
    },
  ];
}

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
        throw new Error('API not available');
      }
    } catch (err) {
      // Fallback to mock data when API is not available
      console.log('UEBA API not available, using mock data');
      set({
        alerts: generateMockUEBAAlerts(),
        lastUpdated: new Date(),
        loading: false,
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
        throw new Error('API not available');
      }
    } catch (err) {
      // Fallback to mock data
      console.log('UEBA Entity Risks API not available, using mock data');
      set({ entityRisks: generateMockEntityRisks() });
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
