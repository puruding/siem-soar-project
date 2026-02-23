/**
 * PipelinePage — Event Classification Pipeline with Demo Simulator
 *
 * Real-time visualization of the 4-stage SIEM event processing pipeline.
 * Includes a built-in demo simulator for testing without backend.
 */

import { useEffect, useRef, useCallback, useState } from 'react';
import {
  ArrowRight,
  Radio,
  BrainCircuit,
  BookMarked,
  Zap,
  ShieldCheck,
  FileSearch,
  ClipboardList,
  Play,
  Square,
  RefreshCw,
  Wifi,
  WifiOff,
} from 'lucide-react';
import '../styles/pipeline.css';
import { usePipelineStore } from '../stores/pipelineStore';
import { usePipelineWebSocket } from '../hooks/usePipelineWebSocket';
import type { PipelineEvent, Classification, AuditLog, PipelineStats } from '../types/pipeline';

// ─── Demo Asset & Log Templates ────────────────────────────────────────────────

interface DemoAsset {
  id: string;
  name: string;
  type: string;
  ip: string;
  logTemplates: string[];
}

const DEMO_ASSETS: DemoAsset[] = [
  {
    id: 'asset-fw-01',
    name: 'Palo Alto PA-5260',
    type: 'Firewall',
    ip: '10.1.1.1',
    logTemplates: [
      'THREAT,drop,from={src_ip},to={dst_ip},port=443,app=ssl,threat-id=40001',
      'TRAFFIC,allow,from={src_ip},to={dst_ip},port=80,bytes=2048,session-end',
      'THREAT,alert,signature=Suspicious DNS Query,severity=high,from={src_ip}',
    ],
  },
  {
    id: 'asset-edr-01',
    name: 'CrowdStrike Falcon',
    type: 'EDR',
    ip: '10.1.2.50',
    logTemplates: [
      'DetectionSummaryEvent,ProcessName=powershell.exe,CommandLine=-enc JABz...,Severity=Critical',
      'ProcessRollup,ParentProcess=explorer.exe,ChildProcess=cmd.exe,User=CORP\\admin',
      'NetworkConnect,Process=chrome.exe,RemoteIP={dst_ip},RemotePort=443',
    ],
  },
  {
    id: 'asset-srv-01',
    name: 'Windows Server 2022',
    type: 'Server',
    ip: '10.1.3.100',
    logTemplates: [
      'EventID=4625,FailedLogin,User=administrator,Source={src_ip},FailureReason=BadPassword',
      'EventID=4688,ProcessCreate,NewProcess=mimikatz.exe,Creator=cmd.exe,User=SYSTEM',
      'EventID=4672,SpecialPrivileges,User=svc_backup,Privileges=SeDebugPrivilege',
    ],
  },
  {
    id: 'asset-proxy-01',
    name: 'Zscaler Cloud Proxy',
    type: 'Proxy',
    ip: '10.1.4.10',
    logTemplates: [
      'action=blocked,url=http://malware-download.ru/payload.exe,user=jsmith,category=malware',
      'action=allowed,url=https://drive.google.com/download,user=analyst,bytes=50000',
      'action=blocked,url=http://c2-server.xyz/beacon,user=guest,category=command-and-control',
    ],
  },
];

const MALICIOUS_IPS = ['185.220.101.47', '91.219.236.222', '45.33.32.156', '198.51.100.23'];
const BENIGN_IPS = ['8.8.8.8', '1.1.1.1', '142.250.185.46', '151.101.1.140'];

const SIGMA_RULES = [
  { id: 'SIGMA-0091', name: 'Mimikatz Execution', tactic: 'TA0006', technique: 'T1003.001' },
  { id: 'SIGMA-0044', name: 'Suspicious PowerShell Encoded Command', tactic: 'TA0002', technique: 'T1059.001' },
  { id: 'SIGMA-0023', name: 'Multiple Failed Logins', tactic: 'TA0006', technique: 'T1110.003' },
  { id: 'SIGMA-0078', name: 'Outbound C2 Communication', tactic: 'TA0011', technique: 'T1071.001' },
];

const PLAYBOOKS = [
  { id: 'pb-001', name: 'Endpoint Isolation', steps: 5, triggers: ['malware', 'lateral-movement'] },
  { id: 'pb-002', name: 'Account Lockout', steps: 3, triggers: ['brute-force', 'credential-access'] },
  { id: 'pb-003', name: 'Block IP at Firewall', steps: 4, triggers: ['c2', 'exfiltration'] },
  { id: 'pb-004', name: 'Escalate to SOC Tier 2', steps: 2, triggers: ['critical', 'high-severity'] },
];

// ─── Utility Functions ─────────────────────────────────────────────────────────

const randomId = () => Math.random().toString(36).substring(2, 10);
const randomChoice = <T,>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)]!;
const randomInt = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min;

// ─── Utility Sub-components ─────────────────────────────────────────────────────

const LiveBadge = ({ connected }: { connected: boolean }) => (
  <div className={`live-badge${connected ? '' : ' disconnected'}`} role="status">
    <div className="live-dot" />
    <span>{connected ? 'LIVE' : 'DEMO'}</span>
  </div>
);

const StatPill = ({ label, value, accent }: { label: string; value: string | number; accent?: string }) => (
  <div className="stat-pill">
    <span className="stat-pill-label">{label}</span>
    <span className={`stat-pill-value${accent ? ` accent-${accent}` : ''}`}>{value}</span>
  </div>
);

const StageConnector = () => (
  <div className="stage-connector" aria-hidden="true">
    <div className="connector-line" />
    <ArrowRight className="connector-arrow" size={14} />
    <div className="connector-line" />
  </div>
);

// ─── Stage Components ──────────────────────────────────────────────────────────

const EventReceiveStage = () => {
  const events = usePipelineStore((s) => s.events);
  const selectedEventId = usePipelineStore((s) => s.selectedEventId);
  const setSelectedEvent = usePipelineStore((s) => s.setSelectedEvent);

  const filteredEvents = events.filter((e) => e.stage === 'event_receive').slice(0, 8);

  const handleClick = useCallback((eventId: string) => {
    setSelectedEvent(selectedEventId === eventId ? null : eventId);
  }, [selectedEventId, setSelectedEvent]);

  return (
    <div className="stage-card stage-receive">
      <div className="stage-header">
        <div className="stage-index">1</div>
        <Radio className="stage-icon" size={14} />
        <span className="stage-name">이벤트 수신</span>
        {filteredEvents.length > 0 && <span className="stage-event-count">{filteredEvents.length}</span>}
      </div>
      {filteredEvents.length === 0 ? (
        <div className="stage-empty">대기 중...</div>
      ) : (
        <div className="stage-event-list">
          {filteredEvents.map((event, i) => (
            <div
              key={event.id}
              className={`stage-event-item${selectedEventId === event.id ? ' selected' : ''}`}
              onClick={() => handleClick(event.id)}
              style={{ animationDelay: `${i * 40}ms` }}
            >
              <span className={`severity-badge severity-badge--${event.severity}`}>{event.severity}</span>
              <span className="event-source">{event.source.split(' ')[0]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const ClassificationStage = () => {
  const events = usePipelineStore((s) => s.events);
  const classifications = usePipelineStore((s) => s.classifications);

  const filteredEvents = events.filter((e) => e.stage === 'classification').slice(0, 5);

  return (
    <div className="stage-card stage-classify">
      <div className="stage-header">
        <div className="stage-index">2</div>
        <BrainCircuit className="stage-icon" size={14} />
        <span className="stage-name">AI 분류</span>
        {filteredEvents.length > 0 && <span className="stage-event-count">{filteredEvents.length}</span>}
      </div>
      {filteredEvents.length === 0 ? (
        <div className="stage-empty">분류 대기 중...</div>
      ) : (
        <div className="stage-classification-list">
          {filteredEvents.map((event, i) => {
            const cl = classifications.get(event.id);
            return (
              <div key={event.id} className="classification-item" style={{ animationDelay: `${i * 50}ms` }}>
                <div className="classification-label">{cl?.label ?? 'Processing...'}</div>
                {cl && (
                  <div className="confidence-bar">
                    <div
                      className="confidence-bar__fill"
                      style={{
                        width: `${Math.round(cl.confidence * 100)}%`,
                        backgroundColor: cl.confidence >= 0.8 ? 'var(--pip-accent-green)' : cl.confidence >= 0.6 ? 'var(--pip-accent-amber)' : 'var(--pip-accent-red)',
                      }}
                    />
                    <span className="confidence-bar__text">{Math.round(cl.confidence * 100)}%</span>
                  </div>
                )}
                {cl && <span className={`method-badge method-badge--${cl.method.toLowerCase().replace('_', '-')}`}>{cl.method}</span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const PlaybookSelectStage = () => {
  const events = usePipelineStore((s) => s.events);

  const filteredEvents = events.filter((e) => e.stage === 'playbook_select' && e.playbook_match).slice(0, 5);

  return (
    <div className="stage-card stage-playbook">
      <div className="stage-header">
        <div className="stage-index">3</div>
        <BookMarked className="stage-icon" size={14} />
        <span className="stage-name">Playbook 선택</span>
        {filteredEvents.length > 0 && <span className="stage-event-count">{filteredEvents.length}</span>}
      </div>
      {filteredEvents.length === 0 ? (
        <div className="stage-empty">매칭 대기 중...</div>
      ) : (
        <div className="stage-playbook-list">
          {filteredEvents.map((event, i) => {
            const match = event.playbook_match!;
            return (
              <div key={event.id} className="playbook-item" style={{ animationDelay: `${i * 50}ms` }}>
                <div className="playbook-name">{match.playbook_name}</div>
                <div className="playbook-meta">
                  <span className={`match-score${Math.round(match.match_score * 100) >= 90 ? ' match-score--high' : ''}`}>
                    {Math.round(match.match_score * 100)}%
                  </span>
                  <span className="step-count">{match.step_count} steps</span>
                </div>
                <div className="trigger-tags">
                  {match.trigger_tags.slice(0, 2).map((tag) => (
                    <span key={tag} className="trigger-tag">{tag}</span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const FlowExecutionStage = () => {
  const events = usePipelineStore((s) => s.events);

  const filteredEvents = events.filter((e) => e.stage === 'flow_execution' && e.execution).slice(0, 5);

  return (
    <div className="stage-card stage-execute">
      <div className="stage-header">
        <div className="stage-index">4</div>
        <Zap className="stage-icon" size={14} />
        <span className="stage-name">Flow 실행</span>
        {filteredEvents.length > 0 && <span className="stage-event-count">{filteredEvents.length}</span>}
      </div>
      {filteredEvents.length === 0 ? (
        <div className="stage-empty">실행 대기 중...</div>
      ) : (
        <div className="stage-execution-list">
          {filteredEvents.map((event, i) => {
            const exec = event.execution!;
            const progressPct = exec.total_steps > 0 ? Math.round((exec.current_step / exec.total_steps) * 100) : 0;
            return (
              <div key={event.id} className="execution-item" style={{ animationDelay: `${i * 50}ms` }}>
                <div className="execution-header">
                  <span className={`status-badge status-badge--${exec.status.toLowerCase().replace('_', '-')}`}>
                    {exec.status === 'WAITING_APPROVAL' ? 'APPROVAL' : exec.status}
                  </span>
                  <span className="execution-steps">{exec.current_step}/{exec.total_steps}</span>
                </div>
                <div className="execution-progress-track">
                  <div
                    className={`execution-progress-fill${exec.status === 'RUNNING' ? ' running' : exec.status === 'COMPLETED' ? ' completed' : ''}`}
                    style={{ width: `${progressPct}%` }}
                  />
                </div>
                {exec.approval_info && exec.approval_info.status === 'PENDING' && (
                  <div className="approval-gate">
                    <span className="approval-step-name">{exec.approval_info.step_name}</span>
                    <div className="approval-actions">
                      <button className="btn-approve">승인</button>
                      <button className="btn-reject">거부</button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

// ─── Panel Components ──────────────────────────────────────────────────────────

const MitrePanel = () => {
  const selectedEventId = usePipelineStore((s) => s.selectedEventId);
  const classifications = usePipelineStore((s) => s.classifications);
  const cl = selectedEventId ? classifications.get(selectedEventId) : null;

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <ShieldCheck className="detail-panel-icon" size={14} style={{ color: 'var(--pip-accent-cyan)' }} />
        <span className="detail-panel-title">MITRE ATT&CK</span>
        <span className="detail-panel-badge cyan">{cl ? 'Active' : 'Demo'}</span>
      </div>
      <div className="detail-panel-body">
        {cl && cl.mitre_tactics && cl.mitre_tactics.length > 0 ? (
          <div className="mitre-mapping">
            {cl.mitre_tactics.map((tactic, i) => (
              <div key={tactic} className="mitre-tactic" style={{ animationDelay: `${i * 60}ms` }}>
                <div className="mitre-tactic-header">
                  <span className="mitre-tactic-name">{tactic}</span>
                  <span className="mitre-tactic-count">ACTIVE</span>
                </div>
                <div className="mitre-bar-track">
                  <div className="mitre-bar-fill" style={{ width: '75%' }} />
                </div>
                <div className="mitre-technique-list">
                  {(cl.mitre_techniques || []).map((tech) => (
                    <span key={tech} className="mitre-technique-tag">{tech}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ color: 'var(--pip-text-secondary)', fontSize: '12px', padding: '16px 0' }}>
            이벤트를 선택하면 ATT&CK 매핑이 표시됩니다.
          </div>
        )}
      </div>
    </div>
  );
};

const EvidencePanel = () => {
  const selectedEventId = usePipelineStore((s) => s.selectedEventId);
  const classifications = usePipelineStore((s) => s.classifications);
  const cl = selectedEventId ? classifications.get(selectedEventId) : null;

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <FileSearch className="detail-panel-icon" size={14} style={{ color: 'var(--pip-accent-amber)' }} />
        <span className="detail-panel-title">분류 근거</span>
        <span className="detail-panel-badge amber">{cl ? `${(cl.matched_rules?.length ?? 0) + (cl.matched_iocs?.length ?? 0)} items` : '0 items'}</span>
      </div>
      <div className="detail-panel-body">
        {cl ? (
          <div className="evidence-list">
            {(cl.matched_rules || []).map((rule) => (
              <div key={rule} className="evidence-item">
                <span className="evidence-type hash">SIGMA</span>
                <span className="evidence-value">{rule}</span>
              </div>
            ))}
            {(cl.matched_iocs || []).map((ioc) => (
              <div key={ioc} className="evidence-item">
                <span className="evidence-type ip">IOC</span>
                <span className="evidence-value">{ioc}</span>
              </div>
            ))}
            <div style={{ marginTop: '12px', padding: '8px', background: 'var(--pip-bg-elevated)', borderRadius: '4px' }}>
              <div style={{ fontSize: '10px', color: 'var(--pip-text-secondary)', marginBottom: '4px' }}>신뢰도</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: cl.confidence >= 0.8 ? 'var(--pip-accent-green)' : 'var(--pip-accent-amber)' }}>
                {Math.round(cl.confidence * 100)}%
              </div>
            </div>
          </div>
        ) : (
          <div style={{ color: 'var(--pip-text-secondary)', fontSize: '12px', padding: '16px 0' }}>
            이벤트를 선택하면 분류 근거가 표시됩니다.
          </div>
        )}
      </div>
    </div>
  );
};

const AuditLogPanel = () => {
  const auditLogs = usePipelineStore((s) => s.auditLogs);
  const displayLogs = auditLogs.slice(0, 15);

  const formatTime = (iso: string) => {
    try {
      return new Date(iso).toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
    } catch {
      return '--:--:--';
    }
  };

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <ClipboardList className="detail-panel-icon" size={14} style={{ color: 'var(--pip-accent-green)' }} />
        <span className="detail-panel-title">감사 로그</span>
        <span className="detail-panel-badge green">{displayLogs.length > 0 ? 'Live' : 'Waiting'}</span>
      </div>
      <div className="detail-panel-body">
        {displayLogs.length === 0 ? (
          <div style={{ color: 'var(--pip-text-secondary)', fontSize: '12px', padding: '16px 0' }}>
            시뮬레이션을 시작하면 로그가 표시됩니다.
          </div>
        ) : (
          displayLogs.map((log, i) => (
            <div key={log.id} className="audit-entry" style={{ animationDelay: `${Math.min(i * 40, 400)}ms` }}>
              <div className={`audit-dot ${log.actor_type === 'AI' ? 'ai' : log.actor_type === 'SOAR' ? 'success' : 'info'}`} />
              <div className="audit-time">{formatTime(log.created_at)}</div>
              <div className="audit-content">
                <div className="audit-action">{log.message}</div>
                <div className={`audit-actor ${log.actor_type.toLowerCase()}`}>[{log.actor_type}] {log.actor_id}</div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// ─── Main Page ─────────────────────────────────────────────────────────────────

export function PipelinePage() {
  const [mode, setMode] = useState<'demo' | 'live'>('demo');
  const [isRunning, setIsRunning] = useState(false);
  const [eventCount, setEventCount] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const eventQueueRef = useRef<Map<string, { stage: number; nextTime: number }>>(new Map());

  // Live mode WebSocket connection
  const { isConnected: wsConnected, reconnect: wsReconnect, disconnect: wsDisconnect } = usePipelineWebSocket('default');

  const stats = usePipelineStore((s) => s.stats);
  const isConnected = usePipelineStore((s) => s.isConnected);

  // Get store actions once
  const addEvent = usePipelineStore((s) => s.addEvent);
  const updateEvent = usePipelineStore((s) => s.updateEvent);
  const addClassification = usePipelineStore((s) => s.addClassification);
  const addAuditLog = usePipelineStore((s) => s.addAuditLog);
  const setStats = usePipelineStore((s) => s.setStats);
  const setConnectionStatus = usePipelineStore((s) => s.setConnectionStatus);
  const clearEvents = usePipelineStore((s) => s.clearEvents);

  // Generate a new event from a random asset
  const generateEvent = useCallback((): PipelineEvent => {
    const asset = randomChoice(DEMO_ASSETS);
    const template = randomChoice(asset.logTemplates);
    const isMalicious = Math.random() > 0.6;
    const srcIp = isMalicious ? randomChoice(MALICIOUS_IPS) : randomChoice(BENIGN_IPS);
    const dstIp = randomChoice(BENIGN_IPS);

    const rawLog = template
      .replace('{src_ip}', srcIp)
      .replace('{dst_ip}', dstIp);

    const severity = isMalicious
      ? (Math.random() > 0.5 ? 'critical' : 'high')
      : (Math.random() > 0.5 ? 'medium' : 'low');

    return {
      id: `evt-${randomId()}`,
      tenant_id: 'demo-tenant',
      raw_log: rawLog,
      source: `${asset.name} (${asset.ip})`,
      severity,
      stage: 'event_receive',
      created_at: new Date().toISOString(),
    };
  }, []);

  // Process event through pipeline stages
  const processEvent = useCallback((eventId: string, currentStage: number) => {
    const stages: PipelineEvent['stage'][] = ['event_receive', 'classification', 'playbook_select', 'flow_execution'];

    if (currentStage >= stages.length) {
      eventQueueRef.current.delete(eventId);
      return;
    }

    const nextStage = stages[currentStage];
    if (!nextStage) return;

    // Update event stage
    updateEvent(eventId, { stage: nextStage });

    // Stage-specific processing
    if (nextStage === 'classification') {
      setTimeout(() => {
        const rule = randomChoice(SIGMA_RULES);
        const isMalicious = Math.random() > 0.4;
        const classification: Classification = {
          id: `cls-${randomId()}`,
          event_id: eventId,
          label: isMalicious ? rule.name : 'Benign Activity',
          confidence: isMalicious ? randomInt(75, 98) / 100 : randomInt(85, 99) / 100,
          method: randomChoice(['SIGMA', 'TI_IOC', 'HYBRID']),
          matched_rules: isMalicious ? [rule.id] : [],
          matched_iocs: isMalicious && Math.random() > 0.5 ? [randomChoice(MALICIOUS_IPS)] : [],
          mitre_tactics: isMalicious ? [rule.tactic] : [],
          mitre_techniques: isMalicious ? [rule.technique] : [],
          processing_time_ms: randomInt(5, 45),
        };
        addClassification(classification);

        addAuditLog({
          id: `audit-${randomId()}`,
          event_type: 'classification',
          actor_type: 'AI',
          actor_id: 'ml-classifier-v2',
          message: `분류 완료: ${classification.label} (신뢰도 ${Math.round(classification.confidence * 100)}%)`,
          created_at: new Date().toISOString(),
        });
      }, randomInt(200, 500));
    }

    if (nextStage === 'playbook_select') {
      setTimeout(() => {
        const playbook = randomChoice(PLAYBOOKS);
        updateEvent(eventId, {
          playbook_match: {
            playbook_id: playbook.id,
            playbook_name: playbook.name,
            match_score: randomInt(70, 98) / 100,
            trigger_tags: playbook.triggers,
            step_count: playbook.steps,
          },
        });

        addAuditLog({
          id: `audit-${randomId()}`,
          event_type: 'playbook_match',
          actor_type: 'SOAR',
          actor_id: 'playbook-matcher',
          message: `Playbook 매칭: ${playbook.name} (${playbook.steps} 스텝)`,
          created_at: new Date().toISOString(),
        });
      }, randomInt(100, 300));
    }

    if (nextStage === 'flow_execution') {
      setTimeout(() => {
        const needsApproval = Math.random() > 0.7;
        updateEvent(eventId, {
          execution: {
            execution_id: `exec-${randomId()}`,
            status: needsApproval ? 'WAITING_APPROVAL' : 'RUNNING',
            current_step: needsApproval ? 2 : randomInt(1, 3),
            total_steps: randomInt(3, 6),
            approval_info: needsApproval ? {
              approval_id: `appr-${randomId()}`,
              step_name: 'Isolate Endpoint',
              required_role: 'SOC Tier 2',
              status: 'PENDING',
            } : undefined,
          },
        });

        addAuditLog({
          id: `audit-${randomId()}`,
          event_type: 'execution',
          actor_type: 'SOAR',
          actor_id: 'temporal-engine',
          message: needsApproval ? '승인 대기: Isolate Endpoint 단계' : 'Flow 실행 중...',
          created_at: new Date().toISOString(),
        });
      }, randomInt(200, 400));
    }

    // Schedule next stage
    const queueItem = eventQueueRef.current.get(eventId);
    if (queueItem) {
      queueItem.stage = currentStage + 1;
      queueItem.nextTime = Date.now() + randomInt(1500, 3000);
    }
  }, [updateEvent, addClassification, addAuditLog]);

  // Main simulation tick
  const tick = useCallback(() => {
    const now = Date.now();

    // Generate new events periodically
    if (Math.random() > 0.6) {
      const event = generateEvent();
      addEvent(event);
      setEventCount((c) => c + 1);
      eventQueueRef.current.set(event.id, {
        stage: 0,
        nextTime: now + randomInt(800, 1500),
      });

      addAuditLog({
        id: `audit-${randomId()}`,
        event_type: 'event_receive',
        actor_type: 'SYSTEM',
        actor_id: 'log-collector',
        message: `이벤트 수신: ${event.source}`,
        created_at: new Date().toISOString(),
      });
    }

    // Process queued events
    eventQueueRef.current.forEach((item, eventId) => {
      if (now >= item.nextTime) {
        processEvent(eventId, item.stage);
      }
    });

    // Update stats
    const currentState = usePipelineStore.getState();
    const newStats: PipelineStats = {
      total_events: currentState.events.length * 10 + eventCount * 5,
      processed_events: currentState.events.filter((e) => e.stage !== 'event_receive').length,
      auto_classified: currentState.events.filter((e) => e.stage === 'classification' || e.stage === 'playbook_select' || e.stage === 'flow_execution').length,
      automation_rate: 0.72 + Math.random() * 0.15,
      avg_processing_ms: randomInt(8, 25),
    };
    setStats(newStats);
  }, [generateEvent, addEvent, processEvent, addAuditLog, setStats, eventCount]);

  const handleStart = useCallback(() => {
    if (intervalRef.current) return;
    setConnectionStatus('connected');
    setIsRunning(true);

    // Generate initial batch immediately
    for (let i = 0; i < 3; i++) {
      const event = generateEvent();
      addEvent(event);
      eventQueueRef.current.set(event.id, {
        stage: 0,
        nextTime: Date.now() + randomInt(500, 1000) * (i + 1),
      });
    }

    intervalRef.current = setInterval(tick, 1000);
  }, [tick, setConnectionStatus, generateEvent, addEvent]);

  const handleStop = useCallback(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    setConnectionStatus('disconnected');
    setIsRunning(false);
  }, [setConnectionStatus]);

  const handleReset = useCallback(() => {
    handleStop();
    clearEvents();
    eventQueueRef.current.clear();
    setEventCount(0);
  }, [handleStop, clearEvents]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, []);

  const displayStats = stats ?? { total_events: 0, processed_events: 0, automation_rate: 0, avg_processing_ms: 0 };

  return (
    <div className="pipeline-page">
      {/* ── Header ────────────────────────────────────────────── */}
      <header className="pipeline-header">
        <div className="pipeline-title-group">
          <div className="pipeline-eyebrow">SIEM · SOAR Integration Layer</div>
          <h1 className="pipeline-title">Event Classification Pipeline</h1>
        </div>

        <div className="pipeline-stats">
          <LiveBadge connected={isConnected} />
          <StatPill label="수신" value={displayStats.total_events >= 1000 ? `${(displayStats.total_events / 1000).toFixed(1)}K` : displayStats.total_events} accent="cyan" />
          <StatPill label="분류" value={displayStats.processed_events.toLocaleString()} accent="blue" />
          <StatPill label="자동화율" value={`${Math.round(displayStats.automation_rate * 100)}%`} accent="green" />
          <StatPill label="지연" value={`${displayStats.avg_processing_ms}ms`} accent="amber" />

          {/* Mode Toggle */}
          <div className="sim-controls">
            {/* Mode Switcher */}
            <div className="mode-switcher" style={{ display: 'flex', gap: '4px', marginRight: '8px', padding: '2px', background: 'var(--pip-bg-elevated)', borderRadius: '6px' }}>
              <button
                className={`sim-btn ${mode === 'live' ? 'sim-btn--active' : ''}`}
                onClick={() => { setMode('live'); handleStop(); }}
                title="실시간 모드 (백엔드 연결)"
                style={{
                  background: mode === 'live' ? 'var(--pip-accent-green)' : 'transparent',
                  color: mode === 'live' ? '#000' : 'inherit'
                }}
              >
                <Wifi size={14} /> Live
              </button>
              <button
                className={`sim-btn ${mode === 'demo' ? 'sim-btn--active' : ''}`}
                onClick={() => { setMode('demo'); wsDisconnect(); }}
                title="데모 모드 (시뮬레이션)"
                style={{
                  background: mode === 'demo' ? 'var(--pip-accent-cyan)' : 'transparent',
                  color: mode === 'demo' ? '#000' : 'inherit'
                }}
              >
                <Play size={14} /> Demo
              </button>
            </div>

            {/* Demo Controls */}
            {mode === 'demo' && (
              <>
                {!isRunning ? (
                  <button className="sim-btn sim-btn--start" onClick={handleStart} title="시뮬레이션 시작">
                    <Play size={14} /> 시작
                  </button>
                ) : (
                  <button className="sim-btn sim-btn--stop" onClick={handleStop} title="시뮬레이션 중지">
                    <Square size={14} /> 중지
                  </button>
                )}
              </>
            )}

            {/* Live Controls */}
            {mode === 'live' && (
              <>
                {!wsConnected ? (
                  <button className="sim-btn sim-btn--start" onClick={wsReconnect} title="WebSocket 연결">
                    <Wifi size={14} /> 연결
                  </button>
                ) : (
                  <button className="sim-btn sim-btn--stop" onClick={wsDisconnect} title="WebSocket 연결 해제">
                    <WifiOff size={14} /> 연결 해제
                  </button>
                )}
              </>
            )}

            <button className="sim-btn sim-btn--reset" onClick={handleReset} title="초기화">
              <RefreshCw size={14} />
            </button>
          </div>
        </div>
      </header>

      {/* ── Pipeline Flow — 4 Stages ──────────────────────────── */}
      <section className="pipeline-flow" aria-label="Pipeline stages">
        <EventReceiveStage />
        <StageConnector />
        <ClassificationStage />
        <StageConnector />
        <PlaybookSelectStage />
        <StageConnector />
        <FlowExecutionStage />
      </section>

      {/* ── Detail Panels — 3-column grid ────────────────────── */}
      <section className="detail-panels" aria-label="Detail panels">
        <MitrePanel />
        <EvidencePanel />
        <AuditLogPanel />
      </section>
    </div>
  );
}
