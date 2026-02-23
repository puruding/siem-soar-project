/**
 * AuditLogPanel — Real-time Audit Log Detail Panel
 *
 * Streams the latest audit log entries from the pipeline store (populated by the
 * WebSocket hook) and renders them in a timestamped, colour-coded list.
 *
 * Actor type → CSS class / colour mapping matches the existing pipeline.css:
 *   .audit-actor.system → cyan
 *   .audit-actor.ai     → purple
 *   .audit-actor.user   → amber
 *   .audit-actor.auto   → green   (SOAR automation)
 *
 * Dot colour follows event severity implied by actor_type:
 *   AI → ai (purple)   SYSTEM → info (blue)   SOAR → success (green)   USER → warn (amber)
 */

import { ClipboardList } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';
import type { AuditLog } from '../../types/pipeline';

// ─── Mapping helpers ───────────────────────────────────────────────────────────

type DotVariant    = 'info' | 'success' | 'warn' | 'error' | 'ai';
type ActorVariant  = 'system' | 'ai' | 'user' | 'auto';

const ACTOR_TYPE_TO_CSS: Record<AuditLog['actor_type'], ActorVariant> = {
  AI:     'ai',
  SYSTEM: 'system',
  SOAR:   'auto',
  USER:   'user',
};

const ACTOR_TYPE_TO_DOT: Record<AuditLog['actor_type'], DotVariant> = {
  AI:     'ai',
  SYSTEM: 'info',
  SOAR:   'success',
  USER:   'warn',
};

/**
 * Format an ISO timestamp into HH:MM:SS using the user's locale time zone.
 * Falls back to raw string if parsing fails.
 */
const formatTime = (isoString: string): string => {
  try {
    return new Date(isoString).toLocaleTimeString('ko-KR', {
      hour:   '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return isoString;
  }
};

// ─── Component ─────────────────────────────────────────────────────────────────

export const AuditLogPanel = () => {
  // Keep rendering snappy by slicing before subscribing — Zustand selector runs
  // on every store update so we limit the slice inside the selector itself.
  const auditLogs   = usePipelineStore((s) => s.auditLogs.slice(0, 50));
  const isConnected = usePipelineStore((s) => s.isConnected);

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <ClipboardList className="detail-panel-icon" size={14} color="var(--pip-accent-green)" />
        <span className="detail-panel-title">감사 로그</span>

        {isConnected ? (
          <span className="detail-panel-badge green">
            {/* Inline LIVE indicator using the existing .live-badge styles would
                require nesting, so we replicate the visual with inline styles
                to stay within the established badge slot. */}
            <span
              style={{
                display: 'inline-block',
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: 'var(--pip-accent-green)',
                boxShadow: '0 0 6px var(--pip-accent-green)',
                animation: 'pip-pulse 2s ease-in-out infinite',
                marginRight: '5px',
                verticalAlign: 'middle',
              }}
            />
            LIVE
          </span>
        ) : (
          <span className="detail-panel-badge green">Real-time</span>
        )}
      </div>

      <div className="detail-panel-body">
        {auditLogs.length === 0 ? (
          <div
            style={{
              color:       'var(--pip-text-secondary)',
              fontSize:    '12px',
              paddingTop:  '12px',
              letterSpacing: '0.04em',
            }}
          >
            대기 중 — 파이프라인에 연결하면 로그가 표시됩니다.
          </div>
        ) : (
          auditLogs.map((log, i) => {
            const actorCss = ACTOR_TYPE_TO_CSS[log.actor_type] ?? 'system';
            const dotCss   = ACTOR_TYPE_TO_DOT[log.actor_type] ?? 'info';

            return (
              <div
                key={log.id}
                className="audit-entry"
                style={{ animationDelay: `${Math.min(i * 40, 480)}ms` }}
              >
                <div className={`audit-dot ${dotCss}`} />
                <div className="audit-time">{formatTime(log.created_at)}</div>
                <div className="audit-content">
                  <div className="audit-action">{log.message}</div>
                  <div className={`audit-actor ${actorCss}`}>
                    [{log.actor_type}] {log.actor_id}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
