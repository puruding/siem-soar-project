/**
 * stages/shared.tsx — Shared sub-components for Pipeline Stage cards
 *
 * SeverityBadge, ConfidenceBar, StatusBadge, MethodBadge, formatTime
 */

// ─── SeverityBadge ────────────────────────────────────────────────────────────

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'severity-badge--critical',
  high: 'severity-badge--high',
  medium: 'severity-badge--medium',
  low: 'severity-badge--low',
  info: 'severity-badge--info',
};

export const SeverityBadge = ({ severity }: { severity: string }) => {
  const cls = SEVERITY_CLASS[severity] ?? 'severity-badge--info';
  return <span className={`severity-badge ${cls}`}>{severity}</span>;
};

// ─── ConfidenceBar ────────────────────────────────────────────────────────────

export const ConfidenceBar = ({ confidence }: { confidence: number }) => {
  const pct = Math.round(confidence * 100);
  const fillColor =
    confidence >= 0.8
      ? 'var(--pip-accent-green)'
      : confidence >= 0.6
        ? 'var(--pip-accent-amber)'
        : 'var(--pip-accent-red)';

  return (
    <div className="confidence-bar">
      <div
        className="confidence-bar__fill"
        style={{ width: `${pct}%`, backgroundColor: fillColor }}
      />
      <span className="confidence-bar__text">{pct}%</span>
    </div>
  );
};

// ─── StatusBadge ──────────────────────────────────────────────────────────────

const STATUS_CLASS: Record<string, string> = {
  PENDING: 'status-badge--pending',
  RUNNING: 'status-badge--running',
  WAITING_APPROVAL: 'status-badge--waiting',
  COMPLETED: 'status-badge--completed',
  FAILED: 'status-badge--failed',
};

const STATUS_LABEL: Record<string, string> = {
  PENDING: 'PENDING',
  RUNNING: 'RUNNING',
  WAITING_APPROVAL: 'APPROVAL',
  COMPLETED: 'DONE',
  FAILED: 'FAILED',
};

export const StatusBadge = ({ status }: { status?: string }) => {
  if (!status) return null;
  const cls = STATUS_CLASS[status] ?? '';
  const label = STATUS_LABEL[status] ?? status;
  return <span className={`status-badge ${cls}`}>{label}</span>;
};

// ─── MethodBadge ──────────────────────────────────────────────────────────────

const METHOD_CLASS: Record<string, string> = {
  SIGMA: 'method-badge--sigma',
  TI_IOC: 'method-badge--ti',
  HYBRID: 'method-badge--hybrid',
};

export const MethodBadge = ({ method }: { method?: string }) => {
  if (!method) return null;
  const cls = METHOD_CLASS[method] ?? '';
  return <span className={`method-badge ${cls}`}>{method}</span>;
};

// ─── formatTime ───────────────────────────────────────────────────────────────

export const formatTime = (timestamp: string): string => {
  try {
    return new Date(timestamp).toLocaleTimeString('ko-KR', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return '--:--:--';
  }
};
