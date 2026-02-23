/**
 * EvidencePanel — AI Classification Evidence Detail Panel
 *
 * Reads the currently selected event's Classification record from the pipeline
 * store and renders the matched rules, IOCs, and MITRE mappings as itemised
 * evidence, together with processing metadata.
 *
 * When no event is selected the panel shows an empty-state prompt.
 */

import { FileSearch } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';

// ─── Evidence item shape derived from a Classification ────────────────────────

type EvidenceCategory = 'rule' | 'ioc' | 'mitre';
type EvidenceImportance = 'high' | 'medium' | 'low';

interface EvidenceItem {
  key: string;
  category: EvidenceCategory;
  importance: EvidenceImportance;
  label: string;
  detail: string;
}

// ─── Evidence type → existing CSS class mapping ───────────────────────────────

// The existing CSS defines .evidence-type.ip / .hash / .domain / .user / .process
// We map our three categories to the closest styled variant.
const CATEGORY_CSS: Record<EvidenceCategory, string> = {
  rule:  'hash',    // purple — rule / signature match
  ioc:   'ip',      // blue  — network indicator
  mitre: 'domain',  // cyan  — ATT&CK framework mapping
};

const CATEGORY_LABEL: Record<EvidenceCategory, string> = {
  rule:  'SIGMA RULE',
  ioc:   'IOC MATCH',
  mitre: 'ATT&CK',
};

// ─── Component ─────────────────────────────────────────────────────────────────

export const EvidencePanel = () => {
  const selectedEventId = usePipelineStore((s) => s.selectedEventId);
  const classifications = usePipelineStore((s) => s.classifications);

  const classification = selectedEventId
    ? (classifications.get(selectedEventId) ?? null)
    : null;

  // ── Empty state ────────────────────────────────────────────────────────────

  if (!classification) {
    return (
      <div className="detail-panel">
        <div className="detail-panel-header">
          <FileSearch className="detail-panel-icon" size={14} color="var(--pip-accent-amber)" />
          <span className="detail-panel-title">AI 분류 근거</span>
          <span className="detail-panel-badge amber">0 items</span>
        </div>
        <div
          className="detail-panel-body"
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--pip-text-secondary)',
            fontSize: '12px',
            textAlign: 'center',
            letterSpacing: '0.04em',
          }}
        >
          이벤트를 선택하면<br />분류 근거가 표시됩니다.
        </div>
      </div>
    );
  }

  // ── Build evidence items from classification data ──────────────────────────

  const items: EvidenceItem[] = [];

  (classification.matched_rules ?? []).forEach((rule) => {
    items.push({
      key:        `rule-${rule}`,
      category:   'rule',
      importance: 'high',
      label:      rule,
      detail:     'Sigma 규칙과 패턴 일치',
    });
  });

  (classification.matched_iocs ?? []).forEach((ioc) => {
    items.push({
      key:        `ioc-${ioc}`,
      category:   'ioc',
      importance: 'high',
      label:      ioc,
      detail:     'TI 피드에서 알려진 악성 지표',
    });
  });

  (classification.mitre_tactics ?? []).forEach((tactic) => {
    items.push({
      key:        `tactic-${tactic}`,
      category:   'mitre',
      importance: 'medium',
      label:      tactic,
      detail:     '공격 체인 단계 매핑',
    });
  });

  (classification.mitre_techniques ?? []).forEach((tech) => {
    items.push({
      key:        `tech-${tech}`,
      category:   'mitre',
      importance: 'low',
      label:      tech,
      detail:     'ATT&CK 기술 식별자',
    });
  });

  const confidencePct = Math.round(classification.confidence * 100);

  // Importance → confidence proxy for display
  const importanceColor: Record<EvidenceImportance, string> = {
    high:   'var(--pip-accent-red)',
    medium: 'var(--pip-accent-amber)',
    low:    'var(--pip-accent-blue)',
  };

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <FileSearch className="detail-panel-icon" size={14} color="var(--pip-accent-amber)" />
        <span className="detail-panel-title">AI 분류 근거</span>
        <span className="detail-panel-badge amber">{items.length} items</span>
      </div>

      <div className="detail-panel-body">

        {/* Confidence summary row */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: '12px',
            padding: '6px 8px',
            background: 'var(--pip-bg-elevated)',
            borderRadius: '4px',
            border: '1px solid var(--pip-border)',
          }}
        >
          <span style={{ fontSize: '10px', color: 'var(--pip-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            신뢰도
          </span>
          <span style={{ fontSize: '13px', fontFamily: "'DM Mono', monospace", fontWeight: 700, color: confidencePct >= 80 ? 'var(--pip-accent-green)' : confidencePct >= 60 ? 'var(--pip-accent-amber)' : 'var(--pip-accent-red)' }}>
            {confidencePct}%
          </span>
          <span style={{ fontSize: '10px', color: 'var(--pip-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            방법
          </span>
          <span style={{ fontSize: '11px', fontFamily: "'DM Mono', monospace", fontWeight: 600, color: 'var(--pip-accent-cyan)' }}>
            {classification.method}
          </span>
          <span style={{ fontSize: '10px', color: 'var(--pip-text-secondary)', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            처리
          </span>
          <span style={{ fontSize: '11px', fontFamily: "'DM Mono', monospace", fontWeight: 600, color: 'var(--pip-text-primary)' }}>
            {classification.processing_time_ms}ms
          </span>
        </div>

        {/* Evidence items */}
        {items.length === 0 ? (
          <div style={{ color: 'var(--pip-text-secondary)', fontSize: '12px' }}>
            분류 근거 데이터가 없습니다.
          </div>
        ) : (
          items.map((item, i) => (
            <div
              key={item.key}
              className="evidence-item"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="evidence-item-header">
                <span className={`evidence-type ${CATEGORY_CSS[item.category]}`}>
                  {CATEGORY_LABEL[item.category]}
                </span>
                <span
                  className="evidence-confidence"
                  style={{ color: importanceColor[item.importance] }}
                >
                  {item.importance.toUpperCase()}
                </span>
              </div>
              <div className="evidence-value">{item.label}</div>
              <div className="evidence-meta">{item.detail}</div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};
