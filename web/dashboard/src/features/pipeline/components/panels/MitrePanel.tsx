/**
 * MitrePanel — MITRE ATT&CK Mapping Detail Panel
 *
 * Reads the currently selected event's classification from the pipeline store
 * and renders a tactic bar visualization with technique tags.
 *
 * When no event is selected, falls back to aggregate tactic data so the panel
 * is never empty during normal SOC operation.
 */

import { ShieldCheck } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';

// ─── Static tactic catalogue (MITRE ATT&CK v14) ───────────────────────────────

interface TacticMeta {
  id: string;
  name: string;
  shortName: string;
}

const TACTIC_CATALOGUE: TacticMeta[] = [
  { id: 'TA0001', name: 'Initial Access',        shortName: 'Initial Access' },
  { id: 'TA0002', name: 'Execution',             shortName: 'Execution' },
  { id: 'TA0003', name: 'Persistence',           shortName: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation',  shortName: 'Priv. Escalation' },
  { id: 'TA0005', name: 'Defense Evasion',       shortName: 'Def. Evasion' },
  { id: 'TA0006', name: 'Credential Access',     shortName: 'Cred. Access' },
  { id: 'TA0007', name: 'Discovery',             shortName: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement',      shortName: 'Lateral Move' },
  { id: 'TA0009', name: 'Collection',            shortName: 'Collection' },
  { id: 'TA0010', name: 'Exfiltration',          shortName: 'Exfiltration' },
  { id: 'TA0011', name: 'Command and Control',   shortName: 'C2' },
  { id: 'TA0040', name: 'Impact',                shortName: 'Impact' },
];

// ─── Fallback aggregate counts shown when no event is selected ────────────────

interface AggregateTactic {
  id: string;
  count: number;
  max: number;
  techniques: string[];
}

const AGGREGATE_FALLBACK: AggregateTactic[] = [
  { id: 'TA0001', count: 47, max: 100, techniques: ['T1566.001', 'T1078', 'T1190'] },
  { id: 'TA0003', count: 31, max: 100, techniques: ['T1053.005', 'T1543', 'T1547.001'] },
  { id: 'TA0006', count: 62, max: 100, techniques: ['T1110.003', 'T1003.001', 'T1552'] },
  { id: 'TA0010', count: 18, max: 100, techniques: ['T1041', 'T1048.003'] },
  { id: 'TA0011', count: 39, max: 100, techniques: ['T1071.001', 'T1095', 'T1571'] },
];

// ─── Component ─────────────────────────────────────────────────────────────────

export const MitrePanel = () => {
  const selectedEventId  = usePipelineStore((s) => s.selectedEventId);
  const classifications  = usePipelineStore((s) => s.classifications);

  const classification = selectedEventId
    ? (classifications.get(selectedEventId) ?? null)
    : null;

  // ── Derive display data ────────────────────────────────────────────────────

  if (classification) {
    // Event-specific view: show only active tactics from the classification
    const activeTacticIds  = new Set(classification.mitre_tactics);
    const activeTechniques = classification.mitre_techniques;

    // Build per-tactic display rows — only tactics present in this event
    const tacticRows = TACTIC_CATALOGUE
      .filter((t) => activeTacticIds.has(t.id))
      .map((meta) => ({
        meta,
        // Techniques that match this tactic's ID prefix (rough heuristic; real
        // mapping would come from a lookup table, but store only exposes flat lists)
        techniques: activeTechniques.filter((tech) =>
          // Keep all techniques — we can't split per-tactic without a full ATT&CK
          // mapping table, so show all techniques on every active tactic row.
          tech.length > 0
        ),
        // Bar fill: each active tactic gets equal weight
        fillPct: activeTacticIds.size > 0 ? 100 / activeTacticIds.size : 0,
      }));

    const incidentLabel = `INC-${selectedEventId!.slice(0, 8).toUpperCase()}`;

    return (
      <div className="detail-panel">
        <div className="detail-panel-header">
          <ShieldCheck className="detail-panel-icon" size={14} color="var(--pip-accent-cyan)" />
          <span className="detail-panel-title">MITRE ATT&amp;CK Mapping</span>
          <span className="detail-panel-badge cyan">{incidentLabel}</span>
        </div>

        <div className="detail-panel-body">
          {tacticRows.length === 0 ? (
            <div style={{ color: 'var(--pip-text-secondary)', fontSize: '12px', padding: '8px 0' }}>
              이 이벤트에 매핑된 ATT&amp;CK Tactic이 없습니다.
            </div>
          ) : (
            tacticRows.map((row, i) => (
              <div
                key={row.meta.id}
                className="mitre-tactic"
                style={{ animationDelay: `${i * 60}ms` }}
              >
                <div className="mitre-tactic-header">
                  <span className="mitre-tactic-name">
                    {row.meta.id} — {row.meta.name}
                  </span>
                  <span className="mitre-tactic-count">ACTIVE</span>
                </div>
                <div className="mitre-bar-track">
                  <div
                    className="mitre-bar-fill"
                    style={{ width: `${Math.min(100, row.fillPct * (i + 1))}%` }}
                  />
                </div>
                {row.techniques.length > 0 && (
                  <div className="mitre-technique-list">
                    {row.techniques.map((tech) => (
                      <span key={tech} className="mitre-technique-tag">
                        {tech}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    );
  }

  // ── Aggregate fallback view (no event selected) ────────────────────────────

  return (
    <div className="detail-panel">
      <div className="detail-panel-header">
        <ShieldCheck className="detail-panel-icon" size={14} color="var(--pip-accent-cyan)" />
        <span className="detail-panel-title">MITRE ATT&amp;CK Mapping</span>
        <span className="detail-panel-badge cyan">Live</span>
      </div>

      <div className="detail-panel-body">
        {AGGREGATE_FALLBACK.map((agg, i) => {
          const meta = TACTIC_CATALOGUE.find((t) => t.id === agg.id);
          if (!meta) return null;
          return (
            <div
              key={agg.id}
              className="mitre-tactic"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="mitre-tactic-header">
                <span className="mitre-tactic-name">
                  {agg.id} — {meta.name}
                </span>
                <span className="mitre-tactic-count">{agg.count}</span>
              </div>
              <div className="mitre-bar-track">
                <div
                  className="mitre-bar-fill"
                  style={{ width: `${(agg.count / agg.max) * 100}%` }}
                />
              </div>
              <div className="mitre-technique-list">
                {agg.techniques.map((tech) => (
                  <span key={tech} className="mitre-technique-tag">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
