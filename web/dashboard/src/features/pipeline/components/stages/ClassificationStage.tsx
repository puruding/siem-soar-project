/**
 * ClassificationStage — Stage 2: AI 분류
 *
 * Shows the AI classification result for events currently in the
 * 'classification' stage: label, confidence bar, method badge,
 * and MITRE tactic tags.
 */

import { BrainCircuit } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';
import { ConfidenceBar, MethodBadge } from './shared';

export const ClassificationStage = () => {
  const events = usePipelineStore((s) =>
    s.events.filter((e) => e.stage === 'classification').slice(0, 5)
  );
  const classifications = usePipelineStore((s) => s.classifications);

  return (
    <div className="stage-card stage-classify">
      <div className="stage-header">
        <div className="stage-index">2</div>
        <BrainCircuit className="stage-icon" size={14} aria-hidden="true" />
        <span className="stage-name">AI 분류</span>
        {events.length > 0 && (
          <span className="stage-event-count">{events.length}</span>
        )}
      </div>

      {events.length === 0 ? (
        <div className="stage-empty">분류 대기 중...</div>
      ) : (
        <div className="stage-classification-list" role="list" aria-label="AI 분류 결과">
          {events.map((event, i) => {
            const cl = classifications.get(event.id);

            return (
              <div
                key={event.id}
                role="listitem"
                className="classification-item"
                style={{ animationDelay: `${i * 50}ms` }}
              >
                <div className="classification-label">
                  {cl?.label ?? (
                    <span className="classification-processing">Processing…</span>
                  )}
                </div>

                <ConfidenceBar confidence={cl?.confidence ?? 0} />

                <div className="classification-meta">
                  <MethodBadge method={cl?.method} />
                  {cl && cl.processing_time_ms > 0 && (
                    <span className="classification-latency">
                      {cl.processing_time_ms}ms
                    </span>
                  )}
                </div>

                {cl && cl.mitre_tactics.length > 0 && (
                  <div className="mitre-tags">
                    {cl.mitre_tactics.map((tactic) => (
                      <span key={tactic} className="mitre-tag">
                        {tactic}
                      </span>
                    ))}
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
