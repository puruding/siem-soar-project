/**
 * PlaybookSelectStage — Stage 3: Playbook 선택
 *
 * Shows the top 5 events in the 'playbook_select' stage that have a
 * playbook match. Displays playbook name, match score, step count, and
 * trigger tags.
 */

import { BookMarked } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';

export const PlaybookSelectStage = () => {
  const events = usePipelineStore((s) =>
    s.events
      .filter((e) => e.stage === 'playbook_select' && e.playbook_match != null)
      .slice(0, 5)
  );

  return (
    <div className="stage-card stage-playbook">
      <div className="stage-header">
        <div className="stage-index">3</div>
        <BookMarked className="stage-icon" size={14} aria-hidden="true" />
        <span className="stage-name">Playbook 선택</span>
        {events.length > 0 && (
          <span className="stage-event-count">{events.length}</span>
        )}
      </div>

      {events.length === 0 ? (
        <div className="stage-empty">매칭 대기 중...</div>
      ) : (
        <div className="stage-playbook-list" role="list" aria-label="Playbook 선택 결과">
          {events.map((event, i) => {
            const match = event.playbook_match!;
            const matchPct = Math.round(match.match_score * 100);

            return (
              <div
                key={event.id}
                role="listitem"
                className="playbook-item"
                style={{ animationDelay: `${i * 50}ms` }}
              >
                <div className="playbook-name">{match.playbook_name}</div>

                <div className="playbook-meta">
                  <span
                    className={`match-score${matchPct >= 90 ? ' match-score--high' : matchPct >= 70 ? ' match-score--medium' : ' match-score--low'}`}
                  >
                    매칭 {matchPct}%
                  </span>
                  <span className="step-count">{match.step_count} 스텝</span>
                </div>

                {match.trigger_tags.length > 0 && (
                  <div className="trigger-tags">
                    {match.trigger_tags.map((tag) => (
                      <span key={tag} className="trigger-tag">
                        {tag}
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
