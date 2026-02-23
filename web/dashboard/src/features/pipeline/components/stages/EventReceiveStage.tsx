/**
 * EventReceiveStage — Stage 1: 이벤트 수신
 *
 * Displays the 10 most recent events at the event_receive stage.
 * Clicking an event item selects it in the global pipeline store.
 */

import { Radio } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';
import { SeverityBadge, formatTime } from './shared';

export const EventReceiveStage = () => {
  const events = usePipelineStore((s) =>
    s.events.filter((e) => e.stage === 'event_receive').slice(0, 10)
  );
  const selectedEventId = usePipelineStore((s) => s.selectedEventId);
  const setSelectedEvent = usePipelineStore((s) => s.setSelectedEvent);

  return (
    <div className="stage-card stage-receive">
      <div className="stage-header">
        <div className="stage-index">1</div>
        <Radio className="stage-icon" size={14} aria-hidden="true" />
        <span className="stage-name">이벤트 수신</span>
        {events.length > 0 && (
          <span className="stage-event-count">{events.length}</span>
        )}
      </div>

      {events.length === 0 ? (
        <div className="stage-empty">대기 중...</div>
      ) : (
        <div className="stage-event-list" role="list" aria-label="수신된 이벤트 목록">
          {events.map((event, i) => (
            <div
              key={event.id}
              role="listitem"
              className={`stage-event-item${selectedEventId === event.id ? ' selected' : ''}`}
              onClick={() =>
                setSelectedEvent(selectedEventId === event.id ? null : event.id)
              }
              style={{ animationDelay: `${i * 40}ms` }}
              title={event.raw_log}
            >
              <SeverityBadge severity={event.severity} />
              <span className="event-source">{event.source}</span>
              <span className="event-time">{formatTime(event.created_at)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
