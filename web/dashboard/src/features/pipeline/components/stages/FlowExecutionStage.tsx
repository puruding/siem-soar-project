/**
 * FlowExecutionStage — Stage 4: Flow 실행
 *
 * Shows the top 5 events in the 'flow_execution' stage with an execution
 * record. Renders a progress bar for current/total steps, an inline
 * approval gate when the flow is WAITING_APPROVAL, and approve/reject
 * action buttons.
 */

import { Zap } from 'lucide-react';
import { usePipelineStore } from '../../stores/pipelineStore';
import { StatusBadge } from './shared';

export const FlowExecutionStage = () => {
  const events = usePipelineStore((s) =>
    s.events
      .filter((e) => e.stage === 'flow_execution' && e.execution != null)
      .slice(0, 5)
  );

  const handleApprove = async (approvalId: string) => {
    try {
      await fetch(`/api/v1/pipeline/approvals/${approvalId}/approve`, {
        method: 'POST',
      });
    } catch {
      // Network errors are silently ignored; the store update arrives via WS
    }
  };

  const handleReject = async (approvalId: string) => {
    try {
      await fetch(`/api/v1/pipeline/approvals/${approvalId}/reject`, {
        method: 'POST',
      });
    } catch {
      // Network errors are silently ignored; the store update arrives via WS
    }
  };

  return (
    <div className="stage-card stage-execute">
      <div className="stage-header">
        <div className="stage-index">4</div>
        <Zap className="stage-icon" size={14} aria-hidden="true" />
        <span className="stage-name">Flow 실행</span>
        {events.length > 0 && (
          <span className="stage-event-count">{events.length}</span>
        )}
      </div>

      {events.length === 0 ? (
        <div className="stage-empty">실행 대기 중...</div>
      ) : (
        <div className="stage-execution-list" role="list" aria-label="Flow 실행 현황">
          {events.map((event, i) => {
            const exec = event.execution!;
            const approval = exec.approval_info;
            const progressPct =
              exec.total_steps > 0
                ? Math.round((exec.current_step / exec.total_steps) * 100)
                : 0;

            return (
              <div
                key={event.id}
                role="listitem"
                className="execution-item"
                style={{ animationDelay: `${i * 50}ms` }}
              >
                {/* Header: status badge + step counter */}
                <div className="execution-header">
                  <StatusBadge status={exec.status} />
                  <span className="execution-steps">
                    {exec.current_step} / {exec.total_steps}
                  </span>
                </div>

                {/* Progress bar */}
                <div
                  className="execution-progress-track"
                  role="progressbar"
                  aria-valuenow={progressPct}
                  aria-valuemin={0}
                  aria-valuemax={100}
                >
                  <div
                    className={`execution-progress-fill${exec.status === 'RUNNING' ? ' running' : exec.status === 'COMPLETED' ? ' completed' : exec.status === 'FAILED' ? ' failed' : ''}`}
                    style={{ width: `${progressPct}%` }}
                  />
                </div>

                {/* Inline Approval Gate */}
                {approval && approval.status === 'PENDING' && (
                  <div className="approval-gate" role="group" aria-label="승인 요청">
                    <div className="approval-info">
                      <span className="approval-step-name">{approval.step_name}</span>
                      <span className="approval-role">
                        승인 필요: {approval.required_role}
                      </span>
                    </div>
                    <div className="approval-actions">
                      <button
                        type="button"
                        className="btn-approve"
                        onClick={() => handleApprove(approval.approval_id)}
                        aria-label={`${approval.step_name} 승인`}
                      >
                        승인
                      </button>
                      <button
                        type="button"
                        className="btn-reject"
                        onClick={() => handleReject(approval.approval_id)}
                        aria-label={`${approval.step_name} 거부`}
                      >
                        거부
                      </button>
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
