import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { ShieldAlert, ShieldCheck, ShieldX, CheckCircle2, XCircle, Clock, User, Users, Settings2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ApprovalGateNodeData {
  label: string;
  description?: string;
  approverRoles?: string[]; // e.g., ['SOC Manager', 'Security Lead']
  timeout?: number; // timeout in seconds
  autoReject?: boolean; // auto reject on timeout
  status?: 'pending' | 'awaiting_approval' | 'approved' | 'rejected';
  requestedAt?: Date;
  requestedBy?: string;
  respondedAt?: Date;
  respondedBy?: string;
  comment?: string;
}

const ApprovalGateNode = ({ data, selected }: NodeProps) => {
  const nodeData = data as unknown as ApprovalGateNodeData;

  const formatDuration = (seconds: number) => {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    const hours = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
  };

  const formatDate = (date: Date) => {
    return new Date(date).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getShieldIcon = () => {
    switch (nodeData.status) {
      case 'approved':
        return <ShieldCheck className="w-5 h-5 text-[#F59E0B]" />;
      case 'rejected':
        return <ShieldX className="w-5 h-5 text-[#F59E0B]" />;
      case 'awaiting_approval':
        return <ShieldAlert className="w-5 h-5 text-[#F59E0B] animate-pulse" />;
      default:
        return <ShieldAlert className="w-5 h-5 text-[#F59E0B]" />;
    }
  };

  const getStatusIcon = () => {
    switch (nodeData.status) {
      case 'awaiting_approval':
        return <Clock className="w-3.5 h-3.5 text-[#F59E0B] animate-spin" style={{ animationDuration: '3s' }} />;
      case 'approved':
        return <CheckCircle2 className="w-3.5 h-3.5 text-[#5CC05C]" />;
      case 'rejected':
        return <XCircle className="w-3.5 h-3.5 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  const getStatusBadge = () => {
    if (nodeData.status === 'awaiting_approval') {
      return (
        <span className="px-2 py-0.5 rounded-full bg-[#F59E0B]/30 text-2xs font-semibold text-[#F59E0B] uppercase tracking-wide animate-pulse">
          Awaiting Approval
        </span>
      );
    }
    if (nodeData.status === 'approved') {
      return (
        <span className="px-2 py-0.5 rounded-full bg-[#5CC05C]/20 text-2xs font-semibold text-[#5CC05C] uppercase tracking-wide">
          Approved
        </span>
      );
    }
    if (nodeData.status === 'rejected') {
      return (
        <span className="px-2 py-0.5 rounded-full bg-[#DC4E41]/20 text-2xs font-semibold text-[#DC4E41] uppercase tracking-wide">
          Rejected
        </span>
      );
    }
    return (
      <span className="px-2 py-0.5 rounded-full bg-[#F59E0B]/20 text-2xs font-medium text-[#F59E0B] uppercase tracking-wide w-fit">
        Approval Gate
      </span>
    );
  };

  const isApproved = nodeData.status === 'approved';
  const isRejected = nodeData.status === 'rejected';
  const isAwaiting = nodeData.status === 'awaiting_approval';

  return (
    <div
      className={cn(
        'relative min-w-[220px] transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#F59E0B] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Approval Gate Shape - Rounded rectangle */}
      <div
        className={cn(
          'relative px-5 py-4 rounded-2xl bg-gradient-to-br transition-all duration-300',
          'border-2 shadow-lg backdrop-blur-sm',
          isAwaiting &&
            'from-[#F59E0B]/30 via-[#F59E0B]/20 to-[#F59E0B]/10 border-[#F59E0B]',
          isApproved && 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60',
          isRejected && 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60',
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#F59E0B]/15 via-card to-card border-[#F59E0B]/40 hover:border-[#F59E0B]'
        )}
      >
        <div className="flex items-start gap-3">
          {/* Shield Icon Container */}
          <div className="relative shrink-0">
            <div
              className={cn(
                'p-2.5 rounded-xl transition-all duration-300',
                'bg-gradient-to-br from-[#F59E0B]/30 to-[#F59E0B]/10',
                'border border-[#F59E0B]/30'
              )}
            >
              {getShieldIcon()}
            </div>
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            {/* Label row */}
            <div className="flex items-center gap-2 mb-1">
              <h4 className="font-semibold text-sm text-foreground truncate">
                {nodeData.label}
              </h4>
              {nodeData.status && (
                <div className="shrink-0">{getStatusIcon()}</div>
              )}
            </div>

            {nodeData.description && (
              <p className="text-2xs text-muted-foreground line-clamp-1 mb-2">
                {nodeData.description}
              </p>
            )}

            {/* Status badge */}
            <div className="mb-2">
              {getStatusBadge()}
            </div>

            {/* Approver roles */}
            {nodeData.approverRoles && nodeData.approverRoles.length > 0 && (
              <div className="flex items-center gap-1 mb-1.5">
                <Users className="w-3 h-3 text-muted-foreground shrink-0" />
                <div className="flex flex-wrap gap-1">
                  {nodeData.approverRoles.map((role) => (
                    <span
                      key={role}
                      className="px-1.5 py-0.5 rounded bg-[#F59E0B]/10 text-2xs text-[#F59E0B] font-medium truncate max-w-[100px]"
                    >
                      {role}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Timeout info */}
            {nodeData.timeout && !isApproved && !isRejected && (
              <div className="flex items-center gap-1 text-2xs text-muted-foreground mb-1">
                <Clock className="w-3 h-3 shrink-0" />
                <span>
                  Timeout: {formatDuration(nodeData.timeout)}
                  {nodeData.autoReject && (
                    <span className="text-[#DC4E41]/70"> · auto-reject</span>
                  )}
                </span>
              </div>
            )}

            {/* Request info */}
            {nodeData.requestedBy && (
              <div className="flex items-center gap-1 text-2xs text-muted-foreground mt-1">
                <User className="w-3 h-3 shrink-0" />
                <span className="truncate">
                  Requested by <span className="text-foreground font-medium">{nodeData.requestedBy}</span>
                  {nodeData.requestedAt && (
                    <span> · {formatDate(nodeData.requestedAt)}</span>
                  )}
                </span>
              </div>
            )}

            {/* Response info (approved / rejected) */}
            {nodeData.respondedBy && (isApproved || isRejected) && (
              <div
                className={cn(
                  'flex items-center gap-1 text-2xs mt-1',
                  isApproved ? 'text-[#5CC05C]' : 'text-[#DC4E41]'
                )}
              >
                {isApproved ? (
                  <CheckCircle2 className="w-3 h-3 shrink-0" />
                ) : (
                  <XCircle className="w-3 h-3 shrink-0" />
                )}
                <span className="truncate">
                  {isApproved ? 'Approved' : 'Rejected'} by{' '}
                  <span className="font-medium">{nodeData.respondedBy}</span>
                  {nodeData.respondedAt && (
                    <span className="text-muted-foreground"> · {formatDate(nodeData.respondedAt)}</span>
                  )}
                </span>
              </div>
            )}

            {/* Comment */}
            {nodeData.comment && (isApproved || isRejected) && (
              <div className="mt-1.5 px-2 py-1 rounded-lg bg-background/60 border border-border/40">
                <p className="text-2xs text-muted-foreground italic line-clamp-2">
                  "{nodeData.comment}"
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Pulse animation when awaiting approval */}
        {isAwaiting && (
          <>
            <div className="absolute inset-0 rounded-2xl bg-[#F59E0B]/10 animate-ping pointer-events-none" />
            <div className="absolute inset-0 rounded-2xl bg-gradient-to-r from-[#F59E0B]/0 via-[#F59E0B]/10 to-[#F59E0B]/0 animate-pulse pointer-events-none" />
          </>
        )}

        {/* Settings button */}
        <button
          className={cn(
            'absolute top-2 right-2 p-1 rounded-lg',
            'bg-background/50 backdrop-blur-sm border border-border/50',
            'opacity-0 group-hover:opacity-100 transition-opacity',
            'hover:bg-background/80 hover:border-[#F59E0B]/50'
          )}
          onClick={(e) => {
            e.stopPropagation();
          }}
        >
          <Settings2 className="w-3 h-3 text-muted-foreground" />
        </button>
      </div>

      {/* Input Handle (Top) */}
      <Handle
        type="target"
        position={Position.Top}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          isApproved ? '!bg-[#5CC05C]' : isRejected ? '!bg-[#DC4E41]' : '!bg-[#F59E0B]',
          'hover:!scale-125'
        )}
      />

      {/* Output Handle (Bottom) */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          isApproved ? '!bg-[#5CC05C]' : isRejected ? '!bg-[#DC4E41]' : '!bg-[#F59E0B]',
          'hover:!scale-125'
        )}
      />
    </div>
  );
};

export default memo(ApprovalGateNode);
