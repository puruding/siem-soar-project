import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { Shield, Database, Cloud, Ticket, Plug, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import { StatusIndicator } from '../execution/StatusIndicator';
import type { NodeExecutionStatus } from '../../types/execution.types';

export interface IntegrationNodeData {
  label: string;
  integrationType: 'siem' | 'edr' | 'firewall' | 'ticketing' | 'custom';
  connectionStatus?: 'connected' | 'disconnected' | 'error';
  description?: string;
  executionStatus?: NodeExecutionStatus;
  executionDuration?: number;
}

const IntegrationNode = ({ data, selected }: NodeProps) => {
  // Type assertion since NodeProps<T> doesn't properly type data
  const nodeData = data as unknown as IntegrationNodeData;

  const getIcon = () => {
    switch (nodeData.integrationType) {
      case 'siem':
        return Shield;
      case 'edr':
        return Shield;
      case 'firewall':
        return Shield;
      case 'ticketing':
        return Ticket;
      case 'custom':
        return Plug;
      default:
        return Cloud;
    }
  };

  const getConnectionIcon = () => {
    switch (nodeData.connectionStatus) {
      case 'connected':
        return <CheckCircle2 className="w-3 h-3 text-[#5CC05C]" />;
      case 'disconnected':
        return <AlertCircle className="w-3 h-3 text-muted-foreground" />;
      case 'error':
        return <XCircle className="w-3 h-3 text-[#DC4E41]" />;
      default:
        return null;
    }
  };

  const Icon = getIcon();

  // Border glow effect based on execution status
  const getStatusBorderClass = () => {
    if (!nodeData.executionStatus) return '';
    switch (nodeData.executionStatus) {
      case 'running':
        return 'ring-2 ring-blue-500/50 animate-pulse';
      case 'success':
        return 'ring-2 ring-[#5CC05C]/50';
      case 'error':
        return 'ring-2 ring-[#DC4E41]/50 animate-shake';
      default:
        return '';
    }
  };

  return (
    <div
      className={cn(
        'relative transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#7B61FF] ring-offset-2 ring-offset-background scale-105 z-10',
        getStatusBorderClass()
      )}
    >
      {/* Circular Container */}
      <div
        className={cn(
          'relative w-[160px] h-[160px] rounded-full',
          'bg-gradient-to-br border-2 shadow-lg backdrop-blur-sm transition-all duration-300',
          nodeData.connectionStatus === 'connected' &&
            'from-[#7B61FF]/25 via-[#7B61FF]/15 to-[#7B61FF]/5 border-[#7B61FF] shadow-[#7B61FF]/20',
          nodeData.connectionStatus === 'disconnected' &&
            'from-muted/20 to-muted/5 border-muted/40 opacity-70',
          nodeData.connectionStatus === 'error' &&
            'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60 shadow-[#DC4E41]/20',
          !nodeData.connectionStatus &&
            'from-[#7B61FF]/20 via-[#7B61FF]/10 to-transparent border-[#7B61FF]/50 hover:border-[#7B61FF]'
        )}
      >
        {/* Execution Status Indicator */}
        {nodeData.executionStatus && (
          <div className="absolute -top-2 -right-2 z-10">
            <StatusIndicator status={nodeData.executionStatus} size="sm" />
          </div>
        )}
        {/* Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-4">
          {/* Icon Container with pulse for connected */}
          <div
            className={cn(
              'relative p-3 rounded-full transition-all duration-300',
              'bg-gradient-to-br from-[#7B61FF]/30 to-[#7B61FF]/10',
              'border border-[#7B61FF]/30',
              nodeData.connectionStatus === 'connected' && 'animate-pulse'
            )}
          >
            <Icon className="w-6 h-6 text-[#7B61FF]" />
            {nodeData.connectionStatus === 'connected' && (
              <span className="absolute inset-0 rounded-full bg-[#7B61FF] opacity-20 animate-ping" />
            )}
          </div>

          {/* Label */}
          <div className="font-semibold text-sm text-center text-foreground line-clamp-2 max-w-[120px]">
            {nodeData.label}
          </div>

          {/* Description */}
          {nodeData.description && (
            <div className="text-2xs text-muted-foreground text-center line-clamp-2 max-w-[110px]">
              {nodeData.description}
            </div>
          )}

          {/* Type Badge */}
          <div className="px-2.5 py-0.5 rounded-full bg-[#7B61FF]/20 text-2xs font-medium text-[#7B61FF] uppercase tracking-wide">
            {nodeData.integrationType}
          </div>
        </div>

        {/* Connection Status Indicator */}
        {nodeData.connectionStatus && (
          <div
            className={cn(
              'absolute -top-1 -right-1 p-1.5 rounded-full border-2 border-background',
              'bg-background shadow-lg transition-all duration-300',
              nodeData.connectionStatus === 'connected' && 'bg-[#5CC05C]/10',
              nodeData.connectionStatus === 'error' && 'bg-[#DC4E41]/10'
            )}
          >
            {getConnectionIcon()}
          </div>
        )}

        {/* Orbital rings for connected state */}
        {nodeData.connectionStatus === 'connected' && (
          <>
            <div className="absolute inset-0 rounded-full border border-[#7B61FF]/20 animate-ping" />
            <div className="absolute inset-2 rounded-full border border-[#7B61FF]/10 animate-pulse" />
          </>
        )}

        {/* Glow effect */}
        {nodeData.connectionStatus === 'connected' && (
          <div className="absolute inset-0 rounded-full bg-[#7B61FF]/10 blur-2xl -z-10 animate-pulse" />
        )}
      </div>

      {/* Input Handle */}
      <Handle
        type="target"
        position={Position.Top}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#7B61FF] hover:!scale-125'
        )}
        style={{ top: '0px', left: '50%', transform: 'translateX(-50%)' }}
      />

      {/* Output Handle */}
      <Handle
        type="source"
        position={Position.Bottom}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#7B61FF] hover:!scale-125'
        )}
        style={{ bottom: '0px', left: '50%', transform: 'translateX(-50%)' }}
      />

      {/* Connection Status Label */}
      {nodeData.connectionStatus && (
        <div
          className={cn(
            'absolute -bottom-6 left-1/2 -translate-x-1/2',
            'px-2 py-0.5 rounded-full text-2xs font-medium whitespace-nowrap',
            'border backdrop-blur-sm pointer-events-none',
            nodeData.connectionStatus === 'connected' &&
              'bg-[#5CC05C]/10 text-[#5CC05C] border-[#5CC05C]/30',
            nodeData.connectionStatus === 'disconnected' &&
              'bg-muted/50 text-muted-foreground border-muted',
            nodeData.connectionStatus === 'error' &&
              'bg-[#DC4E41]/10 text-[#DC4E41] border-[#DC4E41]/30'
          )}
        >
          {nodeData.connectionStatus}
        </div>
      )}
    </div>
  );
};

export default memo(IntegrationNode);
