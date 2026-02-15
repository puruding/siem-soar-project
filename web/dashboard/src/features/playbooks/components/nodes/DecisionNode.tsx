import { memo } from 'react';
import { Handle, Position, NodeProps } from '@xyflow/react';
import { GitBranch, CheckCircle2, XCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface DecisionNodeData {
  label: string;
  condition: string;
  outcomes?: { yes: string; no: string };
  conditionResult?: boolean;
  status?: 'pending' | 'evaluating' | 'evaluated';
}

const DecisionNode = ({ data, selected }: NodeProps) => {
  // Type assertion since NodeProps<T> doesn't properly type data
  const nodeData = data as unknown as DecisionNodeData;

  return (
    <div
      className={cn(
        'relative transition-all duration-300',
        'hover:scale-105 hover:z-10',
        selected && 'ring-2 ring-[#F79836] ring-offset-2 ring-offset-background scale-105 z-10'
      )}
    >
      {/* Diamond Shape */}
      <div
        className={cn(
          'relative w-[180px] h-[180px] transition-all duration-300',
          'bg-gradient-to-br border-2 shadow-lg',
          nodeData.status === 'evaluating' &&
            'from-[#F79836]/30 via-[#F79836]/20 to-[#F79836]/10 border-[#F79836] animate-pulse',
          nodeData.status === 'evaluated' &&
            nodeData.conditionResult !== undefined &&
            (nodeData.conditionResult
              ? 'from-[#5CC05C]/20 to-[#5CC05C]/5 border-[#5CC05C]/60'
              : 'from-[#DC4E41]/20 to-[#DC4E41]/5 border-[#DC4E41]/60'),
          (!nodeData.status || nodeData.status === 'pending') &&
            'from-[#F79836]/20 via-[#F79836]/10 to-transparent border-[#F79836]/60 hover:border-[#F79836]'
        )}
        style={{
          transform: 'rotate(45deg)',
        }}
      >
        {/* Content (counter-rotated) */}
        <div
          className="absolute inset-0 flex items-center justify-center"
          style={{ transform: 'rotate(-45deg)' }}
        >
          <div className="flex flex-col items-center gap-2 text-center px-4 max-w-[140px]">
            {/* Icon */}
            <div
              className={cn(
                'relative p-2 rounded-full transition-all duration-300',
                'bg-[#F79836]/20'
              )}
            >
              <GitBranch className="w-4 h-4 text-[#F79836]" />
              {nodeData.status === 'evaluating' && (
                <span className="absolute inset-0 rounded-full bg-[#F79836] opacity-30 animate-ping" />
              )}
            </div>

            {/* Label */}
            <div className="font-semibold text-xs text-foreground">
              {nodeData.label}
            </div>

            {/* Condition */}
            <div className="text-2xs text-muted-foreground font-mono line-clamp-2">
              {nodeData.condition}
            </div>

            {/* Result indicator */}
            {nodeData.status === 'evaluated' && nodeData.conditionResult !== undefined && (
              <div
                className={cn(
                  'flex items-center gap-1 px-2 py-1 rounded-full text-2xs font-semibold uppercase tracking-wide',
                  nodeData.conditionResult
                    ? 'bg-[#5CC05C]/20 text-[#5CC05C]'
                    : 'bg-[#DC4E41]/20 text-[#DC4E41]'
                )}
              >
                {nodeData.conditionResult ? (
                  <>
                    <CheckCircle2 className="w-3 h-3" />
                    Yes
                  </>
                ) : (
                  <>
                    <XCircle className="w-3 h-3" />
                    No
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Animated border for evaluating state */}
        {nodeData.status === 'evaluating' && (
          <div className="absolute inset-0 bg-gradient-to-r from-[#F79836]/0 via-[#F79836]/30 to-[#F79836]/0 animate-pulse pointer-events-none" />
        )}
      </div>

      {/* Input Handle (Top) */}
      <Handle
        type="target"
        position={Position.Top}
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#F79836] hover:!scale-125'
        )}
        style={{ top: '-8px' }}
      />

      {/* Output Handles */}
      {/* Yes Handle (Bottom Left) */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="yes"
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#5CC05C] hover:!scale-125'
        )}
        style={{
          left: '35%',
          bottom: '-8px',
        }}
      />

      {/* No Handle (Bottom Right) */}
      <Handle
        type="source"
        position={Position.Bottom}
        id="no"
        className={cn(
          '!w-4 !h-4 !border-2 !border-background transition-all duration-300',
          '!bg-[#DC4E41] hover:!scale-125'
        )}
        style={{
          left: '65%',
          bottom: '-8px',
        }}
      />

      {/* Handle Labels */}
      {nodeData.outcomes && (
        <>
          <div className="absolute left-[35%] -bottom-7 -translate-x-1/2 text-2xs font-medium text-[#5CC05C] whitespace-nowrap pointer-events-none">
            {nodeData.outcomes.yes}
          </div>
          <div className="absolute left-[65%] -bottom-7 -translate-x-1/2 text-2xs font-medium text-[#DC4E41] whitespace-nowrap pointer-events-none">
            {nodeData.outcomes.no}
          </div>
        </>
      )}
    </div>
  );
};

export default memo(DecisionNode);
