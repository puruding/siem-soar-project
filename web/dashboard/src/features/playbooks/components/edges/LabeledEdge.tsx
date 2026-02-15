import { memo } from 'react';
import {
  EdgeProps,
  getBezierPath,
  EdgeLabelRenderer,
  BaseEdge,
} from '@xyflow/react';
import { cn } from '@/lib/utils';

export interface LabeledEdgeData {
  label?: string;
  animated?: boolean;
  condition?: 'yes' | 'no' | 'default';
}

const LabeledEdge = ({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style = {},
  markerEnd,
  data,
  selected,
}: EdgeProps) => {
  // Type assertion since EdgeProps<T> doesn't properly type data
  const edgeData = (data || {}) as LabeledEdgeData;
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const getEdgeColor = () => {
    if (edgeData.condition === 'yes') return '#5CC05C';
    if (edgeData.condition === 'no') return '#DC4E41';
    const edgeStyle = style as React.CSSProperties;
    if (edgeStyle?.stroke) return edgeStyle.stroke as string;
    return '#64748b';
  };

  const edgeColor = getEdgeColor();

  return (
    <>
      {/* Main edge path */}
      <BaseEdge
        id={id}
        path={edgePath}
        markerEnd={markerEnd}
        style={{
          ...style,
          strokeWidth: selected ? 3 : 2,
          stroke: edgeColor,
          strokeDasharray: edgeData.animated ? '5,5' : 'none',
        }}
        className={cn(
          'transition-all duration-300',
          edgeData.animated && 'animate-dash',
          selected && 'drop-shadow-glow'
        )}
      />

      {/* Animated dots for flow direction */}
      {edgeData.animated && (
        <>
          <circle r="3" fill={edgeColor} className="animate-flow-1">
            <animateMotion dur="2s" repeatCount="indefinite" path={edgePath} />
          </circle>
          <circle r="3" fill={edgeColor} className="animate-flow-2">
            <animateMotion
              dur="2s"
              repeatCount="indefinite"
              path={edgePath}
              begin="0.5s"
            />
          </circle>
          <circle r="3" fill={edgeColor} className="animate-flow-3">
            <animateMotion
              dur="2s"
              repeatCount="indefinite"
              path={edgePath}
              begin="1s"
            />
          </circle>
        </>
      )}

      {/* Edge label */}
      {edgeData.label && (
        <EdgeLabelRenderer>
          <div
            style={{
              position: 'absolute',
              transform: `translate(-50%, -50%) translate(${labelX}px,${labelY}px)`,
              pointerEvents: 'all',
            }}
            className={cn(
              'px-2.5 py-1 rounded-full text-xs font-semibold',
              'border backdrop-blur-md transition-all duration-300',
              'shadow-lg hover:scale-110',
              selected && 'ring-2 ring-offset-1 ring-offset-background',
              edgeData.condition === 'yes' &&
                'bg-[#5CC05C]/20 text-[#5CC05C] border-[#5CC05C]/40 ring-[#5CC05C]',
              edgeData.condition === 'no' &&
                'bg-[#DC4E41]/20 text-[#DC4E41] border-[#DC4E41]/40 ring-[#DC4E41]',
              !edgeData.condition &&
                'bg-background/90 text-foreground border-border hover:border-primary/50'
            )}
          >
            {edgeData.label}
          </div>
        </EdgeLabelRenderer>
      )}

      {/* Glow effect for selected edge */}
      {selected && (
        <g>
          <path
            d={edgePath}
            fill="none"
            stroke={edgeColor}
            strokeWidth="8"
            opacity="0.2"
            className="blur-sm"
          />
        </g>
      )}
    </>
  );
};

export default memo(LabeledEdge);
