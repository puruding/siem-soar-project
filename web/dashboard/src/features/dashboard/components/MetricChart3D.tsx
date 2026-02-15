import { useState, useMemo, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';
import { BarChart3, PieChart, TrendingUp, Activity } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

interface ChartDataItem {
  label: string;
  value: number;
  color?: string;
}

interface MetricChart3DProps {
  type: '3d-bar' | '3d-pie' | '3d-area';
  data: ChartDataItem[];
  title?: string;
  height?: number;
  className?: string;
  showValues?: boolean;
  animated?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_COLORS = [
  '#00A4A6', // Primary teal
  '#F79836', // Orange
  '#DC4E41', // Red
  '#5CC05C', // Green
  '#7B61FF', // Purple
  '#FFB84D', // Yellow
  '#6B7280', // Gray
  '#00D4FF', // Cyan
];

// ============================================================================
// Sub-Components: 3D Bar Chart
// ============================================================================

interface Bar3DProps {
  value: number;
  maxValue: number;
  color: string;
  label: string;
  index: number;
  total: number;
  height: number;
  isHovered: boolean;
  onHover: (active: boolean) => void;
  showValue: boolean;
  animated: boolean;
}

function Bar3D({
  value,
  maxValue,
  color,
  label,
  index,
  total,
  height,
  isHovered,
  onHover,
  showValue,
  animated,
}: Bar3DProps) {
  const barHeight = (value / maxValue) * (height - 80);
  const barWidth = Math.min(50, (100 / total) * 0.7);
  const depth = 20;

  return (
    <div
      className="relative flex flex-col items-center cursor-pointer group"
      style={{
        flex: 1,
        minWidth: '40px',
        maxWidth: '80px',
      }}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      {/* Value label on top */}
      {(showValue || isHovered) && (
        <div
          className={cn(
            'absolute text-xs font-mono font-medium transition-all duration-200',
            isHovered ? 'text-foreground scale-110' : 'text-muted-foreground'
          )}
          style={{
            bottom: barHeight + 20,
            animation: animated ? 'fade-in 0.3s ease-out' : undefined,
          }}
        >
          {value.toLocaleString()}
        </div>
      )}

      {/* 3D Bar */}
      <div
        className="absolute bottom-8 transition-all duration-300"
        style={{
          width: `${barWidth}px`,
          height: `${barHeight}px`,
          transformStyle: 'preserve-3d',
          transform: isHovered
            ? 'translateY(-4px) rotateX(-5deg)'
            : 'translateY(0) rotateX(0)',
        }}
      >
        {/* Front face */}
        <div
          className="absolute inset-0 rounded-t transition-all duration-300"
          style={{
            background: `linear-gradient(180deg, ${color} 0%, ${color}99 100%)`,
            boxShadow: isHovered
              ? `0 8px 30px ${color}60, inset 0 1px 0 ${color}aa`
              : `0 4px 20px ${color}40, inset 0 1px 0 ${color}aa`,
            animation: animated
              ? `bar-grow 0.6s ease-out ${index * 0.1}s both`
              : undefined,
          }}
        >
          {/* Shine effect */}
          <div
            className="absolute top-0 left-0 right-0 h-1/3 rounded-t"
            style={{
              background: 'linear-gradient(180deg, rgba(255,255,255,0.2) 0%, transparent 100%)',
            }}
          />

          {/* Grid lines for visual depth */}
          <div
            className="absolute inset-0 opacity-20"
            style={{
              backgroundImage: `repeating-linear-gradient(
                0deg,
                transparent,
                transparent 10px,
                rgba(255,255,255,0.1) 10px,
                rgba(255,255,255,0.1) 11px
              )`,
            }}
          />
        </div>

        {/* Top face (3D effect) */}
        <div
          className="absolute rounded-t"
          style={{
            width: `${barWidth}px`,
            height: `${depth}px`,
            top: `-${depth * 0.7}px`,
            transform: 'rotateX(70deg)',
            transformOrigin: 'bottom center',
            background: `linear-gradient(180deg, ${color}ee 0%, ${color} 100%)`,
          }}
        />

        {/* Right side face (3D effect) */}
        <div
          className="absolute"
          style={{
            width: `${depth}px`,
            height: `${barHeight}px`,
            left: `${barWidth}px`,
            transform: 'skewY(-40deg)',
            transformOrigin: 'left top',
            background: `linear-gradient(90deg, ${color}88 0%, ${color}44 100%)`,
          }}
        />
      </div>

      {/* Label */}
      <div
        className={cn(
          'absolute bottom-0 text-2xs font-medium text-center truncate px-1 transition-colors',
          isHovered ? 'text-foreground' : 'text-muted-foreground'
        )}
        style={{ maxWidth: '60px' }}
      >
        {label}
      </div>

      {/* Glow effect on hover */}
      {isHovered && (
        <div
          className="absolute bottom-8 rounded-full blur-xl opacity-50"
          style={{
            width: `${barWidth + 20}px`,
            height: `${barHeight / 2}px`,
            backgroundColor: color,
          }}
        />
      )}

      <style>{`
        @keyframes bar-grow {
          from {
            transform: scaleY(0);
            opacity: 0;
          }
          to {
            transform: scaleY(1);
            opacity: 1;
          }
        }
      `}</style>
    </div>
  );
}

// ============================================================================
// Sub-Components: 3D Pie/Donut Chart
// ============================================================================

interface Pie3DProps {
  data: ChartDataItem[];
  size: number;
  hoveredIndex: number | null;
  onHover: (index: number | null) => void;
  animated: boolean;
}

function Pie3D({ data, size, hoveredIndex, onHover, animated }: Pie3DProps) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  const radius = size / 2 - 20;
  const innerRadius = radius * 0.5; // Donut hole

  // Calculate segments
  const segments = useMemo(() => {
    let currentAngle = -90; // Start from top
    return data.map((item, index) => {
      const angle = (item.value / total) * 360;
      const startAngle = currentAngle;
      const endAngle = currentAngle + angle;
      currentAngle = endAngle;

      const color = item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length];

      // Calculate SVG arc path
      const startRad = (startAngle * Math.PI) / 180;
      const endRad = (endAngle * Math.PI) / 180;

      const x1 = Math.cos(startRad) * radius;
      const y1 = Math.sin(startRad) * radius;
      const x2 = Math.cos(endRad) * radius;
      const y2 = Math.sin(endRad) * radius;

      const x1Inner = Math.cos(startRad) * innerRadius;
      const y1Inner = Math.sin(startRad) * innerRadius;
      const x2Inner = Math.cos(endRad) * innerRadius;
      const y2Inner = Math.sin(endRad) * innerRadius;

      const largeArc = angle > 180 ? 1 : 0;

      const path = `
        M ${x1Inner} ${y1Inner}
        L ${x1} ${y1}
        A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}
        L ${x2Inner} ${y2Inner}
        A ${innerRadius} ${innerRadius} 0 ${largeArc} 0 ${x1Inner} ${y1Inner}
        Z
      `;

      // Calculate label position
      const midAngle = (startAngle + endAngle) / 2;
      const midRad = (midAngle * Math.PI) / 180;
      const labelRadius = (radius + innerRadius) / 2;
      const labelX = Math.cos(midRad) * labelRadius;
      const labelY = Math.sin(midRad) * labelRadius;

      return {
        path,
        color,
        item,
        index,
        labelX,
        labelY,
        percentage: ((item.value / total) * 100).toFixed(1),
      };
    });
  }, [data, total, radius, innerRadius]);

  return (
    <div
      className="relative"
      style={{
        width: size,
        height: size,
        perspective: '600px',
      }}
    >
      {/* 3D tilted pie */}
      <svg
        width={size}
        height={size}
        viewBox={`${-size / 2} ${-size / 2} ${size} ${size}`}
        className="transition-transform duration-300"
        style={{
          transform: 'rotateX(20deg)',
          transformStyle: 'preserve-3d',
        }}
      >
        {/* Shadow/depth layer */}
        <g transform="translate(0, 15)" opacity="0.3">
          {segments.map((seg, i) => (
            <path
              key={`shadow-${i}`}
              d={seg.path}
              fill={seg.color}
              filter="blur(8px)"
            />
          ))}
        </g>

        {/* Main segments */}
        {segments.map((seg, i) => (
          <g
            key={i}
            className="cursor-pointer transition-transform duration-200"
            style={{
              transform: hoveredIndex === i ? 'scale(1.05)' : 'scale(1)',
              transformOrigin: 'center center',
            }}
            onMouseEnter={() => onHover(i)}
            onMouseLeave={() => onHover(null)}
          >
            <path
              d={seg.path}
              fill={seg.color}
              stroke="hsl(var(--card))"
              strokeWidth="2"
              style={{
                filter: hoveredIndex === i ? `drop-shadow(0 0 10px ${seg.color})` : undefined,
                animation: animated
                  ? `pie-grow 0.8s ease-out ${i * 0.1}s both`
                  : undefined,
              }}
            />

            {/* Highlight gradient */}
            <path
              d={seg.path}
              fill="url(#pie-highlight)"
              opacity="0.3"
            />
          </g>
        ))}

        {/* Gradient definitions */}
        <defs>
          <linearGradient id="pie-highlight" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="white" stopOpacity="0.4" />
            <stop offset="50%" stopColor="white" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* Center label */}
        <circle
          r={innerRadius - 5}
          fill="hsl(var(--card))"
          stroke="hsl(var(--border))"
          strokeWidth="1"
        />
        <text
          textAnchor="middle"
          dominantBaseline="central"
          className="fill-foreground font-bold"
          style={{ fontSize: '18px' }}
        >
          {total.toLocaleString()}
        </text>
        <text
          y="18"
          textAnchor="middle"
          className="fill-muted-foreground"
          style={{ fontSize: '10px' }}
        >
          TOTAL
        </text>
      </svg>

      {/* Hover tooltip */}
      {hoveredIndex !== null && segments[hoveredIndex] && (
        <div
          className="absolute top-2 left-1/2 -translate-x-1/2 px-3 py-2 bg-card border border-border rounded-lg shadow-lg z-10"
          style={{ animation: 'fade-in 0.15s ease-out' }}
        >
          <div className="flex items-center gap-2">
            <div
              className="w-3 h-3 rounded-full"
              style={{ backgroundColor: segments[hoveredIndex]?.color || '#ccc' }}
            />
            <span className="text-sm font-medium">{segments[hoveredIndex]?.item.label || ''}</span>
          </div>
          <div className="text-xs text-muted-foreground mt-1">
            {segments[hoveredIndex]?.item.value.toLocaleString() || 0} ({segments[hoveredIndex]?.percentage || 0}%)
          </div>
        </div>
      )}

      <style>{`
        @keyframes pie-grow {
          from {
            opacity: 0;
            transform: scale(0.5);
          }
          to {
            opacity: 1;
            transform: scale(1);
          }
        }
      `}</style>
    </div>
  );
}

// ============================================================================
// Sub-Components: 3D Area Chart
// ============================================================================

interface Area3DProps {
  data: ChartDataItem[];
  width: number;
  height: number;
  color: string;
  hoveredIndex: number | null;
  onHover: (index: number | null) => void;
  animated: boolean;
}

function Area3D({ data, width, height, color, hoveredIndex, onHover, animated }: Area3DProps) {
  const padding = { top: 20, right: 20, bottom: 40, left: 40 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;

  const maxValue = Math.max(...data.map(d => d.value));
  const minValue = Math.min(...data.map(d => d.value));
  const range = maxValue - minValue || 1;

  // Calculate points
  const points = data.map((item, index) => ({
    x: padding.left + (index / (data.length - 1)) * chartWidth,
    y: padding.top + chartHeight - ((item.value - minValue) / range) * chartHeight,
    item,
    index,
  }));

  // Create path for the area
  const areaPath = points.length > 0 ? `
    M ${points[0]?.x || 0} ${padding.top + chartHeight}
    L ${points[0]?.x || 0} ${points[0]?.y || 0}
    ${points.slice(1).map(p => `L ${p?.x || 0} ${p?.y || 0}`).join(' ')}
    L ${points[points.length - 1]?.x || 0} ${padding.top + chartHeight}
    Z
  ` : '';

  // Create path for the line
  const linePath = points.length > 0 ? `
    M ${points[0]?.x || 0} ${points[0]?.y || 0}
    ${points.slice(1).map(p => `L ${p?.x || 0} ${p?.y || 0}`).join(' ')}
  ` : '';

  return (
    <div
      className="relative"
      style={{
        width,
        height,
        perspective: '800px',
      }}
    >
      <svg
        width={width}
        height={height}
        className="transition-transform duration-300"
        style={{
          transform: 'rotateX(10deg)',
          transformStyle: 'preserve-3d',
        }}
      >
        {/* Grid lines */}
        <g opacity="0.1">
          {[0, 0.25, 0.5, 0.75, 1].map((ratio, i) => (
            <line
              key={i}
              x1={padding.left}
              y1={padding.top + chartHeight * ratio}
              x2={width - padding.right}
              y2={padding.top + chartHeight * ratio}
              stroke="currentColor"
              strokeDasharray="4 4"
            />
          ))}
        </g>

        {/* 3D depth shadow */}
        <path
          d={areaPath}
          fill={color}
          opacity="0.2"
          transform="translate(0, 10)"
          filter="blur(8px)"
        />

        {/* Area fill with gradient */}
        <defs>
          <linearGradient id="area-gradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor={color} stopOpacity="0.6" />
            <stop offset="100%" stopColor={color} stopOpacity="0.1" />
          </linearGradient>
          <filter id="area-glow">
            <feGaussianBlur stdDeviation="4" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        <path
          d={areaPath}
          fill="url(#area-gradient)"
          style={{
            animation: animated ? 'area-grow 1s ease-out' : undefined,
          }}
        />

        {/* Main line */}
        <path
          d={linePath}
          fill="none"
          stroke={color}
          strokeWidth="3"
          strokeLinecap="round"
          strokeLinejoin="round"
          filter="url(#area-glow)"
          style={{
            animation: animated ? 'line-draw 1s ease-out' : undefined,
          }}
        />

        {/* Data points */}
        {points.map((point, i) => (
          <g
            key={i}
            className="cursor-pointer"
            onMouseEnter={() => onHover(i)}
            onMouseLeave={() => onHover(null)}
          >
            {/* Hover area */}
            <rect
              x={point.x - chartWidth / data.length / 2}
              y={padding.top}
              width={chartWidth / data.length}
              height={chartHeight}
              fill="transparent"
            />

            {/* Point dot */}
            <circle
              cx={point.x}
              cy={point.y}
              r={hoveredIndex === i ? 8 : 5}
              fill={color}
              stroke="hsl(var(--card))"
              strokeWidth="2"
              className="transition-all duration-200"
              style={{
                filter: hoveredIndex === i ? `drop-shadow(0 0 8px ${color})` : undefined,
              }}
            />

            {/* Value label on hover */}
            {hoveredIndex === i && (
              <g>
                <rect
                  x={point.x - 25}
                  y={point.y - 35}
                  width="50"
                  height="22"
                  rx="4"
                  fill="hsl(var(--card))"
                  stroke="hsl(var(--border))"
                />
                <text
                  x={point.x}
                  y={point.y - 20}
                  textAnchor="middle"
                  className="fill-foreground font-mono"
                  style={{ fontSize: '11px' }}
                >
                  {point.item.value.toLocaleString()}
                </text>
              </g>
            )}

            {/* X-axis label */}
            <text
              x={point.x}
              y={height - 10}
              textAnchor="middle"
              className="fill-muted-foreground"
              style={{ fontSize: '10px' }}
            >
              {point.item.label}
            </text>
          </g>
        ))}

        {/* Y-axis labels */}
        {[0, 0.5, 1].map((ratio, i) => (
          <text
            key={i}
            x={padding.left - 8}
            y={padding.top + chartHeight * (1 - ratio) + 4}
            textAnchor="end"
            className="fill-muted-foreground"
            style={{ fontSize: '10px' }}
          >
            {Math.round(minValue + range * ratio)}
          </text>
        ))}
      </svg>

      <style>{`
        @keyframes area-grow {
          from {
            opacity: 0;
            transform: scaleY(0);
            transform-origin: bottom;
          }
          to {
            opacity: 1;
            transform: scaleY(1);
          }
        }
        @keyframes line-draw {
          from {
            stroke-dasharray: 1000;
            stroke-dashoffset: 1000;
          }
          to {
            stroke-dashoffset: 0;
          }
        }
      `}</style>
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function MetricChart3D({
  type,
  data,
  title,
  height = 280,
  className,
  showValues = true,
  animated = true,
}: MetricChart3DProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  // Ensure data has colors
  const coloredData = useMemo(() => {
    return data.map((item, index) => ({
      ...item,
      color: item.color || DEFAULT_COLORS[index % DEFAULT_COLORS.length],
    }));
  }, [data]);

  const maxValue = Math.max(...data.map(d => d.value));
  const total = data.reduce((sum, d) => sum + d.value, 0);

  const getIcon = useCallback(() => {
    switch (type) {
      case '3d-bar':
        return BarChart3;
      case '3d-pie':
        return PieChart;
      case '3d-area':
        return Activity;
      default:
        return TrendingUp;
    }
  }, [type]);

  const Icon = getIcon();

  return (
    <Card className={cn('overflow-hidden', className)}>
      {title && (
        <CardHeader className="flex flex-row items-center gap-2 pb-2">
          <div className="p-1.5 rounded-md bg-primary/10">
            <Icon className="w-4 h-4 text-primary" />
          </div>
          <CardTitle className="text-sm font-medium">{title}</CardTitle>
        </CardHeader>
      )}

      <CardContent className={cn(!title && 'pt-4')}>
        <div
          className="relative flex items-end justify-center"
          style={{
            height,
            perspective: '1000px',
          }}
        >
          {type === '3d-bar' && (
            <div
              className="flex items-end justify-center gap-2 w-full px-4"
              style={{ height: height - 20 }}
            >
              {coloredData.map((item, index) => (
                <Bar3D
                  key={index}
                  value={item.value}
                  maxValue={maxValue}
                  color={item.color!}
                  label={item.label}
                  index={index}
                  total={data.length}
                  height={height - 20}
                  isHovered={hoveredIndex === index}
                  onHover={(active) => setHoveredIndex(active ? index : null)}
                  showValue={showValues}
                  animated={animated}
                />
              ))}
            </div>
          )}

          {type === '3d-pie' && (
            <Pie3D
              data={coloredData}
              size={Math.min(height, 280)}
              hoveredIndex={hoveredIndex}
              onHover={setHoveredIndex}
              animated={animated}
            />
          )}

          {type === '3d-area' && (
            <Area3D
              data={coloredData}
              width={400}
              height={height}
              color={(coloredData[0]?.color as string) || DEFAULT_COLORS[0]!}
              hoveredIndex={hoveredIndex}
              onHover={setHoveredIndex}
              animated={animated}
            />
          )}
        </div>

        {/* Legend for pie chart */}
        {type === '3d-pie' && (
          <div className="flex flex-wrap justify-center gap-3 mt-4">
            {coloredData.map((item, index) => (
              <div
                key={index}
                className={cn(
                  'flex items-center gap-1.5 text-xs cursor-pointer transition-opacity',
                  hoveredIndex !== null && hoveredIndex !== index && 'opacity-50'
                )}
                onMouseEnter={() => setHoveredIndex(index)}
                onMouseLeave={() => setHoveredIndex(null)}
              >
                <div
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: item.color }}
                />
                <span className="text-muted-foreground">{item.label}</span>
                <span className="font-mono font-medium">{item.value}</span>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Sample Data
// ============================================================================

export const sampleBarData: ChartDataItem[] = [
  { label: 'Critical', value: 24, color: '#DC4E41' },
  { label: 'High', value: 67, color: '#F79836' },
  { label: 'Medium', value: 128, color: '#FFB84D' },
  { label: 'Low', value: 45, color: '#5CC05C' },
  { label: 'Info', value: 89, color: '#00A4A6' },
];

export const samplePieData: ChartDataItem[] = [
  { label: 'Malware', value: 340, color: '#DC4E41' },
  { label: 'Phishing', value: 220, color: '#F79836' },
  { label: 'DDoS', value: 180, color: '#FFB84D' },
  { label: 'Intrusion', value: 150, color: '#00A4A6' },
  { label: 'Data Leak', value: 90, color: '#7B61FF' },
];

export const sampleAreaData: ChartDataItem[] = [
  { label: 'Mon', value: 2400 },
  { label: 'Tue', value: 1398 },
  { label: 'Wed', value: 3800 },
  { label: 'Thu', value: 3908 },
  { label: 'Fri', value: 4800 },
  { label: 'Sat', value: 3800 },
  { label: 'Sun', value: 4300 },
];

export default MetricChart3D;
