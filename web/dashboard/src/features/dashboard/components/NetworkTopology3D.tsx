import { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  Network,
  Server,
  Router,
  Shield,
  Monitor,
  Cloud,
  Cpu,
  HardDrive,
  Wifi,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity,
  ZoomIn,
  ZoomOut,
  Maximize2,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface NetworkNode {
  id: string;
  type: 'server' | 'router' | 'firewall' | 'endpoint' | 'cloud';
  name: string;
  status: 'healthy' | 'warning' | 'critical' | 'offline';
  position: { x: number; y: number; z: number };
  connections: string[];
  metrics?: {
    cpu?: number;
    memory?: number;
    traffic?: number;
  };
}

interface NetworkTopology3DProps {
  nodes: NetworkNode[];
  onNodeClick?: (node: NetworkNode) => void;
  className?: string;
}

// ============================================================================
// Constants
// ============================================================================

const STATUS_COLORS = {
  healthy: {
    primary: '#5CC05C',
    glow: 'rgba(92, 192, 92, 0.4)',
    bg: 'rgba(92, 192, 92, 0.15)',
  },
  warning: {
    primary: '#F79836',
    glow: 'rgba(247, 152, 54, 0.4)',
    bg: 'rgba(247, 152, 54, 0.15)',
  },
  critical: {
    primary: '#DC4E41',
    glow: 'rgba(220, 78, 65, 0.4)',
    bg: 'rgba(220, 78, 65, 0.15)',
  },
  offline: {
    primary: '#6B7280',
    glow: 'rgba(107, 114, 128, 0.3)',
    bg: 'rgba(107, 114, 128, 0.15)',
  },
} as const;

const NODE_ICONS = {
  server: Server,
  router: Router,
  firewall: Shield,
  endpoint: Monitor,
  cloud: Cloud,
} as const;

// ============================================================================
// Helper Functions
// ============================================================================

function projectToIsometric(x: number, y: number, z: number, scale: number = 1) {
  // Isometric projection: rotate 45deg around Y, then tilt 30deg
  const isoX = (x - z) * Math.cos(Math.PI / 6) * scale;
  const isoY = y * scale - (x + z) * Math.sin(Math.PI / 6) * scale;
  return { x: isoX, y: isoY };
}

function getConnectionPath(
  from: { x: number; y: number },
  to: { x: number; y: number },
  curved: boolean = true
) {
  if (!curved) {
    return `M ${from.x} ${from.y} L ${to.x} ${to.y}`;
  }

  const midX = (from.x + to.x) / 2;
  const midY = Math.min(from.y, to.y) - 30; // Curve upward

  return `M ${from.x} ${from.y} Q ${midX} ${midY} ${to.x} ${to.y}`;
}

// ============================================================================
// Sub-Components
// ============================================================================

interface NetworkNodeCardProps {
  node: NetworkNode;
  projected: { x: number; y: number };
  zIndex: number;
  isSelected: boolean;
  isHovered: boolean;
  onClick: () => void;
  onHover: (active: boolean) => void;
}

function NetworkNodeCard({
  node,
  projected,
  zIndex,
  isSelected,
  isHovered,
  onClick,
  onHover,
}: NetworkNodeCardProps) {
  const colors = STATUS_COLORS[node.status];
  const Icon = NODE_ICONS[node.type];
  const isPulsing = node.status === 'critical' || node.status === 'warning';

  return (
    <div
      className={cn(
        'absolute cursor-pointer transition-all duration-300',
        isSelected && 'ring-2 ring-primary ring-offset-2 ring-offset-background',
        isHovered && 'scale-110'
      )}
      style={{
        left: `calc(50% + ${projected.x}px)`,
        top: `calc(50% + ${projected.y}px)`,
        transform: 'translate(-50%, -50%)',
        zIndex: zIndex + (isHovered ? 100 : 0),
        willChange: 'transform',
      }}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      {/* Glow effect */}
      <div
        className="absolute inset-0 rounded-lg blur-xl transition-opacity duration-300"
        style={{
          backgroundColor: colors.glow,
          opacity: isHovered || isPulsing ? 1 : 0.5,
          transform: 'scale(1.5)',
        }}
      />

      {/* Pulse animation for warning/critical */}
      {isPulsing && (
        <div
          className="absolute inset-0 rounded-lg animate-ping"
          style={{
            backgroundColor: colors.primary,
            opacity: 0.3,
            animationDuration: node.status === 'critical' ? '1s' : '2s',
          }}
        />
      )}

      {/* Node card */}
      <div
        className={cn(
          'relative flex flex-col items-center gap-1 p-3 rounded-lg border backdrop-blur-sm',
          'transition-all duration-200 min-w-[80px]'
        )}
        style={{
          backgroundColor: colors.bg,
          borderColor: colors.primary,
          boxShadow: `0 4px 20px ${colors.glow}`,
        }}
      >
        {/* Status indicator */}
        <div
          className="absolute -top-1 -right-1 w-3 h-3 rounded-full border-2 border-background"
          style={{ backgroundColor: colors.primary }}
        >
          {node.status === 'healthy' && (
            <CheckCircle className="w-full h-full text-white" strokeWidth={3} />
          )}
          {node.status === 'critical' && (
            <XCircle className="w-full h-full text-white" strokeWidth={3} />
          )}
        </div>

        {/* Icon */}
        <div
          className="p-2 rounded-md"
          style={{ backgroundColor: `${colors.primary}30` }}
        >
          <Icon className="w-5 h-5" style={{ color: colors.primary }} />
        </div>

        {/* Name */}
        <span className="text-xs font-medium text-foreground whitespace-nowrap">
          {node.name}
        </span>

        {/* Type badge */}
        <Badge
          variant="outline"
          className="text-2xs px-1.5 py-0"
          style={{
            color: colors.primary,
            borderColor: `${colors.primary}50`,
          }}
        >
          {node.type}
        </Badge>
      </div>

      {/* Tooltip on hover */}
      {isHovered && node.metrics && (
        <div
          className="absolute top-full left-1/2 -translate-x-1/2 mt-2 p-3 bg-card border border-border rounded-lg shadow-xl z-50 min-w-[140px]"
          style={{
            animation: 'fade-in 0.15s ease-out',
          }}
        >
          <div className="space-y-2">
            {node.metrics.cpu !== undefined && (
              <div className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Cpu className="w-3 h-3" />
                  CPU
                </span>
                <div className="flex items-center gap-2">
                  <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${node.metrics.cpu}%`,
                        backgroundColor:
                          node.metrics.cpu > 80
                            ? STATUS_COLORS.critical.primary
                            : node.metrics.cpu > 60
                            ? STATUS_COLORS.warning.primary
                            : STATUS_COLORS.healthy.primary,
                      }}
                    />
                  </div>
                  <span className="text-xs font-mono">{node.metrics.cpu}%</span>
                </div>
              </div>
            )}

            {node.metrics.memory !== undefined && (
              <div className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <HardDrive className="w-3 h-3" />
                  MEM
                </span>
                <div className="flex items-center gap-2">
                  <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all"
                      style={{
                        width: `${node.metrics.memory}%`,
                        backgroundColor:
                          node.metrics.memory > 85
                            ? STATUS_COLORS.critical.primary
                            : node.metrics.memory > 70
                            ? STATUS_COLORS.warning.primary
                            : STATUS_COLORS.healthy.primary,
                      }}
                    />
                  </div>
                  <span className="text-xs font-mono">{node.metrics.memory}%</span>
                </div>
              </div>
            )}

            {node.metrics.traffic !== undefined && (
              <div className="flex items-center justify-between gap-4">
                <span className="flex items-center gap-1 text-xs text-muted-foreground">
                  <Activity className="w-3 h-3" />
                  Traffic
                </span>
                <span className="text-xs font-mono">
                  {node.metrics.traffic >= 1000
                    ? `${(node.metrics.traffic / 1000).toFixed(1)}GB/s`
                    : `${node.metrics.traffic}MB/s`}
                </span>
              </div>
            )}
          </div>

          {/* Tooltip arrow */}
          <div
            className="absolute -top-1 left-1/2 -translate-x-1/2 w-2 h-2 rotate-45 bg-card border-l border-t border-border"
          />
        </div>
      )}
    </div>
  );
}

interface ConnectionLineProps {
  from: { x: number; y: number };
  to: { x: number; y: number };
  status: 'healthy' | 'warning' | 'critical' | 'offline';
  animated?: boolean;
  index: number;
}

function ConnectionLine({ from, to, status, animated = true, index }: ConnectionLineProps) {
  const colors = STATUS_COLORS[status];
  const path = getConnectionPath(
    { x: from.x + 200, y: from.y + 150 },
    { x: to.x + 200, y: to.y + 150 }
  );

  return (
    <g>
      {/* Glow layer */}
      <path
        d={path}
        fill="none"
        stroke={colors.primary}
        strokeWidth="4"
        strokeOpacity="0.2"
        style={{ filter: 'blur(4px)' }}
      />

      {/* Main line */}
      <path
        d={path}
        fill="none"
        stroke={colors.primary}
        strokeWidth="2"
        strokeOpacity="0.6"
        strokeLinecap="round"
      />

      {/* Animated traffic dots */}
      {animated && status !== 'offline' && (
        <>
          <circle r="3" fill={colors.primary}>
            <animateMotion
              dur={`${2 + index * 0.2}s`}
              repeatCount="indefinite"
              path={path}
            />
          </circle>
          <circle r="3" fill={colors.primary} opacity="0.5">
            <animateMotion
              dur={`${2 + index * 0.2}s`}
              repeatCount="indefinite"
              path={path}
              begin={`${0.5 + index * 0.1}s`}
            />
          </circle>
        </>
      )}
    </g>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function NetworkTopology3D({
  nodes,
  onNodeClick,
  className,
}: NetworkTopology3DProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  // Calculate isometric projections for all nodes
  const projectedNodes = useMemo(() => {
    return nodes.map(node => {
      const projected = projectToIsometric(
        node.position.x,
        node.position.y,
        node.position.z,
        scale * 2
      );
      return {
        node,
        projected: {
          x: projected.x + pan.x,
          y: projected.y + pan.y,
        },
        zIndex: Math.round(node.position.z * 10),
      };
    });
  }, [nodes, scale, pan]);

  // Calculate connections
  const connections = useMemo(() => {
    const result: Array<{
      from: { x: number; y: number };
      to: { x: number; y: number };
      status: NetworkNode['status'];
      index: number;
    }> = [];

    projectedNodes.forEach(({ node, projected: fromPos }) => {
      node.connections.forEach((targetId, idx) => {
        const target = projectedNodes.find(p => p.node.id === targetId);
        if (target) {
          // Determine connection status (worst of the two nodes)
          const statusPriority = { critical: 3, warning: 2, offline: 1, healthy: 0 };
          const worstStatus =
            statusPriority[node.status] > statusPriority[target.node.status]
              ? node.status
              : target.node.status;

          result.push({
            from: fromPos,
            to: target.projected,
            status: worstStatus,
            index: idx,
          });
        }
      });
    });

    return result;
  }, [projectedNodes]);

  // Drag handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if ((e.target as HTMLElement).closest('[data-node]')) return;
    setIsDragging(true);
    dragStart.current = {
      x: e.clientX,
      y: e.clientY,
      panX: pan.x,
      panY: pan.y,
    };
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging) return;
    setPan({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  }, [isDragging]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  // Zoom handlers
  const handleZoomIn = () => setScale(prev => Math.min(2, prev + 0.2));
  const handleZoomOut = () => setScale(prev => Math.max(0.5, prev - 0.2));
  const handleReset = () => {
    setScale(1);
    setPan({ x: 0, y: 0 });
  };

  // Stats summary
  const stats = useMemo(() => {
    return {
      total: nodes.length,
      healthy: nodes.filter(n => n.status === 'healthy').length,
      warning: nodes.filter(n => n.status === 'warning').length,
      critical: nodes.filter(n => n.status === 'critical').length,
      offline: nodes.filter(n => n.status === 'offline').length,
    };
  }, [nodes]);

  return (
    <Card className={cn('h-full overflow-hidden', className)}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-primary/10">
            <Network className="w-5 h-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-base">Network Topology</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Infrastructure overview
            </p>
          </div>
        </div>

        {/* Status summary badges */}
        <div className="flex items-center gap-1">
          <Badge
            variant="outline"
            className="text-2xs"
            style={{
              color: STATUS_COLORS.healthy.primary,
              borderColor: `${STATUS_COLORS.healthy.primary}40`,
            }}
          >
            {stats.healthy} OK
          </Badge>
          {stats.warning > 0 && (
            <Badge
              variant="outline"
              className="text-2xs"
              style={{
                color: STATUS_COLORS.warning.primary,
                borderColor: `${STATUS_COLORS.warning.primary}40`,
              }}
            >
              {stats.warning} Warn
            </Badge>
          )}
          {stats.critical > 0 && (
            <Badge
              variant="outline"
              className="text-2xs animate-pulse"
              style={{
                color: STATUS_COLORS.critical.primary,
                borderColor: `${STATUS_COLORS.critical.primary}40`,
              }}
            >
              {stats.critical} Crit
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {/* 3D Topology Container */}
        <div
          ref={containerRef}
          className={cn(
            'relative h-[320px] rounded-lg overflow-hidden select-none',
            isDragging ? 'cursor-grabbing' : 'cursor-grab'
          )}
          style={{
            background: `
              radial-gradient(ellipse at center, hsl(var(--card)) 0%, hsl(var(--background)) 100%)
            `,
          }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {/* Grid floor */}
          <div
            className="absolute inset-0"
            style={{
              perspective: '800px',
              perspectiveOrigin: '50% 30%',
            }}
          >
            <div
              className="absolute inset-x-0 bottom-0 h-[200px]"
              style={{
                transform: 'rotateX(60deg) translateZ(-50px)',
                transformOrigin: 'bottom center',
                backgroundImage: `
                  linear-gradient(90deg, hsl(var(--primary) / 0.1) 1px, transparent 1px),
                  linear-gradient(0deg, hsl(var(--primary) / 0.1) 1px, transparent 1px)
                `,
                backgroundSize: '40px 40px',
                maskImage: 'linear-gradient(to bottom, transparent, black 20%, black 80%, transparent)',
              }}
            />
          </div>

          {/* Connections SVG layer */}
          <svg
            className="absolute inset-0 pointer-events-none"
            style={{ width: '100%', height: '100%' }}
          >
            <defs>
              <filter id="glow">
                <feGaussianBlur stdDeviation="2" result="coloredBlur" />
                <feMerge>
                  <feMergeNode in="coloredBlur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            <g filter="url(#glow)">
              {connections.map((conn, i) => (
                <ConnectionLine
                  key={i}
                  from={conn.from}
                  to={conn.to}
                  status={conn.status}
                  index={conn.index}
                />
              ))}
            </g>
          </svg>

          {/* Network nodes */}
          {projectedNodes
            .sort((a, b) => a.zIndex - b.zIndex)
            .map(({ node, projected, zIndex }) => (
              <NetworkNodeCard
                key={node.id}
                node={node}
                projected={projected}
                zIndex={zIndex}
                isSelected={selectedNode === node.id}
                isHovered={hoveredNode === node.id}
                onClick={() => {
                  setSelectedNode(node.id);
                  onNodeClick?.(node);
                }}
                onHover={(active) => setHoveredNode(active ? node.id : null)}
              />
            ))}

          {/* Zoom controls */}
          <div className="absolute bottom-2 right-2 flex items-center gap-1 bg-card/80 backdrop-blur-sm rounded-lg border border-border p-1">
            <button
              className="p-1.5 rounded hover:bg-muted transition-colors"
              onClick={handleZoomIn}
              title="Zoom in"
            >
              <ZoomIn className="w-4 h-4 text-muted-foreground" />
            </button>
            <button
              className="p-1.5 rounded hover:bg-muted transition-colors"
              onClick={handleZoomOut}
              title="Zoom out"
            >
              <ZoomOut className="w-4 h-4 text-muted-foreground" />
            </button>
            <div className="w-px h-4 bg-border" />
            <button
              className="p-1.5 rounded hover:bg-muted transition-colors"
              onClick={handleReset}
              title="Reset view"
            >
              <Maximize2 className="w-4 h-4 text-muted-foreground" />
            </button>
          </div>

          {/* Legend */}
          <div className="absolute top-2 left-2 flex flex-col gap-1 text-2xs">
            {(['healthy', 'warning', 'critical', 'offline'] as const).map(status => (
              <div key={status} className="flex items-center gap-1.5">
                <div
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: STATUS_COLORS[status].primary }}
                />
                <span className="text-muted-foreground capitalize">{status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Node type summary */}
        <div className="mt-4 grid grid-cols-5 gap-2">
          {(['server', 'router', 'firewall', 'endpoint', 'cloud'] as const).map(type => {
            const count = nodes.filter(n => n.type === type).length;
            const Icon = NODE_ICONS[type];
            const hasIssue = nodes.some(
              n => n.type === type && (n.status === 'warning' || n.status === 'critical')
            );

            return (
              <div
                key={type}
                className={cn(
                  'flex flex-col items-center gap-1 p-2 rounded-lg bg-muted/30',
                  hasIssue && 'ring-1 ring-warning'
                )}
              >
                <Icon className="w-4 h-4 text-muted-foreground" />
                <span className="text-lg font-bold">{count}</span>
                <span className="text-2xs text-muted-foreground capitalize">{type}s</span>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Sample Data
// ============================================================================

export const sampleNetworkNodes: NetworkNode[] = [
  {
    id: 'fw-1',
    type: 'firewall',
    name: 'FW-Edge-01',
    status: 'healthy',
    position: { x: 0, y: -40, z: 0 },
    connections: ['router-1'],
    metrics: { cpu: 45, memory: 62, traffic: 850 },
  },
  {
    id: 'router-1',
    type: 'router',
    name: 'Core-Router',
    status: 'healthy',
    position: { x: 0, y: 0, z: 30 },
    connections: ['server-1', 'server-2', 'server-3'],
    metrics: { cpu: 38, memory: 55, traffic: 2400 },
  },
  {
    id: 'server-1',
    type: 'server',
    name: 'Web-Server-01',
    status: 'healthy',
    position: { x: -60, y: 30, z: 50 },
    connections: ['endpoint-1'],
    metrics: { cpu: 72, memory: 68, traffic: 320 },
  },
  {
    id: 'server-2',
    type: 'server',
    name: 'DB-Server-01',
    status: 'warning',
    position: { x: 0, y: 30, z: 60 },
    connections: ['endpoint-2'],
    metrics: { cpu: 88, memory: 91, traffic: 180 },
  },
  {
    id: 'server-3',
    type: 'server',
    name: 'App-Server-01',
    status: 'critical',
    position: { x: 60, y: 30, z: 50 },
    connections: ['cloud-1'],
    metrics: { cpu: 95, memory: 87, traffic: 450 },
  },
  {
    id: 'endpoint-1',
    type: 'endpoint',
    name: 'WS-Finance-01',
    status: 'healthy',
    position: { x: -80, y: 60, z: 70 },
    connections: [],
    metrics: { cpu: 25, memory: 48 },
  },
  {
    id: 'endpoint-2',
    type: 'endpoint',
    name: 'WS-Admin-01',
    status: 'healthy',
    position: { x: 0, y: 60, z: 80 },
    connections: [],
    metrics: { cpu: 32, memory: 55 },
  },
  {
    id: 'cloud-1',
    type: 'cloud',
    name: 'AWS-VPC-01',
    status: 'healthy',
    position: { x: 80, y: 60, z: 70 },
    connections: [],
    metrics: { cpu: 42, memory: 58, traffic: 1200 },
  },
];

export default NetworkTopology3D;
