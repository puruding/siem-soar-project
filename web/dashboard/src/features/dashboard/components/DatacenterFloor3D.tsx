import { useState, useMemo, useCallback, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import {
  Building2,
  Server,
  Thermometer,
  Zap,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Wrench,
  Fan,
  ZoomIn,
  ZoomOut,
  Maximize2,
  LayoutGrid,
  Flame,
} from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface ServerUnit {
  id: string;
  name: string;
  status: 'running' | 'stopped' | 'error';
  utilization: number;
}

export interface ServerRack {
  id: string;
  row: number;
  column: number;
  name: string;
  status: 'operational' | 'warning' | 'critical' | 'maintenance';
  servers: ServerUnit[];
  temperature?: number;
  powerDraw?: number;
}

interface DatacenterFloor3DProps {
  racks: ServerRack[];
  onRackClick?: (rack: ServerRack) => void;
  showHeatmap?: boolean;
  className?: string;
}

// ============================================================================
// Constants
// ============================================================================

const RACK_STATUS_COLORS = {
  operational: {
    primary: '#5CC05C',
    secondary: 'rgba(92, 192, 92, 0.3)',
    glow: 'rgba(92, 192, 92, 0.4)',
  },
  warning: {
    primary: '#F79836',
    secondary: 'rgba(247, 152, 54, 0.3)',
    glow: 'rgba(247, 152, 54, 0.4)',
  },
  critical: {
    primary: '#DC4E41',
    secondary: 'rgba(220, 78, 65, 0.3)',
    glow: 'rgba(220, 78, 65, 0.4)',
  },
  maintenance: {
    primary: '#00A4A6',
    secondary: 'rgba(0, 164, 166, 0.3)',
    glow: 'rgba(0, 164, 166, 0.4)',
  },
} as const;

const SERVER_STATUS_COLORS = {
  running: '#5CC05C',
  stopped: '#6B7280',
  error: '#DC4E41',
} as const;

// Heat map color interpolation
function getHeatColor(utilization: number): string {
  if (utilization < 30) return 'rgba(92, 192, 92, 0.6)';
  if (utilization < 50) return 'rgba(92, 192, 92, 0.8)';
  if (utilization < 70) return 'rgba(247, 152, 54, 0.7)';
  if (utilization < 85) return 'rgba(247, 152, 54, 0.9)';
  return 'rgba(220, 78, 65, 0.9)';
}

// ============================================================================
// Sub-Components
// ============================================================================

interface Rack3DProps {
  rack: ServerRack;
  position: { x: number; y: number };
  scale: number;
  isSelected: boolean;
  isHovered: boolean;
  showHeatmap: boolean;
  onClick: () => void;
  onHover: (active: boolean) => void;
}

function Rack3D({
  rack,
  position,
  scale,
  isSelected,
  isHovered,
  showHeatmap,
  onClick,
  onHover,
}: Rack3DProps) {
  const colors = RACK_STATUS_COLORS[rack.status];
  const avgUtilization = rack.servers.length > 0
    ? rack.servers.reduce((sum, s) => sum + s.utilization, 0) / rack.servers.length
    : 0;

  const rackWidth = 50 * scale;
  const rackHeight = 80 * scale;
  const rackDepth = 30 * scale;

  return (
    <div
      className={cn(
        'absolute cursor-pointer transition-all duration-300',
        isSelected && 'ring-2 ring-primary ring-offset-2 ring-offset-background rounded-lg'
      )}
      style={{
        left: position.x,
        top: position.y,
        width: rackWidth,
        transform: isHovered ? 'translateY(-8px)' : 'translateY(0)',
        zIndex: isHovered ? 100 : rack.row * 10 + rack.column,
        willChange: 'transform',
      }}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      {/* 3D Rack container using CSS transforms */}
      <div
        className="relative"
        style={{
          transformStyle: 'preserve-3d',
          perspective: '500px',
        }}
      >
        {/* Status glow effect */}
        <div
          className={cn(
            'absolute inset-0 rounded blur-lg transition-opacity duration-300',
            (rack.status === 'critical' || rack.status === 'warning') && 'animate-pulse'
          )}
          style={{
            backgroundColor: showHeatmap ? getHeatColor(avgUtilization) : colors.glow,
            opacity: isHovered ? 1 : 0.5,
            transform: 'translateZ(-10px) scale(1.2)',
          }}
        />

        {/* Rack top face (isometric) */}
        <div
          className="absolute rounded-t border"
          style={{
            width: rackWidth,
            height: rackDepth,
            transform: `rotateX(-60deg) translateZ(${rackHeight / 2}px)`,
            transformOrigin: 'center bottom',
            background: `linear-gradient(135deg, ${colors.secondary} 0%, hsl(var(--card)) 100%)`,
            borderColor: colors.primary,
          }}
        >
          {/* Air vents pattern */}
          <div
            className="absolute inset-1 opacity-30"
            style={{
              backgroundImage: `repeating-linear-gradient(
                0deg,
                transparent,
                transparent 2px,
                ${colors.primary} 2px,
                ${colors.primary} 3px
              )`,
            }}
          />
        </div>

        {/* Rack front face */}
        <div
          className="relative rounded border overflow-hidden"
          style={{
            width: rackWidth,
            height: rackHeight,
            background: showHeatmap
              ? `linear-gradient(180deg, ${getHeatColor(avgUtilization)} 0%, hsl(var(--card)) 100%)`
              : `linear-gradient(180deg, ${colors.secondary} 0%, hsl(var(--card)) 100%)`,
            borderColor: colors.primary,
            boxShadow: `inset 0 0 20px rgba(0,0,0,0.3), 0 4px 20px ${colors.glow}`,
          }}
        >
          {/* Server units visualization */}
          <div className="absolute inset-1 flex flex-col gap-px">
            {rack.servers.slice(0, 8).map((server, i) => (
              <div
                key={server.id}
                className="flex-1 rounded-sm flex items-center justify-center relative overflow-hidden"
                style={{
                  backgroundColor: showHeatmap
                    ? getHeatColor(server.utilization)
                    : `${SERVER_STATUS_COLORS[server.status]}30`,
                  borderLeft: `2px solid ${SERVER_STATUS_COLORS[server.status]}`,
                }}
              >
                {/* Activity indicator LEDs */}
                <div className="absolute left-1 top-1/2 -translate-y-1/2 flex gap-0.5">
                  <div
                    className={cn(
                      'w-1 h-1 rounded-full',
                      server.status === 'running' && 'animate-pulse'
                    )}
                    style={{
                      backgroundColor: SERVER_STATUS_COLORS[server.status],
                    }}
                  />
                  {server.utilization > 50 && (
                    <div
                      className="w-1 h-1 rounded-full animate-pulse"
                      style={{
                        backgroundColor: '#F79836',
                        animationDelay: `${i * 0.1}s`,
                      }}
                    />
                  )}
                </div>

                {/* Utilization bar */}
                {server.status === 'running' && (
                  <div
                    className="absolute bottom-0 left-0 right-0 h-px"
                    style={{
                      background: `linear-gradient(90deg, ${SERVER_STATUS_COLORS[server.status]} ${server.utilization}%, transparent ${server.utilization}%)`,
                    }}
                  />
                )}
              </div>
            ))}

            {/* Additional servers indicator */}
            {rack.servers.length > 8 && (
              <div className="text-2xs text-center text-muted-foreground py-0.5">
                +{rack.servers.length - 8} more
              </div>
            )}
          </div>

          {/* Rack status indicator */}
          <div className="absolute top-1 right-1">
            {rack.status === 'operational' && (
              <CheckCircle className="w-3 h-3" style={{ color: colors.primary }} />
            )}
            {rack.status === 'warning' && (
              <AlertTriangle className="w-3 h-3 animate-pulse" style={{ color: colors.primary }} />
            )}
            {rack.status === 'critical' && (
              <XCircle className="w-3 h-3 animate-pulse" style={{ color: colors.primary }} />
            )}
            {rack.status === 'maintenance' && (
              <Wrench className="w-3 h-3" style={{ color: colors.primary }} />
            )}
          </div>

          {/* Rack name label */}
          <div
            className="absolute bottom-1 left-1 right-1 text-center text-2xs font-mono truncate px-1"
            style={{ color: colors.primary }}
          >
            {rack.name}
          </div>
        </div>

        {/* Rack right side face (isometric depth) */}
        <div
          className="absolute border-r border-b"
          style={{
            width: rackDepth,
            height: rackHeight,
            left: rackWidth,
            transform: 'skewY(-30deg)',
            transformOrigin: 'left top',
            background: `linear-gradient(90deg, ${colors.secondary} 0%, hsl(var(--muted)) 100%)`,
            borderColor: colors.primary,
            opacity: 0.7,
          }}
        />
      </div>

      {/* Hover tooltip */}
      {isHovered && (
        <div
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 p-3 bg-card border border-border rounded-lg shadow-xl z-50 min-w-[180px]"
          style={{ animation: 'fade-in 0.15s ease-out' }}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="font-medium text-sm">{rack.name}</span>
            <Badge
              variant="outline"
              className="text-2xs"
              style={{
                color: colors.primary,
                borderColor: `${colors.primary}50`,
              }}
            >
              {rack.status}
            </Badge>
          </div>

          <div className="space-y-1.5 text-xs">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1 text-muted-foreground">
                <Server className="w-3 h-3" />
                Servers
              </span>
              <span className="font-mono">
                {rack.servers.filter(s => s.status === 'running').length}/{rack.servers.length}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1 text-muted-foreground">
                <Zap className="w-3 h-3" />
                Avg Utilization
              </span>
              <span className="font-mono">{Math.round(avgUtilization)}%</span>
            </div>

            {rack.temperature !== undefined && (
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1 text-muted-foreground">
                  <Thermometer className="w-3 h-3" />
                  Temperature
                </span>
                <span
                  className="font-mono"
                  style={{
                    color: rack.temperature > 75 ? '#DC4E41' : rack.temperature > 60 ? '#F79836' : '#5CC05C',
                  }}
                >
                  {rack.temperature}°C
                </span>
              </div>
            )}

            {rack.powerDraw !== undefined && (
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1 text-muted-foreground">
                  <Zap className="w-3 h-3" />
                  Power
                </span>
                <span className="font-mono">{rack.powerDraw}W</span>
              </div>
            )}
          </div>

          {/* Tooltip arrow */}
          <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-border" />
        </div>
      )}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function DatacenterFloor3D({
  racks,
  onRackClick,
  showHeatmap: initialShowHeatmap = false,
  className,
}: DatacenterFloor3DProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);
  const [showHeatmap, setShowHeatmap] = useState(initialShowHeatmap);
  const [selectedRack, setSelectedRack] = useState<string | null>(null);
  const [hoveredRack, setHoveredRack] = useState<string | null>(null);

  // Calculate grid dimensions
  const gridInfo = useMemo(() => {
    const maxRow = Math.max(...racks.map(r => r.row));
    const maxCol = Math.max(...racks.map(r => r.column));
    return { rows: maxRow + 1, cols: maxCol + 1 };
  }, [racks]);

  // Calculate rack positions
  const rackPositions = useMemo(() => {
    const baseWidth = 60 * scale;
    const baseHeight = 100 * scale;
    const gapX = 20 * scale;
    const gapY = 30 * scale;

    return racks.map(rack => ({
      rack,
      position: {
        x: 40 + rack.column * (baseWidth + gapX),
        y: 40 + rack.row * (baseHeight + gapY),
      },
    }));
  }, [racks, scale]);

  // Zoom handlers
  const handleZoomIn = () => setScale(prev => Math.min(1.5, prev + 0.1));
  const handleZoomOut = () => setScale(prev => Math.max(0.6, prev - 0.1));
  const handleReset = () => setScale(1);

  // Stats summary
  const stats = useMemo(() => {
    const totalServers = racks.reduce((sum, r) => sum + r.servers.length, 0);
    const runningServers = racks.reduce(
      (sum, r) => sum + r.servers.filter(s => s.status === 'running').length,
      0
    );
    const avgUtilization = racks.length > 0
      ? racks.reduce((sum, r) => {
          const rackAvg = r.servers.length > 0
            ? r.servers.reduce((s, srv) => s + srv.utilization, 0) / r.servers.length
            : 0;
          return sum + rackAvg;
        }, 0) / racks.length
      : 0;

    return {
      totalRacks: racks.length,
      operationalRacks: racks.filter(r => r.status === 'operational').length,
      totalServers,
      runningServers,
      avgUtilization: Math.round(avgUtilization),
      criticalRacks: racks.filter(r => r.status === 'critical').length,
    };
  }, [racks]);

  return (
    <Card className={cn('h-full overflow-hidden', className)}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-primary/10">
            <Building2 className="w-5 h-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-base">Datacenter Floor</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {gridInfo.rows} rows x {gridInfo.cols} columns
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Heatmap toggle */}
          <button
            className={cn(
              'flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors',
              showHeatmap
                ? 'bg-warning/20 text-warning'
                : 'bg-muted text-muted-foreground hover:bg-muted/80'
            )}
            onClick={() => setShowHeatmap(!showHeatmap)}
          >
            <Flame className="w-3 h-3" />
            Heat
          </button>

          {stats.criticalRacks > 0 && (
            <Badge variant="destructive" className="animate-pulse text-2xs">
              {stats.criticalRacks} Critical
            </Badge>
          )}
        </div>
      </CardHeader>

      <CardContent className="pt-0">
        {/* 3D Datacenter Floor Container */}
        <div
          ref={containerRef}
          className="relative h-[320px] rounded-lg overflow-hidden"
          style={{
            perspective: '1200px',
            perspectiveOrigin: '50% 20%',
            background: `
              radial-gradient(ellipse at center bottom, hsl(var(--muted)) 0%, hsl(var(--background)) 70%)
            `,
          }}
        >
          {/* Floor grid */}
          <div
            className="absolute inset-0"
            style={{
              transformStyle: 'preserve-3d',
              transform: 'rotateX(55deg) translateZ(-20px)',
              transformOrigin: 'center center',
            }}
          >
            <div
              className="absolute inset-0"
              style={{
                backgroundImage: `
                  linear-gradient(90deg, hsl(var(--border) / 0.3) 1px, transparent 1px),
                  linear-gradient(0deg, hsl(var(--border) / 0.3) 1px, transparent 1px)
                `,
                backgroundSize: `${60 * scale}px ${60 * scale}px`,
              }}
            />

            {/* Hot/cold aisle indicators */}
            {Array.from({ length: gridInfo.rows }).map((_, rowIdx) => (
              <div
                key={rowIdx}
                className="absolute h-8 flex items-center justify-center"
                style={{
                  left: 0,
                  right: 0,
                  top: `${40 + rowIdx * 130 * scale + 90 * scale}px`,
                  transform: 'rotateX(-55deg)',
                }}
              >
                <div
                  className={cn(
                    'px-2 py-0.5 rounded text-2xs font-mono',
                    rowIdx % 2 === 0 ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'
                  )}
                >
                  {rowIdx % 2 === 0 ? 'HOT' : 'COLD'} AISLE
                </div>
              </div>
            ))}
          </div>

          {/* Rack container (transformed to match floor perspective) */}
          <div
            className="absolute inset-0"
            style={{
              transformStyle: 'preserve-3d',
              transform: 'rotateX(10deg)',
              transformOrigin: 'center bottom',
            }}
          >
            {rackPositions.map(({ rack, position }) => (
              <Rack3D
                key={rack.id}
                rack={rack}
                position={position}
                scale={scale}
                isSelected={selectedRack === rack.id}
                isHovered={hoveredRack === rack.id}
                showHeatmap={showHeatmap}
                onClick={() => {
                  setSelectedRack(rack.id);
                  onRackClick?.(rack);
                }}
                onHover={(active) => setHoveredRack(active ? rack.id : null)}
              />
            ))}
          </div>

          {/* Ambient effects */}
          <div className="absolute bottom-0 left-0 right-0 h-20 bg-gradient-to-t from-background to-transparent pointer-events-none" />

          {/* HVAC/Cooling indicator */}
          <div className="absolute top-2 right-2 flex items-center gap-1 bg-card/80 backdrop-blur-sm px-2 py-1 rounded border border-border">
            <Fan className="w-3 h-3 text-primary animate-spin" style={{ animationDuration: '3s' }} />
            <span className="text-2xs text-muted-foreground">HVAC Active</span>
          </div>

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
          <div className="absolute top-2 left-2 flex flex-col gap-1 text-2xs bg-card/80 backdrop-blur-sm p-2 rounded border border-border">
            <div className="flex items-center gap-1.5 text-muted-foreground mb-1">
              <LayoutGrid className="w-3 h-3" />
              <span>Rack Status</span>
            </div>
            {(['operational', 'warning', 'critical', 'maintenance'] as const).map(status => (
              <div key={status} className="flex items-center gap-1.5">
                <div
                  className="w-2 h-2 rounded-sm"
                  style={{ backgroundColor: RACK_STATUS_COLORS[status].primary }}
                />
                <span className="text-muted-foreground capitalize">{status}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Stats bar */}
        <div className="mt-4 grid grid-cols-4 gap-2">
          <div className="flex flex-col items-center p-2 rounded-lg bg-muted/30">
            <span className="text-lg font-bold">{stats.totalRacks}</span>
            <span className="text-2xs text-muted-foreground">Total Racks</span>
          </div>
          <div className="flex flex-col items-center p-2 rounded-lg bg-muted/30">
            <span className="text-lg font-bold text-success">{stats.operationalRacks}</span>
            <span className="text-2xs text-muted-foreground">Operational</span>
          </div>
          <div className="flex flex-col items-center p-2 rounded-lg bg-muted/30">
            <span className="text-lg font-bold">
              {stats.runningServers}/{stats.totalServers}
            </span>
            <span className="text-2xs text-muted-foreground">Servers Up</span>
          </div>
          <div className="flex flex-col items-center p-2 rounded-lg bg-muted/30">
            <span
              className="text-lg font-bold"
              style={{
                color:
                  stats.avgUtilization > 80
                    ? '#DC4E41'
                    : stats.avgUtilization > 60
                    ? '#F79836'
                    : '#5CC05C',
              }}
            >
              {stats.avgUtilization}%
            </span>
            <span className="text-2xs text-muted-foreground">Avg Load</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Sample Data
// ============================================================================

function generateServers(count: number): ServerUnit[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `srv-${i}`,
    name: `Server-${i + 1}`,
    status: Math.random() > 0.1 ? 'running' : Math.random() > 0.5 ? 'stopped' : 'error',
    utilization: Math.round(Math.random() * 100),
  }));
}

export const sampleServerRacks: ServerRack[] = [
  { id: 'rack-1', row: 0, column: 0, name: 'RACK-A1', status: 'operational', servers: generateServers(12), temperature: 42, powerDraw: 3200 },
  { id: 'rack-2', row: 0, column: 1, name: 'RACK-A2', status: 'operational', servers: generateServers(10), temperature: 45, powerDraw: 2800 },
  { id: 'rack-3', row: 0, column: 2, name: 'RACK-A3', status: 'warning', servers: generateServers(12), temperature: 68, powerDraw: 4100 },
  { id: 'rack-4', row: 0, column: 3, name: 'RACK-A4', status: 'operational', servers: generateServers(8), temperature: 41, powerDraw: 2400 },
  { id: 'rack-5', row: 1, column: 0, name: 'RACK-B1', status: 'operational', servers: generateServers(12), temperature: 44, powerDraw: 3100 },
  { id: 'rack-6', row: 1, column: 1, name: 'RACK-B2', status: 'critical', servers: generateServers(12), temperature: 82, powerDraw: 4500 },
  { id: 'rack-7', row: 1, column: 2, name: 'RACK-B3', status: 'maintenance', servers: generateServers(6), temperature: 38, powerDraw: 1200 },
  { id: 'rack-8', row: 1, column: 3, name: 'RACK-B4', status: 'operational', servers: generateServers(10), temperature: 43, powerDraw: 2900 },
  { id: 'rack-9', row: 2, column: 0, name: 'RACK-C1', status: 'operational', servers: generateServers(12), temperature: 46, powerDraw: 3300 },
  { id: 'rack-10', row: 2, column: 1, name: 'RACK-C2', status: 'operational', servers: generateServers(12), temperature: 44, powerDraw: 3000 },
  { id: 'rack-11', row: 2, column: 2, name: 'RACK-C3', status: 'warning', servers: generateServers(12), temperature: 71, powerDraw: 4200 },
  { id: 'rack-12', row: 2, column: 3, name: 'RACK-C4', status: 'operational', servers: generateServers(10), temperature: 42, powerDraw: 2700 },
];

export default DatacenterFloor3D;
