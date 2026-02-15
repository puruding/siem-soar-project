import { useState, useRef, useCallback, useMemo, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { Globe, MapPin, Zap, Shield, AlertTriangle } from 'lucide-react';

// ============================================================================
// Types
// ============================================================================

export interface ThreatLocation {
  id: string;
  lat: number;
  lng: number;
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
  count: number;
  country: string;
}

interface ThreatGlobe3DProps {
  threats: ThreatLocation[];
  onLocationClick?: (location: ThreatLocation) => void;
  autoRotate?: boolean;
  className?: string;
}

// ============================================================================
// Constants
// ============================================================================

const THREAT_COLORS = {
  critical: {
    primary: '#DC4E41',
    glow: 'rgba(220, 78, 65, 0.6)',
    ring: 'rgba(220, 78, 65, 0.3)',
  },
  high: {
    primary: '#F79836',
    glow: 'rgba(247, 152, 54, 0.6)',
    ring: 'rgba(247, 152, 54, 0.3)',
  },
  medium: {
    primary: '#FFB84D',
    glow: 'rgba(255, 184, 77, 0.6)',
    ring: 'rgba(255, 184, 77, 0.3)',
  },
  low: {
    primary: '#5CC05C',
    glow: 'rgba(92, 192, 92, 0.6)',
    ring: 'rgba(92, 192, 92, 0.3)',
  },
} as const;

// World Map SVG - simplified but recognizable world map outline
// This is a simplified vector representation of the world continents
const WORLD_MAP_SVG = `
<svg viewBox="0 0 100 50" xmlns="http://www.w3.org/2000/svg">
  <!-- North America -->
  <path d="M5,8 L8,6 L12,5 L18,6 L22,8 L24,12 L26,10 L28,12 L26,16 L22,18 L20,22 L16,24 L12,22 L8,20 L6,16 L4,12 Z" fill="currentColor" opacity="0.6"/>
  <!-- Greenland -->
  <path d="M30,4 L34,3 L38,5 L37,9 L33,10 L30,8 Z" fill="currentColor" opacity="0.5"/>
  <!-- South America -->
  <path d="M18,26 L22,24 L26,26 L28,30 L26,36 L24,42 L20,44 L18,40 L16,34 L17,28 Z" fill="currentColor" opacity="0.6"/>
  <!-- Europe -->
  <path d="M44,6 L48,5 L52,6 L54,10 L52,14 L48,16 L44,14 L42,10 Z" fill="currentColor" opacity="0.6"/>
  <!-- UK -->
  <path d="M40,8 L42,7 L43,10 L41,12 L39,10 Z" fill="currentColor" opacity="0.5"/>
  <!-- Africa -->
  <path d="M44,18 L50,16 L56,18 L58,24 L56,32 L52,38 L46,40 L42,36 L40,28 L42,22 Z" fill="currentColor" opacity="0.6"/>
  <!-- Asia -->
  <path d="M56,4 L64,3 L72,4 L80,6 L86,10 L88,16 L86,22 L80,26 L72,28 L64,26 L58,22 L54,16 L56,10 Z" fill="currentColor" opacity="0.6"/>
  <!-- Middle East -->
  <path d="M56,16 L62,14 L66,18 L64,22 L58,24 L54,20 Z" fill="currentColor" opacity="0.5"/>
  <!-- India -->
  <path d="M68,20 L74,18 L76,24 L74,30 L70,32 L66,28 L68,24 Z" fill="currentColor" opacity="0.5"/>
  <!-- Southeast Asia -->
  <path d="M78,22 L84,20 L88,24 L86,30 L80,32 L76,28 Z" fill="currentColor" opacity="0.5"/>
  <!-- Japan -->
  <path d="M88,12 L90,10 L92,12 L91,16 L88,18 L86,14 Z" fill="currentColor" opacity="0.5"/>
  <!-- Australia -->
  <path d="M80,34 L88,32 L94,36 L92,42 L86,46 L78,44 L76,38 Z" fill="currentColor" opacity="0.6"/>
  <!-- New Zealand -->
  <path d="M94,42 L96,40 L98,44 L96,48 L94,46 Z" fill="currentColor" opacity="0.5"/>
  <!-- Indonesia -->
  <path d="M78,30 L86,28 L90,30 L88,34 L82,36 L78,32 Z" fill="currentColor" opacity="0.4"/>
</svg>
`;

// Simplified continent paths for visual representation (backup/overlay)
const CONTINENT_PATHS = [
  // North America
  'M 15,25 Q 25,20 35,22 Q 40,25 38,32 Q 35,38 28,40 Q 20,38 15,30 Z',
  // South America
  'M 28,45 Q 32,48 33,55 Q 32,65 28,70 Q 25,68 24,60 Q 24,52 28,45 Z',
  // Europe
  'M 48,22 Q 52,20 55,22 Q 57,26 55,30 Q 52,32 48,30 Q 46,26 48,22 Z',
  // Africa
  'M 48,35 Q 55,32 58,38 Q 60,50 55,58 Q 50,60 46,55 Q 44,45 48,35 Z',
  // Asia
  'M 58,18 Q 75,15 85,20 Q 90,30 85,38 Q 75,42 65,38 Q 58,32 58,18 Z',
  // Australia
  'M 78,55 Q 85,52 88,56 Q 88,62 84,65 Q 78,64 78,55 Z',
];

// ============================================================================
// Helper Functions
// ============================================================================

function latLngToPosition(lat: number, lng: number, globeSize: number) {
  // Convert lat/lng to percentage position on a flat representation
  const x = ((lng + 180) / 360) * 100;
  const y = ((90 - lat) / 180) * 100;
  return { x, y };
}

function calculateDepthOffset(rotation: { x: number; y: number }, x: number, y: number) {
  // Calculate how "forward" a point is based on globe rotation
  const normalizedX = (x - 50) / 50;
  const normalizedY = (y - 50) / 50;

  const rotX = rotation.x * (Math.PI / 180);
  const rotY = rotation.y * (Math.PI / 180);

  const depth = Math.cos(normalizedX * Math.PI / 2 - rotY) *
                Math.cos(normalizedY * Math.PI / 2 + rotX);

  return Math.max(0, depth);
}

// ============================================================================
// Sub-Components
// ============================================================================

interface GlobeMarkerProps {
  threat: ThreatLocation;
  position: { x: number; y: number };
  depth: number;
  isActive: boolean;
  onClick: () => void;
  onHover: (active: boolean) => void;
}

function GlobeMarker({ threat, position, depth, isActive, onClick, onHover }: GlobeMarkerProps) {
  const colors = THREAT_COLORS[threat.threatLevel];
  const scale = 0.5 + depth * 0.5;
  const opacity = 0.3 + depth * 0.7;
  const pulseDelay = Math.random() * 2;

  if (depth < 0.2) return null; // Hide markers on the "back" of the globe

  return (
    <div
      className="absolute cursor-pointer group"
      style={{
        left: `${position.x}%`,
        top: `${position.y}%`,
        transform: `translate(-50%, -50%) scale(${scale})`,
        opacity,
        zIndex: Math.round(depth * 100),
        willChange: 'transform, opacity',
      }}
      onClick={onClick}
      onMouseEnter={() => onHover(true)}
      onMouseLeave={() => onHover(false)}
    >
      {/* Outer pulse ring */}
      <div
        className="absolute inset-0 rounded-full animate-ping"
        style={{
          width: `${Math.max(16, Math.min(32, threat.count / 3))}px`,
          height: `${Math.max(16, Math.min(32, threat.count / 3))}px`,
          backgroundColor: colors.ring,
          animationDuration: '2s',
          animationDelay: `${pulseDelay}s`,
          transform: 'translate(-50%, -50%)',
          left: '50%',
          top: '50%',
        }}
      />

      {/* Middle glow */}
      <div
        className="absolute rounded-full"
        style={{
          width: `${Math.max(12, Math.min(24, threat.count / 4))}px`,
          height: `${Math.max(12, Math.min(24, threat.count / 4))}px`,
          backgroundColor: colors.glow,
          filter: 'blur(4px)',
          transform: 'translate(-50%, -50%)',
          left: '50%',
          top: '50%',
        }}
      />

      {/* Core marker */}
      <div
        className="relative rounded-full shadow-lg transition-transform duration-200 group-hover:scale-125"
        style={{
          width: `${Math.max(8, Math.min(16, threat.count / 5))}px`,
          height: `${Math.max(8, Math.min(16, threat.count / 5))}px`,
          backgroundColor: colors.primary,
          boxShadow: `0 0 12px ${colors.glow}`,
        }}
      />

      {/* Tooltip */}
      {isActive && (
        <div
          className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-card border border-border rounded-lg shadow-xl whitespace-nowrap z-50"
          style={{
            animation: 'fade-in 0.2s ease-out',
          }}
        >
          <div className="flex items-center gap-2 mb-1">
            <MapPin className="w-3 h-3" style={{ color: colors.primary }} />
            <span className="text-sm font-medium">{threat.country}</span>
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Zap className="w-3 h-3" />
            <span>{threat.count} active threats</span>
          </div>
          <Badge
            className="mt-1 text-2xs"
            style={{
              backgroundColor: `${colors.primary}20`,
              color: colors.primary,
              borderColor: `${colors.primary}40`,
            }}
          >
            {threat.threatLevel.toUpperCase()}
          </Badge>
          {/* Tooltip arrow */}
          <div
            className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent"
            style={{ borderTopColor: 'hsl(var(--border))' }}
          />
        </div>
      )}
    </div>
  );
}

interface AttackLineProps {
  from: { x: number; y: number };
  to: { x: number; y: number };
  color: string;
  delay: number;
}

function AttackLine({ from, to, color, delay }: AttackLineProps) {
  return (
    <svg
      className="absolute inset-0 pointer-events-none"
      style={{ width: '100%', height: '100%' }}
    >
      <defs>
        <linearGradient id={`line-grad-${delay}`} x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor={color} stopOpacity="0" />
          <stop offset="50%" stopColor={color} stopOpacity="0.8" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <line
        x1={`${from.x}%`}
        y1={`${from.y}%`}
        x2={`${to.x}%`}
        y2={`${to.y}%`}
        stroke={`url(#line-grad-${delay})`}
        strokeWidth="1.5"
        strokeDasharray="4 4"
        style={{
          animation: `dash 2s linear infinite`,
          animationDelay: `${delay}s`,
        }}
      />
      <style>{`
        @keyframes dash {
          to { stroke-dashoffset: -16; }
        }
      `}</style>
    </svg>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function ThreatGlobe3D({
  threats,
  onLocationClick,
  autoRotate = true,
  className,
}: ThreatGlobe3DProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [rotation, setRotation] = useState({ x: 15, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [activeMarker, setActiveMarker] = useState<string | null>(null);
  const dragStart = useRef({ x: 0, y: 0, rotX: 0, rotY: 0 });

  // Auto-rotation effect
  useEffect(() => {
    if (!autoRotate || isDragging) return;

    const interval = setInterval(() => {
      setRotation(prev => ({
        ...prev,
        y: (prev.y + 0.3) % 360,
      }));
    }, 50);

    return () => clearInterval(interval);
  }, [autoRotate, isDragging]);

  // Mouse drag handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    setIsDragging(true);
    dragStart.current = {
      x: e.clientX,
      y: e.clientY,
      rotX: rotation.x,
      rotY: rotation.y,
    };
  }, [rotation]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!isDragging) return;

    const deltaX = e.clientX - dragStart.current.x;
    const deltaY = e.clientY - dragStart.current.y;

    setRotation({
      x: Math.max(-60, Math.min(60, dragStart.current.rotX - deltaY * 0.3)),
      y: dragStart.current.rotY + deltaX * 0.5,
    });
  }, [isDragging]);

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  // Calculate marker positions and depths
  const markerData = useMemo(() => {
    return threats.map(threat => {
      const position = latLngToPosition(threat.lat, threat.lng, 100);
      const depth = calculateDepthOffset(rotation, position.x, position.y);
      return { threat, position, depth };
    });
  }, [threats, rotation]);

  // Calculate center point (target location)
  const centerPoint = { x: 50, y: 50 };

  // Stats summary
  const stats = useMemo(() => {
    const total = threats.reduce((sum, t) => sum + t.count, 0);
    const critical = threats.filter(t => t.threatLevel === 'critical').length;
    const high = threats.filter(t => t.threatLevel === 'high').length;
    return { total, critical, high };
  }, [threats]);

  return (
    <Card className={cn('h-full overflow-hidden', className)}>
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div className="flex items-center gap-2">
          <div className="p-2 rounded-lg bg-primary/10">
            <Globe className="w-5 h-5 text-primary" />
          </div>
          <div>
            <CardTitle className="text-base">Global Threat Monitor</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Real-time attack vectors
            </p>
          </div>
        </div>
        <Badge variant="destructive" className="animate-pulse">
          {stats.total} Active
        </Badge>
      </CardHeader>

      <CardContent className="pt-0">
        {/* 3D Globe Container */}
        <div
          ref={containerRef}
          className="relative h-[280px] rounded-lg overflow-hidden cursor-grab active:cursor-grabbing select-none"
          style={{
            perspective: '1000px',
            perspectiveOrigin: '50% 50%',
            background: 'linear-gradient(180deg, hsl(var(--muted)) 0%, hsl(var(--background)) 100%)',
          }}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
        >
          {/* Background stars/noise */}
          <div
            className="absolute inset-0 opacity-30"
            style={{
              backgroundImage: `radial-gradient(1px 1px at 20px 30px, hsl(var(--primary)) 1px, transparent 0),
                               radial-gradient(1px 1px at 40px 70px, hsl(var(--primary)) 1px, transparent 0),
                               radial-gradient(1px 1px at 50px 160px, hsl(var(--primary)) 1px, transparent 0),
                               radial-gradient(1px 1px at 90px 40px, hsl(var(--primary)) 1px, transparent 0),
                               radial-gradient(1px 1px at 130px 80px, hsl(var(--primary)) 1px, transparent 0),
                               radial-gradient(1px 1px at 160px 120px, hsl(var(--primary)) 1px, transparent 0)`,
              backgroundSize: '200px 200px',
            }}
          />

          {/* Flat World Map with 3D effect */}
          <div
            className="absolute inset-4"
            style={{
              transformStyle: 'preserve-3d',
              transform: `perspective(800px) rotateX(${rotation.x * 0.3}deg)`,
              transition: isDragging ? 'none' : 'transform 0.1s ease-out',
            }}
          >
            {/* Map background */}
            <div
              className="absolute inset-0 rounded-lg"
              style={{
                background: `
                  linear-gradient(180deg,
                    hsl(var(--primary) / 0.05) 0%,
                    hsl(var(--primary) / 0.1) 50%,
                    hsl(var(--primary) / 0.05) 100%)
                `,
                border: '1px solid hsl(var(--primary) / 0.2)',
              }}
            />

            {/* Grid lines */}
            <svg className="absolute inset-0 opacity-30" viewBox="0 0 100 50" preserveAspectRatio="none">
              {/* Latitude lines */}
              {[10, 20, 30, 40].map(y => (
                <line
                  key={`lat-${y}`}
                  x1="0" y1={y} x2="100" y2={y}
                  stroke="hsl(var(--primary))"
                  strokeWidth="0.2"
                  strokeDasharray="2 2"
                />
              ))}
              {/* Longitude lines */}
              {[10, 20, 30, 40, 50, 60, 70, 80, 90].map(x => (
                <line
                  key={`lng-${x}`}
                  x1={x} y1="0" x2={x} y2="50"
                  stroke="hsl(var(--primary))"
                  strokeWidth="0.2"
                  strokeDasharray="2 2"
                />
              ))}
            </svg>

            {/* World Map SVG - Main visual */}
            <div
              className="absolute inset-0 text-primary"
              dangerouslySetInnerHTML={{ __html: WORLD_MAP_SVG }}
            />
          </div>

          {/* Attack lines (connecting threats to center) */}
          {markerData
            .filter(({ depth }) => depth > 0.3)
            .slice(0, 5)
            .map(({ threat, position }, i) => (
              <AttackLine
                key={`line-${threat.id}`}
                from={position}
                to={centerPoint}
                color={THREAT_COLORS[threat.threatLevel].primary}
                delay={i * 0.4}
              />
            ))}

          {/* Threat markers */}
          {markerData.map(({ threat, position, depth }) => (
            <GlobeMarker
              key={threat.id}
              threat={threat}
              position={position}
              depth={depth}
              isActive={activeMarker === threat.id}
              onClick={() => onLocationClick?.(threat)}
              onHover={(active) => setActiveMarker(active ? threat.id : null)}
            />
          ))}

          {/* Center target indicator */}
          <div
            className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none"
            style={{ zIndex: 50 }}
          >
            <div className="relative">
              <div
                className="absolute -inset-4 rounded-full border-2 border-dashed animate-spin"
                style={{
                  borderColor: 'hsl(var(--primary))',
                  opacity: 0.3,
                  animationDuration: '20s',
                }}
              />
              <div
                className="absolute -inset-2 rounded-full"
                style={{
                  background: 'radial-gradient(circle, hsl(var(--primary)) 0%, transparent 70%)',
                  opacity: 0.3,
                }}
              />
              <Shield className="w-6 h-6 text-primary" />
            </div>
          </div>

          {/* Scan line effect */}
          <div
            className="absolute inset-0 pointer-events-none"
            style={{
              background: 'linear-gradient(0deg, transparent 0%, hsl(var(--primary) / 0.1) 50%, transparent 100%)',
              backgroundSize: '100% 200%',
              animation: 'scan 4s linear infinite',
            }}
          />
          <style>{`
            @keyframes scan {
              0% { background-position: 0% 200%; }
              100% { background-position: 0% -100%; }
            }
          `}</style>
        </div>

        {/* Top threat sources */}
        <div className="mt-4 space-y-2">
          <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
            <span className="flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              Top Threat Sources
            </span>
            <span>{threats.length} origins tracked</span>
          </div>

          {threats
            .sort((a, b) => b.count - a.count)
            .slice(0, 4)
            .map((threat, i) => {
              const colors = THREAT_COLORS[threat.threatLevel];
              const maxCount = Math.max(...threats.map(t => t.count));
              const percentage = (threat.count / maxCount) * 100;

              return (
                <div
                  key={threat.id}
                  className="relative flex items-center justify-between p-2 rounded-lg bg-muted/30 overflow-hidden cursor-pointer hover:bg-muted/50 transition-colors"
                  onClick={() => onLocationClick?.(threat)}
                >
                  {/* Progress bar background */}
                  <div
                    className="absolute left-0 top-0 bottom-0 opacity-20"
                    style={{
                      width: `${percentage}%`,
                      backgroundColor: colors.primary,
                      transition: 'width 0.3s ease-out',
                    }}
                  />

                  <div className="relative flex items-center gap-2">
                    <span className="text-xs text-muted-foreground w-4 font-mono">
                      #{i + 1}
                    </span>
                    <div
                      className="w-2 h-2 rounded-full"
                      style={{ backgroundColor: colors.primary }}
                    />
                    <span className="text-sm font-medium">{threat.country}</span>
                  </div>

                  <div className="relative flex items-center gap-2">
                    <Badge
                      variant="outline"
                      className="text-2xs"
                      style={{
                        color: colors.primary,
                        borderColor: `${colors.primary}40`,
                      }}
                    >
                      {threat.threatLevel}
                    </Badge>
                    <span
                      className="text-sm font-mono font-medium"
                      style={{ color: colors.primary }}
                    >
                      {threat.count}
                    </span>
                  </div>
                </div>
              );
            })}
        </div>
      </CardContent>
    </Card>
  );
}

// ============================================================================
// Default Export with Sample Data
// ============================================================================

export const sampleThreatLocations: ThreatLocation[] = [
  { id: '1', lat: 37.1, lng: -95.7, threatLevel: 'critical', count: 145, country: 'United States' },
  { id: '2', lat: 35.9, lng: 104.2, threatLevel: 'high', count: 89, country: 'China' },
  { id: '3', lat: 61.5, lng: 105.3, threatLevel: 'critical', count: 67, country: 'Russia' },
  { id: '4', lat: 51.2, lng: 10.5, threatLevel: 'medium', count: 45, country: 'Germany' },
  { id: '5', lat: -14.2, lng: -51.9, threatLevel: 'low', count: 38, country: 'Brazil' },
  { id: '6', lat: 20.6, lng: 78.9, threatLevel: 'medium', count: 32, country: 'India' },
  { id: '7', lat: 35.9, lng: 127.8, threatLevel: 'high', count: 28, country: 'South Korea' },
  { id: '8', lat: 52.1, lng: 5.3, threatLevel: 'low', count: 24, country: 'Netherlands' },
  { id: '9', lat: 36.2, lng: 138.3, threatLevel: 'medium', count: 19, country: 'Japan' },
  { id: '10', lat: 55.4, lng: -3.4, threatLevel: 'low', count: 15, country: 'United Kingdom' },
];

export default ThreatGlobe3D;
