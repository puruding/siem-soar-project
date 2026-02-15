import { useState, useCallback } from 'react';
import { StatsCard } from './StatsCard';
import { AlertTrend } from './AlertTrend';
import { TopAlerts } from './TopAlerts';
import { RecentCases } from './RecentCases';
import { useDashboardData } from '../hooks/useDashboardData';

// 3D Components
import { ThreatGlobe3D, sampleThreatLocations, type ThreatLocation } from './ThreatGlobe3D';
import { NetworkTopology3D, sampleNetworkNodes, type NetworkNode } from './NetworkTopology3D';
import { DatacenterFloor3D, sampleServerRacks, type ServerRack } from './DatacenterFloor3D';
import { MetricChart3D, sampleBarData, samplePieData } from './MetricChart3D';

import {
  AlertTriangle,
  Shield,
  Activity,
  FolderKanban,
  Clock,
  TrendingUp,
  Layers,
  Eye,
  EyeOff,
} from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';

// ============================================================================
// Dashboard Layout Component
// ============================================================================

export function Dashboard() {
  const { stats, isLoading } = useDashboardData();
  const [show3DViews, setShow3DViews] = useState(true);
  const [selectedThreat, setSelectedThreat] = useState<ThreatLocation | null>(null);
  const [selectedNode, setSelectedNode] = useState<NetworkNode | null>(null);
  const [selectedRack, setSelectedRack] = useState<ServerRack | null>(null);

  // Handlers for 3D component interactions
  const handleThreatClick = useCallback((threat: ThreatLocation) => {
    setSelectedThreat(threat);
    // In production, this would open a detail panel or trigger an investigation
    console.log('Threat selected:', threat);
  }, []);

  const handleNodeClick = useCallback((node: NetworkNode) => {
    setSelectedNode(node);
    console.log('Network node selected:', node);
  }, []);

  const handleRackClick = useCallback((rack: ServerRack) => {
    setSelectedRack(rack);
    console.log('Rack selected:', rack);
  }, []);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight flex items-center gap-2">
            Security Operations Center
            <Badge variant="outline" className="ml-2 text-xs font-normal">
              IGLOO Dashboard
            </Badge>
          </h1>
          <p className="text-muted-foreground">
            Real-time threat monitoring and incident response
          </p>
        </div>
        <div className="flex items-center gap-4">
          {/* 3D View Toggle */}
          <button
            onClick={() => setShow3DViews(!show3DViews)}
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-colors text-sm',
              show3DViews
                ? 'bg-primary/10 border-primary/30 text-primary'
                : 'bg-muted border-border text-muted-foreground hover:bg-muted/80'
            )}
          >
            {show3DViews ? (
              <>
                <Eye className="w-4 h-4" />
                3D Views
              </>
            ) : (
              <>
                <EyeOff className="w-4 h-4" />
                3D Views
              </>
            )}
          </button>

          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="w-4 h-4" />
            <span>Last updated: Just now</span>
          </div>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard
          title="Active Alerts"
          value={stats.activeAlerts}
          change={12.5}
          changeType="increase"
          icon={AlertTriangle}
          iconColor="text-threat-critical"
          loading={isLoading}
        />
        <StatsCard
          title="Events Per Second"
          value={stats.eps}
          suffix="EPS"
          change={8.2}
          changeType="increase"
          icon={Activity}
          iconColor="text-primary"
          loading={isLoading}
        />
        <StatsCard
          title="Open Cases"
          value={stats.openCases}
          change={-5.3}
          changeType="decrease"
          icon={FolderKanban}
          iconColor="text-warning"
          loading={isLoading}
        />
        <StatsCard
          title="Detection Rate"
          value={stats.detectionRate}
          suffix="%"
          change={2.1}
          changeType="increase"
          icon={Shield}
          iconColor="text-success"
          loading={isLoading}
        />
      </div>

      {/* 3D Visualization Section */}
      {show3DViews && (
        <div className="space-y-6">
          {/* Section header */}
          <div className="flex items-center gap-2 pt-2">
            <Layers className="w-5 h-5 text-primary" />
            <h2 className="text-lg font-semibold">3D Infrastructure Overview</h2>
            <div className="flex-1 h-px bg-border ml-4" />
          </div>

          {/* 3D Charts Row - Alert Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <MetricChart3D
              type="3d-bar"
              data={sampleBarData}
              title="Alerts by Severity"
              height={260}
            />
            <MetricChart3D
              type="3d-pie"
              data={samplePieData}
              title="Threat Categories"
              height={260}
            />
            <div className="hidden lg:block">
              <MetricChart3D
                type="3d-area"
                data={[
                  { label: '00:00', value: 1200 },
                  { label: '04:00', value: 800 },
                  { label: '08:00', value: 2400 },
                  { label: '12:00', value: 3600 },
                  { label: '16:00', value: 4200 },
                  { label: '20:00', value: 2800 },
                  { label: '24:00', value: 1600 },
                ]}
                title="Events Timeline"
                height={260}
              />
            </div>
          </div>

          {/* Main 3D Visualizations Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* 3D Threat Globe */}
            <ThreatGlobe3D
              threats={sampleThreatLocations}
              onLocationClick={handleThreatClick}
              autoRotate={true}
            />

            {/* 3D Network Topology */}
            <NetworkTopology3D
              nodes={sampleNetworkNodes}
              onNodeClick={handleNodeClick}
            />
          </div>

          {/* Datacenter Floor View */}
          <DatacenterFloor3D
            racks={sampleServerRacks}
            onRackClick={handleRackClick}
            showHeatmap={false}
          />
        </div>
      )}

      {/* Traditional Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <AlertTrend />
        </div>
        <div>
          {/* Replaced SeverityDistribution with 3D pie when 3D is enabled */}
          {show3DViews ? (
            <MetricChart3D
              type="3d-pie"
              data={[
                { label: 'Resolved', value: 245, color: '#5CC05C' },
                { label: 'In Progress', value: 89, color: '#F79836' },
                { label: 'Pending', value: 42, color: '#DC4E41' },
                { label: 'Escalated', value: 18, color: '#7B61FF' },
              ]}
              title="Case Status"
              height={280}
            />
          ) : (
            <MetricChart3D
              type="3d-bar"
              data={sampleBarData}
              title="Severity Distribution"
              height={280}
            />
          )}
        </div>
      </div>

      {/* Alerts and Cases Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <TopAlerts />
        <RecentCases />
      </div>

      {/* MTTR and Performance */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="metric-card group hover:border-primary/30 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-muted-foreground">MTTD</h3>
            <TrendingUp className="w-4 h-4 text-success" />
          </div>
          <p className="text-3xl font-display font-bold">3.2m</p>
          <p className="text-sm text-muted-foreground mt-1">
            Mean Time to Detect
          </p>
          {/* Mini progress indicator */}
          <div className="mt-3 h-1 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-success to-primary rounded-full transition-all duration-1000"
              style={{ width: '78%' }}
            />
          </div>
        </div>

        <div className="metric-card group hover:border-primary/30 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-muted-foreground">MTTR</h3>
            <TrendingUp className="w-4 h-4 text-success" />
          </div>
          <p className="text-3xl font-display font-bold">24m</p>
          <p className="text-sm text-muted-foreground mt-1">
            Mean Time to Respond
          </p>
          <div className="mt-3 h-1 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-warning to-success rounded-full transition-all duration-1000"
              style={{ width: '65%' }}
            />
          </div>
        </div>

        <div className="metric-card group hover:border-primary/30 transition-all duration-300">
          <div className="flex items-center justify-between mb-4">
            <h3 className="font-medium text-muted-foreground">
              False Positive Rate
            </h3>
            <TrendingUp className="w-4 h-4 text-success" />
          </div>
          <p className="text-3xl font-display font-bold">4.2%</p>
          <p className="text-sm text-muted-foreground mt-1">
            Down from 12.8% last month
          </p>
          <div className="mt-3 h-1 bg-muted rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-success to-primary rounded-full transition-all duration-1000"
              style={{ width: '92%' }}
            />
          </div>
        </div>
      </div>

      {/* Selection panels (shown when items are selected from 3D views) */}
      {(selectedThreat || selectedNode || selectedRack) && (
        <div className="fixed bottom-4 right-4 z-50 bg-card border border-border rounded-lg shadow-xl p-4 max-w-sm animate-slide-up">
          <div className="flex items-center justify-between mb-2">
            <h4 className="font-semibold">Selected Item</h4>
            <button
              onClick={() => {
                setSelectedThreat(null);
                setSelectedNode(null);
                setSelectedRack(null);
              }}
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              &times;
            </button>
          </div>

          {selectedThreat && (
            <div className="space-y-2 text-sm">
              <p><strong>Country:</strong> {selectedThreat.country}</p>
              <p><strong>Threat Level:</strong> {selectedThreat.threatLevel}</p>
              <p><strong>Active Threats:</strong> {selectedThreat.count}</p>
              <p><strong>Location:</strong> {selectedThreat.lat.toFixed(2)}, {selectedThreat.lng.toFixed(2)}</p>
            </div>
          )}

          {selectedNode && (
            <div className="space-y-2 text-sm">
              <p><strong>Name:</strong> {selectedNode.name}</p>
              <p><strong>Type:</strong> {selectedNode.type}</p>
              <p><strong>Status:</strong> {selectedNode.status}</p>
              {selectedNode.metrics && (
                <>
                  <p><strong>CPU:</strong> {selectedNode.metrics.cpu}%</p>
                  <p><strong>Memory:</strong> {selectedNode.metrics.memory}%</p>
                </>
              )}
            </div>
          )}

          {selectedRack && (
            <div className="space-y-2 text-sm">
              <p><strong>Rack:</strong> {selectedRack.name}</p>
              <p><strong>Status:</strong> {selectedRack.status}</p>
              <p><strong>Servers:</strong> {selectedRack.servers.length}</p>
              {selectedRack.temperature && (
                <p><strong>Temperature:</strong> {selectedRack.temperature}°C</p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default Dashboard;
