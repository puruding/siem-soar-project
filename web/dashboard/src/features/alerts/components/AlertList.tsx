import { useState, useEffect, useCallback, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Search,
  Filter,
  RefreshCw,
  CheckSquare,
  XSquare,
  AlertTriangle,
  ChevronRight,
  Loader2,
  Plus,
  Brain,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import { AlertDetail } from './AlertDetail';
import { useToast } from '@/components/ui/toaster';
import { useUEBAStore, ANOMALY_TYPES, UEBA_TO_MITRE } from '@/features/ueba';

// MITRE tactic names for UEBA mapping
const UEBA_MITRE_TACTICS: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0004: 'Privilege Escalation',
  TA0006: 'Credential Access',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
};

interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'closed';
  source: string;
  target: string;
  timestamp: Date;
  tactic?: string;
  technique?: string;
  // UEBA specific data
  uebaData?: {
    anomalyType: string;
    score: number;
    entityType: 'user' | 'host' | 'ip';
  };
}

// MITRE tactic mapping
const MITRE_TACTICS: Record<string, string> = {
  TA0001: 'Initial Access',
  TA0002: 'Execution',
  TA0003: 'Persistence',
  TA0004: 'Privilege Escalation',
  TA0005: 'Defense Evasion',
  TA0006: 'Credential Access',
  TA0007: 'Discovery',
  TA0008: 'Lateral Movement',
  TA0009: 'Collection',
  TA0010: 'Exfiltration',
  TA0011: 'Command and Control',
  TA0040: 'Impact',
};

const statusStyles: Record<string, string> = {
  new: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  acknowledged: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

interface CreateAlertForm {
  title: string;
  description: string;
  severity: Alert['severity'];
  source: string;
  target: string;
  tactic: string;
  technique: string;
}

const initialFormState: CreateAlertForm = {
  title: '',
  description: '',
  severity: 'medium',
  source: '',
  target: '',
  tactic: '',
  technique: '',
};

export function AlertList() {
  const { toast } = useToast();
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  const [createForm, setCreateForm] = useState<CreateAlertForm>(initialFormState);

  // Get UEBA alerts from shared store (select raw alerts and convert locally)
  const uebaAlertsRaw = useUEBAStore((state) => state.alerts);

  // Convert UEBA alerts to standard Alert format
  const uebaAlerts = useMemo((): Alert[] => {
    if (!uebaAlertsRaw || !Array.isArray(uebaAlertsRaw)) {
      return [];
    }
    return uebaAlertsRaw.map((alert) => {
      const tacticId = UEBA_TO_MITRE[alert.anomalyType];
      return {
        id: alert.id,
        title: alert.title || `${ANOMALY_TYPES[alert.anomalyType] || alert.anomalyType} - ${alert.entityId}`,
        description: alert.explanation,
        severity: alert.severity as Alert['severity'],
        status: alert.status as Alert['status'],
        source: 'UEBA',
        target: alert.entityId,
        timestamp: new Date(alert.detectedAt),
        tactic: tacticId ? UEBA_MITRE_TACTICS[tacticId] : undefined,
        technique: undefined,
        uebaData: {
          anomalyType: alert.anomalyType,
          score: alert.score,
          entityType: alert.entityType,
        },
      };
    });
  }, [uebaAlertsRaw]);

  // Fetch alerts from API
  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/v1/alerts');
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      const data = await response.json();

      // Map API response to Alert interface
      const mappedAlerts: Alert[] = (data.alerts || []).map((alert: any) => {
        // Extract target from fields
        let target = alert.source_type || 'Unknown';
        if (alert.fields?.user) {
          target = alert.fields.user;
        } else if (alert.fields?.source_ip) {
          target = alert.fields.source_ip;
        } else if (alert.matched_fields) {
          const firstKey = Object.keys(alert.matched_fields)[0];
          if (firstKey) {
            target = String(alert.matched_fields[firstKey]);
          }
        }

        // Build description
        let description = `Alert from ${alert.source_type}`;
        if (alert.matched_fields && Object.keys(alert.matched_fields).length > 0) {
          description += `: ${JSON.stringify(alert.matched_fields)}`;
        }

        // Get tactic name
        let tactic: string | undefined;
        if (alert.mitre_tactics && alert.mitre_tactics.length > 0) {
          const tacticId = alert.mitre_tactics[0];
          tactic = MITRE_TACTICS[tacticId] || tacticId;
        }

        return {
          id: alert.id || alert.alert_id,
          title: alert.rule_name || alert.title || 'Unknown Alert',
          description,
          severity: (alert.severity || 'medium').toLowerCase() as Alert['severity'],
          status: (alert.status || 'new').toLowerCase() as Alert['status'],
          source: alert.source || 'Detection',
          target,
          timestamp: new Date(alert.timestamp),
          tactic,
          technique: alert.mitre_techniques?.[0],
        };
      });

      setAlerts(mappedAlerts);
    } catch (err) {
      console.error('Failed to fetch alerts:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch alerts');
    } finally {
      setLoading(false);
    }
  };

  // Initial fetch
  useEffect(() => {
    fetchAlerts();
  }, []);

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(fetchAlerts, 10000);
    return () => clearInterval(interval);
  }, []);

  // Merge alerts from Detection API and UEBA store
  const allAlerts = useMemo(() => {
    const safeAlerts = Array.isArray(alerts) ? alerts : [];
    const safeUebaAlerts = Array.isArray(uebaAlerts) ? uebaAlerts : [];
    const combined = [...safeAlerts, ...safeUebaAlerts];
    // Remove duplicates by ID and sort by timestamp (newest first)
    const uniqueMap = new Map<string, Alert>();
    combined.forEach((alert) => {
      if (alert && alert.id && !uniqueMap.has(alert.id)) {
        uniqueMap.set(alert.id, alert);
      }
    });
    return Array.from(uniqueMap.values()).sort(
      (a, b) => (b.timestamp?.getTime() || 0) - (a.timestamp?.getTime() || 0)
    );
  }, [alerts, uebaAlerts]);

  const filteredAlerts = allAlerts.filter((alert) => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter)
      return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
    if (sourceFilter !== 'all' && alert.source !== sourceFilter) return false;
    if (
      searchQuery &&
      !alert.title.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !alert.id.toLowerCase().includes(searchQuery.toLowerCase())
    )
      return false;
    return true;
  });

  const toggleAlertSelection = (alertId: string) => {
    const newSelection = new Set(selectedAlerts);
    if (newSelection.has(alertId)) {
      newSelection.delete(alertId);
    } else {
      newSelection.add(alertId);
    }
    setSelectedAlerts(newSelection);
  };

  const selectAll = () => {
    if (selectedAlerts.size === filteredAlerts.length) {
      setSelectedAlerts(new Set());
    } else {
      setSelectedAlerts(new Set(filteredAlerts.map((a) => a.id)));
    }
  };

  const handleCreateAlert = useCallback(async () => {
    if (!createForm.title.trim()) {
      toast({
        title: 'Validation Error',
        description: 'Alert title is required.',
        variant: 'destructive',
      });
      return;
    }

    setIsCreating(true);
    try {
      // Try to call API first
      const response = await fetch('/api/v1/alerts', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          rule_name: createForm.title,
          description: createForm.description,
          severity: createForm.severity,
          source_type: createForm.source || 'Manual',
          fields: {
            target: createForm.target,
          },
          mitre_tactics: createForm.tactic ? [createForm.tactic] : [],
          mitre_techniques: createForm.technique ? [createForm.technique] : [],
          status: 'new',
        }),
      });

      if (response.ok) {
        const data = await response.json();
        toast({
          title: 'Alert Created',
          description: `Alert "${createForm.title}" has been created successfully.`,
        });
        setIsCreateDialogOpen(false);
        setCreateForm(initialFormState);
        fetchAlerts(); // Refresh the list
      } else {
        throw new Error(`HTTP ${response.status}`);
      }
    } catch (err) {
      // If API fails, create locally (mock mode)
      const newAlert: Alert = {
        id: `manual-${Date.now()}`,
        title: createForm.title,
        description: createForm.description || 'Manually created alert',
        severity: createForm.severity,
        status: 'new',
        source: createForm.source || 'Manual',
        target: createForm.target || 'N/A',
        timestamp: new Date(),
        tactic: createForm.tactic ? MITRE_TACTICS[createForm.tactic] || createForm.tactic : undefined,
        technique: createForm.technique || undefined,
      };

      setAlerts((prev) => [newAlert, ...prev]);
      toast({
        title: 'Alert Created (Local)',
        description: `Alert "${createForm.title}" has been created locally.`,
      });
      setIsCreateDialogOpen(false);
      setCreateForm(initialFormState);
    } finally {
      setIsCreating(false);
    }
  }, [createForm, toast]);

  const handleFormChange = (field: keyof CreateAlertForm, value: string) => {
    setCreateForm((prev) => ({ ...prev, [field]: value }));
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Security Alerts
          </h1>
          <p className="text-muted-foreground">
            Monitor and investigate security events
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={fetchAlerts}
            disabled={loading}
          >
            <RefreshCw className={cn("w-4 h-4 mr-2", loading && "animate-spin")} />
            Refresh
          </Button>
          <Button size="sm" onClick={() => setIsCreateDialogOpen(true)}>
            <Plus className="w-4 h-4 mr-2" />
            Create Alert
          </Button>
        </div>
      </div>

      <div className="flex gap-6">
        {/* Main content */}
        <div className="flex-1">
          <Card>
            <CardHeader className="pb-4">
              {/* Filters */}
              <div className="flex items-center gap-4">
                <div className="relative flex-1 max-w-sm">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search alerts..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <Select value={severityFilter} onValueChange={setSeverityFilter}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Severity</SelectItem>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="new">New</SelectItem>
                    <SelectItem value="acknowledged">Acknowledged</SelectItem>
                    <SelectItem value="investigating">Investigating</SelectItem>
                    <SelectItem value="resolved">Resolved</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={sourceFilter} onValueChange={setSourceFilter}>
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Source" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Sources</SelectItem>
                    <SelectItem value="Detection">Detection</SelectItem>
                    <SelectItem value="UEBA">UEBA / ML</SelectItem>
                    <SelectItem value="Manual">Manual</SelectItem>
                  </SelectContent>
                </Select>
                <Button variant="outline" size="icon">
                  <Filter className="w-4 h-4" />
                </Button>
              </div>

              {/* Bulk actions */}
              {selectedAlerts.size > 0 && (
                <div className="flex items-center gap-4 pt-4 border-t border-border mt-4">
                  <span className="text-sm text-muted-foreground">
                    {selectedAlerts.size} selected
                  </span>
                  <Button variant="outline" size="sm">
                    <CheckSquare className="w-4 h-4 mr-2" />
                    Acknowledge
                  </Button>
                  <Button variant="outline" size="sm">
                    <XSquare className="w-4 h-4 mr-2" />
                    Close
                  </Button>
                  <Button variant="outline" size="sm">Create Case</Button>
                </div>
              )}
            </CardHeader>
            <CardContent>
              {loading && alerts.length === 0 ? (
                <div className="flex items-center justify-center h-64">
                  <div className="flex flex-col items-center gap-3">
                    <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">Loading alerts...</p>
                  </div>
                </div>
              ) : error ? (
                <div className="flex items-center justify-center h-64">
                  <div className="flex flex-col items-center gap-3">
                    <AlertTriangle className="w-8 h-8 text-destructive" />
                    <p className="text-sm text-destructive font-medium">Error loading alerts</p>
                    <p className="text-xs text-muted-foreground">{error}</p>
                    <Button variant="outline" size="sm" onClick={fetchAlerts}>
                      <RefreshCw className="w-4 h-4 mr-2" />
                      Retry
                    </Button>
                  </div>
                </div>
              ) : filteredAlerts.length === 0 ? (
                <div className="flex items-center justify-center h-64">
                  <div className="flex flex-col items-center gap-3">
                    <AlertTriangle className="w-8 h-8 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">No alerts found</p>
                    <p className="text-xs text-muted-foreground">
                      {alerts.length === 0
                        ? 'Send log messages through the pipeline to generate alerts'
                        : 'Try adjusting your filters'}
                    </p>
                  </div>
                </div>
              ) : (
                <ScrollArea className="h-[calc(100vh-320px)]">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-[40px]">
                          <input
                            type="checkbox"
                            checked={
                              selectedAlerts.size === filteredAlerts.length &&
                              filteredAlerts.length > 0
                            }
                            onChange={selectAll}
                            className="rounded border-border"
                          />
                        </TableHead>
                        <TableHead className="w-[100px]">Severity</TableHead>
                        <TableHead>Alert</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Source</TableHead>
                        <TableHead>Target</TableHead>
                        <TableHead>Time</TableHead>
                        <TableHead className="w-[40px]"></TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {filteredAlerts.map((alert) => (
                      <TableRow
                        key={alert.id}
                        className={cn(
                          'cursor-pointer',
                          selectedAlert?.id === alert.id && 'bg-primary/5'
                        )}
                        onClick={() => setSelectedAlert(alert)}
                      >
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            checked={selectedAlerts.has(alert.id)}
                            onChange={() => toggleAlertSelection(alert.id)}
                            className="rounded border-border"
                          />
                        </TableCell>
                        <TableCell>
                          <Badge variant={alert.severity}>
                            {alert.severity.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div>
                            <p className="font-medium">{alert.title}</p>
                            <p className="text-xs text-muted-foreground">
                              {alert.id}
                            </p>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={cn(
                              'capitalize',
                              statusStyles[alert.status]
                            )}
                          >
                            {alert.status}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <span className="text-sm">{alert.source}</span>
                            {alert.source === 'UEBA' && (
                              <Badge variant="outline" className="text-xs bg-primary/10">
                                <Brain className="w-3 h-3 mr-1" />
                                ML
                              </Badge>
                            )}
                          </div>
                        </TableCell>
                        <TableCell className="font-mono text-sm">
                          {alert.target}
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">
                          {formatRelativeTime(alert.timestamp)}
                        </TableCell>
                        <TableCell>
                          <ChevronRight className="w-4 h-4 text-muted-foreground" />
                        </TableCell>
                      </TableRow>
                    ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Detail panel */}
        {selectedAlert && (
          <AlertDetail
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
            onStatusChange={(alertId, newStatus) => {
              // Update alert status in local state
              setAlerts(prev =>
                prev.map(a =>
                  a.id === alertId ? { ...a, status: newStatus as Alert['status'] } : a
                )
              );
              // Update selected alert if it's the one being changed
              if (selectedAlert.id === alertId) {
                setSelectedAlert(prev =>
                  prev ? { ...prev, status: newStatus as Alert['status'] } : null
                );
              }
            }}
            onAlertSelect={(alertId) => {
              // Find and select the related alert
              const relatedAlert = alerts.find(a => a.id === alertId);
              if (relatedAlert) {
                setSelectedAlert(relatedAlert);
              }
            }}
          />
        )}
      </div>

      {/* Create Alert Dialog */}
      <Dialog open={isCreateDialogOpen} onOpenChange={setIsCreateDialogOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Create New Alert</DialogTitle>
            <DialogDescription>
              Create a manual security alert for investigation or tracking purposes.
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="alert-title">Alert Title *</Label>
              <Input
                id="alert-title"
                placeholder="e.g., Suspicious Login Activity"
                value={createForm.title}
                onChange={(e) => handleFormChange('title', e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="alert-description">Description</Label>
              <Textarea
                id="alert-description"
                placeholder="Describe the security event or concern..."
                value={createForm.description}
                onChange={(e) => handleFormChange('description', e.target.value)}
                rows={3}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="alert-severity">Severity *</Label>
                <Select
                  value={createForm.severity}
                  onValueChange={(value) => handleFormChange('severity', value)}
                >
                  <SelectTrigger id="alert-severity">
                    <SelectValue placeholder="Select severity" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">
                      <div className="flex items-center gap-2">
                        <Badge variant="critical" className="w-16 justify-center">CRITICAL</Badge>
                      </div>
                    </SelectItem>
                    <SelectItem value="high">
                      <div className="flex items-center gap-2">
                        <Badge variant="high" className="w-16 justify-center">HIGH</Badge>
                      </div>
                    </SelectItem>
                    <SelectItem value="medium">
                      <div className="flex items-center gap-2">
                        <Badge variant="medium" className="w-16 justify-center">MEDIUM</Badge>
                      </div>
                    </SelectItem>
                    <SelectItem value="low">
                      <div className="flex items-center gap-2">
                        <Badge variant="low" className="w-16 justify-center">LOW</Badge>
                      </div>
                    </SelectItem>
                    <SelectItem value="info">
                      <div className="flex items-center gap-2">
                        <Badge variant="info" className="w-16 justify-center">INFO</Badge>
                      </div>
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="alert-source">Source</Label>
                <Input
                  id="alert-source"
                  placeholder="e.g., EDR, Firewall, Manual"
                  value={createForm.source}
                  onChange={(e) => handleFormChange('source', e.target.value)}
                />
              </div>
            </div>
            <div className="grid gap-2">
              <Label htmlFor="alert-target">Target (IP/Host/User)</Label>
              <Input
                id="alert-target"
                placeholder="e.g., 192.168.1.100 or john.doe"
                value={createForm.target}
                onChange={(e) => handleFormChange('target', e.target.value)}
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="alert-tactic">MITRE Tactic</Label>
                <Select
                  value={createForm.tactic || 'none'}
                  onValueChange={(value) => handleFormChange('tactic', value === 'none' ? '' : value)}
                >
                  <SelectTrigger id="alert-tactic">
                    <SelectValue placeholder="Select tactic" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="none">None</SelectItem>
                    {Object.entries(MITRE_TACTICS).map(([id, name]) => (
                      <SelectItem key={id} value={id}>
                        {id}: {name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-2">
                <Label htmlFor="alert-technique">MITRE Technique</Label>
                <Input
                  id="alert-technique"
                  placeholder="e.g., T1078"
                  value={createForm.technique}
                  onChange={(e) => handleFormChange('technique', e.target.value)}
                />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setIsCreateDialogOpen(false);
                setCreateForm(initialFormState);
              }}
              disabled={isCreating}
            >
              Cancel
            </Button>
            <Button onClick={handleCreateAlert} disabled={isCreating}>
              {isCreating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Creating...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4 mr-2" />
                  Create Alert
                </>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
