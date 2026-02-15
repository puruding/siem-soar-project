import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
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
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Search,
  Filter,
  RefreshCw,
  CheckSquare,
  XSquare,
  AlertTriangle,
  ChevronRight,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import { AlertDetail } from './AlertDetail';

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
}

const mockAlerts: Alert[] = [
  {
    id: 'ALT-2024-001',
    title: 'Ransomware Detection - LockBit 3.0',
    description:
      'Ransomware encryption behavior detected on endpoint. Immediate action required.',
    severity: 'critical',
    status: 'new',
    source: 'EDR',
    target: 'DESKTOP-A1B2C3',
    timestamp: new Date(Date.now() - 1000 * 60 * 2),
    tactic: 'Impact',
    technique: 'T1486',
  },
  {
    id: 'ALT-2024-002',
    title: 'Suspicious PowerShell Execution',
    description:
      'Encoded PowerShell command execution detected with network callback.',
    severity: 'high',
    status: 'new',
    source: 'SIEM',
    target: 'SERVER-WEB-01',
    timestamp: new Date(Date.now() - 1000 * 60 * 15),
    tactic: 'Execution',
    technique: 'T1059.001',
  },
  {
    id: 'ALT-2024-003',
    title: 'Brute Force Attack Detected',
    description: 'Multiple failed authentication attempts from single IP.',
    severity: 'high',
    status: 'acknowledged',
    source: 'Firewall',
    target: '192.168.1.100',
    timestamp: new Date(Date.now() - 1000 * 60 * 32),
    tactic: 'Credential Access',
    technique: 'T1110',
  },
  {
    id: 'ALT-2024-004',
    title: 'Data Exfiltration Attempt',
    description: 'Large data transfer to external cloud storage detected.',
    severity: 'critical',
    status: 'investigating',
    source: 'DLP',
    target: 'user@company.com',
    timestamp: new Date(Date.now() - 1000 * 60 * 45),
    tactic: 'Exfiltration',
    technique: 'T1567',
  },
  {
    id: 'ALT-2024-005',
    title: 'Unauthorized API Access',
    description: 'Unauthorized access attempt to admin API endpoint.',
    severity: 'medium',
    status: 'new',
    source: 'API Gateway',
    target: '/api/admin/users',
    timestamp: new Date(Date.now() - 1000 * 60 * 58),
    tactic: 'Initial Access',
    technique: 'T1190',
  },
  {
    id: 'ALT-2024-006',
    title: 'Privilege Escalation Detected',
    description: 'User elevated privileges using known vulnerability.',
    severity: 'high',
    status: 'new',
    source: 'SIEM',
    target: 'DC-01',
    timestamp: new Date(Date.now() - 1000 * 60 * 72),
    tactic: 'Privilege Escalation',
    technique: 'T1068',
  },
  {
    id: 'ALT-2024-007',
    title: 'Malicious Domain Connection',
    description: 'Connection to known C2 domain detected.',
    severity: 'critical',
    status: 'new',
    source: 'DNS',
    target: 'LAPTOP-XYZ123',
    timestamp: new Date(Date.now() - 1000 * 60 * 85),
    tactic: 'Command and Control',
    technique: 'T1071',
  },
  {
    id: 'ALT-2024-008',
    title: 'Port Scan Detected',
    description: 'Horizontal port scan from internal host.',
    severity: 'medium',
    status: 'resolved',
    source: 'IDS',
    target: '10.0.0.50',
    timestamp: new Date(Date.now() - 1000 * 60 * 120),
    tactic: 'Discovery',
    technique: 'T1046',
  },
];

const statusStyles: Record<string, string> = {
  new: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  acknowledged: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

export function AlertList() {
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [selectedAlerts, setSelectedAlerts] = useState<Set<string>>(new Set());
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const filteredAlerts = mockAlerts.filter((alert) => {
    if (severityFilter !== 'all' && alert.severity !== severityFilter)
      return false;
    if (statusFilter !== 'all' && alert.status !== statusFilter) return false;
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
          <Button variant="outline" size="sm">
            <RefreshCw className="w-4 h-4 mr-2" />
            Refresh
          </Button>
          <Button size="sm">
            <AlertTriangle className="w-4 h-4 mr-2" />
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
                        <TableCell className="text-sm">{alert.source}</TableCell>
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
            </CardContent>
          </Card>
        </div>

        {/* Detail panel */}
        {selectedAlert && (
          <AlertDetail
            alert={selectedAlert}
            onClose={() => setSelectedAlert(null)}
          />
        )}
      </div>
    </div>
  );
}
