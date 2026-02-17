import { useParams, Link } from 'react-router-dom';
import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  ArrowLeft,
  Clock,
  AlertTriangle,
  User,
  MessageSquare,
  Paperclip,
  Play,
  CheckCircle,
  Plus,
  MoreHorizontal,
  FileText,
  Link as LinkIcon,
  Target,
  Loader2,
} from 'lucide-react';
import { formatTimestamp, formatRelativeTime, cn } from '@/lib/utils';
import { CaseTimeline } from './CaseTimeline';

const statusStyles: Record<string, string> = {
  open: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  'in-progress': 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  pending: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

// Default case data (used as fallback)
const defaultCase = {
  id: 'CASE-2024-001',
  title: 'Ransomware Incident - Finance Department',
  description:
    'LockBit 3.0 ransomware detected on multiple endpoints in the finance department. Initial infection vector appears to be phishing email with malicious attachment. 5 systems affected, immediate containment required.',
  status: 'in-progress',
  severity: 'critical',
  assignee: { name: 'John Doe', initials: 'JD', email: 'john.doe@company.com' },
  alerts: 5,
  created: new Date(Date.now() - 1000 * 60 * 60 * 2),
  updated: new Date(Date.now() - 1000 * 60 * 15),
  tags: ['ransomware', 'finance', 'priority', 'lockbit'],
  impactedAssets: [
    { name: 'DESKTOP-FIN01', type: 'endpoint', status: 'infected' },
    { name: 'DESKTOP-FIN02', type: 'endpoint', status: 'infected' },
    { name: 'DESKTOP-FIN03', type: 'endpoint', status: 'contained' },
    { name: 'FILE-SRV-01', type: 'server', status: 'at-risk' },
  ],
  relatedAlerts: [
    {
      id: 'ALT-2024-001',
      title: 'Ransomware Detection',
      severity: 'critical',
    },
    {
      id: 'ALT-2024-015',
      title: 'Suspicious File Encryption',
      severity: 'high',
    },
    { id: 'ALT-2024-016', title: 'C2 Communication', severity: 'critical' },
  ],
  evidence: [
    { name: 'malware_sample.zip', type: 'file', size: '2.4 MB' },
    { name: 'network_capture.pcap', type: 'file', size: '156 MB' },
    { name: 'memory_dump.raw', type: 'file', size: '4.2 GB' },
    { name: 'Screenshot_infection.png', type: 'image', size: '1.2 MB' },
  ],
};

export function CaseDetail() {
  const { id } = useParams<{ id: string }>();
  const [caseData, setCaseData] = useState(defaultCase);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchCase = async () => {
      try {
        const response = await fetch(`/api/cases/${id}`);
        if (response.ok) {
          const data = await response.json();
          if (data.success && data.data) {
            setCaseData({
              ...data.data,
              created: new Date(data.data.created),
              updated: new Date(data.data.updated),
            });
          }
        }
      } catch (error) {
        console.warn('Failed to fetch case, using default data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchCase();
  }, [id]);

  // Use caseData instead of currentCase
  const currentCase = caseData;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Back navigation and header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Link to="/cases">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="w-5 h-5" />
            </Button>
          </Link>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <span className="text-sm text-muted-foreground font-mono">
                {currentCase.id}
              </span>
              <Badge variant={currentCase.severity as 'critical' | 'high' | 'medium' | 'low'}>
                {currentCase.severity}
              </Badge>
              <Badge
                variant="outline"
                className={cn(
                  'capitalize',
                  statusStyles[currentCase.status]
                )}
              >
                {currentCase.status.replace('-', ' ')}
              </Badge>
            </div>
            <h1 className="text-2xl font-display font-bold">{currentCase.title}</h1>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline">
            <Play className="w-4 h-4 mr-2" />
            Run Playbook
          </Button>
          <Button variant="outline">
            <CheckCircle className="w-4 h-4 mr-2" />
            Resolve
          </Button>
          <Button variant="ghost" size="icon">
            <MoreHorizontal className="w-5 h-5" />
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-6">
        {/* Main content */}
        <div className="col-span-2 space-y-6">
          {/* Description */}
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">{currentCase.description}</p>
              <div className="flex flex-wrap gap-2 mt-4">
                {currentCase.tags.map((tag) => (
                  <Badge key={tag} variant="secondary">
                    {tag}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Tabs */}
          <Tabs defaultValue="timeline" className="w-full">
            <TabsList className="w-full justify-start">
              <TabsTrigger value="timeline">Timeline</TabsTrigger>
              <TabsTrigger value="alerts">Alerts ({currentCase.relatedAlerts.length})</TabsTrigger>
              <TabsTrigger value="evidence">Evidence ({currentCase.evidence.length})</TabsTrigger>
              <TabsTrigger value="tasks">Tasks</TabsTrigger>
              <TabsTrigger value="notes">Notes</TabsTrigger>
            </TabsList>

            <TabsContent value="timeline" className="mt-4">
              <CaseTimeline />
            </TabsContent>

            <TabsContent value="alerts" className="mt-4">
              <Card>
                <CardContent className="pt-6">
                  <div className="space-y-3">
                    {currentCase.relatedAlerts.map((alert) => (
                      <div
                        key={alert.id}
                        className="flex items-center justify-between p-4 rounded-lg border border-border hover:bg-card hover:border-primary/30 transition-colors cursor-pointer"
                      >
                        <div className="flex items-center gap-4">
                          <Badge variant={alert.severity as 'critical' | 'high' | 'medium'}>
                            {alert.severity}
                          </Badge>
                          <div>
                            <p className="text-xs text-muted-foreground font-mono">
                              {alert.id}
                            </p>
                            <p className="font-medium">{alert.title}</p>
                          </div>
                        </div>
                        <Button variant="ghost" size="sm">
                          <LinkIcon className="w-4 h-4 mr-2" />
                          View
                        </Button>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="evidence" className="mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>Evidence Files</CardTitle>
                  <Button size="sm">
                    <Plus className="w-4 h-4 mr-2" />
                    Upload
                  </Button>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {currentCase.evidence.map((file, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className="p-2 rounded bg-card border border-border">
                            {file.type === 'file' ? (
                              <FileText className="w-4 h-4 text-muted-foreground" />
                            ) : (
                              <Paperclip className="w-4 h-4 text-muted-foreground" />
                            )}
                          </div>
                          <div>
                            <p className="font-medium text-sm">{file.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {file.size}
                            </p>
                          </div>
                        </div>
                        <Button variant="ghost" size="sm">
                          Download
                        </Button>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="tasks" className="mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>Investigation Tasks</CardTitle>
                  <Button size="sm">
                    <Plus className="w-4 h-4 mr-2" />
                    Add Task
                  </Button>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {[
                      {
                        task: 'Isolate affected endpoints',
                        status: 'completed',
                        assignee: 'JD',
                      },
                      {
                        task: 'Collect forensic artifacts',
                        status: 'in-progress',
                        assignee: 'JS',
                      },
                      {
                        task: 'Identify initial infection vector',
                        status: 'in-progress',
                        assignee: 'JD',
                      },
                      {
                        task: 'Review backup integrity',
                        status: 'pending',
                        assignee: null,
                      },
                      {
                        task: 'Prepare incident report',
                        status: 'pending',
                        assignee: null,
                      },
                    ].map((item, i) => (
                      <div
                        key={i}
                        className="flex items-center gap-4 p-3 rounded-lg bg-muted/30"
                      >
                        <input
                          type="checkbox"
                          checked={item.status === 'completed'}
                          className="rounded border-border"
                          onChange={() => {}}
                        />
                        <span
                          className={cn(
                            'flex-1',
                            item.status === 'completed' &&
                              'line-through text-muted-foreground'
                          )}
                        >
                          {item.task}
                        </span>
                        {item.assignee ? (
                          <Avatar className="w-6 h-6">
                            <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                              {item.assignee}
                            </AvatarFallback>
                          </Avatar>
                        ) : (
                          <Button variant="ghost" size="sm" className="text-xs">
                            Assign
                          </Button>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="notes" className="mt-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between">
                  <CardTitle>Investigation Notes</CardTitle>
                  <Button size="sm">
                    <Plus className="w-4 h-4 mr-2" />
                    Add Note
                  </Button>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="p-4 rounded-lg bg-muted/30">
                      <div className="flex items-center gap-2 mb-2">
                        <Avatar className="w-6 h-6">
                          <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                            JD
                          </AvatarFallback>
                        </Avatar>
                        <span className="text-sm font-medium">John Doe</span>
                        <span className="text-xs text-muted-foreground">
                          1 hour ago
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        Initial analysis shows the ransomware entered via a
                        phishing email targeting the CFO. The attachment
                        contained a macro-enabled Word document.
                      </p>
                    </div>
                    <div className="p-4 rounded-lg bg-muted/30">
                      <div className="flex items-center gap-2 mb-2">
                        <Avatar className="w-6 h-6">
                          <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                            JS
                          </AvatarFallback>
                        </Avatar>
                        <span className="text-sm font-medium">Jane Smith</span>
                        <span className="text-xs text-muted-foreground">
                          45 minutes ago
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground">
                        Confirmed C2 communication to known LockBit
                        infrastructure at 185.xx.xx.xx. Have blocked at
                        perimeter firewall.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Details */}
          <Card>
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <label className="text-xs text-muted-foreground uppercase tracking-wider">
                  Assignee
                </label>
                <div className="flex items-center gap-2 mt-1">
                  <Avatar className="w-8 h-8">
                    <AvatarFallback className="bg-primary/20 text-primary">
                      {currentCase.assignee.initials}
                    </AvatarFallback>
                  </Avatar>
                  <div>
                    <p className="text-sm font-medium">
                      {currentCase.assignee.name}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {currentCase.assignee.email}
                    </p>
                  </div>
                </div>
              </div>
              <Separator />
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-muted-foreground uppercase tracking-wider">
                    Created
                  </label>
                  <p className="text-sm mt-1">
                    {formatTimestamp(currentCase.created)}
                  </p>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground uppercase tracking-wider">
                    Updated
                  </label>
                  <p className="text-sm mt-1">
                    {formatRelativeTime(currentCase.updated)}
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Impacted Assets */}
          <Card>
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle>Impacted Assets</CardTitle>
              <Badge variant="outline">{currentCase.impactedAssets.length}</Badge>
            </CardHeader>
            <CardContent>
              <div className="space-y-2">
                {currentCase.impactedAssets.map((asset, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between p-2 rounded-lg bg-muted/30"
                  >
                    <div className="flex items-center gap-2">
                      <Target className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-mono">{asset.name}</span>
                    </div>
                    <Badge
                      variant={
                        asset.status === 'infected'
                          ? 'critical'
                          : asset.status === 'contained'
                            ? 'success'
                            : 'warning'
                      }
                      className="text-2xs"
                    >
                      {asset.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Quick Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button variant="outline" className="w-full justify-start">
                <Play className="w-4 h-4 mr-2" />
                Execute Containment Playbook
              </Button>
              <Button variant="outline" className="w-full justify-start">
                <MessageSquare className="w-4 h-4 mr-2" />
                Notify Stakeholders
              </Button>
              <Button variant="outline" className="w-full justify-start">
                <User className="w-4 h-4 mr-2" />
                Escalate to Management
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
