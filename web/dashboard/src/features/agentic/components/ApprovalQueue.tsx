/**
 * ApprovalQueue - Queue of pending approval requests for high-risk actions.
 */
import { memo, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { Separator } from '@/components/ui/separator';
import { Input } from '@/components/ui/input';
import { cn } from '@/lib/utils';
import {
  Shield,
  Clock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ChevronRight,
  RefreshCcw,
  User,
  Bot,
  Target,
  AlertCircle,
  Timer,
  MessageSquare,
  ThumbsUp,
  ThumbsDown,
} from 'lucide-react';

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'expired';

export interface ApprovalRequest {
  id: string;
  incidentId: string;
  actionType: string;
  targets: string[];
  riskLevel: RiskLevel;
  reason: string;
  context: Record<string, unknown>;
  agentId: string;
  agentName: string;
  status: ApprovalStatus;
  createdAt: Date;
  expiresAt: Date;
  reviewedBy: string | null;
  reviewedAt: Date | null;
  reviewNotes: string | null;
}

interface ApprovalQueueProps {
  requests?: ApprovalRequest[];
  onApprove?: (id: string, notes: string) => void;
  onReject?: (id: string, reason: string) => void;
  className?: string;
}

const defaultRequests: ApprovalRequest[] = [
  {
    id: 'appr-001',
    incidentId: 'INC-2024-046',
    actionType: 'disable_account',
    targets: ['user@company.com', 'admin@company.com', 'service_acc@company.com'],
    riskLevel: 'high',
    reason: 'Detected credential theft attempt - accounts may be compromised',
    context: {
      detection_time: '2024-01-15T10:30:00Z',
      source_ip: '192.168.1.100',
      failed_logins: 15,
    },
    agentId: 'res-001',
    agentName: 'Response Agent',
    status: 'pending',
    createdAt: new Date(Date.now() - 600000),
    expiresAt: new Date(Date.now() + 1800000),
    reviewedBy: null,
    reviewedAt: null,
    reviewNotes: null,
  },
  {
    id: 'appr-002',
    incidentId: 'INC-2024-047',
    actionType: 'isolate_host',
    targets: ['workstation-015.internal'],
    riskLevel: 'critical',
    reason: 'Ransomware indicators detected - immediate containment recommended',
    context: {
      malware_family: 'LockBit',
      encrypted_files: 47,
      lateral_movement: true,
    },
    agentId: 'res-001',
    agentName: 'Response Agent',
    status: 'pending',
    createdAt: new Date(Date.now() - 300000),
    expiresAt: new Date(Date.now() + 900000),
    reviewedBy: null,
    reviewedAt: null,
    reviewNotes: null,
  },
  {
    id: 'appr-003',
    incidentId: 'INC-2024-044',
    actionType: 'block_ip',
    targets: ['45.33.32.156', '91.92.243.18'],
    riskLevel: 'medium',
    reason: 'Suspicious outbound connections to known C2 infrastructure',
    context: {
      threat_intel_match: true,
      connection_count: 23,
      data_transferred_mb: 150,
    },
    agentId: 'res-001',
    agentName: 'Response Agent',
    status: 'approved',
    createdAt: new Date(Date.now() - 3600000),
    expiresAt: new Date(Date.now() - 1800000),
    reviewedBy: 'analyst@company.com',
    reviewedAt: new Date(Date.now() - 3000000),
    reviewNotes: 'Verified with threat intel - approved for blocking',
  },
];

const riskConfig: Record<RiskLevel, { label: string; color: string; bg: string }> = {
  low: { label: 'Low', color: 'text-blue-500', bg: 'bg-blue-500/10' },
  medium: { label: 'Medium', color: 'text-yellow-500', bg: 'bg-yellow-500/10' },
  high: { label: 'High', color: 'text-orange-500', bg: 'bg-orange-500/10' },
  critical: { label: 'Critical', color: 'text-red-500', bg: 'bg-red-500/10' },
};

const actionLabels: Record<string, string> = {
  disable_account: 'Disable Account',
  isolate_host: 'Isolate Host',
  block_ip: 'Block IP',
  quarantine_file: 'Quarantine File',
  kill_process: 'Kill Process',
  shutdown_service: 'Shutdown Service',
};

function ApprovalQueueComponent({
  requests = defaultRequests,
  onApprove,
  onReject,
  className,
}: ApprovalQueueProps) {
  const [statusFilter, setStatusFilter] = useState<string>('pending');
  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 1000);
  };

  const filteredRequests = requests.filter(
    (req) => statusFilter === 'all' || req.status === statusFilter
  );

  const pendingCount = requests.filter((r) => r.status === 'pending').length;

  const formatTimeRemaining = (expiresAt: Date): string => {
    const now = new Date();
    const diff = expiresAt.getTime() - now.getTime();

    if (diff <= 0) return 'Expired';

    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);

    if (hours > 0) return `${hours}h ${minutes % 60}m remaining`;
    return `${minutes}m remaining`;
  };

  const formatRelativeTime = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(minutes / 60);

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return date.toLocaleString();
  };

  const handleApprove = () => {
    if (selectedRequest) {
      onApprove?.(selectedRequest.id, reviewNotes);
      setSelectedRequest(null);
      setReviewNotes('');
    }
  };

  const handleReject = () => {
    if (selectedRequest && reviewNotes) {
      onReject?.(selectedRequest.id, reviewNotes);
      setSelectedRequest(null);
      setReviewNotes('');
    }
  };

  return (
    <>
      <Card className={cn('flex flex-col h-full', className)}>
        <CardHeader className="pb-4 shrink-0">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Approval Queue
              {pendingCount > 0 && (
                <Badge variant="destructive" className="ml-2">
                  {pendingCount} pending
                </Badge>
              )}
            </CardTitle>
            <div className="flex items-center gap-2">
              <Select value={statusFilter} onValueChange={setStatusFilter}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue placeholder="Status" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="pending">Pending</SelectItem>
                  <SelectItem value="approved">Approved</SelectItem>
                  <SelectItem value="rejected">Rejected</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={handleRefresh}>
                <RefreshCcw className={cn('h-4 w-4', isRefreshing && 'animate-spin')} />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="flex-1 min-h-0 p-0">
          <ScrollArea className="h-full px-6 pb-6">
            <div className="space-y-4">
              {filteredRequests.map((request) => {
                const isExpired = request.expiresAt < new Date() && request.status === 'pending';
                return (
                  <div
                    key={request.id}
                    className={cn(
                      'border rounded-lg overflow-hidden transition-colors',
                      request.status === 'pending' && !isExpired && 'border-yellow-500/30 bg-yellow-500/5',
                      isExpired && 'border-red-500/30 bg-red-500/5 opacity-70'
                    )}
                  >
                    {/* Request Header */}
                    <div className="flex items-center justify-between p-4">
                      <div className="flex items-center gap-3">
                        <div className={cn(
                          'p-2 rounded-lg',
                          riskConfig[request.riskLevel].bg
                        )}>
                          <AlertTriangle className={cn(
                            'h-5 w-5',
                            riskConfig[request.riskLevel].color
                          )} />
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium">
                              {actionLabels[request.actionType] || request.actionType}
                            </span>
                            <Badge className={cn(
                              riskConfig[request.riskLevel].bg,
                              riskConfig[request.riskLevel].color,
                              'border-0'
                            )}>
                              {riskConfig[request.riskLevel].label} Risk
                            </Badge>
                            {request.status === 'approved' && (
                              <Badge className="bg-green-500/10 text-green-500 border-0">
                                <CheckCircle2 className="h-3 w-3 mr-1" />
                                Approved
                              </Badge>
                            )}
                            {request.status === 'rejected' && (
                              <Badge className="bg-red-500/10 text-red-500 border-0">
                                <XCircle className="h-3 w-3 mr-1" />
                                Rejected
                              </Badge>
                            )}
                            {isExpired && (
                              <Badge variant="destructive">Expired</Badge>
                            )}
                          </div>
                          <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                            <span className="flex items-center gap-1">
                              <AlertCircle className="h-3 w-3" />
                              {request.incidentId}
                            </span>
                            <span className="flex items-center gap-1">
                              <Bot className="h-3 w-3" />
                              {request.agentName}
                            </span>
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatRelativeTime(request.createdAt)}
                            </span>
                          </div>
                        </div>
                      </div>
                      {request.status === 'pending' && !isExpired && (
                        <div className="flex items-center gap-2">
                          <div className="text-right mr-4">
                            <p className="text-xs text-muted-foreground">Expires in</p>
                            <p className={cn(
                              'text-sm font-medium',
                              request.expiresAt.getTime() - Date.now() < 600000 && 'text-red-500'
                            )}>
                              {formatTimeRemaining(request.expiresAt)}
                            </p>
                          </div>
                          <Button
                            variant="default"
                            size="sm"
                            onClick={() => setSelectedRequest(request)}
                            className="bg-green-600 hover:bg-green-700"
                          >
                            <ThumbsUp className="h-4 w-4 mr-1" />
                            Review
                          </Button>
                        </div>
                      )}
                    </div>

                    {/* Request Details */}
                    <div className="px-4 pb-4">
                      <div className="p-3 rounded-lg bg-muted/30">
                        <p className="text-sm">{request.reason}</p>
                        <div className="mt-3">
                          <p className="text-xs text-muted-foreground mb-1.5">Targets:</p>
                          <div className="flex flex-wrap gap-1.5">
                            {request.targets.map((target, idx) => (
                              <Badge key={idx} variant="outline" className="text-xs">
                                <Target className="h-3 w-3 mr-1" />
                                {target}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </div>

                      {/* Review Info */}
                      {request.reviewedBy && (
                        <div className="mt-3 p-3 rounded-lg bg-muted/30">
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <User className="h-3 w-3" />
                            <span>Reviewed by {request.reviewedBy}</span>
                            <span>-</span>
                            <span>{formatRelativeTime(request.reviewedAt!)}</span>
                          </div>
                          {request.reviewNotes && (
                            <div className="flex items-start gap-2 mt-2">
                              <MessageSquare className="h-3 w-3 mt-0.5 text-muted-foreground" />
                              <p className="text-sm">{request.reviewNotes}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {filteredRequests.length === 0 && (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Shield className="h-12 w-12 mb-3 opacity-30" />
                  <p className="text-sm">No approval requests</p>
                  <p className="text-xs">
                    {statusFilter === 'pending'
                      ? 'All pending requests have been processed'
                      : 'No requests match the current filter'}
                  </p>
                </div>
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Review Dialog */}
      <Dialog open={selectedRequest !== null} onOpenChange={() => setSelectedRequest(null)}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Review Approval Request
            </DialogTitle>
            <DialogDescription>
              Review the action details and approve or reject the request.
            </DialogDescription>
          </DialogHeader>

          {selectedRequest && (
            <div className="space-y-4">
              {/* Action Details */}
              <div className="p-4 rounded-lg border">
                <div className="flex items-center gap-2 mb-3">
                  <Badge className={cn(
                    riskConfig[selectedRequest.riskLevel].bg,
                    riskConfig[selectedRequest.riskLevel].color,
                    'border-0'
                  )}>
                    {riskConfig[selectedRequest.riskLevel].label} Risk
                  </Badge>
                  <span className="font-medium">
                    {actionLabels[selectedRequest.actionType] || selectedRequest.actionType}
                  </span>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{selectedRequest.reason}</p>
                <div>
                  <p className="text-xs text-muted-foreground mb-1.5">Targets:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedRequest.targets.map((target, idx) => (
                      <Badge key={idx} variant="outline" className="text-xs">
                        {target}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>

              {/* Context */}
              <div className="p-4 rounded-lg bg-muted/30">
                <p className="text-xs font-medium text-muted-foreground mb-2">Additional Context</p>
                <div className="space-y-1 text-sm">
                  {Object.entries(selectedRequest.context).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between">
                      <span className="text-muted-foreground">{key.replace(/_/g, ' ')}</span>
                      <span className="font-medium">{String(value)}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Review Notes */}
              <div>
                <label className="text-sm font-medium mb-1.5 block">
                  Review Notes {selectedRequest.riskLevel === 'critical' && <span className="text-red-500">*</span>}
                </label>
                <Input
                  placeholder="Add notes (required for rejection)"
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                />
              </div>
            </div>
          )}

          <DialogFooter className="gap-2">
            <Button
              variant="destructive"
              onClick={handleReject}
              disabled={!reviewNotes}
            >
              <ThumbsDown className="h-4 w-4 mr-1" />
              Reject
            </Button>
            <Button
              onClick={handleApprove}
              className="bg-green-600 hover:bg-green-700"
            >
              <ThumbsUp className="h-4 w-4 mr-1" />
              Approve
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export const ApprovalQueue = memo(ApprovalQueueComponent);
