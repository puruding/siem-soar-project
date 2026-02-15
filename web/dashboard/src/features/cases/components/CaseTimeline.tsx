import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
  AlertTriangle,
  CheckCircle,
  Play,
  MessageSquare,
  Paperclip,
  User,
  Bot,
  Zap,
} from 'lucide-react';
import { formatTimestamp, cn } from '@/lib/utils';

interface TimelineEvent {
  id: string;
  type:
    | 'created'
    | 'alert'
    | 'status'
    | 'comment'
    | 'action'
    | 'playbook'
    | 'ai'
    | 'assignment'
    | 'evidence';
  title: string;
  description?: string;
  timestamp: Date;
  user?: { name: string; initials: string };
  metadata?: Record<string, string>;
}

const mockTimeline: TimelineEvent[] = [
  {
    id: '1',
    type: 'created',
    title: 'Case Created',
    description: 'Case created from critical alert ALT-2024-001',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2),
    user: { name: 'System', initials: 'SYS' },
  },
  {
    id: '2',
    type: 'ai',
    title: 'AI Triage Complete',
    description:
      'AI analysis: High confidence LockBit 3.0 ransomware. Recommended immediate containment.',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.9),
  },
  {
    id: '3',
    type: 'assignment',
    title: 'Case Assigned',
    description: 'Assigned to John Doe',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.8),
    user: { name: 'System', initials: 'SYS' },
  },
  {
    id: '4',
    type: 'status',
    title: 'Status Changed',
    description: 'Status changed from "Open" to "In Progress"',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.7),
    user: { name: 'John Doe', initials: 'JD' },
  },
  {
    id: '5',
    type: 'playbook',
    title: 'Playbook Executed',
    description: 'Endpoint Isolation playbook started',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.5),
    user: { name: 'John Doe', initials: 'JD' },
    metadata: { playbook: 'Endpoint Isolation', status: 'running' },
  },
  {
    id: '6',
    type: 'action',
    title: 'Containment Action',
    description: 'DESKTOP-FIN01 isolated from network',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.4),
    user: { name: 'System', initials: 'SYS' },
  },
  {
    id: '7',
    type: 'action',
    title: 'Containment Action',
    description: 'DESKTOP-FIN02 isolated from network',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.3),
    user: { name: 'System', initials: 'SYS' },
  },
  {
    id: '8',
    type: 'playbook',
    title: 'Playbook Completed',
    description: 'Endpoint Isolation playbook completed successfully',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 1.2),
    metadata: { playbook: 'Endpoint Isolation', status: 'success' },
  },
  {
    id: '9',
    type: 'alert',
    title: 'Related Alert',
    description: 'New alert ALT-2024-015 linked to case',
    timestamp: new Date(Date.now() - 1000 * 60 * 60),
  },
  {
    id: '10',
    type: 'evidence',
    title: 'Evidence Added',
    description: 'malware_sample.zip uploaded',
    timestamp: new Date(Date.now() - 1000 * 60 * 50),
    user: { name: 'Jane Smith', initials: 'JS' },
  },
  {
    id: '11',
    type: 'comment',
    title: 'Comment Added',
    description:
      'Initial analysis shows the ransomware entered via a phishing email targeting the CFO.',
    timestamp: new Date(Date.now() - 1000 * 60 * 45),
    user: { name: 'John Doe', initials: 'JD' },
  },
  {
    id: '12',
    type: 'ai',
    title: 'AI Investigation',
    description:
      'IOC extraction complete: 3 IPs, 2 domains, 5 file hashes identified',
    timestamp: new Date(Date.now() - 1000 * 60 * 30),
  },
  {
    id: '13',
    type: 'action',
    title: 'Firewall Rule Added',
    description: 'Blocked C2 communication to 185.xx.xx.xx',
    timestamp: new Date(Date.now() - 1000 * 60 * 20),
    user: { name: 'Jane Smith', initials: 'JS' },
  },
];

const typeConfig: Record<
  TimelineEvent['type'],
  { icon: typeof AlertTriangle; color: string; bgColor: string }
> = {
  created: {
    icon: Zap,
    color: 'text-neon-cyan',
    bgColor: 'bg-neon-cyan/20',
  },
  alert: {
    icon: AlertTriangle,
    color: 'text-threat-critical',
    bgColor: 'bg-threat-critical/20',
  },
  status: {
    icon: CheckCircle,
    color: 'text-neon-blue',
    bgColor: 'bg-neon-blue/20',
  },
  comment: {
    icon: MessageSquare,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
  },
  action: {
    icon: Zap,
    color: 'text-neon-orange',
    bgColor: 'bg-neon-orange/20',
  },
  playbook: {
    icon: Play,
    color: 'text-neon-green',
    bgColor: 'bg-neon-green/20',
  },
  ai: {
    icon: Bot,
    color: 'text-neon-pink',
    bgColor: 'bg-neon-pink/20',
  },
  assignment: {
    icon: User,
    color: 'text-primary',
    bgColor: 'bg-primary/20',
  },
  evidence: {
    icon: Paperclip,
    color: 'text-muted-foreground',
    bgColor: 'bg-muted',
  },
};

export function CaseTimeline() {
  return (
    <Card>
      <CardContent className="pt-6">
        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-4 top-0 bottom-0 w-px bg-border" />

          {/* Events */}
          <div className="space-y-6">
            {mockTimeline.map((event, i) => {
              const config = typeConfig[event.type];
              const Icon = config.icon;

              return (
                <div key={event.id} className="relative flex gap-4 pl-10">
                  {/* Icon */}
                  <div
                    className={cn(
                      'absolute left-0 p-2 rounded-full border-2 border-background',
                      config.bgColor
                    )}
                  >
                    <Icon className={cn('w-4 h-4', config.color)} />
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <p className="font-medium">{event.title}</p>
                        {event.description && (
                          <p className="text-sm text-muted-foreground mt-1">
                            {event.description}
                          </p>
                        )}
                        {event.metadata && (
                          <div className="flex items-center gap-2 mt-2">
                            {Object.entries(event.metadata).map(([key, value]) => (
                              <Badge
                                key={key}
                                variant={
                                  value === 'success'
                                    ? 'success'
                                    : value === 'running'
                                      ? 'warning'
                                      : 'secondary'
                                }
                                className="text-2xs"
                              >
                                {value}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        {event.user && (
                          <Avatar className="w-6 h-6">
                            <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                              {event.user.initials}
                            </AvatarFallback>
                          </Avatar>
                        )}
                        <span className="text-xs text-muted-foreground">
                          {formatTimestamp(event.timestamp)}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
