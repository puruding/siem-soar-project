import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  X,
  ExternalLink,
  Play,
  CheckCircle,
  XCircle,
  FolderPlus,
  Clock,
  Target,
  Server,
  FileText,
  Bot,
  Sparkles,
} from 'lucide-react';
import { formatTimestamp, cn } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { Message } from '@/features/copilot/components/MessageBubble';

interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: string;
  source: string;
  target: string;
  timestamp: Date;
  tactic?: string;
  technique?: string;
}

interface AlertDetailProps {
  alert: Alert;
  onClose: () => void;
}

const statusStyles: Record<string, string> = {
  new: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  acknowledged: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

export function AlertDetail({ alert, onClose }: AlertDetailProps) {
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);

  // Copilot configuration - connects to real API
  const copilotConfig: CopilotConfig = {
    apiEndpoint: import.meta.env.VITE_COPILOT_API_URL || 'http://localhost:8000',
    wsEndpoint: import.meta.env.VITE_COPILOT_WS_URL || 'ws://localhost:8000/api/v1/chat/stream',
    language: 'auto',
    streamingEnabled: false, // Use REST API for stability
  };

  // Create initial message with alert context
  const getInitialMessages = (): Message[] => {
    return [
      {
        id: 'system-welcome',
        role: 'assistant',
        content: [
          {
            type: 'text',
            content:
              `I'm analyzing alert **${alert.id}**: "${alert.title}"\n\n` +
              `**Severity:** ${alert.severity.toUpperCase()}\n` +
              `**Status:** ${alert.status}\n` +
              `**Source:** ${alert.source}\n` +
              `**Target:** ${alert.target}\n` +
              (alert.technique ? `**MITRE ATT&CK:** ${alert.technique} (${alert.tactic})\n` : '') +
              `\nHow can I help you investigate this alert? I can:\n` +
              `- Analyze the threat and provide context\n` +
              `- Suggest investigation steps\n` +
              `- Recommend playbooks to run\n` +
              `- Find similar historical alerts`,
          },
        ],
        timestamp: new Date(),
      },
    ];
  };

  // Alert context data for AI
  const alertContext = {
    alertId: alert.id,
    alertTitle: alert.title,
    alertDescription: alert.description,
    severity: alert.severity,
    status: alert.status,
    source: alert.source,
    target: alert.target,
    timestamp: alert.timestamp.toISOString(),
    tactic: alert.tactic,
    technique: alert.technique,
  };

  // Mock related data
  const relatedAlerts = [
    { id: 'ALT-2024-003', title: 'Related network activity', severity: 'high' },
    {
      id: 'ALT-2024-007',
      title: 'Similar pattern detected',
      severity: 'medium',
    },
  ];

  const timeline = [
    {
      time: alert.timestamp,
      event: 'Alert created',
      type: 'created',
    },
    {
      time: new Date(alert.timestamp.getTime() + 60000),
      event: 'AI triage: High priority',
      type: 'ai',
    },
    {
      time: new Date(alert.timestamp.getTime() + 120000),
      event: 'Enrichment complete',
      type: 'enriched',
    },
  ];

  return (
    <Card className="w-[420px] flex flex-col h-[calc(100vh-180px)] sticky top-6">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div>
          <p className="text-xs text-muted-foreground font-mono">{alert.id}</p>
          <CardTitle className="text-base mt-1">{alert.title}</CardTitle>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="w-4 h-4" />
        </Button>
      </CardHeader>

      <ScrollArea className="flex-1">
        <CardContent className="space-y-6">
          {/* Status and severity */}
          <div className="flex items-center gap-3">
            <Badge variant={alert.severity}>{alert.severity.toUpperCase()}</Badge>
            <Badge
              variant="outline"
              className={cn('capitalize', statusStyles[alert.status])}
            >
              {alert.status}
            </Badge>
          </div>

          {/* Description */}
          <div>
            <h4 className="text-sm font-medium mb-2">Description</h4>
            <p className="text-sm text-muted-foreground">{alert.description}</p>
          </div>

          <Separator />

          {/* Details grid */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Clock className="w-4 h-4" />
                <span className="text-xs">Detected</span>
              </div>
              <p className="text-sm font-mono">
                {formatTimestamp(alert.timestamp)}
              </p>
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Server className="w-4 h-4" />
                <span className="text-xs">Source</span>
              </div>
              <p className="text-sm">{alert.source}</p>
            </div>
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-muted-foreground">
                <Target className="w-4 h-4" />
                <span className="text-xs">Target</span>
              </div>
              <p className="text-sm font-mono">{alert.target}</p>
            </div>
            {alert.technique && (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <FileText className="w-4 h-4" />
                  <span className="text-xs">MITRE ATT&CK</span>
                </div>
                <p className="text-sm">
                  <span className="text-primary">{alert.technique}</span>
                  <span className="text-muted-foreground ml-2">
                    {alert.tactic}
                  </span>
                </p>
              </div>
            )}
          </div>

          <Separator />

          {/* Quick actions */}
          <div>
            <h4 className="text-sm font-medium mb-3">Quick Actions</h4>
            <div className="grid grid-cols-2 gap-2">
              <Button variant="outline" size="sm" className="justify-start">
                <CheckCircle className="w-4 h-4 mr-2 text-neon-green" />
                Acknowledge
              </Button>
              <Button variant="outline" size="sm" className="justify-start">
                <XCircle className="w-4 h-4 mr-2 text-threat-critical" />
                Close
              </Button>
              <Button variant="outline" size="sm" className="justify-start">
                <FolderPlus className="w-4 h-4 mr-2 text-primary" />
                Create Case
              </Button>
              <Button variant="outline" size="sm" className="justify-start">
                <Play className="w-4 h-4 mr-2 text-neon-orange" />
                Run Playbook
              </Button>
            </div>

            {/* AI Assistant Section */}
            <div className="mt-4 pt-4 border-t border-border">
              <Button
                className="w-full bg-gradient-to-r from-[#7B61FF] to-[#00A4A6] hover:from-[#8B71FF] hover:to-[#10B4B6] text-white"
                size="sm"
                onClick={() => setIsAIAssistantOpen(true)}
              >
                <Bot className="w-4 h-4 mr-2" />
                <span>AI Assistant</span>
                <Sparkles className="w-3 h-3 ml-2 animate-pulse" />
              </Button>
              <p className="text-2xs text-muted-foreground text-center mt-2">
                Get AI-powered analysis and recommendations
              </p>
            </div>
          </div>

          <Separator />

          {/* Timeline */}
          <div>
            <h4 className="text-sm font-medium mb-3">Activity Timeline</h4>
            <div className="space-y-3">
              {timeline.map((event, i) => (
                <div key={i} className="flex gap-3 relative">
                  {i !== timeline.length - 1 && (
                    <div className="absolute left-1.5 top-4 bottom-0 w-px bg-border" />
                  )}
                  <div
                    className={cn(
                      'w-3 h-3 rounded-full mt-1 shrink-0',
                      event.type === 'created' && 'bg-primary',
                      event.type === 'ai' && 'bg-neon-pink',
                      event.type === 'enriched' && 'bg-neon-green'
                    )}
                  />
                  <div className="flex-1 pb-3">
                    <p className="text-sm">{event.event}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatTimestamp(event.time)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <Separator />

          {/* Related alerts */}
          <div>
            <h4 className="text-sm font-medium mb-3">Related Alerts</h4>
            <div className="space-y-2">
              {relatedAlerts.map((related) => (
                <div
                  key={related.id}
                  className="flex items-center justify-between p-2 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer"
                >
                  <div>
                    <p className="text-xs text-muted-foreground font-mono">
                      {related.id}
                    </p>
                    <p className="text-sm">{related.title}</p>
                  </div>
                  <Badge
                    variant={related.severity as 'high' | 'medium'}
                    className="text-2xs"
                  >
                    {related.severity}
                  </Badge>
                </div>
              ))}
            </div>
          </div>

          {/* View full details */}
          <Button className="w-full" variant="outline">
            <ExternalLink className="w-4 h-4 mr-2" />
            View Full Details
          </Button>
        </CardContent>
      </ScrollArea>

      {/* AI Assistant Dialog */}
      <Dialog open={isAIAssistantOpen} onOpenChange={setIsAIAssistantOpen}>
        <DialogContent className="max-w-2xl h-[80vh] p-0 gap-0 flex flex-col">
          <DialogHeader className="px-6 py-4 border-b border-border shrink-0">
            <DialogTitle className="flex items-center gap-2">
              <Bot className="w-5 h-5 text-[#7B61FF]" />
              AI Assistant - {alert.id}
              <Sparkles className="w-4 h-4 text-[#00A4A6] animate-pulse" />
            </DialogTitle>
          </DialogHeader>
          <div className="flex-1 overflow-hidden min-h-0">
            <CopilotChat
              config={copilotConfig}
              initialMessages={getInitialMessages()}
              contextData={alertContext}
              className="h-full border-0 rounded-none"
              onError={(error) => console.error('Copilot error:', error)}
            />
          </div>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
