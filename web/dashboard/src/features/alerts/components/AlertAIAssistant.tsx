/**
 * AlertAIAssistant - AI-powered alert analysis component with demo mode
 * Works without backend by providing intelligent mock responses based on alert context
 */
import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { cn } from '@/lib/utils';
import {
  Send,
  Bot,
  User,
  Sparkles,
  AlertTriangle,
  Shield,
  Target,
  FileText,
  Lightbulb,
  Search,
  Play,
  CheckCircle2,
  Loader2,
} from 'lucide-react';

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

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface AlertAIAssistantProps {
  alert: Alert;
  className?: string;
}

// Generate contextual AI responses based on alert data
function generateAIResponse(alert: Alert, userMessage: string): string {
  const lowerMessage = userMessage.toLowerCase();

  // Threat analysis
  if (lowerMessage.includes('analyze') || lowerMessage.includes('what') || lowerMessage.includes('분석')) {
    return `## Threat Analysis for ${alert.id}

**Alert:** ${alert.title}

### Severity Assessment
This is a **${alert.severity.toUpperCase()}** severity alert that requires ${
      alert.severity === 'critical' ? 'immediate' : alert.severity === 'high' ? 'urgent' : 'timely'
    } attention.

### Attack Vector
- **Source:** ${alert.source}
- **Target:** ${alert.target}
${alert.technique ? `- **MITRE ATT&CK:** ${alert.technique} (${alert.tactic})` : ''}

### Key Indicators
${alert.description}

### Risk Assessment
${
  alert.severity === 'critical'
    ? 'This alert indicates a potentially active compromise. Immediate containment is recommended.'
    : alert.severity === 'high'
    ? 'This alert shows signs of malicious activity that could escalate if not addressed.'
    : 'This alert should be investigated to determine if further action is needed.'
}`;
  }

  // Investigation steps
  if (lowerMessage.includes('investigate') || lowerMessage.includes('steps') || lowerMessage.includes('조사')) {
    return `## Investigation Steps for ${alert.id}

### Immediate Actions
1. **Verify the alert** - Confirm this is not a false positive by checking source logs
2. **Check target status** - Verify ${alert.target} is operational and not compromised
3. **Review related events** - Look for similar activity in the past 24 hours

### Data Collection
- Collect network logs from ${alert.source}
- Gather endpoint telemetry from ${alert.target}
- Check authentication logs for anomalies
${alert.technique ? `- Review ${alert.technique} specific indicators` : ''}

### Analysis Questions
- Is this behavior expected from ${alert.source}?
- Has ${alert.target} shown similar patterns before?
- Are there other affected systems?

### Escalation Criteria
${
  alert.severity === 'critical' || alert.severity === 'high'
    ? '- Escalate to Tier 2/3 if lateral movement is detected\n- Notify incident response team if data exfiltration is suspected'
    : '- Escalate if multiple related alerts appear\n- Document findings for trend analysis'
}`;
  }

  // Playbook recommendations
  if (lowerMessage.includes('playbook') || lowerMessage.includes('response') || lowerMessage.includes('대응')) {
    const playbooks = getRecommendedPlaybooks(alert);
    return `## Recommended Playbooks for ${alert.id}

Based on the alert characteristics, I recommend the following playbooks:

${playbooks.map((p, i) => `### ${i + 1}. ${p.name}
- **Type:** ${p.type}
- **Priority:** ${p.priority}
- **Actions:** ${p.actions.join(', ')}
`).join('\n')}

### Execution Order
1. Start with **${playbooks[0]?.name}** for initial enrichment
2. Based on results, proceed with containment if needed
3. Complete with notification and documentation

Would you like me to explain any of these playbooks in detail?`;
  }

  // Similar alerts
  if (lowerMessage.includes('similar') || lowerMessage.includes('history') || lowerMessage.includes('유사')) {
    return `## Similar Historical Alerts

Based on pattern matching with **${alert.title}**, I found these related alerts:

### Recent Similar Alerts (Last 30 Days)
| Alert ID | Title | Severity | Date |
|----------|-------|----------|------|
| ALT-2024-${Math.floor(Math.random() * 100)} | Similar ${alert.technique || 'network'} activity | ${alert.severity} | 3 days ago |
| ALT-2024-${Math.floor(Math.random() * 100)} | ${alert.source} suspicious connection | medium | 1 week ago |
| ALT-2024-${Math.floor(Math.random() * 100)} | ${alert.target} anomalous behavior | low | 2 weeks ago |

### Pattern Analysis
- **Frequency:** This type of alert occurs approximately 2-3 times per week
- **Common Sources:** Similar alerts often originate from external IPs
- **Resolution Rate:** 85% of similar alerts were resolved as true positives

### Correlation Insights
${alert.technique
  ? `Alerts involving ${alert.technique} have increased 15% this month. Consider reviewing detection rules.`
  : 'No significant correlation patterns detected for this alert type.'}`;
  }

  // MITRE ATT&CK context
  if (lowerMessage.includes('mitre') || lowerMessage.includes('attack') || lowerMessage.includes('technique')) {
    if (alert.technique) {
      return `## MITRE ATT&CK Context

### Technique: ${alert.technique}
**Tactic:** ${alert.tactic}

### Description
This technique is commonly used by threat actors to ${
        alert.tactic === 'Initial Access' ? 'gain initial foothold in target environments' :
        alert.tactic === 'Execution' ? 'execute malicious code on victim systems' :
        alert.tactic === 'Persistence' ? 'maintain presence in compromised environments' :
        alert.tactic === 'Lateral Movement' ? 'move through the network to reach objectives' :
        'achieve their operational goals'
      }.

### Detection Recommendations
- Monitor for ${alert.technique}-related indicators
- Enable enhanced logging on critical systems
- Review network segmentation policies

### Mitigation Strategies
1. Implement application whitelisting
2. Enable multi-factor authentication
3. Segment network to limit lateral movement
4. Deploy endpoint detection and response (EDR)

### Related Techniques
- Look for follow-up techniques commonly chained with ${alert.technique}
- Monitor for data staging and exfiltration attempts`;
    }
    return `No MITRE ATT&CK technique is associated with this alert. Consider enriching the alert with threat intelligence data.`;
  }

  // Default comprehensive response
  return `## AI Analysis Summary for ${alert.id}

### Quick Assessment
- **Severity:** ${alert.severity.toUpperCase()} - ${getSeverityDescription(alert.severity)}
- **Status:** ${alert.status}
- **Risk Level:** ${getRiskLevel(alert)}

### Recommended Actions
1. ${alert.severity === 'critical' ? '**IMMEDIATE:** Isolate affected systems' : 'Review alert details and validate indicators'}
2. Check for related alerts in the past 24 hours
3. ${alert.severity === 'critical' || alert.severity === 'high' ? 'Notify security team lead' : 'Document findings for analysis'}

### Available Commands
You can ask me to:
- **"Analyze this threat"** - Get detailed threat analysis
- **"Investigation steps"** - Get step-by-step investigation guide
- **"Recommend playbooks"** - Get automated response recommendations
- **"Find similar alerts"** - Search historical patterns
${alert.technique ? '- **"MITRE context"** - Get ATT&CK framework details' : ''}

How would you like me to help?`;
}

function getSeverityDescription(severity: string): string {
  switch (severity) {
    case 'critical': return 'Requires immediate action';
    case 'high': return 'Requires urgent attention';
    case 'medium': return 'Should be investigated soon';
    case 'low': return 'Monitor and investigate as capacity allows';
    default: return 'Informational alert';
  }
}

function getRiskLevel(alert: Alert): string {
  if (alert.severity === 'critical') return 'Very High';
  if (alert.severity === 'high') return 'High';
  if (alert.severity === 'medium') return 'Medium';
  return 'Low';
}

function getRecommendedPlaybooks(alert: Alert) {
  const playbooks = [];

  // Always recommend enrichment
  playbooks.push({
    name: 'Alert Enrichment',
    type: 'Enrichment',
    priority: 'High',
    actions: ['GeoIP lookup', 'Threat Intel check', 'Asset correlation'],
  });

  // Severity-based recommendations
  if (alert.severity === 'critical' || alert.severity === 'high') {
    playbooks.push({
      name: 'Incident Containment',
      type: 'Containment',
      priority: 'Critical',
      actions: ['Block source IP', 'Isolate endpoint', 'Disable user account'],
    });
  }

  // Always add notification
  playbooks.push({
    name: 'SOC Notification',
    type: 'Notification',
    priority: 'Medium',
    actions: ['Email alert', 'Slack notification', 'Create ticket'],
  });

  return playbooks;
}

export function AlertAIAssistant({ alert, className }: AlertAIAssistantProps) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  // Generate initial welcome message
  useEffect(() => {
    const welcomeMessage: Message = {
      id: 'welcome',
      role: 'assistant',
      content: `## Analyzing Alert ${alert.id}

**${alert.title}**

I've loaded the context for this **${alert.severity.toUpperCase()}** severity alert. Here's what I can help you with:

- **Threat Analysis** - Understand the nature and risk of this alert
- **Investigation Steps** - Get guided investigation procedures
- **Playbook Recommendations** - Automated response suggestions
- **Similar Alerts** - Find historical patterns
${alert.technique ? `- **MITRE ATT&CK Context** - ${alert.technique} details` : ''}

What would you like to know?`,
      timestamp: new Date(),
    };
    setMessages([welcomeMessage]);
  }, [alert]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

  const handleSend = async () => {
    const trimmedInput = input.trim();
    if (!trimmedInput || isTyping) return;

    // Add user message
    const userMessage: Message = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: trimmedInput,
      timestamp: new Date(),
    };
    setMessages(prev => [...prev, userMessage]);
    setInput('');
    setIsTyping(true);

    // Simulate AI thinking time
    await new Promise(resolve => setTimeout(resolve, 800 + Math.random() * 700));

    // Generate AI response
    const aiResponse = generateAIResponse(alert, trimmedInput);
    const assistantMessage: Message = {
      id: `assistant-${Date.now()}`,
      role: 'assistant',
      content: aiResponse,
      timestamp: new Date(),
    };
    setMessages(prev => [...prev, assistantMessage]);
    setIsTyping(false);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const quickActions = [
    { label: 'Analyze Threat', icon: AlertTriangle, query: 'Analyze this threat in detail' },
    { label: 'Investigation Steps', icon: Search, query: 'What are the investigation steps?' },
    { label: 'Recommend Playbooks', icon: Play, query: 'Recommend playbooks for response' },
    { label: 'Similar Alerts', icon: FileText, query: 'Find similar historical alerts' },
  ];

  return (
    <div className={cn('flex flex-col h-full bg-background', className)}>
      {/* Messages */}
      <ScrollArea className="flex-1 px-4">
        <div className="py-4 space-y-4">
          {messages.map((message) => (
            <div
              key={message.id}
              className={cn(
                'flex gap-3',
                message.role === 'user' && 'flex-row-reverse'
              )}
            >
              <div
                className={cn(
                  'w-8 h-8 rounded-full flex items-center justify-center shrink-0',
                  message.role === 'assistant'
                    ? 'bg-gradient-to-br from-[#7B61FF] to-[#00A4A6]'
                    : 'bg-muted'
                )}
              >
                {message.role === 'assistant' ? (
                  <Bot className="w-4 h-4 text-white" />
                ) : (
                  <User className="w-4 h-4" />
                )}
              </div>
              <div
                className={cn(
                  'max-w-[85%] rounded-lg px-4 py-3',
                  message.role === 'assistant'
                    ? 'bg-muted/50'
                    : 'bg-primary text-primary-foreground'
                )}
              >
                <div
                  className={cn(
                    'text-sm prose prose-sm dark:prose-invert max-w-none',
                    message.role === 'user' && 'prose-invert'
                  )}
                  dangerouslySetInnerHTML={{
                    __html: message.content
                      .replace(/^## (.*$)/gim, '<h3 class="text-base font-semibold mt-3 mb-2">$1</h3>')
                      .replace(/^### (.*$)/gim, '<h4 class="text-sm font-medium mt-2 mb-1">$1</h4>')
                      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
                      .replace(/\n/g, '<br/>')
                      .replace(/- (.*?)(<br\/>|$)/g, '<li class="ml-4">$1</li>')
                  }}
                />
              </div>
            </div>
          ))}

          {/* Typing indicator */}
          {isTyping && (
            <div className="flex gap-3">
              <div className="w-8 h-8 rounded-full flex items-center justify-center bg-gradient-to-br from-[#7B61FF] to-[#00A4A6]">
                <Bot className="w-4 h-4 text-white" />
              </div>
              <div className="bg-muted/50 rounded-lg px-4 py-3">
                <div className="flex items-center gap-2">
                  <Loader2 className="w-4 h-4 animate-spin text-[#7B61FF]" />
                  <span className="text-sm text-muted-foreground">Analyzing...</span>
                </div>
              </div>
            </div>
          )}

          <div ref={scrollRef} />
        </div>
      </ScrollArea>

      {/* Quick Actions */}
      {messages.length <= 1 && (
        <div className="px-4 py-3 border-t border-border">
          <p className="text-xs text-muted-foreground mb-2">Quick Actions</p>
          <div className="flex flex-wrap gap-2">
            {quickActions.map((action) => (
              <Button
                key={action.label}
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={() => {
                  setInput(action.query);
                  setTimeout(() => handleSend(), 100);
                }}
                disabled={isTyping}
              >
                <action.icon className="w-3 h-3 mr-1" />
                {action.label}
              </Button>
            ))}
          </div>
        </div>
      )}

      {/* Input */}
      <div className="p-4 border-t border-border">
        <div className="flex items-end gap-2">
          <div className="flex-1 relative">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about this alert..."
              className={cn(
                'w-full resize-none rounded-lg border border-input bg-background px-4 py-3',
                'text-sm placeholder:text-muted-foreground',
                'focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent',
                'min-h-[48px] max-h-[120px]'
              )}
              rows={1}
              disabled={isTyping}
            />
          </div>
          <Button
            size="icon"
            className="h-12 w-12 shrink-0 bg-gradient-to-r from-[#7B61FF] to-[#00A4A6] hover:from-[#8B71FF] hover:to-[#10B4B6]"
            onClick={handleSend}
            disabled={!input.trim() || isTyping}
          >
            <Send className="h-5 w-5" />
          </Button>
        </div>
        <p className="text-xs text-muted-foreground mt-2 text-center">
          <Sparkles className="w-3 h-3 inline mr-1" />
          AI-powered analysis (Demo Mode)
        </p>
      </div>
    </div>
  );
}
