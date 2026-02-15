import { useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Play,
  ChevronDown,
  ChevronRight,
  Clock,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Loader2,
  FlaskConical,
  RotateCcw,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SigmaRule, RuleTestResult } from '../types';

interface RuleTestPanelProps {
  rule: SigmaRule | null;
  onTest: (ruleId: string, testEvents: object[]) => Promise<RuleTestResult>;
  className?: string;
}

const defaultTestEvents = `[
  {
    "event_time": "2024-01-15T14:32:15Z",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ=",
    "User": "DOMAIN\\\\admin",
    "ProcessId": 1234
  },
  {
    "event_time": "2024-01-15T14:33:20Z",
    "Image": "C:\\\\Windows\\\\System32\\\\cmd.exe",
    "CommandLine": "cmd.exe /c whoami",
    "User": "DOMAIN\\\\user",
    "ProcessId": 5678
  },
  {
    "event_time": "2024-01-15T14:34:05Z",
    "Image": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
    "CommandLine": "powershell.exe -EncodedCommand VGVzdA==",
    "User": "DOMAIN\\\\admin",
    "ProcessId": 9012
  }
]`;

export function RuleTestPanel({ rule, onTest, className }: RuleTestPanelProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [testEvents, setTestEvents] = useState(defaultTestEvents);
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);

  // Validate JSON input
  const validateInput = useCallback((input: string): object[] | null => {
    try {
      const parsed = JSON.parse(input);
      if (!Array.isArray(parsed)) {
        setParseError('Input must be a JSON array of events');
        return null;
      }
      setParseError(null);
      return parsed;
    } catch (e) {
      setParseError(`Invalid JSON: ${(e as Error).message}`);
      return null;
    }
  }, []);

  // Handle test execution
  const handleTest = useCallback(async () => {
    if (!rule) return;

    const events = validateInput(testEvents);
    if (!events) return;

    setIsRunning(true);
    setResult(null);

    try {
      const testResult = await onTest(rule.id, events);
      setResult(testResult);
    } catch (e) {
      setResult({
        success: false,
        matchedEvents: 0,
        totalEvents: events.length,
        matches: [],
        executionTime: 0,
        error: (e as Error).message,
      });
    } finally {
      setIsRunning(false);
    }
  }, [rule, testEvents, onTest, validateInput]);

  // Handle reset
  const handleReset = useCallback(() => {
    setTestEvents(defaultTestEvents);
    setResult(null);
    setParseError(null);
  }, []);

  if (!rule) {
    return null;
  }

  return (
    <Collapsible open={!isCollapsed} onOpenChange={(open) => setIsCollapsed(!open)}>
      <Card className={cn('flex flex-col', className)}>
        <CardHeader className="pb-3 shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FlaskConical className="w-5 h-5 text-primary" />
              <CardTitle className="text-base">Rule Test Panel</CardTitle>
              {result && (
                <Badge
                  variant="outline"
                  className={cn(
                    result.success && result.matchedEvents > 0
                      ? 'bg-neon-green/20 text-neon-green border-neon-green/50'
                      : result.success
                      ? 'bg-muted/50 text-muted-foreground border-border'
                      : 'bg-threat-critical/20 text-threat-critical border-threat-critical/50'
                  )}
                >
                  {result.matchedEvents}/{result.totalEvents} matched
                </Badge>
              )}
            </div>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="icon">
                {isCollapsed ? (
                  <ChevronRight className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </Button>
            </CollapsibleTrigger>
          </div>
        </CardHeader>

        <CollapsibleContent>
          <CardContent className="space-y-4">
            {/* Test Events Input */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <label className="text-sm font-medium">Test Events (JSON Array)</label>
                <Button variant="ghost" size="sm" onClick={handleReset}>
                  <RotateCcw className="w-3 h-3 mr-1" />
                  Reset
                </Button>
              </div>
              <Textarea
                value={testEvents}
                onChange={(e) => {
                  setTestEvents(e.target.value);
                  validateInput(e.target.value);
                }}
                placeholder="Enter JSON array of events to test..."
                className={cn(
                  'font-mono text-sm min-h-[150px]',
                  parseError && 'border-threat-critical focus-visible:ring-threat-critical'
                )}
              />
              {parseError && (
                <p className="text-xs text-threat-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3 h-3" />
                  {parseError}
                </p>
              )}
            </div>

            {/* Actions */}
            <div className="flex items-center gap-2">
              <Button
                onClick={handleTest}
                disabled={isRunning || !!parseError}
                className="flex-1"
              >
                {isRunning ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Testing...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Test Rule
                  </>
                )}
              </Button>
            </div>

            {/* Results */}
            {result && (
              <>
                <Separator />
                <div className="space-y-4">
                  {/* Summary */}
                  <div className="flex items-center gap-4">
                    {result.success ? (
                      <div className="flex items-center gap-2 text-sm text-neon-green">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Test completed successfully</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-2 text-sm text-threat-critical">
                        <XCircle className="w-4 h-4" />
                        <span>Test failed: {result.error}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                      <Clock className="w-4 h-4" />
                      <span>{result.executionTime}ms</span>
                    </div>
                  </div>

                  {/* Match Details */}
                  {result.success && result.matches.length > 0 && (
                    <div>
                      <p className="text-sm font-medium mb-2">Matched Events</p>
                      <ScrollArea className="h-[150px]">
                        <div className="space-y-2">
                          {result.matches.map((match, index) => (
                            <div
                              key={index}
                              className="p-3 rounded-lg bg-neon-green/10 border border-neon-green/30"
                            >
                              <div className="flex items-center justify-between mb-2">
                                <span className="text-sm font-medium">
                                  Event #{match.eventIndex + 1}
                                </span>
                                <Badge
                                  variant="outline"
                                  className="text-xs bg-neon-green/20 text-neon-green border-neon-green/50"
                                >
                                  Matched
                                </Badge>
                              </div>
                              <div className="flex flex-wrap gap-1">
                                {match.matchedConditions.map((condition, i) => (
                                  <Badge
                                    key={i}
                                    variant="outline"
                                    className="text-xs"
                                  >
                                    {condition}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </ScrollArea>
                    </div>
                  )}

                  {result.success && result.matches.length === 0 && (
                    <div className="p-4 rounded-lg bg-muted/30 border border-border text-center">
                      <AlertCircle className="w-8 h-8 mx-auto mb-2 text-muted-foreground" />
                      <p className="text-sm text-muted-foreground">
                        No events matched the rule conditions
                      </p>
                      <p className="text-xs text-muted-foreground mt-1">
                        Try different test events or verify the rule logic
                      </p>
                    </div>
                  )}
                </div>
              </>
            )}
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
