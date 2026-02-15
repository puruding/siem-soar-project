import { useState, useCallback } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Play,
  CheckCircle2,
  XCircle,
  Clock,
  FileText,
  Copy,
  Trash2,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Parser, TestResult } from '../types';

interface GrokTestPanelProps {
  parser: Parser;
  isRunning: boolean;
  result: TestResult | null;
  onTest: (sampleLog: string) => void;
  onClear: () => void;
}

export function GrokTestPanel({
  parser,
  isRunning,
  result,
  onTest,
  onClear,
}: GrokTestPanelProps) {
  const [sampleLog, setSampleLog] = useState(parser.sampleLogs[0] || '');
  const [showRawData, setShowRawData] = useState(false);

  const handleTest = useCallback(() => {
    onTest(sampleLog);
  }, [sampleLog, onTest]);

  const handleCopyResult = useCallback(() => {
    if (result?.extractedData) {
      navigator.clipboard.writeText(JSON.stringify(result.extractedData, null, 2));
    }
  }, [result]);

  const handleUseSampleLog = useCallback((log: string) => {
    setSampleLog(log);
  }, []);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-border/50">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-sm uppercase tracking-wider text-muted-foreground">
            Test Panel
          </h2>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setSampleLog('');
                onClear();
              }}
              disabled={isRunning}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Clear
            </Button>
            <Button
              size="sm"
              onClick={handleTest}
              disabled={isRunning || !sampleLog.trim()}
              className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80 hover:from-[#00A4A6]/90 hover:to-[#00A4A6]/70"
            >
              <Play className="w-4 h-4 mr-2" />
              {isRunning ? 'Testing...' : 'Test'}
            </Button>
          </div>
        </div>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4 space-y-4">
          {/* Sample Log Input */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="py-3 px-4 border-b border-border/50">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <FileText className="w-4 h-4" />
                  Sample Log
                </CardTitle>
                {parser.sampleLogs.length > 0 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-xs"
                    onClick={() => handleUseSampleLog(parser.sampleLogs[0] || '')}
                  >
                    Use Default
                  </Button>
                )}
              </div>
            </CardHeader>
            <CardContent className="p-4">
              <Textarea
                value={sampleLog}
                onChange={(e) => setSampleLog(e.target.value)}
                placeholder="Paste a log line here to test the parser..."
                className="min-h-[120px] font-mono text-sm bg-background/50 resize-y"
              />
              {parser.sampleLogs.length > 1 && (
                <div className="mt-3">
                  <p className="text-xs text-muted-foreground mb-2">More samples:</p>
                  <div className="space-y-1">
                    {parser.sampleLogs.slice(1).map((log, i) => (
                      <button
                        key={i}
                        onClick={() => handleUseSampleLog(log)}
                        className="w-full text-left p-2 text-xs font-mono bg-muted/30 rounded hover:bg-muted/50 truncate transition-colors"
                      >
                        {log}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Test Results */}
          {result && (
            <Card className={cn(
              'border-border/50',
              result.success ? 'border-[#5CC05C]/30' : 'border-destructive/30'
            )}>
              <CardHeader className="py-3 px-4 border-b border-border/50">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    {result.success ? (
                      <>
                        <CheckCircle2 className="w-4 h-4 text-[#5CC05C]" />
                        <span className="text-[#5CC05C]">Test Passed</span>
                      </>
                    ) : (
                      <>
                        <XCircle className="w-4 h-4 text-destructive" />
                        <span className="text-destructive">Test Failed</span>
                      </>
                    )}
                  </CardTitle>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3.5 h-3.5" />
                      {result.executionTime}ms
                    </span>
                    {result.success && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2"
                        onClick={handleCopyResult}
                      >
                        <Copy className="w-3.5 h-3.5" />
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-4">
                {result.error ? (
                  <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/30">
                    <p className="text-sm text-destructive font-medium">Error</p>
                    <p className="text-sm text-destructive/80 mt-1">{result.error}</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Matched Fields */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                          Matched Fields ({result.matchedFields.length})
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {result.matchedFields.map((field) => (
                          <Badge
                            key={field}
                            variant="outline"
                            className="text-xs bg-[#5CC05C]/10 border-[#5CC05C]/30 text-[#5CC05C]"
                          >
                            {field}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    {/* Extracted Data Table */}
                    {Object.keys(result.extractedData).length > 0 && (
                      <div>
                        <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">
                          Extracted Data
                        </p>
                        <div className="rounded-lg border border-border/50 overflow-hidden">
                          <Table>
                            <TableHeader>
                              <TableRow className="bg-muted/30">
                                <TableHead className="text-xs font-semibold w-1/3">Field</TableHead>
                                <TableHead className="text-xs font-semibold">Value</TableHead>
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {Object.entries(result.extractedData).map(([key, value]) => (
                                <TableRow key={key}>
                                  <TableCell className="font-mono text-xs text-primary">
                                    {key}
                                  </TableCell>
                                  <TableCell className="font-mono text-xs truncate max-w-[200px]">
                                    {typeof value === 'object'
                                      ? JSON.stringify(value)
                                      : String(value)}
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </div>
                    )}

                    {/* Raw JSON Toggle */}
                    <div>
                      <button
                        onClick={() => setShowRawData(!showRawData)}
                        className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
                      >
                        {showRawData ? (
                          <ChevronUp className="w-3.5 h-3.5" />
                        ) : (
                          <ChevronDown className="w-3.5 h-3.5" />
                        )}
                        {showRawData ? 'Hide' : 'Show'} Raw JSON
                      </button>
                      {showRawData && (
                        <pre className="mt-2 p-3 rounded-lg bg-muted/30 text-xs font-mono overflow-x-auto">
                          {JSON.stringify(result.extractedData, null, 2)}
                        </pre>
                      )}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}

          {/* Empty State */}
          {!result && !isRunning && (
            <div className="text-center py-8 text-muted-foreground">
              <Play className="w-12 h-12 mx-auto mb-4 opacity-20" />
              <p className="text-sm">
                Enter a sample log and click Test to validate the parser
              </p>
              <p className="text-xs mt-2">
                The parser will attempt to extract fields based on the pattern
              </p>
            </div>
          )}

          {/* Loading State */}
          {isRunning && (
            <div className="text-center py-8">
              <div className="w-8 h-8 border-2 border-primary border-t-transparent rounded-full animate-spin mx-auto mb-4" />
              <p className="text-sm text-muted-foreground">Testing parser...</p>
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
