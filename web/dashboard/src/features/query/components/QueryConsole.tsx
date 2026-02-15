import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import CodeMirror from '@uiw/react-codemirror';
import { sql } from '@codemirror/lang-sql';
import { oneDark } from '@codemirror/theme-one-dark';
import {
  Play,
  Save,
  Clock,
  Database,
  Download,
  Sparkles,
  History,
  BookMarked,
  Trash2,
  Copy,
} from 'lucide-react';
import { formatDuration } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { QueryResultData } from '@/features/copilot/components/QueryResult';

const defaultQuery = `-- Query security events from ClickHouse
SELECT
    event_time,
    event_type,
    source_ip,
    destination_ip,
    severity,
    description
FROM events
WHERE
    event_time >= now() - INTERVAL 1 HOUR
    AND severity IN ('critical', 'high')
ORDER BY event_time DESC
LIMIT 100`;

const mockResults = [
  {
    event_time: '2024-01-15 14:32:15',
    event_type: 'malware_detected',
    source_ip: '192.168.1.45',
    destination_ip: '10.0.0.5',
    severity: 'critical',
    description: 'Ransomware signature detected',
  },
  {
    event_time: '2024-01-15 14:31:42',
    event_type: 'failed_login',
    source_ip: '203.45.67.89',
    destination_ip: '10.0.0.10',
    severity: 'high',
    description: 'Multiple failed login attempts',
  },
  {
    event_time: '2024-01-15 14:30:58',
    event_type: 'port_scan',
    source_ip: '192.168.1.100',
    destination_ip: '10.0.0.0/24',
    severity: 'high',
    description: 'Horizontal port scan detected',
  },
  {
    event_time: '2024-01-15 14:29:33',
    event_type: 'data_exfil',
    source_ip: '192.168.1.22',
    destination_ip: '185.45.67.89',
    severity: 'critical',
    description: 'Large data transfer to external IP',
  },
  {
    event_time: '2024-01-15 14:28:17',
    event_type: 'privilege_escalation',
    source_ip: '192.168.1.15',
    destination_ip: '10.0.0.1',
    severity: 'high',
    description: 'Unauthorized privilege elevation',
  },
];

const savedQueries = [
  {
    id: '1',
    name: 'Critical Alerts - Last Hour',
    query: 'SELECT * FROM alerts WHERE severity = "critical" AND ...',
    updated: '2h ago',
  },
  {
    id: '2',
    name: 'Failed Login Attempts',
    query: 'SELECT * FROM events WHERE event_type = "failed_login" ...',
    updated: '1d ago',
  },
  {
    id: '3',
    name: 'Network Traffic Analysis',
    query: 'SELECT source_ip, destination_ip, COUNT(*) ...',
    updated: '3d ago',
  },
];

const queryHistory = [
  {
    id: '1',
    query: 'SELECT * FROM events WHERE severity = "critical" LIMIT 100',
    duration: 245,
    rows: 47,
    time: '5m ago',
  },
  {
    id: '2',
    query: 'SELECT COUNT(*) FROM alerts GROUP BY severity',
    duration: 89,
    rows: 4,
    time: '15m ago',
  },
  {
    id: '3',
    query: 'SELECT * FROM events WHERE source_ip = "192.168.1.45"',
    duration: 156,
    rows: 23,
    time: '1h ago',
  },
];

const copilotConfig: CopilotConfig = {
  apiEndpoint: import.meta.env.VITE_COPILOT_API_URL || 'http://localhost:8002',
  wsEndpoint: import.meta.env.VITE_COPILOT_WS_URL || 'ws://localhost:8002/ws',
  language: 'auto',
  streamingEnabled: true,
};

export function QueryConsole() {
  const [query, setQuery] = useState(defaultQuery);
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<typeof mockResults | null>(null);
  const [queryStats, setQueryStats] = useState<{
    duration: number;
    rows: number;
  } | null>(null);
  const [showCopilot, setShowCopilot] = useState(false);

  const runQuery = () => {
    setIsRunning(true);
    // Simulate query execution
    setTimeout(() => {
      setResults(mockResults);
      setQueryStats({ duration: 234, rows: mockResults.length });
      setIsRunning(false);
    }, 1000);
  };

  const handleQueryResult = (data: QueryResultData) => {
    // When AI generates a query, update the editor and run it
    if (data.query) {
      setQuery(data.query);
    }
    // Update results from the AI query
    if (data.rows && data.rows.length > 0) {
      setResults(data.rows as typeof mockResults);
      setQueryStats({
        duration: data.executionTime || 0,
        rows: data.totalRows || data.rows.length,
      });
    }
  };

  return (
    <div className="space-y-6 animate-fade-in h-[calc(100vh-140px)] flex flex-col">
      {/* Page header */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Query Console
          </h1>
          <p className="text-muted-foreground">
            Explore security data with SQL queries
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowCopilot(true)}>
            <Sparkles className="w-4 h-4 mr-2" />
            AI Assistant
          </Button>
          <Button variant="outline" size="sm">
            <Database className="w-4 h-4 mr-2" />
            Schema
          </Button>
        </div>
      </div>

      <div className="flex gap-6 flex-1 min-h-0">
        {/* Main content */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Query editor */}
          <Card className="flex-none">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">Query Editor</CardTitle>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setQuery('')}
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Clear
                  </Button>
                  <Button variant="outline" size="sm">
                    <Save className="w-4 h-4 mr-2" />
                    Save
                  </Button>
                  <Button size="sm" onClick={runQuery} disabled={isRunning}>
                    <Play className="w-4 h-4 mr-2" />
                    {isRunning ? 'Running...' : 'Run Query'}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="border border-border rounded-lg overflow-hidden">
                <CodeMirror
                  value={query}
                  height="200px"
                  theme={oneDark}
                  extensions={[sql()]}
                  onChange={(value) => setQuery(value)}
                  basicSetup={{
                    lineNumbers: true,
                    highlightActiveLineGutter: true,
                    highlightSpecialChars: true,
                    foldGutter: true,
                    drawSelection: true,
                    dropCursor: true,
                    allowMultipleSelections: true,
                    indentOnInput: true,
                    syntaxHighlighting: true,
                    bracketMatching: true,
                    closeBrackets: true,
                    autocompletion: true,
                    rectangularSelection: true,
                    crosshairCursor: true,
                    highlightActiveLine: true,
                    highlightSelectionMatches: true,
                    closeBracketsKeymap: true,
                    defaultKeymap: true,
                    searchKeymap: true,
                    historyKeymap: true,
                    foldKeymap: true,
                    completionKeymap: true,
                    lintKeymap: true,
                  }}
                />
              </div>
            </CardContent>
          </Card>

          {/* Results */}
          <Card className="flex-1 mt-4 flex flex-col min-h-0">
            <CardHeader className="pb-2 shrink-0">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <CardTitle className="text-base">Results</CardTitle>
                  {queryStats && (
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <Clock className="w-4 h-4" />
                        {formatDuration(queryStats.duration)}
                      </span>
                      <span>{queryStats.rows} rows</span>
                    </div>
                  )}
                </div>
                {results && (
                  <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm">
                      <Copy className="w-4 h-4 mr-2" />
                      Copy
                    </Button>
                    <Button variant="outline" size="sm">
                      <Download className="w-4 h-4 mr-2" />
                      Export CSV
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent className="flex-1 min-h-0">
              {results ? (
                <ScrollArea className="h-full">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        {Object.keys(results[0] || {}).map((key) => (
                          <TableHead key={key} className="font-mono text-xs">
                            {key}
                          </TableHead>
                        ))}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.map((row, i) => (
                        <TableRow key={i}>
                          {Object.entries(row).map(([key, value]) => (
                            <TableCell key={key} className="font-mono text-sm">
                              {key === 'severity' ? (
                                <Badge
                                  variant={
                                    value === 'critical'
                                      ? 'critical'
                                      : value === 'high'
                                        ? 'high'
                                        : 'medium'
                                  }
                                >
                                  {value}
                                </Badge>
                              ) : (
                                value
                              )}
                            </TableCell>
                          ))}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  <div className="text-center">
                    <Database className="w-12 h-12 mx-auto mb-4 opacity-20" />
                    <p>Run a query to see results</p>
                    <p className="text-sm">
                      Press{' '}
                      <kbd className="px-1 py-0.5 bg-muted rounded text-xs">
                        Ctrl+Enter
                      </kbd>{' '}
                      to execute
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="w-80 shrink-0">
          <Tabs defaultValue="saved" className="h-full">
            <TabsList className="w-full">
              <TabsTrigger value="saved" className="flex-1">
                <BookMarked className="w-4 h-4 mr-2" />
                Saved
              </TabsTrigger>
              <TabsTrigger value="history" className="flex-1">
                <History className="w-4 h-4 mr-2" />
                History
              </TabsTrigger>
            </TabsList>

            <TabsContent value="saved" className="mt-4">
              <Card className="h-[calc(100vh-320px)]">
                <CardContent className="pt-6">
                  <ScrollArea className="h-full">
                    <div className="space-y-2">
                      {savedQueries.map((q) => (
                        <div
                          key={q.id}
                          className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                          onClick={() => setQuery(q.query)}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <p className="font-medium text-sm">{q.name}</p>
                            <span className="text-xs text-muted-foreground">
                              {q.updated}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground font-mono truncate">
                            {q.query}
                          </p>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="history" className="mt-4">
              <Card className="h-[calc(100vh-320px)]">
                <CardContent className="pt-6">
                  <ScrollArea className="h-full">
                    <div className="space-y-2">
                      {queryHistory.map((q) => (
                        <div
                          key={q.id}
                          className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                          onClick={() => setQuery(q.query)}
                        >
                          <p className="text-xs text-muted-foreground font-mono truncate mb-2">
                            {q.query}
                          </p>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground">
                            <span>{formatDuration(q.duration)}</span>
                            <span>{q.rows} rows</span>
                            <span className="ml-auto">{q.time}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>
      </div>

      {/* AI Assistant Panel */}
      <Sheet open={showCopilot} onOpenChange={setShowCopilot}>
        <SheetContent side="right" className="w-[450px] sm:w-[540px] p-0">
          <SheetHeader className="sr-only">
            <SheetTitle>AI Assistant</SheetTitle>
          </SheetHeader>
          <CopilotChat
            config={copilotConfig}
            contextData={{ currentQuery: query }}
            onQueryResult={handleQueryResult}
            className="h-full border-0 rounded-none"
          />
        </SheetContent>
      </Sheet>
    </div>
  );
}
