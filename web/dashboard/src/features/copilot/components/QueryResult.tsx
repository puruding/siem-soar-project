/**
 * QueryResult - Display component for SQL query results with visualization options.
 */
import { memo, useState, useMemo } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { cn } from '@/lib/utils';
import {
  Download,
  Copy,
  Check,
  Table2,
  BarChart3,
  Code,
  Clock,
  Database,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from 'lucide-react';

export interface QueryResultData {
  columns: string[];
  rows: Record<string, unknown>[];
  totalRows: number;
  executionTime?: number;
  query?: string;
  warnings?: string[];
}

interface QueryResultProps {
  data: QueryResultData;
  className?: string;
  maxHeight?: string;
  showQuery?: boolean;
  onRowClick?: (row: Record<string, unknown>, index: number) => void;
  onExport?: (format: 'csv' | 'json') => void;
}

function QueryResultComponent({
  data,
  className,
  maxHeight = '400px',
  showQuery = true,
  onRowClick,
  onExport,
}: QueryResultProps) {
  const [copied, setCopied] = useState(false);
  const [queryExpanded, setQueryExpanded] = useState(false);
  const [activeView, setActiveView] = useState<'table' | 'json'>('table');

  const copyToClipboard = async (text: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportCSV = () => {
    if (onExport) {
      onExport('csv');
      return;
    }

    const headers = data.columns.join(',');
    const rows = data.rows.map((row) =>
      data.columns.map((col) => {
        const value = row[col];
        if (typeof value === 'string' && value.includes(',')) {
          return `"${value}"`;
        }
        return String(value ?? '');
      }).join(',')
    );
    const csv = [headers, ...rows].join('\n');
    downloadFile(csv, 'query-results.csv', 'text/csv');
  };

  const handleExportJSON = () => {
    if (onExport) {
      onExport('json');
      return;
    }

    const json = JSON.stringify(data.rows, null, 2);
    downloadFile(json, 'query-results.json', 'application/json');
  };

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityVariant = (value: unknown): 'critical' | 'high' | 'medium' | 'low' | 'info' | undefined => {
    const val = String(value).toLowerCase();
    if (val === 'critical') return 'critical';
    if (val === 'high') return 'high';
    if (val === 'medium') return 'medium';
    if (val === 'low') return 'low';
    if (val === 'info') return 'info';
    return undefined;
  };

  const formatCellValue = (value: unknown, column: string): React.ReactNode => {
    if (value === null || value === undefined) {
      return <span className="text-muted-foreground italic">null</span>;
    }

    // Handle severity columns
    if (column.toLowerCase().includes('severity')) {
      const variant = getSeverityVariant(value);
      if (variant) {
        return <Badge variant={variant}>{String(value)}</Badge>;
      }
    }

    // Handle status columns
    if (column.toLowerCase().includes('status')) {
      const val = String(value).toLowerCase();
      if (val === 'open' || val === 'active') {
        return <Badge variant="warning">{String(value)}</Badge>;
      }
      if (val === 'closed' || val === 'resolved') {
        return <Badge variant="success">{String(value)}</Badge>;
      }
      if (val === 'in_progress' || val === 'pending') {
        return <Badge variant="info">{String(value)}</Badge>;
      }
    }

    // Handle IP addresses
    if (column.toLowerCase().includes('ip')) {
      return (
        <span className="font-mono text-neon-cyan">{String(value)}</span>
      );
    }

    // Handle timestamps
    if (column.toLowerCase().includes('time') || column.toLowerCase().includes('date')) {
      try {
        const date = new Date(String(value));
        if (!isNaN(date.getTime())) {
          return (
            <span className="text-muted-foreground">
              {date.toLocaleString('ko-KR')}
            </span>
          );
        }
      } catch {
        // Not a valid date, fall through
      }
    }

    // Handle boolean
    if (typeof value === 'boolean') {
      return (
        <Badge variant={value ? 'success' : 'secondary'}>
          {value ? 'Yes' : 'No'}
        </Badge>
      );
    }

    // Handle objects/arrays
    if (typeof value === 'object') {
      return (
        <code className="text-xs bg-muted px-1 py-0.5 rounded">
          {JSON.stringify(value)}
        </code>
      );
    }

    return String(value);
  };

  const jsonView = useMemo(
    () => JSON.stringify(data.rows, null, 2),
    [data.rows]
  );

  return (
    <Card className={cn('overflow-hidden', className)}>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <CardTitle className="text-base flex items-center gap-2">
              <Database className="h-4 w-4 text-neon-cyan" />
              Query Results
            </CardTitle>
            <div className="flex items-center gap-3 text-sm text-muted-foreground">
              <span className="flex items-center gap-1">
                <Table2 className="h-3.5 w-3.5" />
                {data.totalRows} rows
              </span>
              {data.executionTime !== undefined && (
                <span className="flex items-center gap-1">
                  <Clock className="h-3.5 w-3.5" />
                  {data.executionTime}ms
                </span>
              )}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Tabs value={activeView} onValueChange={(v) => setActiveView(v as 'table' | 'json')}>
              <TabsList className="h-8">
                <TabsTrigger value="table" className="h-7 text-xs">
                  <Table2 className="h-3.5 w-3.5 mr-1" />
                  Table
                </TabsTrigger>
                <TabsTrigger value="json" className="h-7 text-xs">
                  <Code className="h-3.5 w-3.5 mr-1" />
                  JSON
                </TabsTrigger>
              </TabsList>
            </Tabs>
            <Button variant="outline" size="sm" onClick={handleExportCSV}>
              <Download className="h-3.5 w-3.5 mr-1" />
              CSV
            </Button>
            <Button variant="outline" size="sm" onClick={handleExportJSON}>
              <Download className="h-3.5 w-3.5 mr-1" />
              JSON
            </Button>
          </div>
        </div>

        {/* Show query */}
        {showQuery && data.query && (
          <div className="mt-3">
            <button
              onClick={() => setQueryExpanded(!queryExpanded)}
              className="flex items-center gap-2 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              {queryExpanded ? (
                <ChevronUp className="h-3.5 w-3.5" />
              ) : (
                <ChevronDown className="h-3.5 w-3.5" />
              )}
              {queryExpanded ? 'Hide Query' : 'Show Query'}
            </button>
            {queryExpanded && (
              <div className="mt-2 relative group">
                <pre className="bg-background/50 border border-border rounded-lg p-3 overflow-x-auto text-xs font-mono">
                  {data.query}
                </pre>
                <button
                  onClick={() => copyToClipboard(data.query!)}
                  className="absolute top-2 right-2 p-1 rounded hover:bg-muted transition-colors opacity-0 group-hover:opacity-100"
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-neon-green" />
                  ) : (
                    <Copy className="h-4 w-4 text-muted-foreground" />
                  )}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Warnings */}
        {data.warnings && data.warnings.length > 0 && (
          <div className="mt-3 p-2 bg-neon-orange/10 border border-neon-orange/20 rounded-lg">
            <p className="text-xs text-neon-orange font-medium mb-1">Warnings:</p>
            <ul className="text-xs text-muted-foreground space-y-0.5">
              {data.warnings.map((warning, i) => (
                <li key={i}>{warning}</li>
              ))}
            </ul>
          </div>
        )}
      </CardHeader>

      <CardContent className="pt-0">
        {activeView === 'table' ? (
          <ScrollArea style={{ maxHeight }} className="rounded-lg border border-border">
            <Table>
              <TableHeader className="sticky top-0 bg-muted/80 backdrop-blur-sm z-10">
                <TableRow>
                  {data.columns.map((column) => (
                    <TableHead key={column} className="font-mono text-xs whitespace-nowrap">
                      {column}
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.rows.length > 0 ? (
                  data.rows.map((row, rowIndex) => (
                    <TableRow
                      key={rowIndex}
                      className={cn(
                        onRowClick && 'cursor-pointer hover:bg-muted/50'
                      )}
                      onClick={() => onRowClick?.(row, rowIndex)}
                    >
                      {data.columns.map((column) => (
                        <TableCell key={column} className="font-mono text-sm py-2">
                          {formatCellValue(row[column], column)}
                        </TableCell>
                      ))}
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell
                      colSpan={data.columns.length}
                      className="h-24 text-center text-muted-foreground"
                    >
                      No results found
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </ScrollArea>
        ) : (
          <div className="relative group">
            <ScrollArea style={{ maxHeight }} className="rounded-lg border border-border">
              <pre className="p-4 text-xs font-mono">{jsonView}</pre>
            </ScrollArea>
            <button
              onClick={() => copyToClipboard(jsonView)}
              className="absolute top-2 right-4 p-1.5 rounded hover:bg-muted transition-colors opacity-0 group-hover:opacity-100"
            >
              {copied ? (
                <Check className="h-4 w-4 text-neon-green" />
              ) : (
                <Copy className="h-4 w-4 text-muted-foreground" />
              )}
            </button>
          </div>
        )}

        {data.rows.length > 0 && data.rows.length < data.totalRows && (
          <div className="mt-3 text-center">
            <p className="text-xs text-muted-foreground">
              Showing {data.rows.length} of {data.totalRows} rows
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

export const QueryResult = memo(QueryResultComponent);
