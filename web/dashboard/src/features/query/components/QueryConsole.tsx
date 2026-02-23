import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import { SQLEditor } from '@/components/ui/sql-editor';
import { BarChart } from '@/components/widgets/BarChart';
import { PieChart } from '@/components/widgets/PieChart';
import { LineChart } from '@/components/widgets/LineChart';
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
  AlertCircle,
  Loader2,
  TableIcon,
  ChevronRight,
  Key,
  Hash,
  Type,
  Calendar,
  ToggleLeft,
  MessageSquare,
  ArrowRight,
  Wand2,
  BarChart3,
  PieChartIcon,
  LineChartIcon,
  LayoutGrid,
  XCircle,
  Timer,
} from 'lucide-react';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { formatDuration } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { QueryResultData } from '@/features/copilot/components/QueryResult';
import { useToast } from '@/components/ui/toaster';
import {
  executeQuery,
  getQueryHistory,
  getSavedQueries,
  saveQuery,
  deleteSavedQuery,
  getSchema,
  validateQuery,
  downloadQueryResults,
  rowsToObjects,
  type QueryHistoryItem as ApiQueryHistoryItem,
  type SavedQuery as ApiSavedQuery,
  type SchemaTable as ApiSchemaTable,
  type QueryLanguage,
} from '../api/queryApi';

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

// Mock data store for different tables
const mockDataStore: Record<string, Record<string, unknown>[]> = {
  events: [
    { id: 'evt-001', event_time: '2024-01-15 14:32:15', event_type: 'malware_detected', source_ip: '192.168.1.45', destination_ip: '10.0.0.5', severity: 'critical', description: 'Ransomware signature detected', user: 'admin', hostname: 'ws-prod-01' },
    { id: 'evt-002', event_time: '2024-01-15 14:31:42', event_type: 'failed_login', source_ip: '203.45.67.89', destination_ip: '10.0.0.10', severity: 'high', description: 'Multiple failed login attempts', user: 'john.doe', hostname: 'dc-main' },
    { id: 'evt-003', event_time: '2024-01-15 14:30:58', event_type: 'port_scan', source_ip: '192.168.1.100', destination_ip: '10.0.0.0/24', severity: 'high', description: 'Horizontal port scan detected', user: 'scanner', hostname: 'scanner-01' },
    { id: 'evt-004', event_time: '2024-01-15 14:29:33', event_type: 'data_exfil', source_ip: '192.168.1.22', destination_ip: '185.45.67.89', severity: 'critical', description: 'Large data transfer to external IP', user: 'compromised', hostname: 'ws-hr-05' },
    { id: 'evt-005', event_time: '2024-01-15 14:28:17', event_type: 'privilege_escalation', source_ip: '192.168.1.15', destination_ip: '10.0.0.1', severity: 'high', description: 'Unauthorized privilege elevation', user: 'attacker', hostname: 'ws-dev-03' },
  ],
  alerts: [
    { id: 'alt-001', alert_time: '2024-01-15 14:35:00', title: 'Ransomware Attack Detected', severity: 'critical', status: 'open', source: 'EDR', assigned_to: 'analyst1', priority: 1 },
    { id: 'alt-002', alert_time: '2024-01-15 14:33:00', title: 'Brute Force Attack', severity: 'high', status: 'investigating', source: 'SIEM', assigned_to: 'analyst2', priority: 2 },
    { id: 'alt-003', alert_time: '2024-01-15 14:30:00', title: 'Network Scan Detected', severity: 'medium', status: 'open', source: 'IDS', assigned_to: null, priority: 3 },
    { id: 'alt-004', alert_time: '2024-01-15 14:25:00', title: 'Data Exfiltration Attempt', severity: 'critical', status: 'closed', source: 'DLP', assigned_to: 'analyst1', priority: 1 },
  ],
  users: [
    { id: 'usr-001', username: 'admin', email: 'admin@company.com', role: 'administrator', last_login: '2024-01-15 14:00:00', status: 'active' },
    { id: 'usr-002', username: 'john.doe', email: 'john.doe@company.com', role: 'analyst', last_login: '2024-01-15 13:45:00', status: 'active' },
    { id: 'usr-003', username: 'jane.smith', email: 'jane.smith@company.com', role: 'analyst', last_login: '2024-01-14 18:30:00', status: 'active' },
  ],
  assets: [
    { id: 'ast-001', hostname: 'ws-prod-01', ip_address: '192.168.1.45', os: 'Windows 11', department: 'Production', criticality: 'high', last_seen: '2024-01-15 14:32:00' },
    { id: 'ast-002', hostname: 'dc-main', ip_address: '10.0.0.10', os: 'Windows Server 2022', department: 'IT', criticality: 'critical', last_seen: '2024-01-15 14:31:00' },
    { id: 'ast-003', hostname: 'ws-hr-05', ip_address: '192.168.1.22', os: 'Windows 10', department: 'HR', criticality: 'medium', last_seen: '2024-01-15 14:29:00' },
  ],
};

// Extract date/time parts from a datetime string (handles ClickHouse toHour/toDate etc.)
function extractDatePart(dateStr: string, part: 'hour' | 'date' | 'month' | 'year' | 'dayofweek'): string | number {
  try {
    const date = new Date(dateStr.replace(' ', 'T'));
    switch (part) {
      case 'hour':
        return date.getHours();
      case 'date':
        return date.toISOString().split('T')[0] ?? dateStr;
      case 'month':
        return date.getMonth() + 1;
      case 'year':
        return date.getFullYear();
      case 'dayofweek':
        return date.getDay();
      default:
        return dateStr;
    }
  } catch {
    return 'unknown';
  }
}

// Parse SQL query and generate mock results
function generateMockResults(sqlQuery: string): Record<string, unknown>[] {
  // Remove SQL comments before parsing
  const queryWithoutComments = sqlQuery
    .replace(/--.*$/gm, '')           // Remove single-line comments (-- ...)
    .replace(/\/\*[\s\S]*?\*\//g, ''); // Remove multi-line comments (/* ... */)

  const normalizedQuery = queryWithoutComments.replace(/\s+/g, ' ').trim().toLowerCase();

  // Extract table name
  const fromMatch = normalizedQuery.match(/from\s+(\w+)/i);
  const tableName = fromMatch?.[1]?.toLowerCase() ?? 'events';

  // Check table existence
  const validTables = Object.keys(mockDataStore);
  if (!validTables.includes(tableName)) {
    throw new Error(`Table '${tableName}' does not exist. Available tables: ${validTables.join(', ')}`);
  }

  // Get base data for the table
  const baseData = mockDataStore[tableName];

  // Guard against undefined baseData
  if (!baseData) {
    throw new Error(`No data found for table '${tableName}'`);
  }

  // Check if it's a COUNT query with GROUP BY
  if (normalizedQuery.includes('count(*)') || normalizedQuery.includes('count(1)')) {
    const groupByMatch = normalizedQuery.match(/group\s+by\s+([\w,\s]+?)(?=\s+order\s|\s+limit\s|\s+having\s|\s*$)/i);

    if (groupByMatch?.[1]) {
      const groupByColumn = groupByMatch[1].trim();

      // Check for function aliases in SELECT clause
      // e.g., toHour(event_time) as hour → need to apply toHour to event_time
      const selectClause = normalizedQuery.match(/select\s+([\s\S]+?)\s+from/i)?.[1] || '';

      // Parse function mappings: toHour(col) as alias, toDate(col) as alias
      const functionMappings: Record<string, { func: string; column: string }> = {};
      const funcPattern = /to(hour|date|month|year|dayofweek)\s*\(\s*(\w+)\s*\)\s+as\s+(\w+)/gi;
      let funcMatch;
      while ((funcMatch = funcPattern.exec(selectClause)) !== null) {
        const funcName = (funcMatch[1] ?? '').toLowerCase();
        const sourceColumn = funcMatch[2] ?? '';
        const alias = (funcMatch[3] ?? '').toLowerCase();
        if (funcName && sourceColumn && alias) {
          functionMappings[alias] = { func: funcName, column: sourceColumn };
        }
      }

      const grouped: Record<string, number> = {};
      baseData.forEach((row) => {
        let key: string | number;

        // Check if groupByColumn is a function alias
        if (functionMappings[groupByColumn]) {
          const { func, column } = functionMappings[groupByColumn];
          const sourceValue = String(row[column] ?? '');
          key = extractDatePart(sourceValue, func as 'hour' | 'date' | 'month' | 'year' | 'dayofweek');
        } else {
          // Direct column access
          key = String(row[groupByColumn] ?? 'unknown');
        }

        const keyStr = String(key);
        grouped[keyStr] = (grouped[keyStr] ?? 0) + 1;
      });

      // Sort results numerically if possible, otherwise alphabetically
      const sortedEntries = Object.entries(grouped).sort((a, b) => {
        const aNum = Number(a[0]);
        const bNum = Number(b[0]);
        if (!isNaN(aNum) && !isNaN(bNum)) {
          return aNum - bNum;
        }
        return a[0].localeCompare(b[0]);
      });

      // Use the alias from SELECT if available (e.g., error_count instead of count)
      const countAliasMatch = selectClause.match(/count\s*\(\s*\*\s*\)\s+as\s+(\w+)/i);
      const countAlias = countAliasMatch?.[1] || 'count';

      return sortedEntries.map(([key, count]) => ({
        [groupByColumn]: isNaN(Number(key)) ? key : Number(key),
        [countAlias]: count,
      }));
    }

    return [{ count: baseData.length }];
  }

  // Extract SELECT columns
  const selectMatch = normalizedQuery.match(/select\s+([\s\S]+?)\s+from/i);
  let columns: string[] = [];

  if (selectMatch?.[1]) {
    const selectPart = selectMatch[1].trim();
    if (selectPart === '*') {
      // Return all columns
      const firstRow = baseData[0];
      columns = firstRow ? Object.keys(firstRow) : [];
    } else {
      // Parse column list
      columns = selectPart
        .split(',')
        .map((col) => col.trim().replace(/\s+as\s+\w+/i, '').trim())
        .filter((col) => col && !col.includes('('));
    }
  }

  // Apply WHERE filter if present
  let filteredData = [...baseData];
  const whereMatch = normalizedQuery.match(/where\s+([\s\S]+?)(?:order|group|limit|$)/i);
  if (whereMatch?.[1]) {
    const whereClause = whereMatch[1].trim();

    // Simple equality filter: column = 'value'
    const eqMatch = whereClause.match(/(\w+)\s*=\s*['"]([^'"]+)['"]/);
    if (eqMatch) {
      const col = eqMatch[1];
      const val = eqMatch[2];
      if (col && val) {
        filteredData = filteredData.filter((row) =>
          String(row[col] ?? '').toLowerCase() === val.toLowerCase()
        );
      }
    }

    // IN filter: column IN ('value1', 'value2')
    const inMatch = whereClause.match(/(\w+)\s+in\s*\(\s*([^)]+)\s*\)/i);
    if (inMatch) {
      const col = inMatch[1];
      const valuesStr = inMatch[2];
      if (col && valuesStr) {
        const values = valuesStr.split(',').map((v) => v.trim().replace(/['"]/g, '').toLowerCase());
        filteredData = filteredData.filter((row) =>
          values.includes(String(row[col] ?? '').toLowerCase())
        );
      }
    }
  }

  // Apply LIMIT
  const limitMatch = normalizedQuery.match(/limit\s+(\d+)/i);
  const limitStr = limitMatch?.[1];
  const limit = limitStr ? parseInt(limitStr, 10) : filteredData.length;
  filteredData = filteredData.slice(0, limit);

  // Project only selected columns
  if (columns.length > 0) {
    return filteredData.map((row) => {
      const projected: Record<string, unknown> = {};
      columns.forEach((col) => {
        if (col in row) {
          projected[col] = row[col];
        }
      });
      return projected;
    });
  }

  return filteredData;
}

// Default query history (used as fallback when localStorage is empty)
const queryHistory: LocalQueryHistoryItem[] = [
  {
    id: '1',
    query: 'SELECT * FROM events WHERE severity = "critical" LIMIT 100',
    duration: 245,
    rows: 47,
    time: '5m ago',
    timestamp: Date.now() - 5 * 60 * 1000,
    language: 'sql',
  },
  {
    id: '2',
    query: 'SELECT COUNT(*) FROM alerts GROUP BY severity',
    duration: 89,
    rows: 4,
    time: '15m ago',
    timestamp: Date.now() - 15 * 60 * 1000,
    language: 'sql',
  },
  {
    id: '3',
    query: 'SELECT * FROM events WHERE source_ip = "192.168.1.45"',
    duration: 156,
    rows: 23,
    time: '1h ago',
    timestamp: Date.now() - 60 * 60 * 1000,
    language: 'sql',
  },
];

// Database schema definition
interface SchemaColumn {
  name: string;
  type: string;
  nullable: boolean;
  isPrimaryKey?: boolean;
  description?: string;
}

interface SchemaTable {
  name: string;
  description: string;
  columns: SchemaColumn[];
  rowCount?: number;
}

const databaseSchema: SchemaTable[] = [
  {
    name: 'events',
    description: 'Security events from all sources',
    rowCount: 1250000,
    columns: [
      { name: 'id', type: 'String', nullable: false, isPrimaryKey: true, description: 'Unique event identifier' },
      { name: 'event_time', type: 'DateTime', nullable: false, description: 'Event timestamp' },
      { name: 'event_type', type: 'String', nullable: false, description: 'Type of security event' },
      { name: 'source_ip', type: 'String', nullable: true, description: 'Source IP address' },
      { name: 'destination_ip', type: 'String', nullable: true, description: 'Destination IP address' },
      { name: 'severity', type: 'Enum', nullable: false, description: 'Event severity level' },
      { name: 'description', type: 'String', nullable: true, description: 'Event description' },
      { name: 'user', type: 'String', nullable: true, description: 'Associated username' },
      { name: 'hostname', type: 'String', nullable: true, description: 'Source hostname' },
      { name: 'raw_log', type: 'String', nullable: true, description: 'Original raw log message' },
    ],
  },
  {
    name: 'alerts',
    description: 'Generated security alerts',
    rowCount: 8500,
    columns: [
      { name: 'id', type: 'String', nullable: false, isPrimaryKey: true, description: 'Alert ID' },
      { name: 'alert_time', type: 'DateTime', nullable: false, description: 'Alert creation time' },
      { name: 'title', type: 'String', nullable: false, description: 'Alert title' },
      { name: 'severity', type: 'Enum', nullable: false, description: 'Alert severity' },
      { name: 'status', type: 'Enum', nullable: false, description: 'Alert status' },
      { name: 'source', type: 'String', nullable: true, description: 'Alert source system' },
      { name: 'assigned_to', type: 'String', nullable: true, description: 'Assigned analyst' },
      { name: 'priority', type: 'Int32', nullable: false, description: 'Alert priority (1-5)' },
      { name: 'mitre_tactic', type: 'String', nullable: true, description: 'MITRE ATT&CK tactic' },
      { name: 'mitre_technique', type: 'String', nullable: true, description: 'MITRE ATT&CK technique' },
    ],
  },
  {
    name: 'users',
    description: 'User accounts and profiles',
    rowCount: 1250,
    columns: [
      { name: 'id', type: 'String', nullable: false, isPrimaryKey: true, description: 'User ID' },
      { name: 'username', type: 'String', nullable: false, description: 'Username' },
      { name: 'email', type: 'String', nullable: false, description: 'Email address' },
      { name: 'role', type: 'Enum', nullable: false, description: 'User role' },
      { name: 'department', type: 'String', nullable: true, description: 'Department' },
      { name: 'last_login', type: 'DateTime', nullable: true, description: 'Last login time' },
      { name: 'status', type: 'Enum', nullable: false, description: 'Account status' },
      { name: 'risk_score', type: 'Float32', nullable: true, description: 'User risk score (0-100)' },
    ],
  },
  {
    name: 'assets',
    description: 'Network assets and endpoints',
    rowCount: 3200,
    columns: [
      { name: 'id', type: 'String', nullable: false, isPrimaryKey: true, description: 'Asset ID' },
      { name: 'hostname', type: 'String', nullable: false, description: 'Hostname' },
      { name: 'ip_address', type: 'String', nullable: false, description: 'IP address' },
      { name: 'mac_address', type: 'String', nullable: true, description: 'MAC address' },
      { name: 'os', type: 'String', nullable: true, description: 'Operating system' },
      { name: 'os_version', type: 'String', nullable: true, description: 'OS version' },
      { name: 'department', type: 'String', nullable: true, description: 'Department' },
      { name: 'criticality', type: 'Enum', nullable: false, description: 'Asset criticality level' },
      { name: 'last_seen', type: 'DateTime', nullable: true, description: 'Last activity time' },
      { name: 'agent_version', type: 'String', nullable: true, description: 'Security agent version' },
    ],
  },
  {
    name: 'network_flows',
    description: 'Network traffic flow records',
    rowCount: 45000000,
    columns: [
      { name: 'id', type: 'UInt64', nullable: false, isPrimaryKey: true, description: 'Flow ID' },
      { name: 'timestamp', type: 'DateTime', nullable: false, description: 'Flow timestamp' },
      { name: 'src_ip', type: 'String', nullable: false, description: 'Source IP' },
      { name: 'dst_ip', type: 'String', nullable: false, description: 'Destination IP' },
      { name: 'src_port', type: 'UInt16', nullable: false, description: 'Source port' },
      { name: 'dst_port', type: 'UInt16', nullable: false, description: 'Destination port' },
      { name: 'protocol', type: 'String', nullable: false, description: 'Protocol (TCP/UDP/ICMP)' },
      { name: 'bytes_in', type: 'UInt64', nullable: false, description: 'Bytes received' },
      { name: 'bytes_out', type: 'UInt64', nullable: false, description: 'Bytes sent' },
      { name: 'packets', type: 'UInt32', nullable: false, description: 'Packet count' },
      { name: 'duration_ms', type: 'UInt32', nullable: true, description: 'Flow duration (ms)' },
    ],
  },
  {
    name: 'threat_intel',
    description: 'Threat intelligence indicators',
    rowCount: 125000,
    columns: [
      { name: 'id', type: 'String', nullable: false, isPrimaryKey: true, description: 'IOC ID' },
      { name: 'indicator', type: 'String', nullable: false, description: 'IOC value' },
      { name: 'type', type: 'Enum', nullable: false, description: 'IOC type (IP/domain/hash)' },
      { name: 'source', type: 'String', nullable: false, description: 'Intelligence source' },
      { name: 'confidence', type: 'Float32', nullable: false, description: 'Confidence score (0-1)' },
      { name: 'severity', type: 'Enum', nullable: false, description: 'Threat severity' },
      { name: 'first_seen', type: 'DateTime', nullable: false, description: 'First observed' },
      { name: 'last_seen', type: 'DateTime', nullable: true, description: 'Last observed' },
      { name: 'tags', type: 'Array(String)', nullable: true, description: 'Associated tags' },
    ],
  },
];

// Helper to get type icon
function getTypeIcon(type: string) {
  if (type.includes('Int') || type.includes('Float') || type.includes('UInt')) return Hash;
  if (type.includes('DateTime') || type.includes('Date')) return Calendar;
  if (type.includes('Bool') || type.includes('Enum')) return ToggleLeft;
  return Type;
}

// Format row count
function formatRowCount(count: number): string {
  if (count >= 1000000) return `${(count / 1000000).toFixed(1)}M`;
  if (count >= 1000) return `${(count / 1000).toFixed(1)}K`;
  return count.toString();
}

const copilotConfig: CopilotConfig = {
  apiEndpoint: '/api',
  wsEndpoint: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`,
  language: 'auto',
  streamingEnabled: false,
  mockMode: true,
};

// API configuration
const USE_MOCK_DATA = import.meta.env.VITE_USE_MOCK_DATA === 'true' || !import.meta.env.VITE_QUERY_API_URL;

// Local history item type (extended from API type for UI state)
interface LocalQueryHistoryItem {
  id: string;
  query: string;
  duration: number;
  rows: number;
  time: string;
  timestamp: number;
  language?: QueryLanguage;
}

interface QueryError {
  message: string;
  code?: string;
  details?: string;
}

interface LocalValidationError {
  code: string;
  message: string;
  position?: number;
  line?: number;
  severity: 'error' | 'warning';
}

// Client-side SQL syntax validator
function validateSQLLocal(sql: string): LocalValidationError[] {
  const errors: LocalValidationError[] = [];
  const trimmed = sql.trim();

  if (!trimmed) return errors;

  // Strip comment lines for keyword analysis
  const withoutComments = trimmed
    .split('\n')
    .filter((line) => !line.trim().startsWith('--'))
    .join('\n');

  const upper = withoutComments.toUpperCase().replace(/\s+/g, ' ').trim();

  // Must start with a valid DML/DDL keyword
  const validStartKeywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'WITH', 'EXPLAIN', 'SHOW', 'DESCRIBE', 'DESC', 'CREATE', 'DROP', 'ALTER', 'TRUNCATE'];
  const startsWithValid = validStartKeywords.some((kw) => upper.startsWith(kw));

  if (!startsWithValid) {
    // Try to detect common typos like SELEC, SLECT, etc.
    const firstWord = upper.split(/\s+/)[0] ?? '';
    errors.push({
      code: 'INVALID_KEYWORD',
      message: `Syntax error at line 1, position 0: Unknown keyword '${firstWord}'`,
      line: 1,
      position: 0,
      severity: 'error',
    });
    return errors;
  }

  // For SELECT queries: require FROM clause (unless SELECT 1 / SELECT now() style)
  if (upper.startsWith('SELECT')) {
    const hasFrom = /\bFROM\b/.test(upper);
    const hasSubqueryOrConst = /^SELECT\s+[\d'"]/.test(upper) || /^SELECT\s+\w+\s*\(/.test(upper);

    if (!hasFrom && !hasSubqueryOrConst) {
      // Find approximate line number of FROM absence
      errors.push({
        code: 'MISSING_FROM',
        message: "Syntax error: SELECT statement is missing a FROM clause",
        severity: 'error',
      });
    }

    // Check for unbalanced parentheses
    let depth = 0;
    let errorPos: number | undefined;
    for (let i = 0; i < trimmed.length; i++) {
      if (trimmed[i] === '(') depth++;
      else if (trimmed[i] === ')') {
        depth--;
        if (depth < 0) {
          errorPos = i;
          break;
        }
      }
    }
    if (depth !== 0 || errorPos !== undefined) {
      const lines = trimmed.substring(0, errorPos ?? trimmed.length).split('\n');
      errors.push({
        code: 'UNBALANCED_PARENS',
        message: `Syntax error: Unbalanced parentheses${errorPos !== undefined ? ` at position ${errorPos}` : ''}`,
        line: lines.length,
        position: errorPos,
        severity: 'error',
      });
    }

    // Warn about SELECT * in large queries
    if (/SELECT\s+\*/.test(upper) && /WHERE/.test(upper) === false) {
      errors.push({
        code: 'SELECT_STAR_NO_WHERE',
        message: "Warning: SELECT * without WHERE clause may return very large result sets",
        severity: 'warning',
      });
    }
  }

  // Check for unknown table names in FROM clause
  const tableMatch = withoutComments.match(/from\s+(\w+)/i);
  if (tableMatch?.[1]) {
    const tableName = tableMatch[1].toLowerCase();
    const knownTables = ['events', 'alerts', 'cases', 'assets', 'users', 'threats', 'logs', 'network_flows', 'threat_intel'];
    if (!knownTables.includes(tableName)) {
      const normalizedForPos = withoutComments.toUpperCase().replace(/\s+/g, ' ').trim();
      errors.push({
        code: 'UNKNOWN_TABLE',
        message: `Unknown table '${tableMatch[1]}'. Known tables: ${knownTables.join(', ')}`,
        severity: 'error',
        line: 1,
        position: normalizedForPos.indexOf(tableMatch[1].toUpperCase()) + 1,
      });
    }
  }

  // Check for common misspelled keywords (nearby to valid keywords)
  const misspellings: Array<{ pattern: RegExp; suggestion: string; keyword: string }> = [
    { pattern: /\bSELEC\b/, suggestion: 'SELECT', keyword: 'SELEC' },
    { pattern: /\bSELECT\b.*\bFROM\b.*\bWHER\b(?!E)/, suggestion: 'WHERE', keyword: 'WHER' },
    { pattern: /\bFRON\b/, suggestion: 'FROM', keyword: 'FRON' },
    { pattern: /\bORDED\b/, suggestion: 'ORDER', keyword: 'ORDED' },
    { pattern: /\bGROUB\b/, suggestion: 'GROUP', keyword: 'GROUB' },
    { pattern: /\bHAVING\b.*\bWHEEE\b/, suggestion: 'WHERE', keyword: 'WHEEE' },
    { pattern: /\bLIMT\b/, suggestion: 'LIMIT', keyword: 'LIMT' },
    { pattern: /\bINSERT\s+INOT\b/, suggestion: 'INTO', keyword: 'INOT' },
  ];

  for (const { pattern, suggestion, keyword } of misspellings) {
    if (pattern.test(upper)) {
      const idx = upper.indexOf(keyword);
      const linesBefore = trimmed.substring(0, idx).split('\n');
      errors.push({
        code: 'MISSPELLED_KEYWORD',
        message: `Syntax error: Unknown keyword '${keyword}'. Did you mean '${suggestion}'?`,
        line: linesBefore.length,
        position: idx,
        severity: 'error',
      });
    }
  }

  return errors;
}

export function QueryConsole() {
  const { toast } = useToast();
  const [query, setQuery] = useState(defaultQuery);
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<Record<string, unknown>[] | null>(null);
  const [queryStats, setQueryStats] = useState<{
    duration: number;
    rows: number;
  } | null>(null);
  const [showCopilot, setShowCopilot] = useState(false);
  const [showSchema, setShowSchema] = useState(false);
  const [expandedTables, setExpandedTables] = useState<Set<string>>(new Set(['events']));
  const [error, setError] = useState<QueryError | null>(null);
  const [localHistory, setLocalHistory] = useState<LocalQueryHistoryItem[]>(() => {
    // Load history from localStorage
    const saved = localStorage.getItem('query-history');
    return saved ? JSON.parse(saved) : queryHistory;
  });
  const [savedQueriesState, setSavedQueriesState] = useState<ApiSavedQuery[]>([]);
  const [isLoadingSaved, setIsLoadingSaved] = useState(false);
  const [queryLanguage, setQueryLanguage] = useState<QueryLanguage>('sql');

  // NL2SQL state
  const [nlQuery, setNlQuery] = useState('');
  const [isConverting, setIsConverting] = useState(false);
  const [sqlExplanation, setSqlExplanation] = useState<{
    originalQuery: string;
    explanation: string;
  } | null>(null);

  // Validation state
  const [validationErrors, setValidationErrors] = useState<LocalValidationError[]>([]);

  // Visualization state
  const [viewMode, setViewMode] = useState<'table' | 'chart'>('table');
  const [chartType, setChartType] = useState<'bar' | 'pie' | 'line'>('bar');

  // Timeout and cancellation state
  const [queryTimeout, setQueryTimeout] = useState<number>(30);
  const [elapsedTime, setElapsedTime] = useState<number>(0);
  const abortControllerRef = useRef<AbortController | null>(null);
  const elapsedIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Read URL query parameters on mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const queryParam = urlParams.get('q');
    if (queryParam) {
      try {
        const decodedQuery = decodeURIComponent(queryParam);
        setQuery(decodedQuery);
      } catch {
        // If decoding fails, use the raw value
        setQuery(queryParam);
      }
    }
  }, []);

  // Save history to localStorage when it changes
  useEffect(() => {
    localStorage.setItem('query-history', JSON.stringify(localHistory));
  }, [localHistory]);

  // Debounced client-side SQL validation (300ms)
  useEffect(() => {
    const timer = setTimeout(() => {
      if (!query.trim()) {
        setValidationErrors([]);
        return;
      }
      const errors = validateSQLLocal(query);
      setValidationErrors(errors);
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  // Load saved queries from API
  useEffect(() => {
    const loadSavedQueries = async () => {
      setIsLoadingSaved(true);
      try {
        const response = await getSavedQueries();
        if (response.success && response.data) {
          setSavedQueriesState(response.data.items ?? []);
        }
      } catch (err) {
        console.error('Failed to load saved queries:', err);
      } finally {
        setIsLoadingSaved(false);
      }
    };
    loadSavedQueries();
  }, []);

  // Elapsed time tracking during query execution
  useEffect(() => {
    if (isRunning) {
      setElapsedTime(0);
      elapsedIntervalRef.current = setInterval(() => {
        setElapsedTime(prev => prev + 1);
      }, 1000);
    } else {
      if (elapsedIntervalRef.current) {
        clearInterval(elapsedIntervalRef.current);
        elapsedIntervalRef.current = null;
      }
    }
    return () => {
      if (elapsedIntervalRef.current) {
        clearInterval(elapsedIntervalRef.current);
      }
    };
  }, [isRunning]);

  const addToHistory = useCallback((queryText: string, duration: number, rows: number, language: QueryLanguage = 'sql') => {
    const newEntry: LocalQueryHistoryItem = {
      id: Date.now().toString(),
      query: queryText,
      duration,
      rows,
      time: 'just now',
      timestamp: Date.now(),
      language,
    };
    setLocalHistory((prev) => [newEntry, ...prev.slice(0, 49)]); // Keep last 50 queries
  }, []);

  // Cancel query execution
  const cancelQuery = useCallback(() => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
      abortControllerRef.current = null;
      setIsRunning(false);
      toast({
        title: 'Query Cancelled',
        description: 'Query execution was cancelled by user.',
      });
    }
  }, [toast]);

  // NL2SQL conversion function
  const convertNL2SQL = useCallback(async () => {
    if (!nlQuery.trim()) {
      toast({
        title: 'Empty Input',
        description: 'Please enter a natural language query.',
        variant: 'destructive',
      });
      return;
    }

    setIsConverting(true);

    try {
      // Try API first
      const response = await fetch('/api/v1/nl2sql', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: nlQuery,
          schema: databaseSchema.map(t => ({
            name: t.name,
            columns: t.columns.map(c => c.name),
          })),
        }),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success && data.sql) {
          setQuery(data.sql);
          setSqlExplanation({
            originalQuery: nlQuery,
            explanation: data.explanation || generateExplanation(nlQuery, data.sql),
          });
          toast({
            title: 'SQL Generated',
            description: 'Natural language query converted to SQL.',
            variant: 'success',
          });
          setNlQuery('');
          return;
        }
      }
      throw new Error('API unavailable');
    } catch {
      // Fallback: Generate mock SQL based on keywords
      const generatedSQL = generateMockSQL(nlQuery);
      const explanation = generateExplanation(nlQuery, generatedSQL);
      setQuery(generatedSQL);
      setSqlExplanation({
        originalQuery: nlQuery,
        explanation,
      });
      toast({
        title: 'SQL Generated',
        description: 'Natural language query converted to SQL. (Fallback mode)',
        variant: 'success',
      });
      setNlQuery('');
    } finally {
      setIsConverting(false);
    }
  }, [nlQuery, toast]);

  // Generate explanation for the SQL query
  const generateExplanation = (naturalLanguage: string, sql: string): string => {
    const lower = naturalLanguage.toLowerCase();
    const sqlLower = sql.toLowerCase();

    // Critical alerts
    if (lower.includes('critical') && (lower.includes('alert') || lower.includes('경보'))) {
      return '이 쿼리는 alerts 테이블에서 심각도가 "critical"인 경보를 조회합니다. 결과는 경보 발생 시간 기준 최신순으로 정렬되며, 최대 100건까지 표시됩니다.';
    }

    // High severity events
    if ((lower.includes('high') || lower.includes('높은')) && (lower.includes('severity') || lower.includes('심각'))) {
      return '이 쿼리는 events 테이블에서 심각도가 "critical" 또는 "high"인 이벤트를 조회합니다. 고위험 보안 이벤트를 빠르게 파악할 수 있습니다.';
    }

    // Failed logins
    if (lower.includes('failed') && lower.includes('login') || lower.includes('로그인') && lower.includes('실패')) {
      return '이 쿼리는 로그인 실패 이벤트를 조회합니다. 무차별 대입 공격(Brute Force)이나 비인가 접근 시도를 탐지하는 데 유용합니다.';
    }

    // Today's events
    if (lower.includes('today') || lower.includes('오늘')) {
      return '이 쿼리는 오늘 발생한 모든 보안 이벤트를 조회합니다. today() 함수를 사용하여 오늘 자정 이후의 이벤트만 필터링합니다.';
    }

    // Last hour
    if (lower.includes('last hour') || lower.includes('지난 1시간') || lower.includes('최근 1시간')) {
      return '이 쿼리는 최근 1시간 동안 발생한 이벤트를 조회합니다. INTERVAL 구문을 사용하여 현재 시간 기준 1시간 전까지의 데이터를 필터링합니다.';
    }

    // Count/Statistics
    if (lower.includes('count') || lower.includes('개수') || lower.includes('통계')) {
      return '이 쿼리는 심각도별 이벤트 개수를 집계합니다. GROUP BY를 사용하여 각 심각도 수준의 이벤트 분포를 파악할 수 있습니다.';
    }

    // IP search
    if (sqlLower.includes('source_ip') && sqlLower.includes('destination_ip')) {
      return '이 쿼리는 특정 IP 주소와 관련된 모든 이벤트를 조회합니다. 출발지(source_ip) 또는 목적지(destination_ip)로 해당 IP가 포함된 이벤트를 찾습니다.';
    }

    // User search
    if (lower.includes('user') || lower.includes('사용자')) {
      return '이 쿼리는 사용자 계정 정보를 조회합니다. 마지막 로그인 시간, 역할, 위험 점수 등을 확인할 수 있습니다.';
    }

    // Assets
    if (lower.includes('asset') || lower.includes('자산') || lower.includes('endpoint')) {
      return '이 쿼리는 네트워크 자산 정보를 조회합니다. 호스트명, IP 주소, 운영체제, 중요도 등의 자산 인벤토리를 확인할 수 있습니다.';
    }

    // Default explanation
    return `이 쿼리는 "${naturalLanguage}" 요청을 기반으로 생성되었습니다. events 테이블에서 최신 보안 이벤트를 조회하며, 시간 역순으로 정렬됩니다.`;
  };

  // Mock NL2SQL conversion based on keywords
  const generateMockSQL = (naturalLanguage: string): string => {
    const lower = naturalLanguage.toLowerCase();

    // Critical alerts
    if (lower.includes('critical') && (lower.includes('alert') || lower.includes('경보'))) {
      return `SELECT id, alert_time, title, severity, status, source
FROM alerts
WHERE severity = 'critical'
ORDER BY alert_time DESC
LIMIT 100`;
    }

    // High severity events
    if ((lower.includes('high') || lower.includes('높은')) && (lower.includes('severity') || lower.includes('심각'))) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE severity IN ('critical', 'high')
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Failed logins
    if (lower.includes('failed') && lower.includes('login') || lower.includes('로그인') && lower.includes('실패')) {
      return `SELECT event_time, source_ip, user, hostname, description
FROM events
WHERE event_type = 'failed_login'
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Today's events
    if (lower.includes('today') || lower.includes('오늘')) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE event_time >= today()
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Last hour
    if (lower.includes('last hour') || lower.includes('지난 1시간') || lower.includes('최근 1시간')) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE event_time >= now() - INTERVAL 1 HOUR
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Time-based error/event count (hourly analysis)
    if ((lower.includes('시간대별') || lower.includes('hourly') || lower.includes('by hour') || lower.includes('시간별')) &&
        (lower.includes('오류') || lower.includes('에러') || lower.includes('error'))) {
      let timeFilter = 'event_time >= now() - INTERVAL 1 DAY';
      if (lower.includes('한달') || lower.includes('1개월') || lower.includes('month')) {
        timeFilter = 'event_time >= now() - INTERVAL 1 MONTH';
      } else if (lower.includes('일주일') || lower.includes('1주') || lower.includes('week')) {
        timeFilter = 'event_time >= now() - INTERVAL 1 WEEK';
      }

      return `SELECT
  toHour(event_time) as hour,
  COUNT(*) as error_count
FROM events
WHERE ${timeFilter}
  AND (event_type LIKE '%error%' OR severity IN ('critical', 'high'))
GROUP BY hour
ORDER BY hour`;
    }

    // Daily error/event count
    if ((lower.includes('일별') || lower.includes('daily') || lower.includes('날짜별') || lower.includes('일자별')) &&
        (lower.includes('오류') || lower.includes('에러') || lower.includes('error') || lower.includes('발생'))) {
      let timeFilter = 'event_time >= now() - INTERVAL 1 MONTH';
      if (lower.includes('일주일') || lower.includes('1주') || lower.includes('week')) {
        timeFilter = 'event_time >= now() - INTERVAL 1 WEEK';
      }

      return `SELECT
  toDate(event_time) as date,
  COUNT(*) as error_count
FROM events
WHERE ${timeFilter}
  AND (event_type LIKE '%error%' OR severity IN ('critical', 'high'))
GROUP BY date
ORDER BY date`;
    }

    // Last month
    if (lower.includes('한달') || lower.includes('1개월') || lower.includes('last month') || lower.includes('지난달')) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE event_time >= now() - INTERVAL 1 MONTH
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Last week
    if (lower.includes('일주일') || lower.includes('1주') || lower.includes('last week') || lower.includes('지난주')) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE event_time >= now() - INTERVAL 1 WEEK
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Error events
    if (lower.includes('오류') || lower.includes('에러') || lower.includes('error')) {
      return `SELECT id, event_time, event_type, source_ip, severity, description
FROM events
WHERE event_type LIKE '%error%' OR severity IN ('critical', 'high')
ORDER BY event_time DESC
LIMIT 100`;
    }

    // Hourly statistics (generic)
    if (lower.includes('시간대별') || lower.includes('시간별') || lower.includes('hourly') || lower.includes('by hour')) {
      return `SELECT
  toHour(event_time) as hour,
  COUNT(*) as event_count
FROM events
WHERE event_time >= now() - INTERVAL 1 DAY
GROUP BY hour
ORDER BY hour`;
    }

    // Count by severity
    if (lower.includes('count') || lower.includes('개수') || lower.includes('통계')) {
      return `SELECT severity, COUNT(*) as count
FROM events
GROUP BY severity
ORDER BY count DESC`;
    }

    // IP search
    const ipMatch = lower.match(/ip[:\s]+(\d+\.\d+\.\d+\.\d+)/);
    if (ipMatch) {
      return `SELECT id, event_time, event_type, source_ip, destination_ip, severity, description
FROM events
WHERE source_ip = '${ipMatch[1]}' OR destination_ip = '${ipMatch[1]}'
ORDER BY event_time DESC
LIMIT 100`;
    }

    // User search
    if (lower.includes('user') || lower.includes('사용자')) {
      return `SELECT id, username, email, role, department, last_login, status, risk_score
FROM users
ORDER BY last_login DESC
LIMIT 100`;
    }

    // Assets
    if (lower.includes('asset') || lower.includes('자산') || lower.includes('endpoint') || lower.includes('호스트')) {
      return `SELECT id, hostname, ip_address, os, department, criticality, last_seen
FROM assets
ORDER BY last_seen DESC
LIMIT 100`;
    }

    // Default: Show recent events
    return `-- AI generated query from: "${naturalLanguage}"
SELECT id, event_time, event_type, source_ip, severity, description
FROM events
ORDER BY event_time DESC
LIMIT 100`;
  };

  const runQuery = useCallback(async () => {
    if (!query.trim()) {
      toast({
        title: 'Empty Query',
        description: 'Please enter a query to execute.',
        variant: 'destructive',
      });
      return;
    }

    // Double-check validation before execution
    const preRunErrors = validateSQLLocal(query);
    const hasErrors = preRunErrors.some((e) => e.severity === 'error');
    if (hasErrors) {
      toast({
        title: 'Syntax Error',
        description: 'Please fix the syntax errors before running the query.',
        variant: 'destructive',
      });
      setValidationErrors(preRunErrors);
      return;
    }

    // Initialize abort controller for cancellation
    abortControllerRef.current = new AbortController();
    setIsRunning(true);
    setError(null);
    const startTime = performance.now();

    try {
      if (USE_MOCK_DATA) {
        // Simulate query execution with mock data (cancellable with timeout)
        // Use longer duration (2-5s) to demonstrate loading UI, progress bar, and cancel functionality
        const simulatedDuration = 2000 + Math.random() * 3000;

        await Promise.race([
          new Promise<void>((resolve, reject) => {
            const timeoutId = setTimeout(resolve, simulatedDuration);
            abortControllerRef.current?.signal.addEventListener('abort', () => {
              clearTimeout(timeoutId);
              reject(new DOMException('Query cancelled', 'AbortError'));
            });
          }),
          new Promise<never>((_, reject) => {
            setTimeout(() => {
              reject(new Error(`Query timeout after ${queryTimeout}s`));
            }, queryTimeout * 1000);
          }),
        ]);

        const duration = Math.round(performance.now() - startTime);
        const mockResults = generateMockResults(query);
        setResults(mockResults);
        setQueryStats({ duration, rows: mockResults.length });
        addToHistory(query, duration, mockResults.length, queryLanguage);
        toast({
          title: 'Query Executed',
          description: `Returned ${mockResults.length} rows in ${formatDuration(duration)}`,
        });
      } else {
        // Use the new Query API
        const response = await executeQuery({
          query: query.trim(),
          language: queryLanguage,
          limit: 1000,
          timeout: queryTimeout * 1000,
        });

        const duration = Math.round(performance.now() - startTime);

        if (!response.success || !response.data) {
          throw new Error(response.error?.message || 'Query execution failed');
        }

        const queryResponse = response.data;

        if (!queryResponse.success) {
          throw new Error(queryResponse.error || 'Query execution failed');
        }

        // Convert rows from array format to object format using the helper
        const rows = rowsToObjects(queryResponse.data.columns, queryResponse.data.rows);
        const totalRows = queryResponse.data.total;
        const executionTime = queryResponse.data.executionTimeMs || duration;

        setResults(rows);
        setQueryStats({ duration: executionTime, rows: totalRows });
        addToHistory(query, executionTime, totalRows, queryLanguage);

        toast({
          title: 'Query Executed',
          description: `Returned ${totalRows} rows in ${formatDuration(executionTime)}`,
        });
      }
    } catch (err) {
      // Handle abort/cancellation
      if (err instanceof DOMException && err.name === 'AbortError') {
        // Already handled by cancelQuery, just return
        return;
      }

      // Check if it's a timeout error
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      const isTimeoutError = errorMessage.includes('timeout') || errorMessage.includes('Timeout');

      setError({
        message: isTimeoutError ? `Query timeout after ${queryTimeout}s` : errorMessage,
        details: isTimeoutError
          ? 'The query exceeded the configured timeout limit. Try optimizing your query or increasing the timeout.'
          : err instanceof Error ? err.stack : undefined,
      });
      toast({
        title: isTimeoutError ? 'Query Timeout' : 'Query Failed',
        description: isTimeoutError ? `Query exceeded ${queryTimeout}s timeout limit` : errorMessage,
        variant: 'destructive',
      });
    } finally {
      setIsRunning(false);
      abortControllerRef.current = null;
    }
  }, [query, queryTimeout, toast, addToHistory]);

  const handleQueryResult = useCallback((data: QueryResultData) => {
    // When AI generates a query, update the editor and run it
    if (data.query) {
      setQuery(data.query);
    }
    // Update results from the AI query
    if (data.rows && data.rows.length > 0) {
      setResults(data.rows as Record<string, unknown>[]);
      setQueryStats({
        duration: data.executionTime || 0,
        rows: data.totalRows || data.rows.length,
      });
    }
  }, []);

  // Handle keyboard shortcuts
  const handleKeyDown = useCallback((e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runQuery();
    }
  }, [runQuery]);

  // Handle saving a query
  const handleSaveQuery = useCallback(async () => {
    if (!query.trim()) {
      toast({
        title: 'Empty Query',
        description: 'Cannot save an empty query.',
        variant: 'destructive',
      });
      return;
    }

    // Simple prompt for query name (in production, use a proper dialog)
    const name = window.prompt('Enter a name for this query:');
    if (!name) return;

    const description = window.prompt('Enter a description (optional):') || '';

    try {
      const response = await saveQuery({
        name,
        description,
        query: query.trim(),
        language: queryLanguage,
      });

      if (response.success && response.data) {
        setSavedQueriesState((prev) => [response.data!, ...prev]);
        toast({
          title: 'Query Saved',
          description: `Query "${name}" has been saved.`,
        });
      } else {
        throw new Error(response.error?.message || 'Failed to save query');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to save query';
      toast({
        title: 'Save Failed',
        description: errorMessage,
        variant: 'destructive',
      });
    }
  }, [query, queryLanguage, toast]);

  // Handle deleting a saved query
  const handleDeleteSavedQuery = useCallback(async (id: string, name: string) => {
    if (!window.confirm(`Delete saved query "${name}"?`)) return;

    try {
      const response = await deleteSavedQuery(id);
      if (response.success) {
        setSavedQueriesState((prev) => prev.filter((q) => q.id !== id));
        toast({
          title: 'Query Deleted',
          description: `Query "${name}" has been deleted.`,
        });
      } else {
        throw new Error(response.error?.message || 'Failed to delete query');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to delete query';
      toast({
        title: 'Delete Failed',
        description: errorMessage,
        variant: 'destructive',
      });
    }
  }, [toast]);

  // Handle exporting query results
  const handleExportResults = useCallback(async (format: 'csv' | 'json' | 'xlsx') => {
    if (!query.trim() || !results || results.length === 0) {
      toast({
        title: 'No Results',
        description: 'Run a query first to export results.',
        variant: 'destructive',
      });
      return;
    }

    try {
      await downloadQueryResults({
        query: query.trim(),
        language: queryLanguage,
        format,
        filename: `query_results_${new Date().toISOString().split('T')[0]}`,
      });
      toast({
        title: 'Export Complete',
        description: `Results exported as ${format.toUpperCase()}.`,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Export failed';
      toast({
        title: 'Export Failed',
        description: errorMessage,
        variant: 'destructive',
      });
    }
  }, [query, queryLanguage, results, toast]);

  // Format relative time
  const formatRelativeTime = (timestamp: number) => {
    const diff = Date.now() - timestamp;
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);

    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  };

  // Check if results are suitable for visualization
  const isVisualizableData = useMemo(() => {
    if (!results || results.length === 0) return false;
    const firstRow = results[0];
    if (!firstRow) return false;
    const keys = Object.keys(firstRow);
    // Need at least 2 columns - one for label (string or number) and one number for value
    // Allow numeric labels (e.g., hour 0-23, month 1-12)
    const hasLabelCol = keys.some(k => typeof firstRow[k] === 'string' || typeof firstRow[k] === 'number');
    const hasValueCol = keys.some(k => typeof firstRow[k] === 'number');
    // Need at least 2 columns for chart (label + value)
    return hasLabelCol && hasValueCol && keys.length >= 2 && results.length <= 50;
  }, [results]);

  // Prepare chart data from results
  const chartData = useMemo(() => {
    if (!results || results.length === 0) return null;

    const firstRow = results[0];
    if (!firstRow) return null;

    const keys = Object.keys(firstRow);

    // Find value column first (prioritize columns with 'count', 'total', 'sum', 'avg' in name)
    const valueKey = keys.find(k => /count|total|sum|avg|amount|quantity/i.test(k)) ||
                     keys.find((k, i) => i > 0 && typeof firstRow[k] === 'number') ||
                     keys[keys.length - 1];

    // Find label column (first column that's not the value column)
    const labelKey = keys.find(k => k !== valueKey) || keys[0];

    if (!labelKey || !valueKey || labelKey === valueKey) return null;

    const labels = results.map(row => String(row[labelKey] || 'Unknown'));
    const values = results.map(row => Number(row[valueKey]) || 0);

    // For pie chart
    const pieData = results.map(row => ({
      name: String(row[labelKey] || 'Unknown'),
      value: Number(row[valueKey]) || 0,
    }));

    // For line chart (time series detection)
    const isTimeSeries = labelKey.toLowerCase().includes('time') ||
                         labelKey.toLowerCase().includes('date') ||
                         labelKey.toLowerCase().includes('timestamp') ||
                         labelKey.toLowerCase().includes('hour') ||
                         labelKey.toLowerCase().includes('month') ||
                         labelKey.toLowerCase().includes('year') ||
                         labelKey.toLowerCase().includes('day');

    return {
      labels,
      values,
      pieData,
      labelKey,
      valueKey,
      isTimeSeries,
    };
  }, [results]);

  // Auto-detect best chart type
  const suggestedChartType = useMemo(() => {
    if (!chartData) return 'bar';
    if (chartData.isTimeSeries) return 'line';
    if (chartData.pieData.length <= 8 && chartData.pieData.length >= 2) return 'pie';
    return 'bar';
  }, [chartData]);

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
          <Button variant="outline" size="sm" onClick={() => setShowSchema(true)}>
            <Database className="w-4 h-4 mr-2" />
            Schema
          </Button>
        </div>
      </div>

      <div className="flex gap-6 flex-1 min-h-0">
        {/* Main content */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* NL2SQL - AI Assistant Section */}
          <Card className="flex-none mb-4 border-neon-cyan/30 bg-gradient-to-r from-neon-cyan/5 to-transparent">
            <CardContent className="py-4">
              <div className="flex items-center gap-3 mb-3">
                <div className="p-2 rounded-lg bg-neon-cyan/20">
                  <Wand2 className="w-5 h-5 text-neon-cyan" />
                </div>
                <div>
                  <h3 className="font-semibold text-sm">AI Assistant (NL2SQL)</h3>
                  <p className="text-xs text-muted-foreground">
                    자연어로 질문하면 AI가 SQL로 변환해 줍니다
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="flex-1 relative">
                  <MessageSquare className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    value={nlQuery}
                    onChange={(e) => setNlQuery(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && !e.shiftKey) {
                        e.preventDefault();
                        convertNL2SQL();
                      }
                    }}
                    placeholder="예: 오늘 발생한 critical 경보 보여줘 / Show failed login attempts from last hour"
                    className="pl-10 pr-4 bg-background/50"
                    disabled={isConverting}
                  />
                </div>
                <Button
                  onClick={convertNL2SQL}
                  disabled={!nlQuery.trim() || isConverting}
                  className="shrink-0 min-w-[140px] bg-[#00A4A6] hover:bg-[#00A4A6]/90 text-white font-medium"
                >
                  {isConverting ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Wand2 className="w-4 h-4 mr-2" />
                  )}
                  {isConverting ? 'Converting...' : 'Convert to SQL'}
                </Button>
              </div>
              <div className="flex flex-wrap gap-2 mt-3">
                <span className="text-xs text-muted-foreground">Try:</span>
                {[
                  'Show critical alerts',
                  'Count events by severity',
                  'Failed logins today',
                  'Events from last hour',
                ].map((suggestion) => (
                  <button
                    key={suggestion}
                    onClick={() => setNlQuery(suggestion)}
                    className="text-xs px-2 py-1 rounded-full bg-muted/50 hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>

              {/* 💡 Explanation Section */}
              {sqlExplanation && (
                <div className="mt-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                  <div className="flex items-start gap-3">
                    <div className="p-1.5 rounded bg-amber-500/20 shrink-0 mt-0.5">
                      <Sparkles className="w-4 h-4 text-amber-500" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-1">
                        <h4 className="text-sm font-semibold text-amber-500">💡 Explanation</h4>
                        <button
                          onClick={() => setSqlExplanation(null)}
                          className="text-xs text-muted-foreground hover:text-foreground"
                        >
                          Dismiss
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground mb-2">
                        <span className="font-medium">Query:</span> "{sqlExplanation.originalQuery}"
                      </p>
                      <p className="text-sm text-foreground/90 leading-relaxed">
                        {sqlExplanation.explanation}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Query editor */}
          <Card className="flex-none">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-base">Query Editor</CardTitle>
                <div className="flex items-center gap-2">
                  {/* Timeout Setting */}
                  <div className="flex items-center gap-2 mr-2">
                    <Label htmlFor="timeout" className="text-xs text-muted-foreground flex items-center gap-1">
                      <Timer className="w-3.5 h-3.5" />
                      Timeout:
                    </Label>
                    <Select
                      value={String(queryTimeout)}
                      onValueChange={(v) => setQueryTimeout(Number(v))}
                      disabled={isRunning}
                    >
                      <SelectTrigger className="w-20 h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="10">10s</SelectItem>
                        <SelectItem value="30">30s</SelectItem>
                        <SelectItem value="60">60s</SelectItem>
                        <SelectItem value="120">2min</SelectItem>
                        <SelectItem value="300">5min</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  {/* Language Selector */}
                  <div className="flex items-center gap-2 mr-2">
                    <Label htmlFor="language" className="text-xs text-muted-foreground">
                      Lang:
                    </Label>
                    <Select
                      value={queryLanguage}
                      onValueChange={(v) => setQueryLanguage(v as QueryLanguage)}
                      disabled={isRunning}
                    >
                      <SelectTrigger className="w-20 h-8 text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="sql">SQL</SelectItem>
                        <SelectItem value="kql">KQL</SelectItem>
                        <SelectItem value="spl">SPL</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setQuery('')}
                    disabled={isRunning}
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Clear
                  </Button>
                  <Button variant="outline" size="sm" disabled={isRunning || !query.trim()} onClick={handleSaveQuery}>
                    <Save className="w-4 h-4 mr-2" />
                    Save
                  </Button>
                  {isRunning ? (
                    <Button size="sm" variant="destructive" onClick={cancelQuery}>
                      <XCircle className="w-4 h-4 mr-2" />
                      Cancel
                    </Button>
                  ) : (
                    <Button size="sm" onClick={runQuery} disabled={!query.trim() || validationErrors.some((e) => e.severity === 'error')}>
                      <Play className="w-4 h-4 mr-2" />
                      Run Query
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <SQLEditor
                value={query}
                onChange={setQuery}
                onExecute={runQuery}
                schema={databaseSchema.map(t => ({
                  name: t.name,
                  columns: t.columns.map(c => ({ name: c.name, type: c.type })),
                }))}
                height="200px"
                placeholder="Enter SQL query... (Ctrl+Space for autocomplete)"
                disabled={isRunning}
              />

              {/* Inline validation error/warning panel */}
              {validationErrors.length > 0 && (
                <div className="border-t border-border">
                  {validationErrors.map((ve, idx) => (
                    <div
                      key={idx}
                      className={`flex items-start gap-3 px-4 py-2 text-sm ${
                        ve.severity === 'error'
                          ? 'bg-destructive/10 border-b border-destructive/20'
                          : 'bg-amber-500/10 border-b border-amber-500/20'
                      }`}
                    >
                      <AlertCircle
                        className={`w-4 h-4 mt-0.5 shrink-0 ${
                          ve.severity === 'error' ? 'text-destructive' : 'text-amber-500'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <span
                          className={
                            ve.severity === 'error' ? 'text-destructive' : 'text-amber-500'
                          }
                        >
                          {ve.message}
                        </span>
                        {(ve.line !== undefined || ve.position !== undefined) && (
                          <span className="ml-2 text-xs text-muted-foreground font-mono">
                            {ve.line !== undefined && `line ${ve.line}`}
                            {ve.line !== undefined && ve.position !== undefined && ', '}
                            {ve.position !== undefined && `col ${ve.position}`}
                          </span>
                        )}
                      </div>
                      {ve.severity === 'error' && (
                        <Button
                          size="sm"
                          variant="outline"
                          className="shrink-0 h-6 px-2 text-xs border-destructive/50 text-destructive hover:bg-destructive/10"
                          onClick={() => {
                            // Trigger NL2SQL to fix the query
                            setNlQuery(`Fix this SQL syntax error: ${ve.message}\n\nQuery:\n${query}`);
                            convertNL2SQL();
                          }}
                        >
                          <Wand2 className="w-3 h-3 mr-1" />
                          Fix with AI
                        </Button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Results */}
          <Card className="flex-1 mt-4 flex flex-col min-h-[800px]">
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
                {results && results.length > 0 && (
                  <div className="flex items-center gap-2">
                    {/* View Mode Toggle */}
                    <div className="flex items-center border border-border rounded-md overflow-hidden mr-2">
                      <Button
                        variant={viewMode === 'table' ? 'secondary' : 'ghost'}
                        size="sm"
                        className="rounded-none h-8 px-3"
                        onClick={() => setViewMode('table')}
                      >
                        <LayoutGrid className="w-4 h-4 mr-1" />
                        Table
                      </Button>
                      <Button
                        variant={viewMode === 'chart' ? 'secondary' : 'ghost'}
                        size="sm"
                        className="rounded-none h-8 px-3"
                        onClick={() => {
                          setViewMode('chart');
                          setChartType(suggestedChartType);
                        }}
                        disabled={!isVisualizableData}
                        title={!isVisualizableData ? 'Data not suitable for visualization' : undefined}
                      >
                        <BarChart3 className="w-4 h-4 mr-1" />
                        Chart
                      </Button>
                    </div>

                    {/* Chart Type Selector (only when in chart mode) */}
                    {viewMode === 'chart' && isVisualizableData && (
                      <div className="flex items-center border border-border rounded-md overflow-hidden mr-2">
                        <Button
                          variant={chartType === 'bar' ? 'secondary' : 'ghost'}
                          size="sm"
                          className="rounded-none h-8 px-2"
                          onClick={() => setChartType('bar')}
                          title="Bar Chart"
                        >
                          <BarChart3 className="w-4 h-4" />
                        </Button>
                        <Button
                          variant={chartType === 'pie' ? 'secondary' : 'ghost'}
                          size="sm"
                          className="rounded-none h-8 px-2"
                          onClick={() => setChartType('pie')}
                          title="Pie Chart"
                        >
                          <PieChartIcon className="w-4 h-4" />
                        </Button>
                        <Button
                          variant={chartType === 'line' ? 'secondary' : 'ghost'}
                          size="sm"
                          className="rounded-none h-8 px-2"
                          onClick={() => setChartType('line')}
                          title="Line Chart"
                        >
                          <LineChartIcon className="w-4 h-4" />
                        </Button>
                      </div>
                    )}

                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        if (results) {
                          navigator.clipboard.writeText(JSON.stringify(results, null, 2));
                          toast({
                            title: 'Copied',
                            description: 'Results copied to clipboard as JSON.',
                          });
                        }
                      }}
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Copy
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleExportResults('csv')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export CSV
                    </Button>
                  </div>
                )}
              </div>
            </CardHeader>
            <CardContent className="flex-1 min-h-0">
              {error ? (
                <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-4">
                  <div className="flex items-start gap-3">
                    <AlertCircle className="h-5 w-5 text-destructive mt-0.5" />
                    <div className="flex-1">
                      <h4 className="font-semibold text-destructive">Query Error</h4>
                      <p className="text-sm text-destructive/90 mt-1">{error.message}</p>
                      {error.details && (
                        <pre className="mt-2 text-xs bg-destructive/10 p-2 rounded overflow-auto max-h-32 text-destructive/80">
                          {error.details}
                        </pre>
                      )}
                    </div>
                  </div>
                </div>
              ) : isRunning ? (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  <div className="text-center w-64">
                    <Loader2 className="w-12 h-12 mx-auto mb-4 animate-spin text-primary" />
                    <p className="font-medium text-foreground">Running... {elapsedTime}s</p>
                    <p className="text-sm text-muted-foreground mb-4">
                      Timeout: {queryTimeout}s
                    </p>
                    {/* Progress Bar */}
                    <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                      <div
                        className={`h-2 rounded-full transition-all duration-1000 ${
                          elapsedTime / queryTimeout > 0.8
                            ? 'bg-destructive'
                            : elapsedTime / queryTimeout > 0.5
                              ? 'bg-amber-500'
                              : 'bg-primary'
                        }`}
                        style={{ width: `${Math.min((elapsedTime / queryTimeout) * 100, 100)}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">
                      {Math.round((elapsedTime / queryTimeout) * 100)}% of timeout
                    </p>
                    <Button
                      size="sm"
                      variant="outline"
                      className="mt-4"
                      onClick={cancelQuery}
                    >
                      <XCircle className="w-4 h-4 mr-2" />
                      Cancel Query
                    </Button>
                  </div>
                </div>
              ) : results && results.length > 0 ? (
                viewMode === 'chart' && chartData && isVisualizableData ? (
                  <div className="h-full p-4">
                    <div className="mb-4 p-3 rounded-lg bg-muted/30 border border-border">
                      <div className="flex items-center gap-2 text-sm">
                        <BarChart3 className="w-4 h-4 text-primary" />
                        <span className="font-medium">Visualization</span>
                        <span className="text-muted-foreground">
                          | Label: <code className="text-xs bg-muted px-1 rounded">{chartData.labelKey}</code>
                          | Value: <code className="text-xs bg-muted px-1 rounded">{chartData.valueKey}</code>
                        </span>
                      </div>
                    </div>
                    {chartType === 'bar' && (
                      <BarChart
                        data={{
                          labels: chartData.labels,
                          values: chartData.values,
                        }}
                        height="300px"
                        horizontal={chartData.labels.length > 10}
                        showValues={chartData.values.length <= 15}
                      />
                    )}
                    {chartType === 'pie' && (
                      <PieChart
                        data={chartData.pieData}
                        height="300px"
                        donut={true}
                        showLegend={true}
                      />
                    )}
                    {chartType === 'line' && (
                      <LineChart
                        data={{
                          labels: chartData.labels,
                          series: [{
                            name: chartData.valueKey,
                            data: chartData.values,
                          }],
                        }}
                        height="300px"
                        smooth={true}
                        area={true}
                      />
                    )}
                  </div>
                ) : (
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
                                  {String(value)}
                                </Badge>
                              ) : typeof value === 'object' ? (
                                JSON.stringify(value)
                              ) : (
                                String(value ?? '')
                              )}
                            </TableCell>
                          ))}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </ScrollArea>
                )
              ) : results && results.length === 0 ? (
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  <div className="text-center">
                    <Database className="w-12 h-12 mx-auto mb-4 opacity-20" />
                    <p>No results found</p>
                    <p className="text-sm">
                      The query returned 0 rows
                    </p>
                  </div>
                </div>
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
                      {isLoadingSaved ? (
                        <div className="text-center text-muted-foreground py-8">
                          <Loader2 className="w-8 h-8 mx-auto mb-2 animate-spin opacity-30" />
                          <p className="text-sm">Loading saved queries...</p>
                        </div>
                      ) : !savedQueriesState || savedQueriesState.length === 0 ? (
                        <div className="text-center text-muted-foreground py-8">
                          <BookMarked className="w-8 h-8 mx-auto mb-2 opacity-30" />
                          <p className="text-sm">No saved queries yet</p>
                          <p className="text-xs mt-1">Save a query to see it here</p>
                        </div>
                      ) : (
                        savedQueriesState.map((q) => (
                          <div
                            key={q.id}
                            className="p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors group"
                            onClick={() => {
                              setQuery(q.query);
                              setQueryLanguage(q.language as QueryLanguage);
                            }}
                          >
                            <div className="flex items-center justify-between mb-1">
                              <p className="font-medium text-sm">{q.name}</p>
                              <div className="flex items-center gap-2">
                                <Badge variant="outline" className="text-[10px] px-1 py-0">
                                  {q.language.toUpperCase()}
                                </Badge>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 w-6 p-0 opacity-0 group-hover:opacity-100 transition-opacity"
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    handleDeleteSavedQuery(q.id, q.name);
                                  }}
                                >
                                  <Trash2 className="w-3 h-3 text-destructive" />
                                </Button>
                              </div>
                            </div>
                            {q.description && (
                              <p className="text-xs text-muted-foreground mb-1">
                                {q.description}
                              </p>
                            )}
                            <p className="text-xs text-muted-foreground font-mono truncate">
                              {q.query}
                            </p>
                            <p className="text-[10px] text-muted-foreground mt-1">
                              Created {new Date(q.createdAt).toLocaleDateString()}
                            </p>
                          </div>
                        ))
                      )}
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
                      {localHistory.length === 0 ? (
                        <div className="text-center text-muted-foreground py-8">
                          <History className="w-8 h-8 mx-auto mb-2 opacity-30" />
                          <p className="text-sm">No query history yet</p>
                        </div>
                      ) : (
                        localHistory.map((q) => (
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
                              <span className="ml-auto">
                                {q.timestamp ? formatRelativeTime(q.timestamp) : q.time}
                              </span>
                            </div>
                          </div>
                        ))
                      )}
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

      {/* Schema Browser Panel */}
      <Sheet open={showSchema} onOpenChange={setShowSchema}>
        <SheetContent side="right" className="w-[450px] sm:w-[500px]">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Database className="w-5 h-5" />
              Database Schema
            </SheetTitle>
          </SheetHeader>
          <div className="mt-4">
            <p className="text-sm text-muted-foreground mb-4">
              Click on a table to view its columns. Click on a column name to insert it into your query.
            </p>
            <ScrollArea className="h-[calc(100vh-180px)]">
              <div className="space-y-2 pr-4">
                {databaseSchema.map((table) => (
                  <Collapsible
                    key={table.name}
                    open={expandedTables.has(table.name)}
                    onOpenChange={(open) => {
                      const newExpanded = new Set(expandedTables);
                      if (open) {
                        newExpanded.add(table.name);
                      } else {
                        newExpanded.delete(table.name);
                      }
                      setExpandedTables(newExpanded);
                    }}
                  >
                    <CollapsibleTrigger className="w-full">
                      <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors">
                        <div className="flex items-center gap-2">
                          <ChevronRight
                            className={`w-4 h-4 transition-transform ${
                              expandedTables.has(table.name) ? 'rotate-90' : ''
                            }`}
                          />
                          <TableIcon className="w-4 h-4 text-primary" />
                          <span className="font-medium">{table.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {table.rowCount && (
                            <Badge variant="secondary" className="text-xs">
                              {formatRowCount(table.rowCount)} rows
                            </Badge>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 px-2 text-xs"
                            onClick={(e) => {
                              e.stopPropagation();
                              setQuery((prev) => {
                                const selectAll = `SELECT * FROM ${table.name} LIMIT 100`;
                                if (!prev.trim()) return selectAll;
                                return prev + '\n\n' + selectAll;
                              });
                              toast({
                                title: 'Query Added',
                                description: `SELECT * FROM ${table.name} added to editor`,
                              });
                            }}
                          >
                            SELECT *
                          </Button>
                        </div>
                      </div>
                    </CollapsibleTrigger>
                    <CollapsibleContent>
                      <div className="ml-6 mt-1 border-l-2 border-muted pl-4 py-2 space-y-1">
                        <p className="text-xs text-muted-foreground mb-2">
                          {table.description}
                        </p>
                        {table.columns.map((column) => {
                          const TypeIcon = getTypeIcon(column.type);
                          return (
                            <div
                              key={column.name}
                              className="flex items-center justify-between p-2 rounded hover:bg-muted/30 cursor-pointer group"
                              onClick={() => {
                                setQuery((prev) => {
                                  const insertion = `${table.name}.${column.name}`;
                                  if (!prev.trim()) return `SELECT ${insertion} FROM ${table.name}`;
                                  return prev + insertion;
                                });
                              }}
                              title={column.description}
                            >
                              <div className="flex items-center gap-2">
                                {column.isPrimaryKey ? (
                                  <Key className="w-3.5 h-3.5 text-amber-500" />
                                ) : (
                                  <TypeIcon className="w-3.5 h-3.5 text-muted-foreground" />
                                )}
                                <span className="text-sm font-mono">{column.name}</span>
                                {!column.nullable && (
                                  <span className="text-[10px] text-destructive">*</span>
                                )}
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="text-xs text-muted-foreground">
                                  {column.type}
                                </span>
                                <Copy className="w-3 h-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </CollapsibleContent>
                  </Collapsible>
                ))}
              </div>
            </ScrollArea>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
