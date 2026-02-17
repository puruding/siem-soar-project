import { useState, useCallback, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
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
} from 'lucide-react';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import { formatDuration } from '@/lib/utils';
import { CopilotChat, CopilotConfig } from '@/features/copilot/components/CopilotChat';
import { QueryResultData } from '@/features/copilot/components/QueryResult';
import { useToast } from '@/components/ui/toaster';

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

// Parse SQL query and generate mock results
function generateMockResults(sqlQuery: string): Record<string, unknown>[] {
  const normalizedQuery = sqlQuery.replace(/\s+/g, ' ').trim().toLowerCase();

  // Extract table name
  const fromMatch = normalizedQuery.match(/from\s+(\w+)/i);
  const tableName = fromMatch?.[1]?.toLowerCase() ?? 'events';

  // Get base data for the table
  const baseData = mockDataStore[tableName] ?? mockDataStore.events ?? [];

  // Check if it's a COUNT query
  if (normalizedQuery.includes('count(*)') || normalizedQuery.includes('count(1)')) {
    // Check for GROUP BY
    const groupByMatch = normalizedQuery.match(/group\s+by\s+(\w+)/i);
    if (groupByMatch?.[1]) {
      const groupByColumn = groupByMatch[1];
      const grouped: Record<string, number> = {};
      baseData.forEach((row) => {
        const key = String(row[groupByColumn] ?? 'unknown');
        grouped[key] = (grouped[key] ?? 0) + 1;
      });
      return Object.entries(grouped).map(([key, count]) => ({
        [groupByColumn]: key,
        count: count,
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
const QUERY_API_URL = import.meta.env.VITE_QUERY_API_URL || '/api/v1/query';

interface QueryHistoryItem {
  id: string;
  query: string;
  duration: number;
  rows: number;
  time: string;
  timestamp: number;
}

interface QueryError {
  message: string;
  code?: string;
  details?: string;
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
  const [localHistory, setLocalHistory] = useState<QueryHistoryItem[]>(() => {
    // Load history from localStorage
    const saved = localStorage.getItem('query-history');
    return saved ? JSON.parse(saved) : queryHistory;
  });

  // NL2SQL state
  const [nlQuery, setNlQuery] = useState('');
  const [isConverting, setIsConverting] = useState(false);
  const [sqlExplanation, setSqlExplanation] = useState<{
    originalQuery: string;
    explanation: string;
  } | null>(null);

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

  const addToHistory = useCallback((queryText: string, duration: number, rows: number) => {
    const newEntry: QueryHistoryItem = {
      id: Date.now().toString(),
      query: queryText,
      duration,
      rows,
      time: 'just now',
      timestamp: Date.now(),
    };
    setLocalHistory((prev) => [newEntry, ...prev.slice(0, 49)]); // Keep last 50 queries
  }, []);

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
        description: 'Please enter a SQL query to execute.',
        variant: 'destructive',
      });
      return;
    }

    setIsRunning(true);
    setError(null);
    const startTime = performance.now();

    try {
      if (USE_MOCK_DATA) {
        // Simulate query execution with mock data
        await new Promise((resolve) => setTimeout(resolve, 300 + Math.random() * 500));
        const duration = Math.round(performance.now() - startTime);
        const mockResults = generateMockResults(query);
        setResults(mockResults);
        setQueryStats({ duration, rows: mockResults.length });
        addToHistory(query, duration, mockResults.length);
        toast({
          title: 'Query Executed',
          description: `Returned ${mockResults.length} rows in ${formatDuration(duration)}`,
        });
      } else {
        // Make actual API call
        const response = await fetch(QUERY_API_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            query: query.trim(),
            timeout: 30000, // 30 second timeout
            format: 'json',
          }),
        });

        const duration = Math.round(performance.now() - startTime);

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(errorData.message || `Query failed with status ${response.status}`);
        }

        const data = await response.json();

        // Handle different response formats
        const rows = data.rows || data.data || data.results || [];
        const totalRows = data.total_rows || data.totalRows || rows.length;
        const executionTime = data.execution_time || data.executionTime || duration;

        setResults(rows);
        setQueryStats({ duration: executionTime, rows: totalRows });
        addToHistory(query, executionTime, totalRows);

        toast({
          title: 'Query Executed',
          description: `Returned ${totalRows} rows in ${formatDuration(executionTime)}`,
        });
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error occurred';
      setError({
        message: errorMessage,
        details: err instanceof Error ? err.stack : undefined,
      });
      toast({
        title: 'Query Failed',
        description: errorMessage,
        variant: 'destructive',
      });
    } finally {
      setIsRunning(false);
    }
  }, [query, toast, addToHistory]);

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
                  <Button size="sm" onClick={runQuery} disabled={isRunning || !query.trim()}>
                    {isRunning ? (
                      <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Play className="w-4 h-4 mr-2" />
                    )}
                    {isRunning ? 'Running...' : 'Run Query'}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Textarea
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className="font-mono text-sm h-[200px] bg-[#1e1e1e] text-[#d4d4d4] border-border resize-none"
                placeholder="Enter SQL query..."
                disabled={isRunning}
              />
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
                  <div className="text-center">
                    <Loader2 className="w-12 h-12 mx-auto mb-4 animate-spin text-primary" />
                    <p>Executing query...</p>
                    <p className="text-sm text-muted-foreground">
                      This may take a few seconds
                    </p>
                  </div>
                </div>
              ) : results && results.length > 0 ? (
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
