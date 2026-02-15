import { useState, useCallback } from 'react';
import type { Parser, TestResult } from '../types';

const mockParsers: Parser[] = [
  {
    id: 'parser-001',
    name: 'Syslog RFC5424',
    productId: 'SYSLOG',
    format: 'grok',
    pattern: '%{SYSLOG5424PRI}%{NONNEGINT:syslog5424_ver} +(?:%{TIMESTAMP_ISO8601:syslog5424_ts}|-) +(?:%{IPORHOST:syslog5424_host}|-) +(?:%{SYSLOG5424PRINTASCII:syslog5424_app}|-) +(?:%{SYSLOG5424PRINTASCII:syslog5424_proc}|-) +(?:%{SYSLOG5424PRINTASCII:syslog5424_msgid}|-) +(?:%{SYSLOG5424SD:syslog5424_sd}|-|) +%{GREEDYDATA:syslog5424_msg}',
    fieldMappings: [
      { sourceField: 'syslog5424_host', targetField: 'principal.hostname' },
      { sourceField: 'syslog5424_ts', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
      { sourceField: 'syslog5424_app', targetField: 'target.application' },
    ],
    sampleLogs: [
      '<165>1 2024-01-15T14:32:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application"] An application event log entry...',
    ],
    status: 'active',
    version: 3,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-15'),
  },
  {
    id: 'parser-002',
    name: 'AWS CloudTrail',
    productId: 'AWS_CLOUDTRAIL',
    format: 'json',
    pattern: '{"eventVersion": "%{DATA:eventVersion}", "userIdentity": %{GREEDYDATA:userIdentity}, "eventTime": "%{TIMESTAMP_ISO8601:eventTime}", "eventSource": "%{DATA:eventSource}", "eventName": "%{DATA:eventName}", "awsRegion": "%{DATA:awsRegion}"}',
    fieldMappings: [
      { sourceField: 'eventSource', targetField: 'target.application' },
      { sourceField: 'eventName', targetField: 'metadata.product_event_type' },
      { sourceField: 'awsRegion', targetField: 'principal.location.name' },
      { sourceField: 'eventTime', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
    ],
    sampleLogs: [
      '{"eventVersion": "1.08", "userIdentity": {"type": "IAMUser", "userName": "alice"}, "eventTime": "2024-01-15T14:32:15Z", "eventSource": "s3.amazonaws.com", "eventName": "GetObject", "awsRegion": "us-east-1"}',
    ],
    status: 'active',
    version: 5,
    createdAt: new Date('2023-11-20'),
    updatedAt: new Date('2024-01-10'),
  },
  {
    id: 'parser-003',
    name: 'Windows Security Event',
    productId: 'WINDOWS_SEC',
    format: 'cef',
    pattern: 'CEF:%{INT:cefVersion}|%{DATA:deviceVendor}|%{DATA:deviceProduct}|%{DATA:deviceVersion}|%{DATA:signatureId}|%{DATA:name}|%{DATA:severity}|%{GREEDYDATA:extension}',
    fieldMappings: [
      { sourceField: 'deviceVendor', targetField: 'metadata.vendor_name' },
      { sourceField: 'deviceProduct', targetField: 'metadata.product_name' },
      { sourceField: 'signatureId', targetField: 'security_result.rule_id' },
      { sourceField: 'severity', targetField: 'security_result.severity' },
    ],
    sampleLogs: [
      'CEF:0|Microsoft|Windows|10.0|4624|An account was successfully logged on|5|src=192.168.1.100 dst=10.0.0.5 suser=admin shost=WORKSTATION1',
    ],
    status: 'active',
    version: 2,
    createdAt: new Date('2023-12-05'),
    updatedAt: new Date('2024-01-12'),
  },
  {
    id: 'parser-004',
    name: 'Palo Alto Firewall',
    productId: 'PAN_FW',
    format: 'leef',
    pattern: 'LEEF:%{DATA:leefVersion}|%{DATA:vendor}|%{DATA:product}|%{DATA:version}|%{DATA:eventId}|%{GREEDYDATA:attributes}',
    fieldMappings: [
      { sourceField: 'vendor', targetField: 'metadata.vendor_name' },
      { sourceField: 'product', targetField: 'metadata.product_name' },
      { sourceField: 'eventId', targetField: 'metadata.product_event_type' },
    ],
    sampleLogs: [
      'LEEF:2.0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|cat=TRAFFIC\tdevTime=Jan 15 2024 14:32:15\tsrc=192.168.1.50\tdst=8.8.8.8\tproto=TCP\tdstPort=443',
    ],
    status: 'testing',
    version: 1,
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-01-14'),
  },
  {
    id: 'parser-005',
    name: 'Apache Access Log',
    productId: 'APACHE_ACCESS',
    format: 'grok',
    pattern: '%{IPORHOST:clientip} %{USER:ident} %{USER:auth} \\[%{HTTPDATE:timestamp}\\] "%{WORD:verb} %{URIPATHPARAM:request} HTTP/%{NUMBER:httpversion}" %{NUMBER:response} (?:%{NUMBER:bytes}|-)',
    fieldMappings: [
      { sourceField: 'clientip', targetField: 'principal.ip' },
      { sourceField: 'timestamp', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
      { sourceField: 'verb', targetField: 'network.http.method', transformation: 'uppercase' },
      { sourceField: 'request', targetField: 'target.url' },
      { sourceField: 'response', targetField: 'network.http.response_code' },
    ],
    sampleLogs: [
      '192.168.1.100 - admin [15/Jan/2024:14:32:15 +0000] "GET /api/users HTTP/1.1" 200 1234',
    ],
    status: 'active',
    version: 4,
    createdAt: new Date('2023-10-15'),
    updatedAt: new Date('2024-01-08'),
  },
  {
    id: 'parser-006',
    name: 'Nginx Error Log',
    productId: 'NGINX_ERROR',
    format: 'regex',
    pattern: '(?<timestamp>\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2}) \\[(?<level>\\w+)\\] (?<pid>\\d+)#(?<tid>\\d+): \\*(?<cid>\\d+) (?<message>.+)',
    fieldMappings: [
      { sourceField: 'timestamp', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
      { sourceField: 'level', targetField: 'security_result.severity', transformation: 'uppercase' },
      { sourceField: 'message', targetField: 'security_result.description' },
    ],
    sampleLogs: [
      '2024/01/15 14:32:15 [error] 1234#5678: *9999 connect() failed (111: Connection refused) while connecting to upstream',
    ],
    status: 'draft',
    version: 1,
    createdAt: new Date('2024-01-14'),
    updatedAt: new Date('2024-01-14'),
  },
  {
    id: 'parser-007',
    name: 'Cisco ASA Syslog',
    productId: 'CISCO_ASA',
    format: 'grok',
    pattern: '%{CISCOTIMESTAMP:timestamp} %{SYSLOGHOST:device} %%{CISCOTAG:ciscotag}: %{GREEDYDATA:message}',
    fieldMappings: [
      { sourceField: 'timestamp', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
      { sourceField: 'device', targetField: 'principal.hostname' },
      { sourceField: 'ciscotag', targetField: 'metadata.product_event_type' },
      { sourceField: 'message', targetField: 'security_result.description' },
    ],
    sampleLogs: [
      'Jan 15 14:32:15 fw01 %ASA-6-302013: Built inbound TCP connection 12345 for outside:192.168.1.100/54321 to inside:10.0.0.5/443',
    ],
    status: 'active',
    version: 6,
    createdAt: new Date('2023-08-20'),
    updatedAt: new Date('2024-01-05'),
  },
  {
    id: 'parser-008',
    name: 'Key-Value Generic',
    productId: 'GENERIC_KV',
    format: 'kv',
    pattern: '%{GREEDYDATA:kvpairs}',
    fieldMappings: [
      { sourceField: 'src', targetField: 'principal.ip' },
      { sourceField: 'dst', targetField: 'target.ip' },
      { sourceField: 'user', targetField: 'principal.user.userid', transformation: 'lowercase' },
      { sourceField: 'action', targetField: 'security_result.action' },
    ],
    sampleLogs: [
      'timestamp=2024-01-15T14:32:15Z src=192.168.1.100 dst=10.0.0.5 user=ADMIN action=ALLOW proto=TCP dport=443',
    ],
    status: 'disabled',
    version: 2,
    createdAt: new Date('2023-09-10'),
    updatedAt: new Date('2023-12-20'),
  },
  {
    id: 'parser-009',
    name: 'CrowdStrike Falcon',
    productId: 'CROWDSTRIKE',
    format: 'json',
    pattern: '{"metadata": {"eventType": "%{DATA:eventType}", "eventCreationTime": %{NUMBER:eventCreationTime}}, "event": %{GREEDYDATA:event}}',
    fieldMappings: [
      { sourceField: 'eventType', targetField: 'metadata.product_event_type' },
      { sourceField: 'eventCreationTime', targetField: 'metadata.event_timestamp' },
    ],
    sampleLogs: [
      '{"metadata": {"eventType": "DetectionSummaryEvent", "eventCreationTime": 1705329135000}, "event": {"DetectName": "Malware.Generic", "Severity": 4, "ComputerName": "WORKSTATION1"}}',
    ],
    status: 'active',
    version: 3,
    createdAt: new Date('2023-11-01'),
    updatedAt: new Date('2024-01-13'),
  },
  {
    id: 'parser-010',
    name: 'Okta System Log',
    productId: 'OKTA',
    format: 'json',
    pattern: '{"uuid": "%{DATA:uuid}", "published": "%{TIMESTAMP_ISO8601:published}", "eventType": "%{DATA:eventType}", "actor": %{GREEDYDATA:actor}}',
    fieldMappings: [
      { sourceField: 'uuid', targetField: 'metadata.product_log_id' },
      { sourceField: 'published', targetField: 'metadata.event_timestamp', transformation: 'parse_date' },
      { sourceField: 'eventType', targetField: 'metadata.product_event_type' },
    ],
    sampleLogs: [
      '{"uuid": "abc123", "published": "2024-01-15T14:32:15.000Z", "eventType": "user.session.start", "actor": {"id": "00u1abcd", "type": "User", "displayName": "John Doe"}}',
    ],
    status: 'testing',
    version: 2,
    createdAt: new Date('2024-01-05'),
    updatedAt: new Date('2024-01-15'),
  },
];

// Simulate Grok pattern parsing for test results
const grokPatternFields: Record<string, string[]> = {
  SYSLOG5424: ['syslog5424_ver', 'syslog5424_ts', 'syslog5424_host', 'syslog5424_app', 'syslog5424_proc', 'syslog5424_msgid', 'syslog5424_sd', 'syslog5424_msg'],
  CLOUDTRAIL: ['eventVersion', 'userIdentity', 'eventTime', 'eventSource', 'eventName', 'awsRegion'],
  CEF: ['cefVersion', 'deviceVendor', 'deviceProduct', 'deviceVersion', 'signatureId', 'name', 'severity', 'extension'],
  APACHE: ['clientip', 'ident', 'auth', 'timestamp', 'verb', 'request', 'httpversion', 'response', 'bytes'],
  NGINX: ['timestamp', 'level', 'pid', 'tid', 'cid', 'message'],
  CISCO: ['timestamp', 'device', 'ciscotag', 'message'],
  KV: ['timestamp', 'src', 'dst', 'user', 'action', 'proto', 'dport'],
};

export function useParsers() {
  const [parsers, setParsers] = useState<Parser[]>(mockParsers);
  const [selectedParser, setSelectedParser] = useState<Parser | null>(null);

  const createParser = useCallback((parser: Omit<Parser, 'id' | 'version' | 'createdAt' | 'updatedAt'>) => {
    const newParser: Parser = {
      ...parser,
      id: `parser-${Date.now()}`,
      version: 1,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    setParsers((prev) => [...prev, newParser]);
    return newParser;
  }, []);

  const updateParser = useCallback((id: string, updates: Partial<Parser>) => {
    setParsers((prev) =>
      prev.map((p) =>
        p.id === id
          ? { ...p, ...updates, version: p.version + 1, updatedAt: new Date() }
          : p
      )
    );
  }, []);

  const deleteParser = useCallback((id: string) => {
    setParsers((prev) => prev.filter((p) => p.id !== id));
    if (selectedParser?.id === id) {
      setSelectedParser(null);
    }
  }, [selectedParser]);

  const duplicateParser = useCallback((id: string) => {
    const parser = parsers.find((p) => p.id === id);
    if (parser) {
      const newParser: Parser = {
        ...parser,
        id: `parser-${Date.now()}`,
        name: `${parser.name} (Copy)`,
        status: 'draft',
        version: 1,
        createdAt: new Date(),
        updatedAt: new Date(),
      };
      setParsers((prev) => [...prev, newParser]);
      return newParser;
    }
    return null;
  }, [parsers]);

  return {
    parsers,
    selectedParser,
    setSelectedParser,
    createParser,
    updateParser,
    deleteParser,
    duplicateParser,
  };
}

export function useParserTest() {
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  const runTest = useCallback(async (parser: Parser, sampleLog: string): Promise<TestResult> => {
    setIsRunning(true);
    setResult(null);

    // Simulate parsing delay
    await new Promise((resolve) => setTimeout(resolve, 300 + Math.random() * 500));

    const startTime = performance.now();

    // Determine which fields to "extract" based on format
    let matchedFields: string[] = [];
    let extractedData: Record<string, unknown> = {};
    let success = true;
    let error: string | undefined;

    try {
      // Simple simulation of pattern matching
      if (!sampleLog.trim()) {
        throw new Error('Empty log input');
      }

      // Simulate field extraction based on parser format
      switch (parser.format) {
        case 'grok':
          if (parser.name.includes('Syslog')) {
            matchedFields = grokPatternFields.SYSLOG5424 || [];
          } else if (parser.name.includes('Apache')) {
            matchedFields = grokPatternFields.APACHE || [];
          } else if (parser.name.includes('Cisco')) {
            matchedFields = grokPatternFields.CISCO || [];
          } else {
            matchedFields = ['field1', 'field2', 'field3'];
          }
          break;
        case 'json':
          try {
            const parsed = JSON.parse(sampleLog);
            matchedFields = Object.keys(parsed).slice(0, 8);
            extractedData = parsed;
          } catch {
            throw new Error('Invalid JSON format');
          }
          break;
        case 'cef':
          matchedFields = grokPatternFields.CEF || [];
          break;
        case 'leef':
          matchedFields = ['leefVersion', 'vendor', 'product', 'version', 'eventId', 'attributes'];
          break;
        case 'regex':
          matchedFields = grokPatternFields.NGINX || [];
          break;
        case 'kv':
          matchedFields = grokPatternFields.KV || [];
          const kvPairs = sampleLog.match(/(\w+)=([^\s]+)/g) || [];
          kvPairs.forEach((pair) => {
            const parts = pair.split('=');
            const key = parts[0];
            const value = parts[1];
            if (key) {
              extractedData[key] = value;
            }
          });
          break;
      }

      // Generate mock extracted data if not already set
      if (Object.keys(extractedData).length === 0) {
        matchedFields.forEach((field, i) => {
          extractedData[field] = `extracted_value_${i + 1}`;
        });
      }

      // Simulate some failures
      if (sampleLog.includes('INVALID') || sampleLog.includes('ERROR_TEST')) {
        throw new Error('Pattern did not match log format');
      }
    } catch (e) {
      success = false;
      error = e instanceof Error ? e.message : 'Unknown error occurred';
      matchedFields = [];
      extractedData = {};
    }

    const executionTime = performance.now() - startTime;

    const testResult: TestResult = {
      success,
      matchedFields,
      extractedData,
      executionTime: Math.round(executionTime),
      error,
    };

    setResult(testResult);
    setIsRunning(false);

    return testResult;
  }, []);

  const clearResult = useCallback(() => {
    setResult(null);
  }, []);

  return {
    isRunning,
    result,
    runTest,
    clearResult,
  };
}
