import { useState, useCallback, useEffect } from 'react';
import type { Parser, TestResult } from '../types';
import {
  fetchParsers,
  fetchProductParsers,
  createParser as apiCreateParser,
  updateParser as apiUpdateParser,
  deleteParser as apiDeleteParser,
  type ApiParser,
} from '../api/parsersApi';

// Map API parser_type to Parser format
function mapParserType(parserType: string | null): Parser['format'] {
  if (!parserType) return 'grok';
  const lower = parserType.toLowerCase();
  if (lower === 'json') return 'json';
  if (lower === 'cef') return 'cef';
  if (lower === 'leef') return 'leef';
  if (lower === 'regex' || lower === 'regexp') return 'regex';
  if (lower === 'kv' || lower === 'key_value') return 'kv';
  return 'grok';
}

// Map API status to Parser status
function mapParserStatus(status: string): Parser['status'] {
  const lower = status.toLowerCase();
  if (lower === 'active') return 'active';
  if (lower === 'inactive' || lower === 'disabled') return 'disabled';
  if (lower === 'testing') return 'testing';
  return 'draft';
}

// Convert API parser to frontend Parser type
export function mapApiParserToParser(apiParser: ApiParser): Parser {
  return {
    id: apiParser.id,
    name: apiParser.name,
    productId: apiParser.data_source_id,
    productName: apiParser.product_name ?? undefined,
    vendorName: apiParser.vendor_name ?? undefined,
    format: mapParserType(apiParser.parser_type),
    pattern: apiParser.pattern ?? '',
    fieldMappings: [],
    sampleLogs: apiParser.sample_logs ?? [],
    status: mapParserStatus(apiParser.status),
    version: apiParser.version,
    createdAt: apiParser.created_at ? new Date(apiParser.created_at) : new Date(),
    updatedAt: apiParser.updated_at ? new Date(apiParser.updated_at) : new Date(),
  };
}

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
  const [parsers, setParsers] = useState<Parser[]>([]);
  const [selectedParser, setSelectedParser] = useState<Parser | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    fetchParsers()
      .then((data) => {
        if (!cancelled) {
          setParsers(data.map(mapApiParserToParser));
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error('Failed to fetch parsers'));
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const createParser = useCallback(async (parser: Omit<Parser, 'id' | 'version' | 'createdAt' | 'updatedAt'>) => {
    const created = await apiCreateParser({
      data_source_id: parser.productId ?? '',
      name: parser.name,
      parser_type: parser.format,
      pattern: parser.pattern || null,
      parser_config: null,
      field_mapping: null,
      sample_logs: parser.sampleLogs.length > 0 ? parser.sampleLogs : null,
      status: parser.status === 'active' ? 'ACTIVE' : parser.status === 'disabled' ? 'INACTIVE' : 'DRAFT',
    });
    const mapped = mapApiParserToParser(created);
    setParsers((prev) => [...prev, mapped]);
    return mapped;
  }, []);

  const updateParser = useCallback(async (id: string, updates: Partial<Parser>) => {
    const apiUpdates: Record<string, unknown> = {};
    if (updates.name !== undefined) apiUpdates.name = updates.name;
    if (updates.format !== undefined) apiUpdates.parser_type = updates.format;
    if (updates.pattern !== undefined) apiUpdates.pattern = updates.pattern;
    if (updates.sampleLogs !== undefined) apiUpdates.sample_logs = updates.sampleLogs;
    if (updates.status !== undefined) {
      apiUpdates.status = updates.status === 'active' ? 'ACTIVE' : updates.status === 'disabled' ? 'INACTIVE' : updates.status.toUpperCase();
    }

    const updated = await apiUpdateParser(id, apiUpdates);
    const mapped = mapApiParserToParser(updated);
    setParsers((prev) => prev.map((p) => p.id === id ? mapped : p));
    return mapped;
  }, []);

  const deleteParser = useCallback(async (id: string) => {
    await apiDeleteParser(id);
    setParsers((prev) => prev.filter((p) => p.id !== id));
    if (selectedParser?.id === id) {
      setSelectedParser(null);
    }
  }, [selectedParser]);

  const duplicateParser = useCallback(async (id: string) => {
    const parser = parsers.find((p) => p.id === id);
    if (parser) {
      const created = await apiCreateParser({
        data_source_id: parser.productId ?? '',
        name: `${parser.name} (Copy)`,
        parser_type: parser.format,
        pattern: parser.pattern || null,
        parser_config: null,
        field_mapping: null,
        sample_logs: parser.sampleLogs.length > 0 ? parser.sampleLogs : null,
        status: 'DRAFT',
      });
      const mapped = mapApiParserToParser(created);
      setParsers((prev) => [...prev, mapped]);
      return mapped;
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
    isLoading,
    error,
  };
}

export function useProductParsers(productId: string) {
  const [parsers, setParsers] = useState<Parser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const refetch = useCallback(() => {
    if (!productId) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setError(null);

    fetchProductParsers(productId)
      .then((data) => {
        setParsers(data.map(mapApiParserToParser));
        setIsLoading(false);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err : new Error('Failed to fetch product parsers'));
        setIsLoading(false);
      });
  }, [productId]);

  useEffect(() => {
    refetch();
  }, [refetch]);

  const createParser = useCallback(async (name: string, format: Parser['format']) => {
    const created = await apiCreateParser({
      data_source_id: productId,
      name,
      parser_type: format,
      pattern: null,
      parser_config: null,
      field_mapping: null,
      sample_logs: null,
      status: 'DRAFT',
    });
    const mapped = mapApiParserToParser(created);
    setParsers((prev) => [...prev, mapped]);
    return mapped;
  }, [productId]);

  const deleteParser = useCallback(async (id: string) => {
    await apiDeleteParser(id);
    setParsers((prev) => prev.filter((p) => p.id !== id));
  }, []);

  return {
    parsers,
    isLoading,
    error,
    refetch,
    createParser,
    deleteParser,
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
            const parsed = JSON.parse(sampleLog) as Record<string, unknown>;
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
        case 'kv': {
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
