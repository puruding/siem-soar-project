export interface FieldMapping {
  sourceField: string;
  targetField: string;
  transformation?: 'lowercase' | 'uppercase' | 'trim' | 'parse_date' | 'custom';
}

export interface TestResult {
  success: boolean;
  matchedFields: string[];
  extractedData: Record<string, unknown>;
  executionTime: number;
  error?: string;
}

export interface Parser {
  id: string;
  name: string;
  productId?: string;
  format: 'grok' | 'json' | 'cef' | 'leef' | 'regex' | 'kv';
  pattern: string;
  fieldMappings: FieldMapping[];
  sampleLogs: string[];
  status: 'draft' | 'active' | 'testing' | 'disabled';
  version: number;
  createdAt: Date;
  updatedAt: Date;
}

export type ParserFormat = Parser['format'];
export type ParserStatus = Parser['status'];
