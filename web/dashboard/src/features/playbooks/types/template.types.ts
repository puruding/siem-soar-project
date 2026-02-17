// Schema definition for node output fields
export interface NodeOutputField {
  name: string;
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description?: string;
  example?: unknown;
  children?: NodeOutputField[];
}

export interface NodeOutputSchema {
  nodeId: string;
  nodeName: string;
  nodeType: string;
  fields: NodeOutputField[];
}

// Template token for parsing {{ $node.xxx.json.yyy }} syntax
export interface TemplateToken {
  type: 'text' | 'expression';
  value: string;
  start: number;
  end: number;
  nodeRef?: {
    nodeName: string;
    path: string[];
  };
}

// Completion item for Monaco auto-complete
export interface TemplateCompletionItem {
  label: string;
  kind: 'node' | 'field' | 'method';
  detail: string;
  documentation?: string;
  insertText: string;
  sortPriority?: number;
}
