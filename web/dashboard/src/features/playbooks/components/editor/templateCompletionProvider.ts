import type { Monaco } from '@monaco-editor/react';
import type { NodeOutputSchema, NodeOutputField } from '../../types/template.types';

interface UpstreamNode {
  nodeId: string;
  nodeName: string;
}

/**
 * Create Monaco completion provider for template syntax auto-complete
 * Provides completions for {{ $node.xxx.json.yyy }} patterns
 */
export function createTemplateCompletionProvider(
  monaco: Monaco,
  getUpstreamNodes: () => UpstreamNode[],
  getNodeSchema: (nodeId: string, nodeName: string) => NodeOutputSchema | null
) {
  return {
    triggerCharacters: ['{', '.', '$'],

    provideCompletionItems: (model: any, position: any) => {
      const textUntilPosition = model.getValueInRange({
        startLineNumber: position.lineNumber,
        startColumn: 1,
        endLineNumber: position.lineNumber,
        endColumn: position.column,
      });

      const suggestions: any[] = [];

      // Get the context of what we're completing
      const context = parseCompletionContext(textUntilPosition);

      switch (context.type) {
        case 'start':
          // After {{ - suggest $node, $json, etc.
          suggestions.push(
            {
              label: '$node',
              kind: monaco.languages.CompletionItemKind.Keyword,
              detail: 'Reference a node output',
              documentation: 'Access data from a previous node in the workflow',
              insertText: '$node.',
              range: {
                startLineNumber: position.lineNumber,
                startColumn: position.column,
                endLineNumber: position.lineNumber,
                endColumn: position.column,
              },
            },
            {
              label: '$json',
              kind: monaco.languages.CompletionItemKind.Keyword,
              detail: 'Current node JSON data',
              documentation: 'Access the JSON data of the current node',
              insertText: '$json.',
              range: {
                startLineNumber: position.lineNumber,
                startColumn: position.column,
                endLineNumber: position.lineNumber,
                endColumn: position.column,
              },
            },
            {
              label: '$execution',
              kind: monaco.languages.CompletionItemKind.Keyword,
              detail: 'Execution metadata',
              documentation: 'Access execution ID, mode, and other metadata',
              insertText: '$execution.',
              range: {
                startLineNumber: position.lineNumber,
                startColumn: position.column,
                endLineNumber: position.lineNumber,
                endColumn: position.column,
              },
            }
          );
          break;

        case 'node':
          // After $node. - suggest upstream node names
          const upstreamNodes = getUpstreamNodes();
          upstreamNodes.forEach((node) => {
            suggestions.push({
              label: node.nodeName,
              kind: monaco.languages.CompletionItemKind.Variable,
              detail: `Node: ${node.nodeName}`,
              documentation: `Reference output from ${node.nodeName} node`,
              insertText: `${node.nodeName}.json.`,
              range: {
                startLineNumber: position.lineNumber,
                startColumn: position.column,
                endLineNumber: position.lineNumber,
                endColumn: position.column,
              },
            });
          });
          break;

        case 'accessor':
          // After node name - suggest .json accessor
          suggestions.push({
            label: 'json',
            kind: monaco.languages.CompletionItemKind.Property,
            detail: 'JSON output',
            documentation: 'Access the JSON output of the node',
            insertText: 'json.',
            range: {
              startLineNumber: position.lineNumber,
              startColumn: position.column,
              endLineNumber: position.lineNumber,
              endColumn: position.column,
            },
          });
          break;

        case 'field':
          // After .json. - suggest fields from node schema
          if (context.nodeName) {
            const upstreamNodes = getUpstreamNodes();
            const node = upstreamNodes.find((n) => n.nodeName === context.nodeName);

            if (node) {
              const schema = getNodeSchema(node.nodeId, node.nodeName);
              if (schema) {
                const fields = context.path.length > 0
                  ? getNestedFields(schema.fields, context.path)
                  : schema.fields;

                fields.forEach((field) => {
                  const hasChildren = field.children && field.children.length > 0;
                  suggestions.push({
                    label: field.name,
                    kind: hasChildren
                      ? monaco.languages.CompletionItemKind.Class
                      : getFieldKind(monaco, field.type),
                    detail: field.type,
                    documentation: field.description || `Type: ${field.type}${field.example ? `\nExample: ${JSON.stringify(field.example)}` : ''}`,
                    insertText: hasChildren ? `${field.name}.` : field.name,
                    range: {
                      startLineNumber: position.lineNumber,
                      startColumn: position.column,
                      endLineNumber: position.lineNumber,
                      endColumn: position.column,
                    },
                  });
                });
              }
            }
          }
          break;
      }

      return { suggestions };
    },
  };
}

/**
 * Parse the text before cursor to determine completion context
 */
function parseCompletionContext(text: string): {
  type: 'start' | 'node' | 'accessor' | 'field' | 'none';
  nodeName?: string;
  path: string[];
} {
  // Find the last {{ occurrence
  const lastBraceIndex = text.lastIndexOf('{{');
  if (lastBraceIndex === -1) {
    return { type: 'none', path: [] };
  }

  // Get text after {{
  const afterBraces = text.slice(lastBraceIndex + 2).trim();

  // Empty or whitespace - suggest keywords
  if (!afterBraces || afterBraces === '') {
    return { type: 'start', path: [] };
  }

  // Starts with $node - parse node reference
  if (afterBraces.startsWith('$node.')) {
    const afterNode = afterBraces.slice(6); // Remove '$node.'

    if (!afterNode) {
      return { type: 'node', path: [] };
    }

    // Parse the path after $node.
    const parts = afterNode.split('.');

    // If we have just the node name or node name + partial next part
    if (parts.length === 1 || (parts.length === 2 && !afterNode.endsWith('.'))) {
      return { type: 'node', path: [] };
    }

    // After node name, before .json
    const nodeName = parts[0];
    if (parts.length === 2 && parts[1] === '') {
      return { type: 'accessor', nodeName, path: [] };
    }

    // After .json
    if (parts[1] === 'json') {
      const fieldPath = parts.slice(2);
      // Remove empty last element if path ends with .
      if (fieldPath.length > 0 && fieldPath[fieldPath.length - 1] === '') {
        fieldPath.pop();
      }
      return { type: 'field', nodeName, path: fieldPath };
    }
  }

  // Starts with $json - parse current node reference
  if (afterBraces.startsWith('$json.')) {
    const afterJson = afterBraces.slice(6);
    const parts = afterJson.split('.');
    const fieldPath = parts.filter((p) => p !== '');
    return { type: 'field', path: fieldPath };
  }

  return { type: 'none', path: [] };
}

/**
 * Get nested fields from a field path
 */
function getNestedFields(fields: NodeOutputField[], path: string[]): NodeOutputField[] {
  if (path.length === 0) {
    return fields;
  }

  const [current, ...rest] = path;
  const field = fields.find((f) => f.name === current);

  if (!field || !field.children) {
    return [];
  }

  if (rest.length === 0) {
    return field.children;
  }

  return getNestedFields(field.children, rest);
}

/**
 * Get Monaco completion item kind for a field type
 */
function getFieldKind(monaco: Monaco, type: NodeOutputField['type']): any {
  switch (type) {
    case 'string':
      return monaco.languages.CompletionItemKind.Text;
    case 'number':
      return monaco.languages.CompletionItemKind.Value;
    case 'boolean':
      return monaco.languages.CompletionItemKind.Value;
    case 'object':
      return monaco.languages.CompletionItemKind.Class;
    case 'array':
      return monaco.languages.CompletionItemKind.Variable;
    default:
      return monaco.languages.CompletionItemKind.Field;
  }
}

/**
 * Register the completion provider for template language
 */
export function registerTemplateCompletion(
  monaco: Monaco,
  getUpstreamNodes: () => UpstreamNode[],
  getNodeSchema: (nodeId: string, nodeName: string) => NodeOutputSchema | null
): void {
  monaco.languages.registerCompletionItemProvider(
    'template',
    createTemplateCompletionProvider(monaco, getUpstreamNodes, getNodeSchema)
  );
}
