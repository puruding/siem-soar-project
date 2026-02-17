import { useCallback, useEffect, useRef, useState } from 'react';
import Editor, { Monaco } from '@monaco-editor/react';
import { cn } from '@/lib/utils';
import { registerTemplateLanguage } from './templateLanguage';
import { registerTemplateCompletion } from './templateCompletionProvider';
import { nodeSchemaRegistry } from '../../services/nodeSchemaRegistry';
import type { NodeOutputSchema } from '../../types/template.types';

export interface UpstreamNode {
  nodeId: string;
  nodeName: string;
}

export interface TemplateEditorProps {
  value: string;
  onChange: (value: string) => void;
  upstreamNodes: UpstreamNode[];
  placeholder?: string;
  className?: string;
  minHeight?: number;
  maxHeight?: number;
  readOnly?: boolean;
}

/**
 * Monaco-based template editor with auto-complete for {{ $node.xxx.json.yyy }} syntax
 */
export function TemplateEditor({
  value,
  onChange,
  upstreamNodes,
  placeholder = 'Enter template...',
  className,
  minHeight = 120,
  maxHeight = 400,
  readOnly = false,
}: TemplateEditorProps) {
  const editorRef = useRef<any>(null);
  const monacoRef = useRef<Monaco | null>(null);
  const [editorHeight, setEditorHeight] = useState(minHeight);
  const isLanguageRegistered = useRef(false);

  // Calculate editor height based on content
  const updateEditorHeight = useCallback(() => {
    if (!editorRef.current) return;

    const editor = editorRef.current;
    const contentHeight = Math.min(
      Math.max(editor.getContentHeight(), minHeight),
      maxHeight
    );

    setEditorHeight(contentHeight);
  }, [minHeight, maxHeight]);

  // Handle Monaco mount
  const handleEditorDidMount = useCallback(
    (editor: any, monaco: Monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;

      // Register language and completion provider only once
      if (!isLanguageRegistered.current) {
        registerTemplateLanguage(monaco);
        registerTemplateCompletion(
          monaco,
          () => upstreamNodes,
          (nodeId: string, nodeName: string): NodeOutputSchema | null => {
            // Find the node to get its type
            const node = upstreamNodes.find((n) => n.nodeId === nodeId);
            if (!node) return null;

            // Use nodeSchemaRegistry to get schema
            // We need to create a mock Node object for the registry
            const mockNode = {
              id: nodeId,
              type: 'action', // Default type, could be enhanced
              data: { label: nodeName },
              position: { x: 0, y: 0 },
            };

            return nodeSchemaRegistry.getNodeSchema(mockNode);
          }
        );
        isLanguageRegistered.current = true;
      }

      // Set initial height
      updateEditorHeight();

      // Listen for content changes to update height
      editor.onDidContentSizeChange(() => {
        updateEditorHeight();
      });

      // Focus editor if empty
      if (!value) {
        editor.focus();
      }
    },
    [upstreamNodes, updateEditorHeight, value]
  );

  // Handle value change
  const handleEditorChange = useCallback(
    (newValue: string | undefined) => {
      onChange(newValue || '');
    },
    [onChange]
  );

  // Update completion provider when upstream nodes change
  useEffect(() => {
    if (monacoRef.current && isLanguageRegistered.current) {
      // Re-register completion provider with updated nodes
      registerTemplateCompletion(
        monacoRef.current,
        () => upstreamNodes,
        (nodeId: string, nodeName: string): NodeOutputSchema | null => {
          const node = upstreamNodes.find((n) => n.nodeId === nodeId);
          if (!node) return null;

          const mockNode = {
            id: nodeId,
            type: 'action',
            data: { label: nodeName },
            position: { x: 0, y: 0 },
          };

          return nodeSchemaRegistry.getNodeSchema(mockNode);
        }
      );
    }
  }, [upstreamNodes]);

  return (
    <div
      className={cn(
        'relative border border-border rounded-lg overflow-hidden bg-background',
        className
      )}
      style={{ height: `${editorHeight}px` }}
    >
      <Editor
        height="100%"
        language="template"
        theme="template-dark"
        value={value}
        onChange={handleEditorChange}
        onMount={handleEditorDidMount}
        options={{
          minimap: { enabled: false },
          fontSize: 13,
          fontFamily: "'Roboto Mono', 'JetBrains Mono', 'Consolas', monospace",
          lineNumbers: 'off',
          scrollBeyondLastLine: false,
          wordWrap: 'on',
          automaticLayout: true,
          tabSize: 2,
          insertSpaces: true,
          renderWhitespace: 'selection',
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          smoothScrolling: true,
          padding: { top: 8, bottom: 8 },
          scrollbar: {
            vertical: 'auto',
            horizontal: 'auto',
            verticalScrollbarSize: 10,
            horizontalScrollbarSize: 10,
          },
          suggest: {
            showKeywords: true,
            showSnippets: true,
            showWords: false,
          },
          quickSuggestions: {
            other: true,
            comments: false,
            strings: false,
          },
          suggestOnTriggerCharacters: true,
          acceptSuggestionOnEnter: 'on',
          tabCompletion: 'on',
          wordBasedSuggestions: 'off',
          readOnly,
          contextmenu: !readOnly,
        }}
      />

      {/* Placeholder */}
      {!value && !readOnly && (
        <div className="absolute top-2 left-3 pointer-events-none text-muted-foreground text-sm opacity-50">
          {placeholder}
        </div>
      )}
    </div>
  );
}
