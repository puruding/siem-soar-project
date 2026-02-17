/**
 * SQLEditor - SQL code editor with syntax highlighting and autocompletion
 * Using Monaco Editor for reliable syntax highlighting and autocompletion
 */
import { useRef, useEffect } from 'react';
import Editor, { OnMount, BeforeMount } from '@monaco-editor/react';
import type * as monacoEditor from 'monaco-editor';

export interface SchemaTable {
  name: string;
  columns: { name: string; type: string }[];
}

interface SQLEditorProps {
  value: string;
  onChange: (value: string) => void;
  onExecute?: () => void;
  schema?: SchemaTable[];
  height?: string;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
}

// Custom dark theme for Monaco
const defineTheme: BeforeMount = (monaco) => {
  monaco.editor.defineTheme('sql-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'keyword', foreground: '569CD6', fontStyle: 'bold' },
      { token: 'string', foreground: 'CE9178' },
      { token: 'number', foreground: 'B5CEA8' },
      { token: 'comment', foreground: '6A9955', fontStyle: 'italic' },
      { token: 'operator', foreground: 'D4D4D4' },
      { token: 'identifier', foreground: '9CDCFE' },
    ],
    colors: {
      'editor.background': '#1e1e1e',
      'editor.foreground': '#d4d4d4',
      'editor.lineHighlightBackground': '#00A4A615',
      'editor.selectionBackground': '#00A4A640',
      'editorCursor.foreground': '#00A4A6',
      'editorLineNumber.foreground': '#6e7681',
      'editorLineNumber.activeForeground': '#00A4A6',
      'editor.selectionHighlightBackground': '#00A4A630',
    },
  });
};

export function SQLEditor({
  value,
  onChange,
  onExecute,
  schema = [],
  height = '200px',
  placeholder = 'Enter SQL query...',
  disabled = false,
  className = '',
}: SQLEditorProps) {
  const editorRef = useRef<monacoEditor.editor.IStandaloneCodeEditor | null>(null);

  // Handle editor mount
  const handleEditorMount: OnMount = (editor, monaco) => {
    editorRef.current = editor;

    // Add Ctrl+Enter shortcut for execute
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter, () => {
      onExecute?.();
    });

    // Register SQL completion provider with schema
    if (schema.length > 0) {
      monaco.languages.registerCompletionItemProvider('sql', {
        provideCompletionItems: (model: monacoEditor.editor.ITextModel, position: monacoEditor.Position) => {
          const word = model.getWordUntilPosition(position);
          const range = {
            startLineNumber: position.lineNumber,
            endLineNumber: position.lineNumber,
            startColumn: word.startColumn,
            endColumn: word.endColumn,
          };

          const suggestions: monacoEditor.languages.CompletionItem[] = [];

          // Add table names
          schema.forEach((table) => {
            suggestions.push({
              label: table.name,
              kind: monaco.languages.CompletionItemKind.Class,
              insertText: table.name,
              detail: 'Table',
              range,
            } as monacoEditor.languages.CompletionItem);

            // Add column names
            table.columns.forEach((col) => {
              suggestions.push({
                label: col.name,
                kind: monaco.languages.CompletionItemKind.Field,
                insertText: col.name,
                detail: `${table.name}.${col.type}`,
                range,
              } as monacoEditor.languages.CompletionItem);

              // Add with table prefix
              suggestions.push({
                label: `${table.name}.${col.name}`,
                kind: monaco.languages.CompletionItemKind.Field,
                insertText: `${table.name}.${col.name}`,
                detail: col.type,
                range,
              } as monacoEditor.languages.CompletionItem);
            });
          });

          // Add SQL keywords
          const keywords = [
            'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN',
            'IS', 'NULL', 'ORDER', 'BY', 'ASC', 'DESC', 'LIMIT', 'OFFSET',
            'GROUP', 'HAVING', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON',
            'AS', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'CASE', 'WHEN',
            'THEN', 'ELSE', 'END', 'UNION', 'ALL', 'INSERT', 'INTO', 'VALUES',
            'UPDATE', 'SET', 'DELETE', 'CREATE', 'TABLE', 'DROP', 'ALTER', 'INDEX',
            'WITH', 'INTERVAL', 'NOW', 'TODAY', 'YESTERDAY', 'TRUE', 'FALSE',
          ];

          keywords.forEach((kw) => {
            suggestions.push({
              label: kw,
              kind: monaco.languages.CompletionItemKind.Keyword,
              insertText: kw,
              detail: 'Keyword',
              range,
            } as monacoEditor.languages.CompletionItem);
          });

          // Add SQL functions
          const functions = [
            'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'NULLIF', 'CAST',
            'CONCAT', 'LENGTH', 'LOWER', 'UPPER', 'TRIM', 'SUBSTRING', 'REPLACE',
            'NOW', 'TODAY', 'DATE', 'DATETIME', 'TIMESTAMP',
            'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
            'IF', 'IFNULL', 'ROUND', 'FLOOR', 'CEIL', 'ABS',
          ];

          functions.forEach((fn) => {
            suggestions.push({
              label: fn,
              kind: monaco.languages.CompletionItemKind.Function,
              insertText: `${fn}()`,
              insertTextRules: monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet,
              detail: 'Function',
              range,
            } as monacoEditor.languages.CompletionItem);
          });

          return { suggestions };
        },
      });
    }

    // Focus the editor
    editor.focus();
  };

  // Update editor options when disabled changes
  useEffect(() => {
    if (editorRef.current) {
      editorRef.current.updateOptions({ readOnly: disabled });
    }
  }, [disabled]);

  return (
    <div className={`sql-editor-container rounded-md border border-border overflow-hidden ${className}`}>
      <Editor
        height={height}
        defaultLanguage="sql"
        value={value}
        onChange={(val) => onChange(val || '')}
        beforeMount={defineTheme}
        onMount={handleEditorMount}
        theme="sql-dark"
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
          lineNumbers: 'on',
          lineNumbersMinChars: 3,
          folding: true,
          wordWrap: 'on',
          automaticLayout: true,
          scrollBeyondLastLine: false,
          tabSize: 2,
          insertSpaces: true,
          renderLineHighlight: 'line',
          cursorBlinking: 'smooth',
          cursorStyle: 'line',
          cursorWidth: 2,
          selectOnLineNumbers: true,
          roundedSelection: true,
          readOnly: disabled,
          domReadOnly: disabled,
          quickSuggestions: true,
          suggestOnTriggerCharacters: true,
          acceptSuggestionOnEnter: 'on',
          tabCompletion: 'on',
          wordBasedSuggestions: 'currentDocument',
          parameterHints: { enabled: true },
          formatOnPaste: true,
          formatOnType: true,
          padding: { top: 12, bottom: 12 },
          scrollbar: {
            vertical: 'auto',
            horizontal: 'auto',
            verticalScrollbarSize: 10,
            horizontalScrollbarSize: 10,
          },
        }}
      />
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#1a1a1a] border-t border-border text-xs text-muted-foreground">
        <span>
          <kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">Ctrl</kbd>
          {' + '}
          <kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">Space</kbd>
          {' for autocomplete'}
        </span>
        <span>
          <kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">Ctrl</kbd>
          {' + '}
          <kbd className="px-1 py-0.5 bg-muted rounded text-[10px]">Enter</kbd>
          {' to run'}
        </span>
      </div>
    </div>
  );
}
