/**
 * SQLEditor - SQL code editor with syntax highlighting and autocompletion
 */
import { useMemo } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { sql } from '@codemirror/lang-sql';
import { oneDark } from '@codemirror/theme-one-dark';
import { EditorView, keymap } from '@codemirror/view';

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

// Custom theme to match the app's dark theme
const customTheme = EditorView.theme({
  '&': {
    backgroundColor: '#1e1e1e',
    color: '#d4d4d4',
    fontSize: '14px',
    fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
  },
  '.cm-content': {
    caretColor: '#00A4A6',
    padding: '12px 0',
  },
  '.cm-cursor': {
    borderLeftColor: '#00A4A6',
    borderLeftWidth: '2px',
  },
  '.cm-activeLine': {
    backgroundColor: 'rgba(0, 164, 166, 0.08)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgba(0, 164, 166, 0.08)',
  },
  '.cm-gutters': {
    backgroundColor: '#1e1e1e',
    color: '#6e7681',
    border: 'none',
    borderRight: '1px solid #2d3339',
  },
  '.cm-lineNumbers .cm-gutterElement': {
    padding: '0 12px 0 8px',
    minWidth: '40px',
  },
  '.cm-selectionBackground': {
    backgroundColor: 'rgba(0, 164, 166, 0.3) !important',
  },
  '&.cm-focused .cm-selectionBackground': {
    backgroundColor: 'rgba(0, 164, 166, 0.3) !important',
  },
  '.cm-matchingBracket': {
    backgroundColor: 'rgba(0, 164, 166, 0.3)',
    outline: '1px solid #00A4A6',
  },
  '.cm-tooltip': {
    backgroundColor: '#1F2527',
    border: '1px solid #2D3339',
    borderRadius: '6px',
    boxShadow: '0 4px 12px rgba(0, 0, 0, 0.4)',
  },
  '.cm-tooltip.cm-tooltip-autocomplete': {
    '& > ul': {
      fontFamily: 'JetBrains Mono, Fira Code, Consolas, Monaco, monospace',
      fontSize: '13px',
      maxHeight: '300px',
    },
    '& > ul > li': {
      padding: '6px 12px',
      borderRadius: '4px',
      margin: '2px 4px',
    },
    '& > ul > li[aria-selected]': {
      backgroundColor: 'rgba(0, 164, 166, 0.2)',
      color: '#ffffff',
    },
  },
  '.cm-completionLabel': {
    color: '#d4d4d4',
  },
  '.cm-completionDetail': {
    color: '#9BA7B4',
    fontStyle: 'italic',
    marginLeft: '8px',
  },
  '.cm-completionMatchedText': {
    color: '#00A4A6',
    fontWeight: 'bold',
    textDecoration: 'none',
  },
  '.cm-placeholder': {
    color: '#6e7681',
    fontStyle: 'italic',
  },
}, { dark: true });

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
  // Build schema for SQL language
  const sqlSchema = useMemo(() => {
    const schemaObj: Record<string, string[]> = {};
    schema.forEach((table) => {
      schemaObj[table.name] = table.columns.map((c) => c.name);
    });
    return schemaObj;
  }, [schema]);

  // Extensions
  const extensions = useMemo(() => {
    const exts = [
      sql({ schema: sqlSchema }),
      EditorView.lineWrapping,
      keymap.of([
        {
          key: 'Ctrl-Enter',
          mac: 'Cmd-Enter',
          run: () => {
            onExecute?.();
            return true;
          },
        },
      ]),
    ];
    return exts;
  }, [sqlSchema, onExecute]);

  return (
    <div className={`sql-editor-container rounded-md border border-border overflow-hidden ${className}`}>
      <CodeMirror
        value={value}
        height={height}
        theme={[oneDark, customTheme]}
        extensions={extensions}
        placeholder={placeholder}
        editable={!disabled}
        onChange={onChange}
        basicSetup={{
          lineNumbers: true,
          highlightActiveLineGutter: true,
          highlightSpecialChars: true,
          history: true,
          foldGutter: true,
          drawSelection: true,
          dropCursor: true,
          allowMultipleSelections: true,
          indentOnInput: true,
          syntaxHighlighting: true,
          bracketMatching: true,
          closeBrackets: true,
          autocompletion: true,
          rectangularSelection: true,
          crosshairCursor: false,
          highlightActiveLine: true,
          highlightSelectionMatches: true,
          closeBracketsKeymap: true,
          defaultKeymap: true,
          searchKeymap: true,
          historyKeymap: true,
          foldKeymap: true,
          completionKeymap: true,
          lintKeymap: true,
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
