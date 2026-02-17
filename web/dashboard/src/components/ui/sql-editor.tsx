/**
 * SQLEditor - SQL code editor with syntax highlighting and autocompletion
 */
import { useCallback, useMemo } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { sql, SQLDialect, SQLConfig } from '@codemirror/lang-sql';
import { oneDark } from '@codemirror/theme-one-dark';
import { autocompletion, CompletionContext, Completion } from '@codemirror/autocomplete';
import { EditorView } from '@codemirror/view';

// SQL Keywords for autocompletion
const SQL_KEYWORDS = [
  'SELECT', 'FROM', 'WHERE', 'AND', 'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN',
  'IS', 'NULL', 'ORDER', 'BY', 'ASC', 'DESC', 'LIMIT', 'OFFSET',
  'GROUP', 'HAVING', 'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON',
  'AS', 'DISTINCT', 'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'CASE', 'WHEN',
  'THEN', 'ELSE', 'END', 'UNION', 'ALL', 'INSERT', 'INTO', 'VALUES',
  'UPDATE', 'SET', 'DELETE', 'CREATE', 'TABLE', 'DROP', 'ALTER', 'INDEX',
  'WITH', 'INTERVAL', 'NOW', 'TODAY', 'YESTERDAY', 'TRUE', 'FALSE',
];

// SQL Functions
const SQL_FUNCTIONS = [
  'COUNT', 'SUM', 'AVG', 'MIN', 'MAX', 'COALESCE', 'NULLIF', 'CAST',
  'CONCAT', 'LENGTH', 'LOWER', 'UPPER', 'TRIM', 'SUBSTRING', 'REPLACE',
  'NOW', 'TODAY', 'YESTERDAY', 'DATE', 'DATETIME', 'TIMESTAMP',
  'YEAR', 'MONTH', 'DAY', 'HOUR', 'MINUTE', 'SECOND',
  'IF', 'IFNULL', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'ROUND', 'FLOOR', 'CEIL', 'ABS', 'SQRT', 'POWER', 'MOD',
  'toDateTime', 'toDate', 'toStartOfDay', 'toStartOfHour', 'toStartOfMinute',
  'formatDateTime', 'dateDiff', 'dateAdd', 'dateSub',
  'arrayJoin', 'groupArray', 'uniq', 'uniqExact',
];

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
  // Build completion source from schema
  const schemaCompletions = useMemo(() => {
    const completions: Completion[] = [];

    // Add SQL keywords
    SQL_KEYWORDS.forEach((keyword) => {
      completions.push({
        label: keyword,
        type: 'keyword',
        detail: 'keyword',
        boost: -1,
      });
      // Also add lowercase version
      completions.push({
        label: keyword.toLowerCase(),
        type: 'keyword',
        detail: 'keyword',
        boost: -2,
      });
    });

    // Add SQL functions
    SQL_FUNCTIONS.forEach((func) => {
      completions.push({
        label: func,
        type: 'function',
        detail: 'function',
        apply: `${func}()`,
        boost: 0,
      });
      completions.push({
        label: func.toLowerCase(),
        type: 'function',
        detail: 'function',
        apply: `${func.toLowerCase()}()`,
        boost: -1,
      });
    });

    // Add table names from schema
    schema.forEach((table) => {
      completions.push({
        label: table.name,
        type: 'class',
        detail: 'table',
        boost: 2,
      });

      // Add column names with table prefix
      table.columns.forEach((col) => {
        completions.push({
          label: col.name,
          type: 'property',
          detail: `${table.name}.${col.type}`,
          boost: 1,
        });
        // Also add with table prefix
        completions.push({
          label: `${table.name}.${col.name}`,
          type: 'property',
          detail: col.type,
          boost: 1,
        });
      });
    });

    return completions;
  }, [schema]);

  // Custom completion function
  const customCompletions = useCallback((context: CompletionContext) => {
    const word = context.matchBefore(/[\w.]+/);
    if (!word || (word.from === word.to && !context.explicit)) {
      return null;
    }

    const searchText = word.text.toLowerCase();

    // Filter completions based on input
    const filtered = schemaCompletions.filter((c) =>
      c.label.toLowerCase().includes(searchText)
    );

    // Sort by relevance
    filtered.sort((a, b) => {
      const aStartsWith = a.label.toLowerCase().startsWith(searchText);
      const bStartsWith = b.label.toLowerCase().startsWith(searchText);
      if (aStartsWith && !bStartsWith) return -1;
      if (!aStartsWith && bStartsWith) return 1;
      return (b.boost || 0) - (a.boost || 0);
    });

    return {
      from: word.from,
      options: filtered.slice(0, 50), // Limit to 50 suggestions
      validFor: /^[\w.]*$/,
    };
  }, [schemaCompletions]);

  // SQL dialect configuration
  const sqlConfig: SQLConfig = useMemo(() => ({
    dialect: SQLDialect.define({
      keywords: SQL_KEYWORDS.join(' ').toLowerCase(),
      builtin: SQL_FUNCTIONS.join(' ').toLowerCase(),
      types: 'string int integer float double boolean date datetime timestamp array',
      operatorChars: '+-*/<>=!&|',
    }),
    schema: schema.reduce((acc, table) => {
      acc[table.name] = table.columns.map((c) => c.name);
      return acc;
    }, {} as Record<string, string[]>),
    tables: schema.map((t) => ({ label: t.name, type: 'class' })),
  }), [schema]);

  // Extensions
  const extensions = useMemo(() => [
    sql(sqlConfig),
    autocompletion({
      override: [customCompletions],
      activateOnTyping: true,
      maxRenderedOptions: 50,
      icons: true,
    }),
    EditorView.lineWrapping,
    EditorView.domEventHandlers({
      keydown: (event) => {
        // Ctrl+Enter to execute
        if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
          event.preventDefault();
          onExecute?.();
          return true;
        }
        return false;
      },
    }),
    EditorView.updateListener.of((update) => {
      if (update.docChanged) {
        onChange(update.state.doc.toString());
      }
    }),
  ], [sqlConfig, customCompletions, onExecute, onChange]);

  return (
    <div className={`sql-editor-container rounded-md border border-border overflow-hidden ${className}`}>
      <CodeMirror
        value={value}
        height={height}
        theme={[oneDark, customTheme]}
        extensions={extensions}
        placeholder={placeholder}
        editable={!disabled}
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
          autocompletion: false, // We use custom autocompletion
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
