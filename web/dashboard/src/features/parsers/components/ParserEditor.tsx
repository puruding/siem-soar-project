import { useState, useCallback } from 'react';
import Editor from '@monaco-editor/react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Label } from '@/components/ui/label';
import { Save, RotateCcw, History, Trash2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Parser, ParserFormat } from '../types';
import { FormatSelector } from './FormatSelector';

interface ParserEditorProps {
  parser: Parser;
  onSave: (updates: Partial<Parser>) => void;
  onDelete?: () => void;
}

// Monaco editor options for dark theme
const editorOptions = {
  minimap: { enabled: false },
  lineNumbers: 'on' as const,
  scrollBeyondLastLine: false,
  wordWrap: 'on' as const,
  fontSize: 13,
  fontFamily: 'JetBrains Mono, Fira Code, monospace',
  tabSize: 2,
  automaticLayout: true,
  folding: true,
  renderLineHighlight: 'line' as const,
  cursorBlinking: 'smooth' as const,
  smoothScrolling: true,
  padding: { top: 12, bottom: 12 },
  scrollbar: {
    verticalScrollbarSize: 8,
    horizontalScrollbarSize: 8,
  },
};

// Custom dark theme definition for Monaco
const customTheme = {
  base: 'vs-dark' as const,
  inherit: true,
  rules: [
    { token: 'comment', foreground: '6A737D' },
    { token: 'keyword', foreground: 'FF79C6' },
    { token: 'string', foreground: 'F1FA8C' },
    { token: 'number', foreground: 'BD93F9' },
    { token: 'regexp', foreground: 'FFB86C' },
    { token: 'type', foreground: '8BE9FD' },
    { token: 'variable', foreground: '50FA7B' },
  ],
  colors: {
    'editor.background': '#1A1F23',
    'editor.foreground': '#F8F8F2',
    'editor.lineHighlightBackground': '#2D3339',
    'editor.selectionBackground': '#44475A',
    'editorCursor.foreground': '#00A4A6',
    'editorLineNumber.foreground': '#6272A4',
    'editorLineNumber.activeForeground': '#F8F8F2',
    'editor.selectionHighlightBackground': '#424450',
    'editorBracketMatch.background': '#44475A',
    'editorBracketMatch.border': '#00A4A6',
  },
};

// Language config hints based on parser format
const formatLanguageHints: Record<ParserFormat, { language: string; placeholder: string }> = {
  grok: {
    language: 'plaintext',
    placeholder: '%{PATTERN:field_name}',
  },
  json: {
    language: 'json',
    placeholder: '{"key": "%{DATA:value}"}',
  },
  cef: {
    language: 'plaintext',
    placeholder: 'CEF:%{INT:version}|%{DATA:vendor}|...',
  },
  leef: {
    language: 'plaintext',
    placeholder: 'LEEF:%{DATA:version}|%{DATA:vendor}|...',
  },
  regex: {
    language: 'plaintext',
    placeholder: '(?<field_name>pattern)',
  },
  kv: {
    language: 'plaintext',
    placeholder: 'key1=value1 key2=value2',
  },
};

export function ParserEditor({ parser, onSave, onDelete }: ParserEditorProps) {
  const [name, setName] = useState(parser.name);
  const [productId, setProductId] = useState(parser.productId || '');
  const [format, setFormat] = useState<ParserFormat>(parser.format);
  const [pattern, setPattern] = useState(parser.pattern);
  const [hasChanges, setHasChanges] = useState(false);

  const handlePatternChange = useCallback((value: string | undefined) => {
    setPattern(value || '');
    setHasChanges(true);
  }, []);

  const handleSave = useCallback(() => {
    onSave({
      name,
      productId: productId || undefined,
      format,
      pattern,
    });
    setHasChanges(false);
  }, [name, productId, format, pattern, onSave]);

  const handleReset = useCallback(() => {
    setName(parser.name);
    setProductId(parser.productId || '');
    setFormat(parser.format);
    setPattern(parser.pattern);
    setHasChanges(false);
  }, [parser]);

  const handleEditorMount = useCallback((editor: unknown, monaco: unknown) => {
    // Type assertion for monaco
    const monacoInstance = monaco as {
      editor: {
        defineTheme: (name: string, theme: typeof customTheme) => void;
        setTheme: (name: string) => void;
      };
    };
    // Define custom theme
    monacoInstance.editor.defineTheme('siem-dark', customTheme);
    monacoInstance.editor.setTheme('siem-dark');
  }, []);

  const languageHint = formatLanguageHints[format];

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-border/50">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <h2 className="font-semibold text-lg">{parser.name}</h2>
            <Badge variant="outline" className="text-xs">
              v{parser.version}
            </Badge>
            {hasChanges && (
              <Badge variant="warning" className="text-xs">
                Unsaved
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={handleReset}
              disabled={!hasChanges}
            >
              <RotateCcw className="w-4 h-4 mr-2" />
              Reset
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={onDelete}
              className="text-destructive hover:bg-destructive/10"
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete
            </Button>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={!hasChanges}
              className={cn(
                hasChanges && 'bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80'
              )}
            >
              <Save className="w-4 h-4 mr-2" />
              Save
            </Button>
          </div>
        </div>

        {/* Parser Metadata */}
        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-2">
            <Label htmlFor="parser-name" className="text-xs text-muted-foreground">
              Parser Name
            </Label>
            <Input
              id="parser-name"
              value={name}
              onChange={(e) => {
                setName(e.target.value);
                setHasChanges(true);
              }}
              className="h-9 bg-background/50"
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="product-id" className="text-xs text-muted-foreground">
              Product ID
            </Label>
            <Input
              id="product-id"
              value={productId}
              onChange={(e) => {
                setProductId(e.target.value);
                setHasChanges(true);
              }}
              placeholder="e.g., AWS_CLOUDTRAIL"
              className="h-9 bg-background/50"
            />
          </div>
          <div className="space-y-2">
            <Label className="text-xs text-muted-foreground">Format</Label>
            <FormatSelector
              value={format}
              onChange={(newFormat) => {
                setFormat(newFormat);
                setHasChanges(true);
              }}
            />
          </div>
        </div>
      </div>

      {/* Editor */}
      <div className="flex-1 p-4">
        <Card className="h-full border-border/50 bg-card/50">
          <CardHeader className="py-3 px-4 border-b border-border/50">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-medium">Pattern Editor</CardTitle>
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <History className="w-3.5 h-3.5" />
                <span>Format: {languageHint.placeholder}</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0 h-[calc(100%-48px)]">
            <Editor
              height="100%"
              language={languageHint.language}
              value={pattern}
              onChange={handlePatternChange}
              onMount={handleEditorMount}
              theme="vs-dark"
              options={editorOptions}
              loading={
                <div className="h-full flex items-center justify-center text-muted-foreground">
                  Loading editor...
                </div>
              }
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
