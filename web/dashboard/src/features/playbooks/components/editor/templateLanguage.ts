import type { Monaco } from '@monaco-editor/react';

/**
 * Register custom template language for n8n-style template syntax
 * Supports {{ $node.xxx.json.yyy }} patterns
 */
export function registerTemplateLanguage(monaco: Monaco): void {
  // Register language
  monaco.languages.register({ id: 'template' });

  // Define token provider
  monaco.languages.setMonarchTokensProvider('template', {
    tokenizer: {
      root: [
        // Template expression {{ ... }}
        [/\{\{/, { token: 'delimiter.template', bracket: '@open', next: '@expression' }],
        // Plain text
        [/./, 'text'],
      ],
      expression: [
        // Closing braces
        [/\}\}/, { token: 'delimiter.template', bracket: '@close', next: '@pop' }],
        // Keywords
        [/\$node/, 'keyword.node'],
        [/\$json/, 'keyword.json'],
        [/\$execution/, 'keyword.execution'],
        [/\$workflow/, 'keyword.workflow'],
        [/\$input/, 'keyword.input'],
        // Object/array accessors
        [/\.json/, 'keyword.accessor'],
        [/\[/, { token: 'delimiter.bracket', bracket: '@open' }],
        [/\]/, { token: 'delimiter.bracket', bracket: '@close' }],
        // Dot notation
        [/\./, 'delimiter.dot'],
        // Identifiers (node names, field names)
        [/[a-zA-Z_$][a-zA-Z0-9_$]*/, 'identifier'],
        // Numbers
        [/\d+/, 'number'],
        // Strings
        [/"([^"\\]|\\.)*$/, 'string.invalid'], // non-terminated string
        [/'([^'\\]|\\.)*$/, 'string.invalid'], // non-terminated string
        [/"/, { token: 'string.quote', bracket: '@open', next: '@string_double' }],
        [/'/, { token: 'string.quote', bracket: '@open', next: '@string_single' }],
        // Whitespace
        [/\s+/, 'white'],
      ],
      string_double: [
        [/[^\\"]+/, 'string'],
        [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }],
      ],
      string_single: [
        [/[^\\']+/, 'string'],
        [/'/, { token: 'string.quote', bracket: '@close', next: '@pop' }],
      ],
    },
  });

  // Define theme colors for template tokens
  monaco.editor.defineTheme('template-dark', {
    base: 'vs-dark',
    inherit: true,
    rules: [
      { token: 'delimiter.template', foreground: 'FFA500', fontStyle: 'bold' }, // Orange braces
      { token: 'keyword.node', foreground: 'FF00FF', fontStyle: 'bold' }, // Magenta for $node
      { token: 'keyword.json', foreground: '00D4FF' }, // Cyan for .json
      { token: 'keyword.accessor', foreground: '00D4FF' },
      { token: 'keyword.execution', foreground: 'FF00FF' },
      { token: 'keyword.workflow', foreground: 'FF00FF' },
      { token: 'keyword.input', foreground: 'FF00FF' },
      { token: 'identifier', foreground: 'D4D4D4' }, // Light gray for identifiers
      { token: 'number', foreground: 'B5CEA8' },
      { token: 'string', foreground: 'CE9178' },
      { token: 'delimiter.dot', foreground: 'D4D4D4' },
      { token: 'delimiter.bracket', foreground: 'FFD700' },
    ],
    colors: {
      'editor.background': '#1e1e1e',
      'editor.foreground': '#d4d4d4',
    },
  });

  // Configure bracket matching
  monaco.languages.setLanguageConfiguration('template', {
    brackets: [
      ['{{', '}}'],
      ['[', ']'],
      ['"', '"'],
      ["'", "'"],
    ],
    autoClosingPairs: [
      { open: '{{', close: '}}' },
      { open: '[', close: ']' },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
    surroundingPairs: [
      { open: '{{', close: '}}' },
      { open: '[', close: ']' },
      { open: '"', close: '"' },
      { open: "'", close: "'" },
    ],
  });
}
