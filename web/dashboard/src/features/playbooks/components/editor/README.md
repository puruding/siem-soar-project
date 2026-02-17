# TemplateEditor Component

Monaco-based template editor with auto-complete support for n8n-style template syntax (`{{ $node.xxx.json.yyy }}`).

## Features

- **Custom Language Definition**: Syntax highlighting for template expressions
- **Smart Auto-Complete**: Context-aware suggestions for node references and field paths
- **Schema Integration**: Uses `nodeSchemaRegistry` to provide field completions
- **Auto-Resize**: Adjusts height based on content
- **Dark Theme**: Matches the application's dark mode design

## Components

### 1. templateLanguage.ts

Registers custom Monaco language for template syntax with:
- Token highlighting for `{{ }}`, `$node`, `$json`, etc.
- Bracket matching and auto-closing
- Custom dark theme with color-coded tokens

### 2. templateCompletionProvider.ts

Provides intelligent auto-completion for:
- **Keywords**: `$node`, `$json`, `$execution`, `$workflow`, `$input`
- **Node Names**: Suggests upstream nodes from the workflow
- **Accessors**: `.json` accessor for node outputs
- **Field Paths**: Nested field navigation with type information

### 3. TemplateEditor.tsx

React component that wraps Monaco Editor with:
- Template language support
- Upstream node schema integration
- Auto-resize functionality
- Placeholder support
- Read-only mode

## Usage

### Basic Example

```tsx
import { TemplateEditor } from '@/features/playbooks/components/editor';
import type { UpstreamNode } from '@/features/playbooks/components/editor';

function MyComponent() {
  const [value, setValue] = useState('');

  const upstreamNodes: UpstreamNode[] = [
    { nodeId: 'trigger-1', nodeName: 'AlertTrigger' },
    { nodeId: 'enrich-1', nodeName: 'EnrichAlert' },
  ];

  return (
    <TemplateEditor
      value={value}
      onChange={setValue}
      upstreamNodes={upstreamNodes}
      placeholder="Enter template..."
    />
  );
}
```

### With Custom Height

```tsx
<TemplateEditor
  value={value}
  onChange={setValue}
  upstreamNodes={upstreamNodes}
  minHeight={150}
  maxHeight={500}
/>
```

### Read-Only Mode

```tsx
<TemplateEditor
  value={value}
  onChange={() => {}}
  upstreamNodes={[]}
  readOnly={true}
/>
```

## Auto-Complete Context

The completion provider detects the current context and provides relevant suggestions:

| Context | Trigger | Suggestions |
|---------|---------|-------------|
| Start | `{{ ` | `$node`, `$json`, `$execution` |
| Node | `{{ $node.` | Upstream node names |
| Accessor | `{{ $node.NodeName.` | `.json` accessor |
| Field | `{{ $node.NodeName.json.` | Field names from schema |

### Example Auto-Complete Flow

```
{{ $n      → suggests: $node, $json, $execution
{{ $node.  → suggests: AlertTrigger, EnrichAlert, CheckSeverity
{{ $node.EnrichAlert. → suggests: json
{{ $node.EnrichAlert.json. → suggests: alert, severity, recipient_email, etc.
{{ $node.EnrichAlert.json.alert. → suggests nested fields: id, severity, source, timestamp, iocs
```

## Schema Integration

The editor uses `nodeSchemaRegistry` to provide field completions:

```typescript
import { nodeSchemaRegistry } from '../../services/nodeSchemaRegistry';

// Get schema for a node
const schema = nodeSchemaRegistry.getNodeSchema(node);

// Schema provides:
// - nodeId: string
// - nodeName: string
// - nodeType: string
// - fields: NodeOutputField[]
//   - name: string
//   - type: 'string' | 'number' | 'boolean' | 'object' | 'array'
//   - description?: string
//   - example?: unknown
//   - children?: NodeOutputField[]
```

## Template Syntax

### Supported Patterns

```
{{ $node.NodeName.json.field }}           // Reference node output field
{{ $node.NodeName.json.nested.field }}    // Nested field access
{{ $node.NodeName.json.array[0] }}        // Array indexing
{{ $json.field }}                         // Current node data
{{ $execution.id }}                       // Execution metadata
```

### Token Highlighting

| Token | Color | Example |
|-------|-------|---------|
| Delimiters | Orange | `{{ }}` |
| Keywords | Magenta | `$node`, `$json` |
| Accessors | Cyan | `.json` |
| Identifiers | Gray | `NodeName`, `field` |
| Numbers | Green | `0`, `123` |
| Strings | Brown | `"text"`, `'text'` |

## Props

### TemplateEditor

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `value` | `string` | - | Template content |
| `onChange` | `(value: string) => void` | - | Change handler |
| `upstreamNodes` | `UpstreamNode[]` | - | Upstream nodes for completion |
| `placeholder` | `string` | `'Enter template...'` | Placeholder text |
| `className` | `string` | - | Additional CSS classes |
| `minHeight` | `number` | `120` | Minimum editor height (px) |
| `maxHeight` | `number` | `400` | Maximum editor height (px) |
| `readOnly` | `boolean` | `false` | Read-only mode |

### UpstreamNode

```typescript
interface UpstreamNode {
  nodeId: string;    // Unique node identifier
  nodeName: string;  // Display name for completion
}
```

## Monaco Editor Options

The editor uses the following Monaco options:

```typescript
{
  minimap: { enabled: false },              // Disable minimap
  fontSize: 13,                             // Font size
  fontFamily: 'Roboto Mono, monospace',     // Monospace font
  lineNumbers: 'off',                       // Hide line numbers
  scrollBeyondLastLine: false,              // No scroll past end
  wordWrap: 'on',                           // Enable word wrap
  automaticLayout: true,                    // Auto-resize
  tabSize: 2,                               // 2-space tabs
  insertSpaces: true,                       // Spaces not tabs
  cursorBlinking: 'smooth',                 // Smooth cursor
  smoothScrolling: true,                    // Smooth scroll
  padding: { top: 8, bottom: 8 },           // Vertical padding
  suggest: {
    showKeywords: true,                     // Show keywords
    showSnippets: true,                     // Show snippets
    showWords: false,                       // Hide word completions
  },
  quickSuggestions: {
    other: true,                            // Enable suggestions
    comments: false,
    strings: false,
  },
  suggestOnTriggerCharacters: true,         // Trigger on special chars
  acceptSuggestionOnEnter: 'on',            // Enter accepts
  tabCompletion: 'on',                      // Tab accepts
  wordBasedSuggestions: 'off',              // Disable word-based
}
```

## Extending

### Add Custom Keywords

Edit `templateLanguage.ts`:

```typescript
expression: [
  [/\$myKeyword/, 'keyword.custom'],
  // ... existing rules
]
```

### Add Custom Completion

Edit `templateCompletionProvider.ts`:

```typescript
case 'start':
  suggestions.push({
    label: '$myKeyword',
    kind: monaco.languages.CompletionItemKind.Keyword,
    detail: 'My custom keyword',
    insertText: '$myKeyword.',
    // ...
  });
```

### Customize Theme Colors

Edit `templateLanguage.ts`:

```typescript
monaco.editor.defineTheme('template-dark', {
  base: 'vs-dark',
  inherit: true,
  rules: [
    { token: 'keyword.custom', foreground: '00FF00' }, // Green
    // ... existing rules
  ],
  colors: {
    'editor.background': '#1e1e1e',
    // ... custom colors
  },
});
```

## Architecture

```
TemplateEditor.tsx
├── Monaco Editor (wrapper)
├── templateLanguage.ts (syntax highlighting)
│   ├── Monarch tokenizer
│   ├── Language configuration
│   └── Custom theme
└── templateCompletionProvider.ts (auto-complete)
    ├── Context parser
    ├── Suggestion generator
    └── Schema integration
```

## Performance

- **Language Registration**: Once per session (memoized with `useRef`)
- **Completion Provider**: Re-registers when `upstreamNodes` changes
- **Height Calculation**: Throttled via Monaco's `onDidContentSizeChange`
- **Schema Access**: O(1) lookup via `nodeSchemaRegistry.getNodeSchema()`

## Dependencies

- `@monaco-editor/react` - Monaco wrapper
- `nodeSchemaRegistry` - Schema provider
- `shadcn/ui` - UI components (Card, etc.)

## Testing

Example test cases:

```typescript
// 1. Basic rendering
const { container } = render(
  <TemplateEditor value="" onChange={jest.fn()} upstreamNodes={[]} />
);

// 2. Auto-complete trigger
// Type "{{ $n" and expect suggestions

// 3. Schema integration
// Provide upstream nodes and verify field suggestions

// 4. Height adjustment
// Add multiple lines and verify height changes
```

## Related Files

- `types/template.types.ts` - Type definitions
- `services/nodeSchemaRegistry.ts` - Schema registry
- `components/editor/TemplateEditorExample.tsx` - Usage example
