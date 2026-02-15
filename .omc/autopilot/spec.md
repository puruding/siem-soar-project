# Dashboard UI Restructuring Specification

## Overview

Transform the existing SIEM-SOAR dashboard by adding 5 missing screens based on planning documents.

---

## Part 1: Requirements Analysis (Analyst)

### Functional Requirements

#### 1. Products Management (/products)
- CRUD operations for log source products
- Vendor filtering and search
- Category classification (SIEM, EDR, Firewall, IAM, DLP, NDR, Custom)
- Log format association (Syslog, JSON, CEF, LEEF)
- Parser linking

#### 2. Parsers Management (/parsers)
- Parser CRUD with Monaco Editor for Grok patterns
- Real-time pattern testing with sample logs
- Format selection (Grok, JSON, CEF, LEEF, Regex, KV)
- Field mapping to UDM schema
- Hot reload support
- Status management (draft, active, testing, disabled)

#### 3. Assets Management (/assets)
- Hierarchical tree view with drag-drop
- Grid/Table view toggle
- Bulk operations (tag, move, delete, update criticality)
- CSV/Excel import/export
- Asset types (server, workstation, network_device, container, cloud_instance, IoT)
- Criticality levels (critical, high, medium, low)

#### 4. Rules Management (/rules)
- Sigma rule CRUD with Monaco YAML editor
- ATT&CK MITRE matrix visualization
- Rule testing with sample events
- Import from Sigma repositories
- Severity classification
- Rule versioning

#### 5. Playbooks Enhancement (/playbooks)
- n8n-style features:
  - Loop nodes (forEach, while, times)
  - Parallel execution nodes
  - Wait/delay nodes
  - Sub-playbook calls
- Searchable node palette
- Execution history timeline
- Variable inspector
- Real-time execution visualization

### Non-Functional Requirements

- **Performance**: Initial load < 2s, navigation < 500ms, 10K rows with virtualization < 1s
- **UX**: Consistent with existing dark theme (#1F2527, #00A4A6 accents)
- **Security**: RBAC enforcement on UI elements
- **Accessibility**: Basic keyboard navigation support

### Implicit Requirements

- Empty state designs for each screen
- Error handling patterns
- Loading states
- Confirmation dialogs for destructive operations
- Toast notifications for success/failure

### Out of Scope

- Mobile/tablet responsive layouts (desktop-only)
- Full i18n support (English only for MVP)
- Complex policy inheritance engine UI
- Real-time collaborative editing

---

## Part 2: Technical Specification (Architect)

### Tech Stack Additions

| Package | Version | Purpose |
|---------|---------|---------|
| `@monaco-editor/react` | ^4.6.0 | Monaco Editor for Parsers/Rules |
| `@dnd-kit/core` | ^6.1.0 | Drag-and-drop for asset tree |
| `@dnd-kit/sortable` | ^6.1.0 | Sortable lists |
| `@dnd-kit/utilities` | ^3.2.2 | DnD utilities |
| `react-resizable-panels` | ^2.0.23 | Resizable split panels |
| `yaml` | ^2.3.4 | YAML parsing for Sigma rules |

### File Structure

```
src/features/
├── products/
│   ├── components/
│   │   ├── ProductList.tsx
│   │   ├── ProductDetail.tsx
│   │   ├── ProductForm.tsx
│   │   └── VendorFilter.tsx
│   ├── hooks/
│   │   └── useProducts.ts
│   └── index.ts
│
├── parsers/
│   ├── components/
│   │   ├── ParserList.tsx
│   │   ├── ParserEditor.tsx
│   │   ├── GrokTestPanel.tsx
│   │   ├── ParserDetail.tsx
│   │   └── FormatSelector.tsx
│   ├── hooks/
│   │   └── useParsers.ts
│   └── index.ts
│
├── assets/
│   ├── components/
│   │   ├── AssetList.tsx
│   │   ├── AssetTree.tsx
│   │   ├── AssetDetail.tsx
│   │   ├── AssetBulkActions.tsx
│   │   ├── AssetImport.tsx
│   │   └── AssetTypeIcon.tsx
│   ├── hooks/
│   │   └── useAssets.ts
│   └── index.ts
│
├── rules/
│   ├── components/
│   │   ├── RuleList.tsx
│   │   ├── RuleEditor.tsx
│   │   ├── RuleDetail.tsx
│   │   ├── AttackMatrix.tsx
│   │   ├── RuleTestPanel.tsx
│   │   └── RuleImport.tsx
│   ├── hooks/
│   │   └── useRules.ts
│   └── index.ts
│
├── playbooks/
│   ├── components/
│   │   ├── PlaybookList.tsx (existing)
│   │   ├── PlaybookEditor.tsx (enhanced)
│   │   ├── nodes/
│   │   │   ├── LoopNode.tsx (NEW)
│   │   │   ├── ParallelNode.tsx (NEW)
│   │   │   └── WaitNode.tsx (NEW)
│   │   ├── NodePalette.tsx (NEW)
│   │   ├── ExecutionHistory.tsx (NEW)
│   │   └── VariablePanel.tsx (NEW)
│   ├── hooks/
│   │   └── usePlaybooks.ts
│   └── index.ts
```

### API Types

#### Products
```typescript
interface Product {
  id: string;
  name: string;
  vendorId: string;
  vendor: Vendor;
  version: string;
  category: 'siem' | 'edr' | 'firewall' | 'iam' | 'dlp' | 'ndr' | 'custom';
  status: 'active' | 'inactive' | 'deprecated';
  logFormats: string[];
  parserIds: string[];
  integrationConfig: Record<string, unknown>;
}
```

#### Parsers
```typescript
interface Parser {
  id: string;
  name: string;
  productId?: string;
  format: 'grok' | 'json' | 'cef' | 'leef' | 'regex' | 'kv';
  pattern: string;
  fieldMappings: FieldMapping[];
  sampleLogs: string[];
  testResults?: TestResult;
  status: 'draft' | 'active' | 'testing' | 'disabled';
  version: number;
}
```

#### Assets
```typescript
interface Asset {
  id: string;
  name: string;
  hostname: string;
  ipAddresses: string[];
  type: 'server' | 'workstation' | 'network_device' | 'container' | 'cloud_instance' | 'iot' | 'other';
  osType?: 'windows' | 'linux' | 'macos' | 'ios' | 'android' | 'other';
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'inactive' | 'decommissioned';
  parentId?: string;
  children?: Asset[];
  tags: string[];
}
```

#### Rules
```typescript
interface SigmaRule {
  id: string;
  title: string;
  description: string;
  status: 'draft' | 'testing' | 'active' | 'disabled';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'informational';
  rawYaml: string;
  attack: {
    tactics: AttackTactic[];
    techniques: AttackTechnique[];
  };
  enabled: boolean;
}
```

### Sidebar Navigation Updates

Add after existing items:
```typescript
[
  { title: 'Products', icon: Package, href: '/products' },
  { title: 'Parsers', icon: FileCode, href: '/parsers' },
  { title: 'Assets', icon: Server, href: '/assets' },
  { title: 'Rules', icon: ShieldAlert, href: '/rules' },
]
```

### Routing Updates

Add to App.tsx:
```typescript
<Route path="products" element={<ProductList />} />
<Route path="products/:id" element={<ProductDetail />} />
<Route path="parsers" element={<ParserList />} />
<Route path="parsers/:id" element={<ParserEditor />} />
<Route path="assets" element={<AssetList />} />
<Route path="assets/:id" element={<AssetDetail />} />
<Route path="rules" element={<RuleList />} />
<Route path="rules/:id" element={<RuleEditor />} />
```

---

## Implementation Phases

### Phase 1: Products & Parsers
1. Install new dependencies
2. Create Products feature (CRUD, vendor filter)
3. Create Parsers feature (Monaco editor, Grok test panel)
4. Update Sidebar navigation
5. Add routes

### Phase 2: Assets
1. Create Assets feature (tree view, grid view)
2. Implement drag-drop with @dnd-kit
3. Add bulk operations
4. Add import/export functionality

### Phase 3: Rules
1. Create Rules feature (YAML editor)
2. Implement ATT&CK matrix visualization
3. Add rule testing
4. Add Sigma repository import

### Phase 4: Playbooks Enhancement
1. Add new node types (Loop, Parallel, Wait)
2. Create searchable node palette
3. Add execution history timeline
4. Add variable inspector
5. Implement real-time execution visualization

---

## Success Criteria

1. **Products**: Users can CRUD products with vendor filtering
2. **Parsers**: Pattern validation shows inline errors, test with sample log < 1s
3. **Assets**: Asset list loads < 2s for 10K assets, bulk ops work on 100+ items
4. **Rules**: Sigma rule import works, ATT&CK mapping displays correctly
5. **Playbooks**: New node types work, execution history visible

---

**EXPANSION_COMPLETE**
