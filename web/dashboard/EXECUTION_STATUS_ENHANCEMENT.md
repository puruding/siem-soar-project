# Node Components - Execution Status Enhancement

## Summary

Enhanced node components (ActionNode, IntegrationNode, TriggerNode) to support real-time execution status visualization.

## Changes Made

### 1. Created StatusIndicator Component
**File:** `src/features/playbooks/components/execution/StatusIndicator.tsx`

- Reusable status indicator component
- Supports 7 execution states: pending, queued, running, success, error, skipped, cancelled
- Three size variants: sm, md, lg
- Optional label display
- Animated icons for running/queued states
- Color-coded with design system colors

### 2. Updated ActionNode.tsx
**Changes:**
- Added `executionStatus` and `executionDuration` to `ActionNodeData` interface
- Imported `StatusIndicator` component
- Added status indicator badge (top-right corner, z-index 10)
- Added dynamic border glow effects:
  - Running: blue ring with pulse animation
  - Success: green ring
  - Error: red ring with shake animation

### 3. Updated IntegrationNode.tsx
**Changes:**
- Added `executionStatus` and `executionDuration` to `IntegrationNodeData` interface
- Imported `StatusIndicator` component
- Added status indicator badge (top-right corner, z-index 10)
- Added same dynamic border glow effects as ActionNode

### 4. Updated TriggerNode.tsx
**Changes:**
- Added `executionStatus` and `executionDuration` to `TriggerNodeData` interface
- Imported `StatusIndicator` component
- Added status indicator badge (top-right corner, z-index 10)
- Added same dynamic border glow effects as ActionNode

### 5. Updated tailwind.config.js
**Changes:**
- Added `shake` animation for error states
- Keyframes: horizontal shake effect (-2px to +2px)

### 6. Updated nodes/index.ts
**Changes:**
- Exported `StatusIndicator` component for external use

## Visual Effects

### Status Indicator Badge
- Positioned at top-right corner (-top-2, -right-2)
- Small size (sm) for minimal space usage
- High z-index (10) to appear above node content
- Rounded background with status-specific color

### Border Glow Effects
- **Running**: Blue ring (ring-blue-500/50) with pulse animation
- **Success**: Green ring (ring-[#5CC05C]/50) static
- **Error**: Red ring (ring-[#DC4E41]/50) with shake animation
- Non-intrusive, additive to existing selection rings

## Integration Points

Components are ready for WebSocket integration:

```typescript
// Example usage in PlaybookEditor
const updateNodeStatus = (nodeId: string, status: NodeExecutionStatus) => {
  setNodes((nodes) =>
    nodes.map((node) =>
      node.id === nodeId
        ? {
            ...node,
            data: {
              ...node.data,
              executionStatus: status,
            },
          }
        : node
    )
  );
};
```

## Type Safety

All components use the standardized `NodeExecutionStatus` type from:
`src/features/playbooks/types/execution.types.ts`

## Testing Notes

- No new TypeScript errors introduced
- Pre-existing error in nodeSchemaRegistry.ts unrelated to this change
- Components backward compatible (all new fields optional)

## Next Steps

1. Integrate with WebSocket service (ExecutionMonitor)
2. Connect to real-time execution events
3. Add execution duration display
4. Test with various execution scenarios
