import { useState, useCallback } from 'react';
import {
  DndContext,
  closestCenter,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  DragEndEvent,
  DragOverlay,
  DragStartEvent,
} from '@dnd-kit/core';
import {
  SortableContext,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable';
import { CSS } from '@dnd-kit/utilities';
import { Checkbox } from '@/components/ui/checkbox';
import { cn } from '@/lib/utils';
import { ChevronRight, ChevronDown, GripVertical } from 'lucide-react';
import type { AssetTreeNode, Asset } from '../types';
import { AssetTypeIcon } from './AssetTypeIcon';

interface AssetTreeProps {
  tree: AssetTreeNode[];
  selectedAssets: Set<string>;
  onAssetSelect: (asset: Asset) => void;
  onToggleSelection: (id: string) => void;
  onMoveAsset: (assetId: string, targetGroupId: string) => void;
}

const criticalityColors: Record<Asset['criticality'], string> = {
  critical: 'bg-[#DC4E41]',
  high: 'bg-[#F79836]',
  medium: 'bg-[#FFB84D]',
  low: 'bg-[#5CC05C]',
};

interface TreeNodeProps {
  node: AssetTreeNode;
  level: number;
  selectedAssets: Set<string>;
  expandedGroups: Set<string>;
  onToggleExpand: (id: string) => void;
  onAssetSelect: (asset: Asset) => void;
  onToggleSelection: (id: string) => void;
}

function SortableTreeItem({
  node,
  level,
  selectedAssets,
  expandedGroups,
  onToggleExpand,
  onAssetSelect,
  onToggleSelection,
}: TreeNodeProps) {
  const isGroup = node.type === 'group';
  const isExpanded = expandedGroups.has(node.id);
  const isSelected = selectedAssets.has(node.id);

  const {
    attributes,
    listeners,
    setNodeRef,
    transform,
    transition,
    isDragging,
  } = useSortable({
    id: node.id,
    disabled: isGroup,
  });

  const style = {
    transform: CSS.Transform.toString(transform),
    transition,
    opacity: isDragging ? 0.5 : 1,
  };

  return (
    <div ref={setNodeRef} style={style}>
      <div
        className={cn(
          'flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-muted/50 cursor-pointer transition-colors',
          isSelected && 'bg-primary/10',
          isDragging && 'shadow-lg'
        )}
        style={{ paddingLeft: `${level * 24 + 8}px` }}
        onClick={() => {
          if (isGroup) {
            onToggleExpand(node.id);
          } else if (node.asset) {
            onAssetSelect(node.asset);
          }
        }}
      >
        {/* Drag handle for assets */}
        {!isGroup && (
          <span
            {...attributes}
            {...listeners}
            className="cursor-grab hover:bg-muted rounded p-0.5"
            onClick={(e) => e.stopPropagation()}
          >
            <GripVertical className="w-4 h-4 text-muted-foreground" />
          </span>
        )}

        {/* Checkbox */}
        {!isGroup && (
          <div onClick={(e) => e.stopPropagation()}>
            <Checkbox
              checked={isSelected}
              onCheckedChange={() => onToggleSelection(node.id)}
            />
          </div>
        )}

        {/* Expand/collapse for groups */}
        {isGroup && (
          <span className="w-4 h-4 flex items-center justify-center">
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-muted-foreground" />
            ) : (
              <ChevronRight className="w-4 h-4 text-muted-foreground" />
            )}
          </span>
        )}

        {/* Icon */}
        <AssetTypeIcon
          type={node.type}
          className={cn(
            'w-4 h-4',
            isGroup ? 'text-primary' : 'text-muted-foreground'
          )}
        />

        {/* Name */}
        <span className={cn('flex-1 text-sm', isGroup && 'font-medium')}>
          {node.name}
        </span>

        {/* Criticality indicator for assets */}
        {node.asset && (
          <span
            className={cn(
              'w-2 h-2 rounded-full',
              criticalityColors[node.asset.criticality]
            )}
            title={`Criticality: ${node.asset.criticality}`}
          />
        )}

        {/* Asset count for groups */}
        {isGroup && (
          <span className="text-xs text-muted-foreground px-2 py-0.5 bg-muted rounded">
            {node.assetCount}
          </span>
        )}
      </div>

      {/* Children */}
      {isGroup && isExpanded && node.children.length > 0 && (
        <SortableContext
          items={node.children.map((c) => c.id)}
          strategy={verticalListSortingStrategy}
        >
          {node.children.map((child) => (
            <SortableTreeItem
              key={child.id}
              node={child}
              level={level + 1}
              selectedAssets={selectedAssets}
              expandedGroups={expandedGroups}
              onToggleExpand={onToggleExpand}
              onAssetSelect={onAssetSelect}
              onToggleSelection={onToggleSelection}
            />
          ))}
        </SortableContext>
      )}
    </div>
  );
}

function DragOverlayItem({ node }: { node: AssetTreeNode }) {
  return (
    <div className="flex items-center gap-2 px-3 py-2 bg-background border rounded-md shadow-lg">
      <AssetTypeIcon type={node.type} className="w-4 h-4 text-muted-foreground" />
      <span className="text-sm">{node.name}</span>
      {node.asset && (
        <span
          className={cn(
            'w-2 h-2 rounded-full',
            criticalityColors[node.asset.criticality]
          )}
        />
      )}
    </div>
  );
}

export function AssetTree({
  tree,
  selectedAssets,
  onAssetSelect,
  onToggleSelection,
  onMoveAsset,
}: AssetTreeProps) {
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(
    new Set(tree.map((g) => g.id))
  );
  const [activeNode, setActiveNode] = useState<AssetTreeNode | null>(null);

  const sensors = useSensors(
    useSensor(PointerSensor, {
      activationConstraint: {
        distance: 8,
      },
    }),
    useSensor(KeyboardSensor)
  );

  const handleToggleExpand = useCallback((id: string) => {
    setExpandedGroups((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  }, []);

  const findNodeById = useCallback(
    (id: string): AssetTreeNode | null => {
      for (const group of tree) {
        if (group.id === id) return group;
        for (const child of group.children) {
          if (child.id === id) return child;
        }
      }
      return null;
    },
    [tree]
  );

  const handleDragStart = useCallback(
    (event: DragStartEvent) => {
      const node = findNodeById(String(event.active.id));
      setActiveNode(node);
    },
    [findNodeById]
  );

  const handleDragEnd = useCallback(
    (event: DragEndEvent) => {
      const { active, over } = event;
      setActiveNode(null);

      if (!over || active.id === over.id) return;

      const activeId = String(active.id);
      const overId = String(over.id);

      // Find the target group
      const overNode = findNodeById(overId);
      if (!overNode) return;

      // If dropped on a group, move to that group
      if (overNode.type === 'group') {
        onMoveAsset(activeId, overId);
      } else {
        // If dropped on an asset, move to the same group as that asset
        for (const group of tree) {
          if (group.children.some((c) => c.id === overId)) {
            onMoveAsset(activeId, group.id);
            break;
          }
        }
      }
    },
    [findNodeById, onMoveAsset, tree]
  );

  const allNodeIds = tree.flatMap((g) => [g.id, ...g.children.map((c) => c.id)]);

  return (
    <DndContext
      sensors={sensors}
      collisionDetection={closestCenter}
      onDragStart={handleDragStart}
      onDragEnd={handleDragEnd}
    >
      <SortableContext items={allNodeIds} strategy={verticalListSortingStrategy}>
        <div className="space-y-1">
          {tree.map((group) => (
            <SortableTreeItem
              key={group.id}
              node={group}
              level={0}
              selectedAssets={selectedAssets}
              expandedGroups={expandedGroups}
              onToggleExpand={handleToggleExpand}
              onAssetSelect={onAssetSelect}
              onToggleSelection={onToggleSelection}
            />
          ))}
        </div>
      </SortableContext>
      <DragOverlay>
        {activeNode && <DragOverlayItem node={activeNode} />}
      </DragOverlay>
    </DndContext>
  );
}
