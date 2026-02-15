import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogDescription,
} from '@/components/ui/dialog';
import {
  Tag,
  AlertTriangle,
  FolderInput,
  Trash2,
  X,
} from 'lucide-react';
import { useState } from 'react';
import type { Asset, AssetGroup } from '../types';

interface AssetBulkActionsProps {
  selectedCount: number;
  groups: AssetGroup[];
  onClearSelection: () => void;
  onAddTag: (tag: string) => void;
  onChangeCriticality: (criticality: Asset['criticality']) => void;
  onMoveToGroup: (groupId: string) => void;
  onDelete: () => void;
}

const criticalityColors: Record<Asset['criticality'], string> = {
  critical: 'text-[#DC4E41]',
  high: 'text-[#F79836]',
  medium: 'text-[#FFB84D]',
  low: 'text-[#5CC05C]',
};

export function AssetBulkActions({
  selectedCount,
  groups,
  onClearSelection,
  onAddTag,
  onChangeCriticality,
  onMoveToGroup,
  onDelete,
}: AssetBulkActionsProps) {
  const [tagDialogOpen, setTagDialogOpen] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [newTag, setNewTag] = useState('');

  const handleAddTag = () => {
    if (newTag.trim()) {
      onAddTag(newTag.trim());
      setNewTag('');
      setTagDialogOpen(false);
    }
  };

  const handleDelete = () => {
    onDelete();
    setDeleteDialogOpen(false);
  };

  return (
    <>
      <div className="flex items-center gap-3 p-3 bg-primary/5 border border-primary/20 rounded-lg">
        <span className="text-sm font-medium">
          {selectedCount} selected
        </span>
        <Button variant="ghost" size="sm" onClick={onClearSelection}>
          <X className="w-4 h-4" />
        </Button>
        <div className="h-4 w-px bg-border" />

        {/* Add Tag */}
        <Button
          variant="outline"
          size="sm"
          onClick={() => setTagDialogOpen(true)}
        >
          <Tag className="w-4 h-4 mr-2" />
          Add Tag
        </Button>

        {/* Change Criticality */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm">
              <AlertTriangle className="w-4 h-4 mr-2" />
              Criticality
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Set Criticality</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {(['critical', 'high', 'medium', 'low'] as const).map((level) => (
              <DropdownMenuItem
                key={level}
                onClick={() => onChangeCriticality(level)}
                className={criticalityColors[level]}
              >
                <span className="capitalize">{level}</span>
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Move to Group */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm">
              <FolderInput className="w-4 h-4 mr-2" />
              Move to Group
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent>
            <DropdownMenuLabel>Select Group</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {groups.map((group) => (
              <DropdownMenuItem
                key={group.id}
                onClick={() => onMoveToGroup(group.id)}
              >
                {group.name}
              </DropdownMenuItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Delete */}
        <Button
          variant="outline"
          size="sm"
          className="text-destructive hover:bg-destructive/10"
          onClick={() => setDeleteDialogOpen(true)}
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Delete
        </Button>
      </div>

      {/* Add Tag Dialog */}
      <Dialog open={tagDialogOpen} onOpenChange={setTagDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Tag to Selected Assets</DialogTitle>
            <DialogDescription>
              This tag will be added to {selectedCount} selected asset(s).
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            <Input
              placeholder="Enter tag name..."
              value={newTag}
              onChange={(e) => setNewTag(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleAddTag()}
            />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTagDialogOpen(false)}>
              Cancel
            </Button>
            <Button onClick={handleAddTag} disabled={!newTag.trim()}>
              Add Tag
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Delete Assets</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete {selectedCount} asset(s)? This action cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setDeleteDialogOpen(false)}>
              Cancel
            </Button>
            <Button variant="destructive" onClick={handleDelete}>
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
