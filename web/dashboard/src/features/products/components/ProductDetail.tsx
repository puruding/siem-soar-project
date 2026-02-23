import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  X,
  Edit2,
  Trash2,
  Building2,
  Tag,
  Clock,
  FileCode2,
  ExternalLink,
  Plus,
  ChevronRight,
} from 'lucide-react';
import { formatTimestamp, cn } from '@/lib/utils';
import type { Product } from '../types';
import { categoryLabels, categoryColors, statusLabels, statusColors } from '../hooks/useProducts';
import { useProductParsers } from '@/features/parsers/hooks/useParsers';
import { FormatSelector, FormatBadge } from '@/features/parsers/components/FormatSelector';
import type { ParserFormat } from '@/features/parsers/types';

const formatColors: Record<string, string> = {
  grok: 'bg-purple-500/20 text-purple-400 border-purple-500/50',
  json: 'bg-blue-500/20 text-blue-400 border-blue-500/50',
  cef: 'bg-green-500/20 text-green-400 border-green-500/50',
  leef: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/50',
  regex: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
  kv: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
};

interface ProductDetailProps {
  product: Product;
  onClose: () => void;
  onEdit: (product: Product) => void;
  onDelete: (product: Product) => void;
}

export function ProductDetail({ product, onClose, onEdit, onDelete }: ProductDetailProps) {
  const { parsers, isLoading: parsersLoading, createParser, deleteParser } = useProductParsers(product.id);

  const navigate = useNavigate();
  const [showAddParserDialog, setShowAddParserDialog] = useState(false);
  const [newParserName, setNewParserName] = useState('');
  const [newParserFormat, setNewParserFormat] = useState<ParserFormat>('grok');
  const [addingParser, setAddingParser] = useState(false);

  const handleParserClick = useCallback((parserId: string) => {
    navigate(`/parsers?id=${parserId}`);
  }, [navigate]);

  const handleAddParser = useCallback(async () => {
    if (!newParserName.trim()) return;
    setAddingParser(true);
    try {
      await createParser(newParserName.trim(), newParserFormat);
      setShowAddParserDialog(false);
      setNewParserName('');
      setNewParserFormat('grok');
    } finally {
      setAddingParser(false);
    }
  }, [newParserName, newParserFormat, createParser]);

  const handleDeleteParser = useCallback(async (parserId: string) => {
    await deleteParser(parserId);
  }, [deleteParser]);

  return (
    <Card className="w-[420px] flex flex-col h-[calc(100vh-180px)] sticky top-6">
      <CardHeader className="flex flex-row items-center justify-between pb-2">
        <div>
          <p className="text-xs text-muted-foreground font-mono">{product.id}</p>
          <CardTitle className="text-base mt-1">{product.name}</CardTitle>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose}>
          <X className="w-4 h-4" />
        </Button>
      </CardHeader>

      <ScrollArea className="flex-1">
        <CardContent className="space-y-6">
          {/* Category and Status */}
          <div className="flex items-center gap-3">
            <Badge
              variant="outline"
              className={cn('capitalize', categoryColors[product.category])}
            >
              {categoryLabels[product.category]}
            </Badge>
            <Badge
              variant="outline"
              className={cn('capitalize', statusColors[product.status])}
            >
              {statusLabels[product.status]}
            </Badge>
          </div>

          {/* Description */}
          {product.description && (
            <div>
              <h4 className="text-sm font-medium mb-2">Description</h4>
              <p className="text-sm text-muted-foreground">{product.description}</p>
            </div>
          )}

          <Separator />

          {/* Basic Info */}
          <div>
            <h4 className="text-sm font-medium mb-3">Basic Information</h4>
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Building2 className="w-4 h-4" />
                  <span className="text-xs">Vendor</span>
                </div>
                <p className="text-sm">{product.vendor.name}</p>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Tag className="w-4 h-4" />
                  <span className="text-xs">Version</span>
                </div>
                <p className="text-sm font-mono">{product.version}</p>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Clock className="w-4 h-4" />
                  <span className="text-xs">Created</span>
                </div>
                <p className="text-sm">{formatTimestamp(product.createdAt)}</p>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-muted-foreground">
                  <Clock className="w-4 h-4" />
                  <span className="text-xs">Updated</span>
                </div>
                <p className="text-sm">{formatTimestamp(product.updatedAt)}</p>
              </div>
            </div>
          </div>

          <Separator />

          {/* Parsers Section */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h4 className="text-sm font-medium flex items-center gap-2">
                <FileCode2 className="w-4 h-4" />
                Parsers
                {!parsersLoading && (
                  <Badge variant="outline" className="text-xs ml-1">
                    {parsers.length}
                  </Badge>
                )}
              </h4>
              <Button
                variant="outline"
                size="sm"
                className="h-7 px-2 text-xs"
                onClick={() => setShowAddParserDialog(true)}
              >
                <Plus className="w-3 h-3 mr-1" />
                Add Parser
              </Button>
            </div>

            {parsersLoading ? (
              <p className="text-sm text-muted-foreground">Loading parsers...</p>
            ) : parsers.length === 0 ? (
              <div className="text-center py-4 border border-dashed border-border/50 rounded-lg">
                <p className="text-sm text-muted-foreground mb-2">No parsers configured</p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowAddParserDialog(true)}
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Add First Parser
                </Button>
              </div>
            ) : (
              <div className="space-y-2">
                {parsers.map((parser) => (
                  <div
                    key={parser.id}
                    className="flex items-center gap-2 p-2 rounded-lg bg-muted/30 hover:bg-muted/50 transition-colors group cursor-pointer"
                    onClick={() => handleParserClick(parser.id)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => e.key === 'Enter' && handleParserClick(parser.id)}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <FormatBadge format={parser.format} />
                        <span className="text-sm font-medium truncate">{parser.name}</span>
                      </div>
                      <div className="flex items-center gap-2 mt-1">
                        <Badge
                          variant="outline"
                          className={cn(
                            'text-2xs px-1.5 py-0',
                            parser.status === 'active'
                              ? 'bg-neon-green/20 text-neon-green border-neon-green/50'
                              : parser.status === 'testing'
                              ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50'
                              : 'bg-muted/50 text-muted-foreground'
                          )}
                        >
                          {parser.status}
                        </Badge>
                        <span className="text-2xs text-muted-foreground">v{parser.version}</span>
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity text-red-400 hover:text-red-300 hover:bg-red-400/10"
                      onClick={(e) => {
                        e.stopPropagation();
                        handleDeleteParser(parser.id);
                      }}
                    >
                      <Trash2 className="w-3 h-3" />
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <Separator />

          {/* Actions */}
          <div>
            <h4 className="text-sm font-medium mb-3">Actions</h4>
            <div className="grid grid-cols-2 gap-2">
              <Button
                variant="outline"
                size="sm"
                className="justify-start"
                onClick={() => onEdit(product)}
              >
                <Edit2 className="w-4 h-4 mr-2 text-primary" />
                Edit Product
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="justify-start text-red-400 hover:text-red-300 hover:bg-red-400/10"
                onClick={() => onDelete(product)}
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Delete
              </Button>
            </div>
          </div>

          {/* View full details */}
          <Button className="w-full" variant="outline">
            <ExternalLink className="w-4 h-4 mr-2" />
            View Full Configuration
          </Button>
        </CardContent>
      </ScrollArea>

      {/* Add Parser Dialog */}
      <Dialog open={showAddParserDialog} onOpenChange={setShowAddParserDialog}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Parser to {product.name}</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="parser-name">Parser Name</Label>
              <Input
                id="parser-name"
                value={newParserName}
                onChange={(e) => setNewParserName(e.target.value)}
                placeholder="e.g., Firewall Syslog Parser"
                className="bg-background/50"
              />
            </div>
            <div className="space-y-2">
              <Label>Format</Label>
              <FormatSelector
                value={newParserFormat}
                onChange={setNewParserFormat}
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setShowAddParserDialog(false)}
              disabled={addingParser}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAddParser}
              disabled={!newParserName.trim() || addingParser}
              className="bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80"
            >
              {addingParser ? 'Adding...' : 'Add Parser'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
