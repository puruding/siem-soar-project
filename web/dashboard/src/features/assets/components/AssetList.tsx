import { useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Checkbox } from '@/components/ui/checkbox';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import {
  Search,
  Plus,
  Upload,
  Download,
  TreePine,
  LayoutGrid,
  ChevronRight,
} from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import type { Asset, AssetFilters, ViewMode } from '../types';
import { useAssets, useFilteredAssets, useAssetTree } from '../hooks/useAssets';
import { AssetTree } from './AssetTree';
import { AssetDetail } from './AssetDetail';
import { AssetBulkActions } from './AssetBulkActions';
import { AssetImport } from './AssetImport';
import { AssetTypeIcon, getAssetTypeLabel } from './AssetTypeIcon';

const criticalityStyles: Record<Asset['criticality'], string> = {
  critical: 'bg-[#DC4E41]/20 text-[#DC4E41] border-[#DC4E41]/50',
  high: 'bg-[#F79836]/20 text-[#F79836] border-[#F79836]/50',
  medium: 'bg-[#FFB84D]/20 text-[#FFB84D] border-[#FFB84D]/50',
  low: 'bg-[#5CC05C]/20 text-[#5CC05C] border-[#5CC05C]/50',
};

const statusStyles: Record<Asset['status'], string> = {
  active: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  inactive: 'bg-muted text-muted-foreground border-border',
  decommissioned: 'bg-destructive/20 text-destructive border-destructive/50',
};

export function AssetList() {
  const {
    assets,
    groups,
    selectedAssets,
    deleteAssets,
    moveAssetsToGroup,
    updateAssetsCriticality,
    addTagToAssets,
    toggleAssetSelection,
    selectAllAssets,
    clearSelection,
  } = useAssets();

  const [viewMode, setViewMode] = useState<ViewMode>('tree');
  const [filters, setFilters] = useState<AssetFilters>({
    search: '',
    type: 'all',
    criticality: 'all',
    status: 'all',
  });
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [importDialogOpen, setImportDialogOpen] = useState(false);

  const filteredAssets = useFilteredAssets(assets, filters);
  const assetTree = useAssetTree(filteredAssets, groups);

  const handleSelectAll = () => {
    if (selectedAssets.size === filteredAssets.length && filteredAssets.length > 0) {
      clearSelection();
    } else {
      selectAllAssets(filteredAssets.map((a) => a.id));
    }
  };

  const handleMoveAsset = (assetId: string, groupId: string) => {
    moveAssetsToGroup([assetId], groupId);
  };

  const handleImport = (importedAssets: Partial<Asset>[]) => {
    // In a real app, this would add the assets to the store
    console.log('Importing assets:', importedAssets);
  };

  const handleExport = () => {
    const headers = [
      'Name',
      'Hostname',
      'IP Addresses',
      'Type',
      'OS',
      'Owner',
      'Department',
      'Location',
      'Criticality',
      'Status',
      'Tags',
    ];
    const rows = filteredAssets.map((asset) => [
      asset.name,
      asset.hostname,
      asset.ipAddresses.join(';'),
      asset.type,
      asset.osType || '',
      asset.owner || '',
      asset.department || '',
      asset.location || '',
      asset.criticality,
      asset.status,
      asset.tags.join(';'),
    ]);

    const csv = [headers.join(','), ...rows.map((r) => r.map((v) => `"${v}"`).join(','))].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'assets.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Assets
          </h1>
          <p className="text-muted-foreground">
            Manage and monitor your organization's assets
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => setImportDialogOpen(true)}>
            <Upload className="w-4 h-4 mr-2" />
            Import
          </Button>
          <Button variant="outline" size="sm" onClick={handleExport}>
            <Download className="w-4 h-4 mr-2" />
            Export
          </Button>
          <Button size="sm">
            <Plus className="w-4 h-4 mr-2" />
            Add Asset
          </Button>
        </div>
      </div>

      {/* Filters and view toggle */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 max-w-sm">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search assets..."
                value={filters.search}
                onChange={(e) =>
                  setFilters((prev) => ({ ...prev, search: e.target.value }))
                }
                className="pl-10"
              />
            </div>

            {/* Type filter */}
            <Select
              value={filters.type}
              onValueChange={(value) =>
                setFilters((prev) => ({ ...prev, type: value as Asset['type'] | 'all' }))
              }
            >
              <SelectTrigger className="w-[160px]">
                <SelectValue placeholder="Type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="server">Server</SelectItem>
                <SelectItem value="workstation">Workstation</SelectItem>
                <SelectItem value="network_device">Network Device</SelectItem>
                <SelectItem value="container">Container</SelectItem>
                <SelectItem value="cloud_instance">Cloud Instance</SelectItem>
                <SelectItem value="iot">IoT Device</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>

            {/* Criticality filter */}
            <Select
              value={filters.criticality}
              onValueChange={(value) =>
                setFilters((prev) => ({
                  ...prev,
                  criticality: value as Asset['criticality'] | 'all',
                }))
              }
            >
              <SelectTrigger className="w-[140px]">
                <SelectValue placeholder="Criticality" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Criticality</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>

            {/* View toggle */}
            <div className="flex items-center border rounded-md">
              <Button
                variant={viewMode === 'tree' ? 'secondary' : 'ghost'}
                size="sm"
                className="rounded-r-none"
                onClick={() => setViewMode('tree')}
              >
                <TreePine className="w-4 h-4" />
              </Button>
              <Button
                variant={viewMode === 'grid' ? 'secondary' : 'ghost'}
                size="sm"
                className="rounded-l-none"
                onClick={() => setViewMode('grid')}
              >
                <LayoutGrid className="w-4 h-4" />
              </Button>
            </div>
          </div>

          {/* Bulk actions */}
          {selectedAssets.size > 0 && (
            <div className="mt-4">
              <AssetBulkActions
                selectedCount={selectedAssets.size}
                groups={groups}
                onClearSelection={clearSelection}
                onAddTag={(tag) => addTagToAssets(Array.from(selectedAssets), tag)}
                onChangeCriticality={(criticality) =>
                  updateAssetsCriticality(Array.from(selectedAssets), criticality)
                }
                onMoveToGroup={(groupId) =>
                  moveAssetsToGroup(Array.from(selectedAssets), groupId)
                }
                onDelete={() => deleteAssets(Array.from(selectedAssets))}
              />
            </div>
          )}
        </CardHeader>

        <CardContent>
          <ScrollArea className="h-[calc(100vh-320px)]">
            {viewMode === 'tree' ? (
              <AssetTree
                tree={assetTree}
                selectedAssets={selectedAssets}
                onAssetSelect={setSelectedAsset}
                onToggleSelection={toggleAssetSelection}
                onMoveAsset={handleMoveAsset}
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[40px]">
                      <Checkbox
                        checked={
                          selectedAssets.size === filteredAssets.length &&
                          filteredAssets.length > 0
                        }
                        onCheckedChange={handleSelectAll}
                      />
                    </TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>IP Address</TableHead>
                    <TableHead>Criticality</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Seen</TableHead>
                    <TableHead className="w-[40px]"></TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredAssets.map((asset) => (
                    <TableRow
                      key={asset.id}
                      className={cn(
                        'cursor-pointer',
                        selectedAsset?.id === asset.id && 'bg-primary/5'
                      )}
                      onClick={() => setSelectedAsset(asset)}
                    >
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <Checkbox
                          checked={selectedAssets.has(asset.id)}
                          onCheckedChange={() => toggleAssetSelection(asset.id)}
                        />
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="p-1.5 rounded bg-muted">
                            <AssetTypeIcon type={asset.type} className="w-4 h-4" />
                          </div>
                          <div>
                            <p className="font-medium">{asset.name}</p>
                            <p className="text-xs text-muted-foreground font-mono">
                              {asset.hostname}
                            </p>
                          </div>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary">{getAssetTypeLabel(asset.type)}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-sm">
                        {asset.ipAddresses[0] || '-'}
                        {asset.ipAddresses.length > 1 && (
                          <span className="text-muted-foreground ml-1">
                            +{asset.ipAddresses.length - 1}
                          </span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn('capitalize', criticalityStyles[asset.criticality])}
                        >
                          {asset.criticality}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={cn('capitalize', statusStyles[asset.status])}
                        >
                          {asset.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">
                        {asset.lastSeen ? formatRelativeTime(asset.lastSeen) : '-'}
                      </TableCell>
                      <TableCell>
                        <ChevronRight className="w-4 h-4 text-muted-foreground" />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </ScrollArea>
        </CardContent>
      </Card>

      {/* Asset detail sheet */}
      <AssetDetail
        asset={selectedAsset}
        open={!!selectedAsset}
        onClose={() => setSelectedAsset(null)}
        onDelete={(id) => {
          deleteAssets([id]);
          setSelectedAsset(null);
        }}
      />

      {/* Import dialog */}
      <AssetImport
        open={importDialogOpen}
        onClose={() => setImportDialogOpen(false)}
        onImport={handleImport}
      />
    </div>
  );
}
