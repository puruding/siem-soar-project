import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Edit, Trash2, Copy, ExternalLink } from 'lucide-react';
import { cn, formatTimestamp, formatRelativeTime } from '@/lib/utils';
import type { Asset } from '../types';
import { AssetTypeIcon, getAssetTypeLabel } from './AssetTypeIcon';

interface AssetDetailProps {
  asset: Asset | null;
  open: boolean;
  onClose: () => void;
  onEdit?: (asset: Asset) => void;
  onDelete?: (assetId: string) => void;
}

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

function InfoRow({ label, value, mono = false }: { label: string; value?: string | null; mono?: boolean }) {
  if (!value) return null;
  return (
    <div>
      <label className="text-xs text-muted-foreground uppercase tracking-wider">
        {label}
      </label>
      <p className={cn('text-sm mt-0.5', mono && 'font-mono')}>{value}</p>
    </div>
  );
}

function CopyButton({ value }: { value: string }) {
  const handleCopy = () => {
    navigator.clipboard.writeText(value);
  };
  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-6 w-6"
      onClick={handleCopy}
      title="Copy to clipboard"
    >
      <Copy className="w-3 h-3" />
    </Button>
  );
}

export function AssetDetail({
  asset,
  open,
  onClose,
  onEdit,
  onDelete,
}: AssetDetailProps) {
  if (!asset) return null;

  return (
    <Sheet open={open} onOpenChange={(isOpen) => !isOpen && onClose()}>
      <SheetContent className="w-full sm:max-w-lg overflow-hidden flex flex-col">
        <SheetHeader>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-muted">
              <AssetTypeIcon type={asset.type} className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <SheetTitle className="truncate">{asset.name}</SheetTitle>
              <SheetDescription className="font-mono text-xs">
                {asset.hostname}
              </SheetDescription>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-4">
            <Badge
              variant="outline"
              className={cn('capitalize', criticalityStyles[asset.criticality])}
            >
              {asset.criticality}
            </Badge>
            <Badge
              variant="outline"
              className={cn('capitalize', statusStyles[asset.status])}
            >
              {asset.status}
            </Badge>
            <Badge variant="secondary">{getAssetTypeLabel(asset.type)}</Badge>
          </div>
        </SheetHeader>

        <Tabs defaultValue="info" className="flex-1 flex flex-col mt-6 overflow-hidden">
          <TabsList className="w-full justify-start">
            <TabsTrigger value="info">Info</TabsTrigger>
            <TabsTrigger value="network">Network</TabsTrigger>
            <TabsTrigger value="history">History</TabsTrigger>
          </TabsList>

          <ScrollArea className="flex-1 mt-4">
            <TabsContent value="info" className="m-0 space-y-6">
              {/* Basic Info */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium">Basic Information</h4>
                <div className="grid grid-cols-2 gap-4">
                  <InfoRow label="Hostname" value={asset.hostname} mono />
                  <InfoRow label="Type" value={getAssetTypeLabel(asset.type)} />
                  <InfoRow label="OS" value={asset.osType} />
                  <InfoRow label="OS Version" value={asset.osVersion} />
                  <InfoRow label="Owner" value={asset.owner} />
                  <InfoRow label="Department" value={asset.department} />
                </div>
                <InfoRow label="Location" value={asset.location} />
              </div>

              <Separator />

              {/* Tags */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium">Tags</h4>
                <div className="flex flex-wrap gap-2">
                  {asset.tags.length > 0 ? (
                    asset.tags.map((tag) => (
                      <Badge key={tag} variant="secondary">
                        {tag}
                      </Badge>
                    ))
                  ) : (
                    <span className="text-sm text-muted-foreground">No tags</span>
                  )}
                </div>
              </div>
            </TabsContent>

            <TabsContent value="network" className="m-0 space-y-6">
              {/* IP Addresses */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium">IP Addresses</h4>
                {asset.ipAddresses.length > 0 ? (
                  <div className="space-y-2">
                    {asset.ipAddresses.map((ip, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-muted/50 rounded"
                      >
                        <span className="font-mono text-sm">{ip}</span>
                        <div className="flex items-center gap-1">
                          <CopyButton value={ip} />
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-6 w-6"
                            title="Lookup"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">
                    No IP addresses
                  </span>
                )}
              </div>

              <Separator />

              {/* MAC Addresses */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium">MAC Addresses</h4>
                {asset.macAddresses && asset.macAddresses.length > 0 ? (
                  <div className="space-y-2">
                    {asset.macAddresses.map((mac, idx) => (
                      <div
                        key={idx}
                        className="flex items-center justify-between p-2 bg-muted/50 rounded"
                      >
                        <span className="font-mono text-sm">{mac}</span>
                        <CopyButton value={mac} />
                      </div>
                    ))}
                  </div>
                ) : (
                  <span className="text-sm text-muted-foreground">
                    No MAC addresses
                  </span>
                )}
              </div>
            </TabsContent>

            <TabsContent value="history" className="m-0 space-y-6">
              {/* Timeline */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium">Activity Timeline</h4>
                <div className="space-y-4">
                  {asset.lastSeen && (
                    <div className="flex items-start gap-3">
                      <div className="w-2 h-2 rounded-full bg-neon-green mt-2" />
                      <div>
                        <p className="text-sm font-medium">Last Seen</p>
                        <p className="text-xs text-muted-foreground">
                          {formatRelativeTime(asset.lastSeen)} ({formatTimestamp(asset.lastSeen)})
                        </p>
                      </div>
                    </div>
                  )}
                  <div className="flex items-start gap-3">
                    <div className="w-2 h-2 rounded-full bg-primary mt-2" />
                    <div>
                      <p className="text-sm font-medium">Last Updated</p>
                      <p className="text-xs text-muted-foreground">
                        {formatRelativeTime(asset.updatedAt)} ({formatTimestamp(asset.updatedAt)})
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-3">
                    <div className="w-2 h-2 rounded-full bg-muted-foreground mt-2" />
                    <div>
                      <p className="text-sm font-medium">Created</p>
                      <p className="text-xs text-muted-foreground">
                        {formatTimestamp(asset.createdAt)}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              <Separator />

              {/* Metadata */}
              <div className="space-y-4">
                <h4 className="text-sm font-medium">Metadata</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <label className="text-xs text-muted-foreground">Asset ID</label>
                    <p className="font-mono text-xs mt-0.5">{asset.id}</p>
                  </div>
                  {asset.parentId && (
                    <div>
                      <label className="text-xs text-muted-foreground">Group ID</label>
                      <p className="font-mono text-xs mt-0.5">{asset.parentId}</p>
                    </div>
                  )}
                </div>
              </div>
            </TabsContent>
          </ScrollArea>
        </Tabs>

        {/* Actions */}
        <div className="flex items-center gap-2 pt-4 border-t mt-4">
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => onEdit?.(asset)}
          >
            <Edit className="w-4 h-4 mr-2" />
            Edit
          </Button>
          <Button
            variant="outline"
            className="text-destructive hover:bg-destructive/10"
            onClick={() => onDelete?.(asset.id)}
          >
            <Trash2 className="w-4 h-4" />
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}
