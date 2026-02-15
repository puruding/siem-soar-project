import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  X,
  Edit2,
  Trash2,
  Building2,
  Tag,
  Clock,
  FileText,
  FileCode2,
  ExternalLink,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { formatTimestamp, cn } from '@/lib/utils';
import type { Product } from '../types';
import { categoryLabels, categoryColors, statusLabels, statusColors } from '../hooks/useProducts';

// Parser name mapping (linked to actual parser data)
const parserNameMap: Record<string, { name: string; format: string }> = {
  'parser-001': { name: 'Syslog RFC5424', format: 'grok' },
  'parser-002': { name: 'AWS CloudTrail', format: 'json' },
  'parser-003': { name: 'Windows Security Event', format: 'cef' },
  'parser-004': { name: 'Palo Alto Firewall', format: 'leef' },
  'parser-005': { name: 'Apache Access Log', format: 'grok' },
  'parser-006': { name: 'Nginx Error Log', format: 'regex' },
  'parser-007': { name: 'Cisco ASA Syslog', format: 'grok' },
  'parser-008': { name: 'Key-Value Generic', format: 'kv' },
  'parser-009': { name: 'CrowdStrike Falcon', format: 'json' },
  'parser-010': { name: 'Okta System Log', format: 'json' },
};

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
  const navigate = useNavigate();

  const handleParserClick = (parserId: string) => {
    navigate('/parsers');
  };

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

          {/* Integration Config */}
          <div>
            <h4 className="text-sm font-medium mb-3">Integration Configuration</h4>
            <div className="space-y-4">
              <div>
                <div className="flex items-center gap-2 text-muted-foreground mb-2">
                  <FileText className="w-4 h-4" />
                  <span className="text-xs">Log Formats</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {product.logFormats.map((format) => (
                    <Badge
                      key={format}
                      variant="outline"
                      className="bg-primary/10 text-primary border-primary/30"
                    >
                      {format}
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <Separator />

          {/* Associated Parsers */}
          <div>
            <h4 className="text-sm font-medium mb-3">Associated Parsers</h4>
            <div className="space-y-2">
              {product.parserIds.length > 0 ? (
                product.parserIds.map((parserId) => {
                  const parserInfo = parserNameMap[parserId];
                  return (
                    <div
                      key={parserId}
                      onClick={() => handleParserClick(parserId)}
                      className="flex items-center justify-between p-3 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-primary/10">
                          <FileCode2 className="w-4 h-4 text-primary" />
                        </div>
                        <div>
                          <p className="text-sm font-medium">
                            {parserInfo?.name || parserId}
                          </p>
                          {parserInfo && (
                            <Badge
                              variant="outline"
                              className={cn('text-2xs mt-1', formatColors[parserInfo.format])}
                            >
                              {parserInfo.format.toUpperCase()}
                            </Badge>
                          )}
                        </div>
                      </div>
                      <ExternalLink className="w-4 h-4 text-muted-foreground" />
                    </div>
                  );
                })
              ) : (
                <p className="text-sm text-muted-foreground">No parsers associated</p>
              )}
            </div>
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
    </Card>
  );
}
