import { useState } from 'react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Search, Plus, FileCode2 } from 'lucide-react';
import { cn, formatRelativeTime } from '@/lib/utils';
import type { Parser, ParserStatus } from '../types';
import { FormatBadge } from './FormatSelector';

interface ParserListProps {
  parsers: Parser[];
  selectedParser: Parser | null;
  onSelect: (parser: Parser) => void;
  onCreate: () => void;
}

const statusConfig: Record<ParserStatus, { label: string; variant: 'default' | 'success' | 'warning' | 'outline' }> = {
  active: { label: 'Active', variant: 'success' },
  testing: { label: 'Testing', variant: 'warning' },
  draft: { label: 'Draft', variant: 'outline' },
  disabled: { label: 'Disabled', variant: 'default' },
};

export function ParserList({ parsers, selectedParser, onSelect, onCreate }: ParserListProps) {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredParsers = parsers.filter((parser) =>
    parser.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    parser.productId?.toLowerCase().includes(searchQuery.toLowerCase()) ||
    parser.format.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="p-4 border-b border-border/50 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="font-semibold text-sm uppercase tracking-wider text-muted-foreground">
            Parsers
          </h2>
          <Badge variant="outline" className="text-xs">
            {parsers.length}
          </Badge>
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <Input
            placeholder="Search parsers..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="pl-9 h-9 text-sm bg-background/50"
          />
        </div>

        {/* Create Button */}
        <Button
          onClick={onCreate}
          className="w-full bg-gradient-to-r from-[#00A4A6] to-[#00A4A6]/80 hover:from-[#00A4A6]/90 hover:to-[#00A4A6]/70"
          size="sm"
        >
          <Plus className="w-4 h-4 mr-2" />
          Create Parser
        </Button>
      </div>

      {/* Parser List */}
      <ScrollArea className="flex-1 min-h-0">
        <div className="p-2 space-y-1 pb-4">
          {filteredParsers.length === 0 ? (
            <div className="p-4 text-center text-muted-foreground text-sm">
              {searchQuery ? 'No parsers found' : 'No parsers yet'}
            </div>
          ) : (
            filteredParsers.map((parser) => {
              const status = statusConfig[parser.status];
              const isSelected = selectedParser?.id === parser.id;

              return (
                <button
                  key={parser.id}
                  onClick={() => onSelect(parser)}
                  className={cn(
                    'w-full text-left p-3 rounded-lg transition-all duration-200',
                    'hover:bg-muted/50 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
                    isSelected && 'bg-muted/70 border border-primary/30'
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className={cn(
                      'p-2 rounded-lg shrink-0',
                      isSelected ? 'bg-primary/20' : 'bg-muted/50'
                    )}>
                      <FileCode2 className={cn(
                        'w-4 h-4',
                        isSelected ? 'text-primary' : 'text-muted-foreground'
                      )} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={cn(
                          'font-medium text-sm truncate',
                          isSelected && 'text-primary'
                        )}>
                          {parser.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <FormatBadge format={parser.format} />
                        <Badge
                          variant={status.variant}
                          className="text-2xs px-1.5 py-0"
                        >
                          {status.label}
                        </Badge>
                      </div>
                      <div className="flex items-center justify-between mt-2 text-2xs text-muted-foreground">
                        <span>v{parser.version}</span>
                        <span>{formatRelativeTime(parser.updatedAt)}</span>
                      </div>
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
