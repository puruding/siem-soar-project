import { useState, useMemo } from 'react';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Input } from '@/components/ui/input';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  Search,
  ChevronDown,
  Zap,
  Clock,
  Webhook,
  Play,
  Mail,
  Bell,
  Shield,
  Database,
  Terminal,
  GitBranch,
  Repeat,
  GitFork,
  Timer,
  Ticket,
  Cloud,
  Plug,
  ShieldAlert,
  LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';

interface PaletteItem {
  type: string;
  label: string;
  icon: LucideIcon;
  data: Record<string, unknown>;
  description?: string;
}

interface PaletteCategory {
  category: string;
  color: string;
  items: PaletteItem[];
}

const nodePalette: PaletteCategory[] = [
  {
    category: 'Triggers',
    color: '#5CC05C',
    items: [
      {
        type: 'trigger',
        label: 'Alert Trigger',
        icon: Zap,
        data: { triggerType: 'alert' },
        description: 'Trigger on security alert',
      },
      {
        type: 'trigger',
        label: 'Schedule',
        icon: Clock,
        data: { triggerType: 'schedule' },
        description: 'Run on a schedule',
      },
      {
        type: 'trigger',
        label: 'Webhook',
        icon: Webhook,
        data: { triggerType: 'webhook' },
        description: 'Trigger via HTTP webhook',
      },
      {
        type: 'trigger',
        label: 'Manual',
        icon: Play,
        data: { triggerType: 'manual' },
        description: 'Manual execution',
      },
    ],
  },
  {
    category: 'Actions',
    color: '#00A4A6',
    items: [
      {
        type: 'action',
        label: 'Send Email',
        icon: Mail,
        data: { actionType: 'email' },
        description: 'Send notification email',
      },
      {
        type: 'action',
        label: 'Slack Alert',
        icon: Bell,
        data: { actionType: 'slack' },
        description: 'Post to Slack channel',
      },
      {
        type: 'action',
        label: 'Block IP',
        icon: Shield,
        data: { actionType: 'block_ip' },
        description: 'Block IP at firewall',
      },
      {
        type: 'action',
        label: 'Isolate Host',
        icon: Shield,
        data: { actionType: 'isolate' },
        description: 'Isolate endpoint',
      },
      {
        type: 'action',
        label: 'Create Ticket',
        icon: Database,
        data: { actionType: 'jira' },
        description: 'Create Jira ticket',
      },
      {
        type: 'action',
        label: 'Run Script',
        icon: Terminal,
        data: { actionType: 'custom' },
        description: 'Execute custom script',
      },
    ],
  },
  {
    category: 'Logic',
    color: '#F79836',
    items: [
      {
        type: 'decision',
        label: 'Condition',
        icon: GitBranch,
        data: { condition: 'severity >= high' },
        description: 'Branch based on condition',
      },
      {
        type: 'loop',
        label: 'Loop',
        icon: Repeat,
        data: { loopType: 'forEach', maxIterations: 10 },
        description: 'Iterate over items',
      },
      {
        type: 'parallel',
        label: 'Parallel',
        icon: GitFork,
        data: { branches: 2, waitForAll: true },
        description: 'Execute branches in parallel',
      },
      {
        type: 'wait',
        label: 'Wait',
        icon: Timer,
        data: { waitType: 'duration', duration: 60 },
        description: 'Delay execution',
      },
      {
        type: 'approval',
        label: 'Approval Gate',
        icon: ShieldAlert,
        data: { approverRoles: ['SOC Manager'], timeout: 3600, autoReject: false },
        description: 'Require human approval',
      },
    ],
  },
  {
    category: 'Integrations',
    color: '#7B61FF',
    items: [
      {
        type: 'integration',
        label: 'SIEM',
        icon: Shield,
        data: { integrationType: 'siem' },
        description: 'Query SIEM system',
      },
      {
        type: 'integration',
        label: 'EDR',
        icon: Shield,
        data: { integrationType: 'edr' },
        description: 'EDR actions',
      },
      {
        type: 'integration',
        label: 'Firewall',
        icon: Shield,
        data: { integrationType: 'firewall' },
        description: 'Firewall rules',
      },
      {
        type: 'integration',
        label: 'Ticketing',
        icon: Ticket,
        data: { integrationType: 'ticketing' },
        description: 'Ticketing system',
      },
      {
        type: 'integration',
        label: 'ServiceNow',
        icon: Cloud,
        data: { integrationType: 'servicenow' },
        description: 'ServiceNow ITSM',
      },
      {
        type: 'integration',
        label: 'Custom API',
        icon: Plug,
        data: { integrationType: 'custom' },
        description: 'Custom REST API',
      },
    ],
  },
];

interface NodePaletteProps {
  className?: string;
}

export function NodePalette({ className }: NodePaletteProps) {
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedCategories, setExpandedCategories] = useState<string[]>(
    nodePalette.map((c) => c.category)
  );

  const filteredPalette = useMemo(() => {
    if (!searchQuery.trim()) return nodePalette;

    const query = searchQuery.toLowerCase();
    return nodePalette
      .map((category) => ({
        ...category,
        items: category.items.filter(
          (item) =>
            item.label.toLowerCase().includes(query) ||
            item.description?.toLowerCase().includes(query) ||
            item.type.toLowerCase().includes(query)
        ),
      }))
      .filter((category) => category.items.length > 0);
  }, [searchQuery]);

  const toggleCategory = (category: string) => {
    setExpandedCategories((prev) =>
      prev.includes(category)
        ? prev.filter((c) => c !== category)
        : [...prev, category]
    );
  };

  const handleDragStart = (
    event: React.DragEvent,
    item: PaletteItem
  ) => {
    event.dataTransfer.setData('application/reactflow-type', item.type);
    event.dataTransfer.setData('application/reactflow-label', item.label);
    event.dataTransfer.setData(
      'application/reactflow-data',
      JSON.stringify(item.data)
    );
    event.dataTransfer.effectAllowed = 'move';
  };

  return (
    <div className={cn('flex flex-col h-full', className)}>
      {/* Search Input */}
      <div className="relative mb-4">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
        <Input
          placeholder="Search nodes..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-9 bg-background/50"
        />
      </div>

      {/* Node Categories */}
      <ScrollArea className="flex-1 -mx-2 px-2">
        <div className="space-y-3 pb-4">
          {filteredPalette.map((category) => (
            <Collapsible
              key={category.category}
              open={expandedCategories.includes(category.category)}
              onOpenChange={() => toggleCategory(category.category)}
            >
              <CollapsibleTrigger className="flex items-center justify-between w-full group">
                <div className="flex items-center gap-2">
                  <div
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: category.color }}
                  />
                  <span
                    className="text-xs font-semibold uppercase tracking-wider"
                    style={{ color: category.color }}
                  >
                    {category.category}
                  </span>
                  <span className="text-2xs text-muted-foreground">
                    ({category.items.length})
                  </span>
                </div>
                <ChevronDown
                  className={cn(
                    'w-4 h-4 text-muted-foreground transition-transform',
                    expandedCategories.includes(category.category) &&
                      'rotate-180'
                  )}
                />
              </CollapsibleTrigger>

              <CollapsibleContent className="mt-2 space-y-1.5">
                {category.items.map((item) => {
                  const Icon = item.icon;
                  return (
                    <div
                      key={`${category.category}-${item.label}`}
                      draggable
                      onDragStart={(e) => handleDragStart(e, item)}
                      className={cn(
                        'flex items-center gap-3 p-2.5 rounded-xl cursor-move',
                        'border-2 border-transparent transition-all duration-200',
                        'hover:border-current hover:scale-[1.02] hover:shadow-md',
                        'bg-gradient-to-br from-muted/40 to-muted/10',
                        'active:scale-[0.98]'
                      )}
                      style={{ color: category.color }}
                    >
                      <div
                        className="p-2 rounded-lg shrink-0"
                        style={{
                          backgroundColor: `${category.color}20`,
                        }}
                      >
                        <Icon
                          className="w-4 h-4"
                          style={{ color: category.color }}
                        />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium text-foreground truncate">
                          {item.label}
                        </div>
                        {item.description && (
                          <div className="text-2xs text-muted-foreground truncate">
                            {item.description}
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </CollapsibleContent>
            </Collapsible>
          ))}

          {filteredPalette.length === 0 && (
            <div className="py-8 text-center text-sm text-muted-foreground">
              No nodes match "{searchQuery}"
            </div>
          )}
        </div>
      </ScrollArea>

      {/* Help text */}
      <div className="mt-auto pt-3 border-t border-border/50">
        <p className="text-2xs text-muted-foreground text-center">
          Drag nodes to the canvas to add them
        </p>
      </div>
    </div>
  );
}

export default NodePalette;
