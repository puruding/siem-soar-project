import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import {
  ExternalLink,
  Clock,
  User,
  Tag,
  AlertTriangle,
  Code2,
  Shield,
  Calendar,
  Hash,
  BookOpen,
  Link2,
  Trash2,
  Edit3,
} from 'lucide-react';
import { formatRelativeTime, cn } from '@/lib/utils';
import type { SigmaRule } from '../types';
import { SEVERITY_COLORS, STATUS_STYLES } from '../types';

interface RuleDetailProps {
  rule: SigmaRule | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onEdit?: () => void;
  onDelete?: (ruleId: string) => void;
}

export function RuleDetail({
  rule,
  open,
  onOpenChange,
  onEdit,
  onDelete,
}: RuleDetailProps) {
  if (!rule) return null;

  const severityBadgeVariant = (
    severity: SigmaRule['severity']
  ): 'critical' | 'high' | 'medium' | 'low' | 'info' => {
    if (severity === 'informational') return 'info';
    return severity;
  };

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-[500px] sm:max-w-[500px] overflow-hidden flex flex-col">
        <SheetHeader className="shrink-0">
          <SheetTitle className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-primary" />
            Rule Details
          </SheetTitle>
        </SheetHeader>

        <ScrollArea className="flex-1 -mx-6 px-6 mt-6">
          <div className="space-y-6">
            {/* Header */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Badge
                  variant={severityBadgeVariant(rule.severity)}
                  style={{
                    borderColor: `${SEVERITY_COLORS[rule.severity]}50`,
                    backgroundColor: `${SEVERITY_COLORS[rule.severity]}20`,
                    color: SEVERITY_COLORS[rule.severity],
                  }}
                >
                  {rule.severity.toUpperCase()}
                </Badge>
                <Badge
                  variant="outline"
                  className={cn('capitalize', STATUS_STYLES[rule.status])}
                >
                  {rule.status}
                </Badge>
              </div>
              <h2 className="text-xl font-semibold">{rule.title}</h2>
              <p className="text-sm text-muted-foreground mt-1">
                {rule.description}
              </p>
            </div>

            <Separator />

            {/* Metadata */}
            <div className="grid grid-cols-2 gap-4">
              <div className="flex items-center gap-2 text-sm">
                <Hash className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">ID:</span>
                <span className="font-mono">{rule.id}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <Hash className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Version:</span>
                <span className="font-mono">v{rule.version}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <User className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Author:</span>
                <span>{rule.author}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <Calendar className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Created:</span>
                <span>{formatRelativeTime(rule.createdAt)}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <Clock className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Updated:</span>
                <span>{formatRelativeTime(rule.updatedAt)}</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                <span className="text-muted-foreground">Triggers:</span>
                <span className="font-mono">{rule.triggerCount.toLocaleString()}</span>
              </div>
            </div>

            <Separator />

            {/* Log Sources */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Code2 className="w-4 h-4" />
                Log Sources
              </h3>
              <div className="p-3 rounded-lg bg-muted/30 border border-border space-y-2">
                {rule.logsources.category && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Category:</span>
                    <Badge variant="outline">{rule.logsources.category}</Badge>
                  </div>
                )}
                {rule.logsources.product && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Product:</span>
                    <Badge variant="outline">{rule.logsources.product}</Badge>
                  </div>
                )}
                {rule.logsources.service && (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-muted-foreground">Service:</span>
                    <Badge variant="outline">{rule.logsources.service}</Badge>
                  </div>
                )}
              </div>
            </div>

            <Separator />

            {/* ATT&CK Mapping */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Shield className="w-4 h-4" />
                MITRE ATT&CK Mapping
              </h3>
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                    Tactics
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {rule.attack.tactics.map((tactic) => (
                      <Badge
                        key={tactic.id}
                        variant="outline"
                        className="bg-primary/10 border-primary/30 text-primary"
                      >
                        {tactic.id}: {tactic.name}
                      </Badge>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">
                    Techniques
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {rule.attack.techniques.map((technique) => (
                      <a
                        key={technique.id}
                        href={`https://attack.mitre.org/techniques/${technique.id}${
                          technique.subtechnique ? `/${technique.subtechnique}` : ''
                        }/`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1"
                      >
                        <Badge
                          variant="outline"
                          className="bg-neon-cyan/10 border-neon-cyan/30 text-neon-cyan hover:bg-neon-cyan/20 transition-colors"
                        >
                          {technique.id}
                          {technique.subtechnique && `.${technique.subtechnique}`}:{' '}
                          {technique.name}
                          <ExternalLink className="w-3 h-3 ml-1" />
                        </Badge>
                      </a>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <Separator />

            {/* Tags */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Tag className="w-4 h-4" />
                Tags
              </h3>
              <div className="flex flex-wrap gap-2">
                {rule.tags.map((tag) => (
                  <Badge key={tag} variant="outline" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>

            {/* References */}
            {rule.references.length > 0 && (
              <>
                <Separator />
                <div>
                  <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                    <BookOpen className="w-4 h-4" />
                    References
                  </h3>
                  <div className="space-y-2">
                    {rule.references.map((ref, index) => (
                      <a
                        key={index}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-sm text-primary hover:text-primary/80 transition-colors"
                      >
                        <Link2 className="w-4 h-4 shrink-0" />
                        <span className="truncate">{ref}</span>
                        <ExternalLink className="w-3 h-3 shrink-0" />
                      </a>
                    ))}
                  </div>
                </div>
              </>
            )}

            <Separator />

            {/* Detection Logic Preview */}
            <div>
              <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                <Code2 className="w-4 h-4" />
                Detection Logic
              </h3>
              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <pre className="text-xs font-mono text-muted-foreground whitespace-pre-wrap overflow-x-auto max-h-[200px]">
                  {rule.rawYaml}
                </pre>
              </div>
            </div>
          </div>
        </ScrollArea>

        {/* Actions */}
        <div className="shrink-0 flex gap-2 pt-4 border-t border-border mt-4">
          {onEdit && (
            <Button className="flex-1" onClick={onEdit}>
              <Edit3 className="w-4 h-4 mr-2" />
              Edit Rule
            </Button>
          )}
          {onDelete && (
            <Button
              variant="destructive"
              onClick={() => onDelete(rule.id)}
            >
              <Trash2 className="w-4 h-4 mr-2" />
              Delete
            </Button>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
