import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';
import {
  ChevronDown,
  ChevronRight,
  Shield,
  ExternalLink,
  X,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SigmaRule, AttackTactic, AttackTechnique } from '../types';

interface MatrixTechnique extends AttackTechnique {
  ruleCount: number;
  rules: SigmaRule[];
}

interface MatrixColumn {
  tactic: AttackTactic;
  techniques: MatrixTechnique[];
}

interface AttackMatrixProps {
  matrixData: MatrixColumn[];
  onTechniqueClick: (techniqueId: string | null) => void;
  selectedTechnique: string | null;
  className?: string;
}

export function AttackMatrix({
  matrixData,
  onTechniqueClick,
  selectedTechnique,
  className,
}: AttackMatrixProps) {
  const [isCollapsed, setIsCollapsed] = useState(false);

  // Get total rule coverage
  const totalTechniques = matrixData.reduce(
    (sum, col) => sum + col.techniques.length,
    0
  );
  const coveredTechniques = matrixData.reduce(
    (sum, col) => sum + col.techniques.filter((t) => t.ruleCount > 0).length,
    0
  );
  const coveragePercent = Math.round((coveredTechniques / totalTechniques) * 100);

  return (
    <Collapsible open={!isCollapsed} onOpenChange={(open) => setIsCollapsed(!open)}>
      <Card className={cn('flex flex-col', className)}>
        <CardHeader className="pb-3 shrink-0">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-5 h-5 text-primary" />
              <CardTitle className="text-base">MITRE ATT&CK Matrix</CardTitle>
              <Badge variant="outline" className="text-xs">
                {coveragePercent}% Coverage
              </Badge>
            </div>
            <div className="flex items-center gap-2">
              {selectedTechnique && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => onTechniqueClick(null)}
                >
                  <X className="w-4 h-4 mr-1" />
                  Clear Filter
                </Button>
              )}
              <CollapsibleTrigger asChild>
                <Button variant="ghost" size="icon">
                  {isCollapsed ? (
                    <ChevronRight className="w-4 h-4" />
                  ) : (
                    <ChevronDown className="w-4 h-4" />
                  )}
                </Button>
              </CollapsibleTrigger>
            </div>
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-primary/80" />
              <span>High coverage (3+)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-primary/50" />
              <span>Medium (1-2)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <div className="w-3 h-3 rounded bg-muted/50" />
              <span>No rules</span>
            </div>
          </div>
        </CardHeader>

        <CollapsibleContent>
          <CardContent className="pt-0">
            <ScrollArea className="w-full overflow-x-auto">
              <div className="min-w-max">
                {/* Tactic Headers */}
                <div
                  className="grid gap-1 mb-2"
                  style={{
                    gridTemplateColumns: `repeat(${matrixData.length}, minmax(120px, 1fr))`,
                  }}
                >
                  {matrixData.map((column) => (
                    <div
                      key={column.tactic.id}
                      className="p-2 rounded-t-lg bg-primary/10 border border-primary/30 text-center"
                    >
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <div>
                              <p className="text-xs font-semibold text-primary truncate">
                                {column.tactic.name}
                              </p>
                              <p className="text-2xs text-muted-foreground">
                                {column.tactic.id}
                              </p>
                            </div>
                          </TooltipTrigger>
                          <TooltipContent>
                            <p>{column.tactic.name}</p>
                            <p className="text-xs text-muted-foreground">
                              {column.techniques.filter((t) => t.ruleCount > 0).length}/
                              {column.techniques.length} techniques covered
                            </p>
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                    </div>
                  ))}
                </div>

                {/* Technique Grid */}
                <div
                  className="grid gap-1"
                  style={{
                    gridTemplateColumns: `repeat(${matrixData.length}, minmax(120px, 1fr))`,
                  }}
                >
                  {matrixData.map((column) => (
                    <div key={column.tactic.id} className="space-y-1">
                      {column.techniques.map((technique) => {
                        const techniqueId = technique.subtechnique
                          ? `${technique.id}.${technique.subtechnique}`
                          : technique.id;
                        const isSelected = selectedTechnique === techniqueId;
                        const hasRules = technique.ruleCount > 0;
                        const highCoverage = technique.ruleCount >= 3;

                        return (
                          <TooltipProvider key={techniqueId}>
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <button
                                  onClick={() =>
                                    onTechniqueClick(isSelected ? null : techniqueId)
                                  }
                                  className={cn(
                                    'w-full p-2 rounded text-left transition-all',
                                    'border hover:border-primary/50',
                                    isSelected
                                      ? 'border-primary bg-primary/20 ring-1 ring-primary'
                                      : hasRules
                                      ? highCoverage
                                        ? 'bg-primary/30 border-primary/40'
                                        : 'bg-primary/15 border-primary/30'
                                      : 'bg-muted/20 border-border hover:bg-muted/30'
                                  )}
                                >
                                  <p
                                    className={cn(
                                      'text-2xs font-medium truncate',
                                      hasRules ? 'text-foreground' : 'text-muted-foreground'
                                    )}
                                  >
                                    {technique.name}
                                  </p>
                                  <div className="flex items-center justify-between mt-1">
                                    <span className="text-2xs text-muted-foreground font-mono">
                                      {techniqueId}
                                    </span>
                                    {hasRules && (
                                      <Badge
                                        variant="outline"
                                        className={cn(
                                          'text-2xs py-0 px-1',
                                          highCoverage
                                            ? 'bg-primary/30 border-primary/50 text-primary'
                                            : 'bg-primary/20 border-primary/40 text-primary/80'
                                        )}
                                      >
                                        {technique.ruleCount}
                                      </Badge>
                                    )}
                                  </div>
                                </button>
                              </TooltipTrigger>
                              <TooltipContent side="bottom" className="max-w-[250px]">
                                <div className="space-y-2">
                                  <div>
                                    <p className="font-semibold">{technique.name}</p>
                                    <p className="text-xs text-muted-foreground font-mono">
                                      {techniqueId}
                                    </p>
                                  </div>
                                  {hasRules ? (
                                    <div>
                                      <p className="text-xs text-muted-foreground mb-1">
                                        {technique.ruleCount} rule(s):
                                      </p>
                                      <ul className="text-xs space-y-0.5">
                                        {technique.rules.slice(0, 3).map((rule) => (
                                          <li key={rule.id} className="truncate">
                                            - {rule.title}
                                          </li>
                                        ))}
                                        {technique.rules.length > 3 && (
                                          <li className="text-muted-foreground">
                                            +{technique.rules.length - 3} more
                                          </li>
                                        )}
                                      </ul>
                                    </div>
                                  ) : (
                                    <p className="text-xs text-muted-foreground">
                                      No rules mapped to this technique
                                    </p>
                                  )}
                                  <a
                                    href={`https://attack.mitre.org/techniques/${technique.id}${
                                      technique.subtechnique ? `/${technique.subtechnique}` : ''
                                    }/`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-1 text-xs text-primary hover:underline"
                                    onClick={(e) => e.stopPropagation()}
                                  >
                                    View in ATT&CK
                                    <ExternalLink className="w-3 h-3" />
                                  </a>
                                </div>
                              </TooltipContent>
                            </Tooltip>
                          </TooltipProvider>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </ScrollArea>
          </CardContent>
        </CollapsibleContent>
      </Card>
    </Collapsible>
  );
}
