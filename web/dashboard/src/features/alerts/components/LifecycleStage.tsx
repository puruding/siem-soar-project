import React from 'react';
import { LucideIcon, ChevronRight, Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatRelativeTime } from '@/lib/utils';
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';

export interface LifecycleStageProps {
  icon: LucideIcon;
  title: string;
  timestamp?: Date;
  duration?: string;
  summary: string;
  status: 'completed' | 'in_progress' | 'pending' | 'skipped';
  details?: Record<string, any>;
  isLast?: boolean;
  onClick?: () => void;
}

interface DetailSectionProps {
  title: string;
  items: Array<{ label: string; value: any }>;
}

function DetailSection({ title, items }: DetailSectionProps) {
  return (
    <div className="space-y-1.5">
      <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70 border-b border-border/40 pb-0.5">
        {title}
      </div>
      <div className="space-y-1">
        {items.map((item, idx) => (
          <div key={idx} className="flex justify-between items-start gap-2 text-xs">
            <span className="text-muted-foreground/80 font-medium shrink-0">{item.label}:</span>
            <span className="text-foreground/90 text-right font-mono break-all">
              {typeof item.value === 'object' ? JSON.stringify(item.value) : String(item.value)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function renderDetailsContent(status: string, details?: Record<string, any>) {
  if (!details || Object.keys(details).length === 0) {
    return (
      <div className="text-xs text-muted-foreground/60 italic">
        No additional details available
      </div>
    );
  }

  // Rule Matching details
  if (details.matchedRules || details.ruleConditions || details.tags) {
    const sections: React.ReactNode[] = [];

    if (details.matchedRules) {
      sections.push(
        <DetailSection
          key="rules"
          title="Matched Rules"
          items={[
            { label: 'Count', value: details.matchedRules },
            ...(details.ruleNames
              ? details.ruleNames.map((name: string, idx: number) => ({
                  label: `Rule ${idx + 1}`,
                  value: name,
                }))
              : []),
          ]}
        />
      );
    }

    if (details.ruleConditions) {
      sections.push(
        <DetailSection
          key="conditions"
          title="Conditions"
          items={Object.entries(details.ruleConditions).map(([key, value]) => ({
            label: key,
            value,
          }))}
        />
      );
    }

    if (details.tags && details.tags.length > 0) {
      sections.push(
        <div key="tags" className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70 border-b border-border/40 pb-0.5">
            Tags
          </div>
          <div className="flex flex-wrap gap-1">
            {details.tags.map((tag: string, idx: number) => (
              <Badge key={idx} variant="outline" className="text-[10px] py-0 px-1.5 h-4">
                {tag}
              </Badge>
            ))}
          </div>
        </div>
      );
    }

    return <div className="space-y-3">{sections}</div>;
  }

  // ML Classification details
  if (details.riskFactors || details.probabilities || details.confidence) {
    const sections: React.ReactNode[] = [];

    if (details.confidence !== undefined) {
      sections.push(
        <div key="confidence" className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70 border-b border-border/40 pb-0.5">
            Confidence
          </div>
          <div className="flex items-center gap-2">
            <Progress
              value={details.confidence * 100}
              className="h-1.5"
              indicatorColor="bg-neon-blue"
            />
            <span className="text-xs font-mono text-neon-blue">
              {(details.confidence * 100).toFixed(1)}%
            </span>
          </div>
        </div>
      );
    }

    if (details.riskFactors && Array.isArray(details.riskFactors)) {
      sections.push(
        <div key="risk" className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70 border-b border-border/40 pb-0.5">
            Risk Factors
          </div>
          <div className="space-y-0.5">
            {details.riskFactors.map((factor: any, idx: number) => (
              <div key={idx} className="flex justify-between items-center text-xs">
                <span className="text-muted-foreground/80">{factor.name || factor}</span>
                {factor.weight !== undefined && (
                  <span className="text-neon-orange font-mono text-[10px]">
                    {(factor.weight * 100).toFixed(0)}%
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }

    if (details.probabilities) {
      sections.push(
        <DetailSection
          key="prob"
          title="Class Probabilities"
          items={Object.entries(details.probabilities).map(([key, value]) => ({
            label: key,
            value: `${((value as number) * 100).toFixed(1)}%`,
          }))}
        />
      );
    }

    return <div className="space-y-3">{sections}</div>;
  }

  // SOAR Workflow details
  if (details.progress !== undefined || details.nodeStatus || details.currentNode) {
    const sections: React.ReactNode[] = [];

    if (details.progress !== undefined) {
      sections.push(
        <div key="progress" className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70 border-b border-border/40 pb-0.5">
            Workflow Progress
          </div>
          <div className="flex items-center gap-2">
            <Progress
              value={details.progress * 100}
              className="h-1.5"
              indicatorColor="bg-neon-green"
            />
            <span className="text-xs font-mono text-neon-green">
              {(details.progress * 100).toFixed(0)}%
            </span>
          </div>
        </div>
      );
    }

    if (details.currentNode) {
      sections.push(
        <DetailSection
          key="current"
          title="Current Node"
          items={[
            { label: 'Node', value: details.currentNode },
            ...(details.nodeStatus ? [{ label: 'Status', value: details.nodeStatus }] : []),
          ]}
        />
      );
    }

    if (details.completedNodes || details.totalNodes) {
      sections.push(
        <DetailSection
          key="nodes"
          title="Execution Stats"
          items={[
            ...(details.completedNodes
              ? [{ label: 'Completed', value: details.completedNodes }]
              : []),
            ...(details.totalNodes ? [{ label: 'Total', value: details.totalNodes }] : []),
            ...(details.failedNodes ? [{ label: 'Failed', value: details.failedNodes }] : []),
          ]}
        />
      );
    }

    return <div className="space-y-3">{sections}</div>;
  }

  // Generic details
  return (
    <DetailSection
      title="Details"
      items={Object.entries(details).map(([key, value]) => ({
        label: key,
        value,
      }))}
    />
  );
}

export function LifecycleStage({
  icon: Icon,
  title,
  timestamp,
  duration,
  summary,
  status,
  details,
  isLast = false,
  onClick,
}: LifecycleStageProps) {
  const statusConfig = {
    completed: {
      iconColor: 'text-neon-green',
      borderColor: 'border-neon-green/50',
      bgColor: 'bg-neon-green/5',
      glowColor: 'shadow-neon-green/20',
      connectorColor: 'bg-neon-green/30',
      pulse: false,
      strikethrough: false,
    },
    in_progress: {
      iconColor: 'text-neon-blue',
      borderColor: 'border-neon-blue/60',
      bgColor: 'bg-neon-blue/10',
      glowColor: 'shadow-neon-blue/30',
      connectorColor: 'bg-neon-blue/40',
      pulse: true,
      strikethrough: false,
    },
    pending: {
      iconColor: 'text-muted-foreground/40',
      borderColor: 'border-border/30',
      bgColor: 'bg-muted/10',
      glowColor: '',
      connectorColor: 'bg-border/20',
      pulse: false,
      strikethrough: false,
    },
    skipped: {
      iconColor: 'text-muted-foreground/30',
      borderColor: 'border-border/20',
      bgColor: 'bg-muted/5',
      glowColor: '',
      connectorColor: 'bg-border/10',
      pulse: false,
      strikethrough: true,
    },
  };

  const config = statusConfig[status];

  const cardContent = (
    <div
      className={cn(
        'relative flex flex-col items-center',
        'min-w-[140px] max-w-[160px]',
        'transition-all duration-300 ease-out',
        onClick && 'cursor-pointer',
        onClick && 'hover:scale-105 active:scale-100'
      )}
      onClick={onClick}
    >
      {/* Main Card */}
      <div
        className={cn(
          'relative w-full',
          'border-2 rounded-lg',
          'backdrop-blur-sm',
          'transition-all duration-300',
          config.borderColor,
          config.bgColor,
          config.glowColor && `shadow-lg ${config.glowColor}`,
          onClick && 'hover:shadow-xl',
          onClick && status === 'completed' && 'hover:border-neon-green/70',
          onClick && status === 'in_progress' && 'hover:border-neon-blue/80',
          config.pulse && 'animate-pulse-subtle'
        )}
      >
        {/* Header with Icon */}
        <div className="flex flex-col items-center pt-3 pb-2 px-3 space-y-2">
          {/* Icon Container */}
          <div
            className={cn(
              'relative flex items-center justify-center',
              'w-10 h-10 rounded-md',
              'border border-border/40',
              'bg-background/80',
              'transition-colors duration-300'
            )}
          >
            {status === 'in_progress' ? (
              <Loader2 className={cn('h-5 w-5 animate-spin', config.iconColor)} />
            ) : (
              <Icon className={cn('h-5 w-5', config.iconColor)} />
            )}
          </div>

          {/* Title */}
          <div
            className={cn(
              'text-xs font-bold text-center uppercase tracking-wide',
              'text-foreground/90',
              config.strikethrough && 'line-through opacity-50'
            )}
          >
            {title}
          </div>
        </div>

        {/* Timestamp & Duration */}
        {timestamp && (
          <div className="px-3 pb-2 flex items-center justify-center gap-1.5">
            <span className="text-[10px] text-muted-foreground/60 font-mono">
              {formatRelativeTime(timestamp)}
            </span>
            {duration && (
              <>
                <span className="text-[8px] text-muted-foreground/40">•</span>
                <Badge
                  variant="outline"
                  className={cn(
                    'text-[9px] px-1 py-0 h-3.5 font-mono',
                    status === 'completed' && 'border-neon-green/40 text-neon-green/80',
                    status === 'in_progress' && 'border-neon-blue/40 text-neon-blue/80'
                  )}
                >
                  {duration}
                </Badge>
              </>
            )}
          </div>
        )}

        {/* Summary */}
        <div className="px-3 pb-3 border-t border-border/20 pt-2 mt-1">
          <p
            className={cn(
              'text-[11px] text-muted-foreground/70 text-center line-clamp-2',
              'leading-tight',
              config.strikethrough && 'line-through opacity-40'
            )}
          >
            {summary}
          </p>
        </div>

        {/* Status Indicator Bar */}
        <div
          className={cn(
            'absolute bottom-0 left-0 right-0 h-0.5',
            'rounded-b-md',
            status === 'completed' && 'bg-neon-green',
            status === 'in_progress' && 'bg-neon-blue animate-pulse',
            status === 'pending' && 'bg-muted-foreground/20',
            status === 'skipped' && 'bg-muted-foreground/10'
          )}
        />
      </div>

      {/* Connector Arrow to Next Stage */}
      {!isLast && (
        <div className="absolute -right-6 top-1/2 -translate-y-1/2 flex items-center">
          <div className={cn('h-[2px] w-8', config.connectorColor)} />
          <ChevronRight
            className={cn('h-4 w-4 -ml-1', config.iconColor, 'opacity-60')}
            strokeWidth={3}
          />
        </div>
      )}
    </div>
  );

  // Wrap with tooltip if details exist
  if (details && Object.keys(details).length > 0) {
    return (
      <TooltipProvider delayDuration={200}>
        <Tooltip>
          <TooltipTrigger asChild>{cardContent}</TooltipTrigger>
          <TooltipContent
            side="bottom"
            className={cn(
              'max-w-xs p-3',
              'bg-background/95 backdrop-blur-md',
              'border-2 border-border/50',
              'shadow-2xl',
              'rounded-lg'
            )}
          >
            <div className="space-y-2">
              {/* Tooltip Header */}
              <div className="flex items-center gap-2 pb-1.5 border-b border-border/30">
                <Icon className={cn('h-4 w-4', config.iconColor)} />
                <span className="text-sm font-bold">{title}</span>
              </div>

              {/* Tooltip Content */}
              {renderDetailsContent(status, details)}
            </div>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
    );
  }

  return cardContent;
}

// Styled animation for subtle pulse
const style = document.createElement('style');
style.textContent = `
  @keyframes pulse-subtle {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.85; }
  }
  .animate-pulse-subtle {
    animation: pulse-subtle 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
`;
document.head.appendChild(style);
