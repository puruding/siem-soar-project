/**
 * SuggestionChips - Clickable suggestion chips for quick actions and queries.
 */
import { memo } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import {
  Search,
  FileText,
  Shield,
  Zap,
  Database,
  BookOpen,
  TrendingUp,
  AlertCircle,
  ChevronRight,
} from 'lucide-react';

export interface Suggestion {
  id: string;
  text: string;
  type: 'query' | 'action' | 'playbook' | 'template' | 'quick';
  icon?: 'search' | 'file' | 'shield' | 'zap' | 'database' | 'book' | 'trend' | 'alert';
  description?: string;
  metadata?: Record<string, unknown>;
}

interface SuggestionChipsProps {
  suggestions: Suggestion[];
  onSelect: (suggestion: Suggestion) => void;
  variant?: 'horizontal' | 'vertical' | 'grid';
  showDescriptions?: boolean;
  className?: string;
  title?: string;
}

const iconMap = {
  search: Search,
  file: FileText,
  shield: Shield,
  zap: Zap,
  database: Database,
  book: BookOpen,
  trend: TrendingUp,
  alert: AlertCircle,
};

const typeStyles = {
  query: 'border-neon-cyan/30 hover:border-neon-cyan/60 hover:bg-neon-cyan/10',
  action: 'border-neon-green/30 hover:border-neon-green/60 hover:bg-neon-green/10',
  playbook: 'border-neon-purple/30 hover:border-neon-purple/60 hover:bg-neon-purple/10',
  template: 'border-neon-orange/30 hover:border-neon-orange/60 hover:bg-neon-orange/10',
  quick: 'border-primary/30 hover:border-primary/60 hover:bg-primary/10',
};

const typeLabels = {
  query: 'Query',
  action: 'Action',
  playbook: 'Playbook',
  template: 'Template',
  quick: 'Quick',
};

function SuggestionChipsComponent({
  suggestions,
  onSelect,
  variant = 'horizontal',
  showDescriptions = false,
  className,
  title,
}: SuggestionChipsProps) {
  if (suggestions.length === 0) {
    return null;
  }

  const renderChip = (suggestion: Suggestion) => {
    const IconComponent = suggestion.icon ? iconMap[suggestion.icon] : null;

    if (variant === 'vertical' || showDescriptions) {
      return (
        <button
          key={suggestion.id}
          onClick={() => onSelect(suggestion)}
          className={cn(
            'group w-full flex items-start gap-3 p-3 rounded-lg border bg-background/50',
            'transition-all duration-200 text-left',
            typeStyles[suggestion.type]
          )}
        >
          {IconComponent && (
            <div className="p-2 rounded-md bg-muted/50 shrink-0">
              <IconComponent className="h-4 w-4 text-muted-foreground group-hover:text-foreground transition-colors" />
            </div>
          )}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-medium text-sm truncate">{suggestion.text}</span>
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 shrink-0">
                {typeLabels[suggestion.type]}
              </Badge>
            </div>
            {suggestion.description && (
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                {suggestion.description}
              </p>
            )}
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0 mt-1" />
        </button>
      );
    }

    return (
      <Button
        key={suggestion.id}
        variant="outline"
        size="sm"
        onClick={() => onSelect(suggestion)}
        className={cn(
          'h-auto py-1.5 px-3 rounded-full',
          'transition-all duration-200',
          typeStyles[suggestion.type]
        )}
      >
        {IconComponent && <IconComponent className="h-3.5 w-3.5 mr-1.5" />}
        <span className="text-xs">{suggestion.text}</span>
      </Button>
    );
  };

  return (
    <div className={cn('space-y-2', className)}>
      {title && (
        <p className="text-xs font-medium text-muted-foreground px-1">{title}</p>
      )}
      <div
        className={cn(
          variant === 'horizontal' && 'flex flex-wrap gap-2',
          variant === 'vertical' && 'flex flex-col gap-2',
          variant === 'grid' && 'grid grid-cols-2 gap-2'
        )}
      >
        {suggestions.map(renderChip)}
      </div>
    </div>
  );
}

export const SuggestionChips = memo(SuggestionChipsComponent);

// Pre-defined suggestion sets for common use cases
export const DEFAULT_SUGGESTIONS: Suggestion[] = [
  {
    id: 'critical-alerts',
    text: 'Show critical alerts',
    type: 'query',
    icon: 'alert',
    description: 'Display all critical severity alerts from today',
  },
  {
    id: 'failed-logins',
    text: 'Failed login attempts',
    type: 'query',
    icon: 'search',
    description: 'Find failed authentication events in the last hour',
  },
  {
    id: 'top-ips',
    text: 'Top source IPs',
    type: 'query',
    icon: 'trend',
    description: 'Show the most active source IP addresses',
  },
  {
    id: 'summarize-incident',
    text: 'Summarize incident',
    type: 'action',
    icon: 'file',
    description: 'Generate a summary of the current incident',
  },
  {
    id: 'recommend-playbook',
    text: 'Recommend playbook',
    type: 'playbook',
    icon: 'shield',
    description: 'Get playbook recommendations based on context',
  },
  {
    id: 'similar-cases',
    text: 'Find similar cases',
    type: 'action',
    icon: 'book',
    description: 'Search for historically similar incidents',
  },
];

export const KOREAN_SUGGESTIONS: Suggestion[] = [
  {
    id: 'critical-alerts-ko',
    text: '심각한 경보 보기',
    type: 'query',
    icon: 'alert',
    description: '오늘 발생한 심각한 경보 표시',
  },
  {
    id: 'failed-logins-ko',
    text: '로그인 실패 시도',
    type: 'query',
    icon: 'search',
    description: '최근 1시간 동안의 인증 실패 이벤트',
  },
  {
    id: 'summarize-ko',
    text: '인시던트 요약',
    type: 'action',
    icon: 'file',
    description: '현재 인시던트에 대한 요약 생성',
  },
  {
    id: 'recommend-ko',
    text: '플레이북 추천',
    type: 'playbook',
    icon: 'shield',
    description: '컨텍스트 기반 플레이북 추천',
  },
];
