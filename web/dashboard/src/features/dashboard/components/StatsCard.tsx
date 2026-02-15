import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';
import { Card } from '@/components/ui/card';
import { cn, formatNumber } from '@/lib/utils';

interface StatsCardProps {
  title: string;
  value: number;
  suffix?: string;
  change?: number;
  changeType?: 'increase' | 'decrease';
  icon: LucideIcon;
  iconColor?: string;
  loading?: boolean;
}

export function StatsCard({
  title,
  value,
  suffix = '',
  change,
  changeType,
  icon: Icon,
  iconColor = 'text-primary',
  loading = false,
}: StatsCardProps) {
  return (
    <Card className="p-4 relative overflow-hidden group hover:border-primary/30 transition-all duration-300">
      {/* Background glow effect */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-radial from-primary/10 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />

      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-sm text-muted-foreground font-medium">{title}</p>
          {loading ? (
            <div className="h-9 w-24 bg-muted animate-pulse rounded mt-1" />
          ) : (
            <p className="text-3xl font-display font-bold mt-1">
              {formatNumber(value)}
              {suffix && (
                <span className="text-lg text-muted-foreground ml-1">
                  {suffix}
                </span>
              )}
            </p>
          )}
        </div>
        <div
          className={cn(
            'p-2.5 rounded-lg bg-card border border-border',
            iconColor
          )}
        >
          <Icon className="w-5 h-5" />
        </div>
      </div>

      {change !== undefined && (
        <div className="flex items-center gap-1 mt-3">
          {changeType === 'increase' ? (
            <TrendingUp className="w-4 h-4 text-neon-green" />
          ) : (
            <TrendingDown className="w-4 h-4 text-threat-critical" />
          )}
          <span
            className={cn(
              'text-sm font-medium',
              changeType === 'increase' ? 'text-neon-green' : 'text-threat-critical'
            )}
          >
            {change > 0 ? '+' : ''}
            {change}%
          </span>
          <span className="text-sm text-muted-foreground ml-1">vs last week</span>
        </div>
      )}

      {/* Decorative corner accent */}
      <div className="absolute bottom-0 right-0 w-16 h-16 overflow-hidden">
        <div className="absolute bottom-0 right-0 w-24 h-24 bg-primary/5 rounded-full translate-x-8 translate-y-8" />
      </div>
    </Card>
  );
}
