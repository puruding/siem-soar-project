import { useMemo } from 'react';
import { LucideIcon, TrendingUp, TrendingDown } from 'lucide-react';
import ReactECharts from 'echarts-for-react';
import { Card } from '@/components/ui/card';
import { cn } from '@/lib/utils';

interface MetricProps {
  title: string;
  value: number | string;
  prefix?: string;
  suffix?: string;
  change?: number;
  changeType?: 'increase' | 'decrease';
  changeLabel?: string;
  icon?: LucideIcon;
  iconColor?: string;
  sparklineData?: number[];
  comparison?: {
    label: string;
    value: number | string;
  };
}

export function Metric({
  title,
  value,
  prefix,
  suffix,
  change,
  changeType,
  changeLabel = 'vs last period',
  icon: Icon,
  iconColor = '#00A4A6',
  sparklineData,
  comparison,
}: MetricProps) {
  const displayValue =
    typeof value === 'number' ? value.toLocaleString() : value;

  const sparklineOption = useMemo(() => {
    if (!sparklineData || sparklineData.length === 0) return null;

    return {
      backgroundColor: 'transparent',
      grid: {
        left: 0,
        right: 0,
        top: 0,
        bottom: 0,
      },
      xAxis: {
        type: 'category',
        show: false,
        boundaryGap: false,
      },
      yAxis: {
        type: 'value',
        show: false,
      },
      series: [
        {
          type: 'line',
          data: sparklineData,
          smooth: true,
          showSymbol: false,
          lineStyle: {
            color: iconColor,
            width: 1.5,
          },
          areaStyle: {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                { offset: 0, color: `${iconColor}40` },
                { offset: 1, color: `${iconColor}00` },
              ],
            },
          },
        },
      ],
    };
  }, [sparklineData, iconColor]);

  const trendIcon = useMemo(() => {
    if (change === undefined) return null;
    if (changeType === 'increase' || (changeType === undefined && change >= 0)) {
      return <TrendingUp className="w-4 h-4" />;
    }
    return <TrendingDown className="w-4 h-4" />;
  }, [change, changeType]);

  const trendColor = useMemo(() => {
    if (change === undefined) return '';
    if (changeType === 'increase' || (changeType === undefined && change >= 0)) {
      return '#5CC05C';
    }
    return '#DC4E41';
  }, [change, changeType]);

  return (
    <Card className="p-4 bg-[#1F2527] border-[#2D3339]">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs font-medium text-[#9BA7B4] uppercase tracking-wider">
            {title}
          </p>
          <div className="mt-2 flex items-baseline gap-1">
            {prefix && (
              <span className="text-sm text-[#9BA7B4] font-normal">
                {prefix}
              </span>
            )}
            <span className="text-3xl font-semibold text-[#FFFFFF] tracking-tight">
              {displayValue}
            </span>
            {suffix && (
              <span className="text-sm text-[#9BA7B4] font-normal ml-1">
                {suffix}
              </span>
            )}
          </div>

          {change !== undefined && (
            <div className="flex items-center gap-1.5 mt-2">
              <span style={{ color: trendColor }}>{trendIcon}</span>
              <span
                className="text-sm font-medium"
                style={{ color: trendColor }}
              >
                {change > 0 ? '+' : ''}
                {change}%
              </span>
              <span className="text-xs text-[#9BA7B4]">{changeLabel}</span>
            </div>
          )}

          {comparison && (
            <div className="mt-2 text-xs text-[#9BA7B4]">
              {comparison.label}:{' '}
              <span className="font-medium text-[#FFFFFF]">
                {typeof comparison.value === 'number'
                  ? comparison.value.toLocaleString()
                  : comparison.value}
              </span>
            </div>
          )}
        </div>

        {Icon && !sparklineData && (
          <div
            className="flex items-center justify-center w-10 h-10 rounded bg-[#171D21] border border-[#2D3339]"
            style={{ color: iconColor }}
          >
            <Icon className="w-5 h-5" />
          </div>
        )}
      </div>

      {sparklineOption && (
        <div className="mt-3 -mb-2">
          <ReactECharts
            option={sparklineOption}
            style={{ height: '40px' }}
            notMerge={true}
          />
        </div>
      )}
    </Card>
  );
}
