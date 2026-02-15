import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface BarChartProps {
  title?: string;
  data: {
    labels: string[];
    values: number[];
    colors?: string[];
  };
  height?: string;
  horizontal?: boolean;
  showValues?: boolean;
}

const splunkColors = ['#00A4A6', '#F79836', '#DC4E41', '#5CC05C', '#7B61FF'];

export function BarChart({
  title,
  data,
  height = '300px',
  horizontal = false,
  showValues = false,
}: BarChartProps) {
  const option = {
    backgroundColor: 'transparent',
    textStyle: {
      color: '#9BA7B4',
      fontFamily: 'Roboto, -apple-system, BlinkMacSystemFont, sans-serif',
    },
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#1F2527',
      borderColor: '#2D3339',
      borderWidth: 1,
      textStyle: {
        color: '#FFFFFF',
        fontSize: 12,
      },
      axisPointer: {
        type: 'shadow',
        shadowStyle: {
          color: 'rgba(0, 164, 166, 0.05)',
        },
      },
      padding: [8, 12],
    },
    grid: {
      left: horizontal ? '15%' : '3%',
      right: '4%',
      bottom: '3%',
      top: '10%',
      containLabel: true,
    },
    xAxis: horizontal
      ? {
          type: 'value',
          axisLine: {
            show: false,
          },
          splitLine: {
            lineStyle: {
              color: '#2D3339',
              opacity: 0.3,
              type: 'solid',
            },
          },
          axisLabel: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
          },
        }
      : {
          type: 'category',
          data: data.labels,
          axisLine: {
            lineStyle: {
              color: '#2D3339',
            },
          },
          axisLabel: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
            rotate: data.labels.length > 8 ? 45 : 0,
            interval: 0,
          },
          axisTick: {
            show: false,
          },
        },
    yAxis: horizontal
      ? {
          type: 'category',
          data: data.labels,
          axisLine: {
            show: false,
          },
          axisLabel: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
          },
          axisTick: {
            show: false,
          },
        }
      : {
          type: 'value',
          axisLine: {
            show: false,
          },
          splitLine: {
            lineStyle: {
              color: '#2D3339',
              opacity: 0.3,
              type: 'solid',
            },
          },
          axisLabel: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
          },
        },
    series: [
      {
        type: 'bar',
        data: data.values.map((value, index) => ({
          value,
          itemStyle: {
            color: data.colors?.[index] || splunkColors[index % splunkColors.length],
            borderRadius: horizontal ? [0, 2, 2, 0] : [2, 2, 0, 0],
          },
        })),
        barWidth: '60%',
        label: showValues
          ? {
              show: true,
              position: horizontal ? 'right' : 'top',
              color: '#9BA7B4',
              fontSize: 11,
              fontFamily: 'Roboto, sans-serif',
            }
          : undefined,
        emphasis: {
          itemStyle: {
            shadowBlur: 10,
            shadowColor: 'rgba(0, 164, 166, 0.3)',
          },
        },
      },
    ],
  };

  const content = (
    <ReactECharts option={option} style={{ height }} notMerge={true} />
  );

  if (title) {
    return (
      <Card>
        <CardHeader className="pb-4">
          <CardTitle className="text-sm font-medium text-[#FFFFFF]">
            {title}
          </CardTitle>
        </CardHeader>
        <CardContent>{content}</CardContent>
      </Card>
    );
  }

  return content;
}
