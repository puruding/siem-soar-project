import { useMemo } from 'react';
import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface PieChartProps {
  title?: string;
  data: {
    name: string;
    value: number;
    color?: string;
  }[];
  height?: string;
  donut?: boolean;
  showLegend?: boolean;
  showCenter?: boolean;
}

const splunkColors = ['#00A4A6', '#F79836', '#DC4E41', '#5CC05C', '#7B61FF', '#9B59B6'];

export function PieChart({
  title,
  data,
  height = '300px',
  donut = true,
  showLegend = true,
  showCenter = true,
}: PieChartProps) {
  const total = useMemo(() => {
    return data.reduce((sum, item) => sum + item.value, 0);
  }, [data]);

  const option = {
    backgroundColor: 'transparent',
    textStyle: {
      color: '#9BA7B4',
      fontFamily: 'Roboto, -apple-system, BlinkMacSystemFont, sans-serif',
    },
    tooltip: {
      trigger: 'item',
      backgroundColor: '#1F2527',
      borderColor: '#2D3339',
      borderWidth: 1,
      textStyle: {
        color: '#FFFFFF',
        fontSize: 12,
      },
      padding: [8, 12],
      formatter: (params: any) => {
        return `${params.marker} ${params.name}<br/><span style="font-weight: 500;">${params.value}</span> <span style="color: #9BA7B4;">(${params.percent}%)</span>`;
      },
    },
    legend: showLegend
      ? {
          orient: 'vertical',
          right: 10,
          top: 'center',
          textStyle: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
          },
          itemWidth: 10,
          itemHeight: 10,
          icon: 'circle',
          pageTextStyle: {
            color: '#9BA7B4',
          },
        }
      : undefined,
    graphic: donut && showCenter
      ? {
          type: 'text',
          left: showLegend ? '35%' : 'center',
          top: 'center',
          style: {
            text: `${total}`,
            textAlign: 'center',
            fill: '#FFFFFF',
            fontSize: 24,
            fontWeight: 500,
            fontFamily: 'Roboto, sans-serif',
          },
        }
      : undefined,
    series: [
      {
        type: 'pie',
        radius: donut ? ['45%', '70%'] : '70%',
        center: showLegend ? ['35%', '50%'] : ['50%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 0,
          borderColor: '#171D21',
          borderWidth: 2,
        },
        label: {
          show: false,
        },
        emphasis: {
          scale: true,
          scaleSize: 8,
          label: {
            show: true,
            fontSize: 13,
            fontWeight: 500,
            color: '#FFFFFF',
            fontFamily: 'Roboto, sans-serif',
            formatter: (params: any) => {
              return `${params.name}\n${params.percent}%`;
            },
          },
          itemStyle: {
            shadowBlur: 15,
            shadowColor: 'rgba(0, 0, 0, 0.5)',
          },
        },
        labelLine: {
          show: false,
          length: 15,
          length2: 10,
          lineStyle: {
            color: '#2D3339',
          },
        },
        data: data.map((item, index) => ({
          name: item.name,
          value: item.value,
          itemStyle: {
            color: item.color || splunkColors[index % splunkColors.length],
          },
        })),
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
