import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

interface LineChartProps {
  title?: string;
  data: {
    labels: string[];
    series: {
      name: string;
      data: number[];
      color?: string;
    }[];
  };
  height?: string;
  showLegend?: boolean;
  smooth?: boolean;
  area?: boolean;
  zoom?: boolean;
}

const splunkColors = ['#00A4A6', '#F79836', '#DC4E41', '#5CC05C', '#7B61FF'];

export function LineChart({
  title,
  data,
  height = '300px',
  showLegend = true,
  smooth = true,
  area = false,
  zoom = false,
}: LineChartProps) {
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
      padding: [8, 12],
      axisPointer: {
        type: 'line',
        lineStyle: {
          color: '#2D3339',
          type: 'solid',
        },
      },
    },
    legend: showLegend
      ? {
          data: data.series.map((s) => s.name),
          bottom: 0,
          textStyle: {
            color: '#9BA7B4',
            fontSize: 11,
            fontFamily: 'Roboto, sans-serif',
          },
          itemWidth: 14,
          itemHeight: 2,
          icon: 'rect',
          pageTextStyle: {
            color: '#9BA7B4',
          },
        }
      : undefined,
    grid: {
      left: '3%',
      right: '4%',
      bottom: showLegend ? '12%' : '3%',
      top: '10%',
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
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
      },
      axisTick: {
        show: false,
      },
      splitLine: {
        show: false,
      },
    },
    yAxis: {
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
    dataZoom: zoom
      ? [
          {
            type: 'inside',
            start: 0,
            end: 100,
          },
          {
            start: 0,
            end: 100,
            height: 20,
            bottom: showLegend ? '8%' : '5%',
            textStyle: {
              color: '#9BA7B4',
              fontSize: 10,
            },
            borderColor: '#2D3339',
            fillerColor: 'rgba(0, 164, 166, 0.1)',
            handleStyle: {
              color: '#00A4A6',
              borderColor: '#00A4A6',
            },
            dataBackground: {
              lineStyle: {
                color: '#2D3339',
              },
              areaStyle: {
                color: 'rgba(45, 51, 57, 0.3)',
              },
            },
          },
        ]
      : undefined,
    series: data.series.map((s, index) => ({
      name: s.name,
      type: 'line',
      smooth,
      lineStyle: {
        width: 2,
        color: s.color || splunkColors[index % splunkColors.length],
      },
      showSymbol: false,
      symbolSize: 6,
      emphasis: {
        focus: 'series',
        lineStyle: {
          width: 3,
        },
      },
      areaStyle: area
        ? {
            color: {
              type: 'linear',
              x: 0,
              y: 0,
              x2: 0,
              y2: 1,
              colorStops: [
                {
                  offset: 0,
                  color:
                    (s.color || splunkColors[index % splunkColors.length]) +
                    '40',
                },
                {
                  offset: 1,
                  color:
                    (s.color || splunkColors[index % splunkColors.length]) +
                    '00',
                },
              ],
            },
          }
        : undefined,
      data: s.data,
    })),
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
