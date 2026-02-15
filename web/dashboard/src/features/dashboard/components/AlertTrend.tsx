import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export function AlertTrend() {
  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'hsl(222 47% 8%)',
      borderColor: 'hsl(222 30% 18%)',
      textStyle: {
        color: 'hsl(180 100% 97%)',
        fontFamily: 'JetBrains Mono',
      },
      axisPointer: {
        type: 'cross',
        label: {
          backgroundColor: 'hsl(222 47% 6%)',
        },
      },
    },
    legend: {
      data: ['Critical', 'High', 'Medium', 'Low'],
      bottom: 0,
      textStyle: {
        color: 'hsl(180 20% 60%)',
        fontFamily: 'JetBrains Mono',
      },
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '15%',
      top: '10%',
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      boundaryGap: false,
      data: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'],
      axisLine: {
        lineStyle: {
          color: 'hsl(222 30% 18%)',
        },
      },
      axisLabel: {
        color: 'hsl(180 20% 60%)',
        fontFamily: 'JetBrains Mono',
        fontSize: 11,
      },
    },
    yAxis: {
      type: 'value',
      axisLine: {
        show: false,
      },
      splitLine: {
        lineStyle: {
          color: 'hsl(222 30% 18%)',
          type: 'dashed',
        },
      },
      axisLabel: {
        color: 'hsl(180 20% 60%)',
        fontFamily: 'JetBrains Mono',
        fontSize: 11,
      },
    },
    series: [
      {
        name: 'Critical',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 2,
          color: '#ff2d55',
        },
        showSymbol: false,
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(255, 45, 85, 0.4)' },
              { offset: 1, color: 'rgba(255, 45, 85, 0.05)' },
            ],
          },
        },
        data: [5, 3, 8, 12, 7, 4, 6],
      },
      {
        name: 'High',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 2,
          color: '#ff6b35',
        },
        showSymbol: false,
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(255, 107, 53, 0.4)' },
              { offset: 1, color: 'rgba(255, 107, 53, 0.05)' },
            ],
          },
        },
        data: [18, 15, 22, 28, 25, 19, 21],
      },
      {
        name: 'Medium',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 2,
          color: '#ffc107',
        },
        showSymbol: false,
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(255, 193, 7, 0.4)' },
              { offset: 1, color: 'rgba(255, 193, 7, 0.05)' },
            ],
          },
        },
        data: [45, 38, 52, 68, 55, 42, 48],
      },
      {
        name: 'Low',
        type: 'line',
        stack: 'Total',
        smooth: true,
        lineStyle: {
          width: 2,
          color: '#17c3b2',
        },
        showSymbol: false,
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              { offset: 0, color: 'rgba(23, 195, 178, 0.4)' },
              { offset: 1, color: 'rgba(23, 195, 178, 0.05)' },
            ],
          },
        },
        data: [85, 72, 95, 120, 98, 78, 88],
      },
    ],
  };

  return (
    <Card className="h-full">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle>Alert Trend</CardTitle>
          <Tabs defaultValue="24h" className="w-auto">
            <TabsList className="h-8">
              <TabsTrigger value="24h" className="text-xs px-2">
                24h
              </TabsTrigger>
              <TabsTrigger value="7d" className="text-xs px-2">
                7d
              </TabsTrigger>
              <TabsTrigger value="30d" className="text-xs px-2">
                30d
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </CardHeader>
      <CardContent>
        <ReactECharts
          option={option}
          style={{ height: '300px' }}
          notMerge={true}
        />
      </CardContent>
    </Card>
  );
}
