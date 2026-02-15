import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

export function SeverityDistribution() {
  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: 'hsl(222 47% 8%)',
      borderColor: 'hsl(222 30% 18%)',
      textStyle: {
        color: 'hsl(180 100% 97%)',
        fontFamily: 'JetBrains Mono',
      },
      formatter: '{b}: {c} ({d}%)',
    },
    series: [
      {
        name: 'Severity',
        type: 'pie',
        radius: ['45%', '70%'],
        center: ['50%', '50%'],
        avoidLabelOverlap: false,
        itemStyle: {
          borderRadius: 8,
          borderColor: 'hsl(222 47% 6%)',
          borderWidth: 2,
        },
        label: {
          show: false,
        },
        emphasis: {
          label: {
            show: true,
            fontSize: 14,
            fontWeight: 'bold',
            color: 'hsl(180 100% 97%)',
            fontFamily: 'JetBrains Mono',
          },
          itemStyle: {
            shadowBlur: 20,
            shadowColor: 'rgba(0, 0, 0, 0.5)',
          },
        },
        labelLine: {
          show: false,
        },
        data: [
          {
            value: 24,
            name: 'Critical',
            itemStyle: { color: '#ff2d55' },
          },
          {
            value: 67,
            name: 'High',
            itemStyle: { color: '#ff6b35' },
          },
          {
            value: 148,
            name: 'Medium',
            itemStyle: { color: '#ffc107' },
          },
          {
            value: 256,
            name: 'Low',
            itemStyle: { color: '#17c3b2' },
          },
        ],
      },
    ],
  };

  const stats = [
    { label: 'Critical', value: 24, color: 'bg-threat-critical' },
    { label: 'High', value: 67, color: 'bg-threat-high' },
    { label: 'Medium', value: 148, color: 'bg-threat-medium' },
    { label: 'Low', value: 256, color: 'bg-threat-low' },
  ];

  return (
    <Card className="h-full">
      <CardHeader>
        <CardTitle>Severity Distribution</CardTitle>
      </CardHeader>
      <CardContent>
        <ReactECharts
          option={option}
          style={{ height: '200px' }}
          notMerge={true}
        />
        <div className="grid grid-cols-2 gap-3 mt-4">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className="flex items-center gap-2 p-2 rounded-lg bg-muted/30"
            >
              <div className={`w-3 h-3 rounded-full ${stat.color}`} />
              <span className="text-sm text-muted-foreground flex-1">
                {stat.label}
              </span>
              <span className="text-sm font-mono font-semibold">
                {stat.value}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
