import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

export function ThreatMap() {
  // Simulated attack source data
  const attackData = [
    { name: 'United States', value: 145, coords: [-95.7, 37.1] },
    { name: 'China', value: 89, coords: [104.2, 35.9] },
    { name: 'Russia', value: 67, coords: [105.3, 61.5] },
    { name: 'Germany', value: 45, coords: [10.5, 51.2] },
    { name: 'Brazil', value: 38, coords: [-51.9, -14.2] },
    { name: 'India', value: 32, coords: [78.9, 20.6] },
    { name: 'South Korea', value: 28, coords: [127.8, 35.9] },
    { name: 'Netherlands', value: 24, coords: [5.3, 52.1] },
  ];

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
      formatter: (params: { name: string; value: number }) => {
        return `${params.name}: ${params.value} attacks`;
      },
    },
    geo: {
      map: 'world',
      roam: false,
      zoom: 1.2,
      center: [10, 30],
      itemStyle: {
        areaColor: 'hsl(222 30% 12%)',
        borderColor: 'hsl(222 30% 25%)',
        borderWidth: 0.5,
      },
      emphasis: {
        disabled: true,
      },
      silent: true,
    },
    series: [
      {
        type: 'effectScatter',
        coordinateSystem: 'geo',
        data: attackData.map((item) => ({
          name: item.name,
          value: [...item.coords, item.value],
        })),
        symbolSize: (val: number[]) => Math.max(val[2]! / 5, 8),
        showEffectOn: 'render',
        rippleEffect: {
          brushType: 'stroke',
          scale: 3,
          period: 4,
        },
        itemStyle: {
          color: '#ff2d55',
          shadowBlur: 10,
          shadowColor: 'rgba(255, 45, 85, 0.5)',
        },
      },
    ],
  };

  // We need to register the world map - for demo purposes, show a placeholder
  // In production, you'd load the actual map JSON

  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Threat Origin Map</CardTitle>
        <Badge variant="critical" className="animate-pulse">
          Live
        </Badge>
      </CardHeader>
      <CardContent>
        {/* Placeholder for map - in production load actual world map */}
        <div className="h-[280px] relative bg-muted/20 rounded-lg overflow-hidden">
          {/* Grid overlay */}
          <div
            className="absolute inset-0 opacity-20"
            style={{
              backgroundImage: `
                linear-gradient(rgba(0, 255, 242, 0.1) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 242, 0.1) 1px, transparent 1px)
              `,
              backgroundSize: '40px 40px',
            }}
          />

          {/* Attack indicators */}
          {attackData.map((attack, i) => (
            <div
              key={attack.name}
              className="absolute"
              style={{
                left: `${((attack.coords[0]! + 180) / 360) * 100}%`,
                top: `${((90 - attack.coords[1]!) / 180) * 100}%`,
                transform: 'translate(-50%, -50%)',
              }}
            >
              <div className="relative">
                <div className="w-3 h-3 rounded-full bg-threat-critical animate-ping absolute" />
                <div className="w-3 h-3 rounded-full bg-threat-critical relative" />
              </div>
            </div>
          ))}

          {/* Center marker (target) */}
          <div className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2">
            <div className="w-4 h-4 rounded-full bg-neon-cyan animate-pulse" />
            <div className="absolute inset-0 w-4 h-4 rounded-full bg-neon-cyan/30 animate-ping" />
          </div>
        </div>

        {/* Top attack sources */}
        <div className="mt-4 space-y-2">
          {attackData.slice(0, 4).map((attack, i) => (
            <div
              key={attack.name}
              className="flex items-center justify-between p-2 rounded-lg bg-muted/30"
            >
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground w-4">
                  #{i + 1}
                </span>
                <span className="text-sm">{attack.name}</span>
              </div>
              <span className="text-sm font-mono text-threat-critical">
                {attack.value}
              </span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
