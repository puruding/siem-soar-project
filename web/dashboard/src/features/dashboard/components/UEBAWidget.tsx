import { useState } from 'react';
import ReactECharts from 'echarts-for-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Brain,
  Activity,
  AlertTriangle,
  Users,
  TrendingUp,
  ArrowUpRight,
  Clock,
} from 'lucide-react';
import { formatRelativeTime } from '@/lib/utils';
import { useUEBAStore, ANOMALY_TYPES } from '@/features/ueba';

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_COLORS = {
  critical: '#ff2d55',
  high: '#ff6b35',
  medium: '#ffc107',
  low: '#17c3b2',
};

const mockTimelineData = Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2, '0')}:00`,
  count: Math.floor(Math.random() * 15) + 2,
}));

// ============================================================================
// Helper Functions
// ============================================================================

interface AnomalyData {
  anomalyType: string;
  [key: string]: any;
}

function getAnomalyTypeDistribution(anomalies: AnomalyData[]) {
  const distribution: Record<string, number> = {};
  anomalies.forEach((anomaly) => {
    distribution[anomaly.anomalyType] = (distribution[anomaly.anomalyType] || 0) + 1;
  });
  return Object.entries(distribution).map(([type, count]) => ({
    name: ANOMALY_TYPES[type] || type,
    value: count,
  }));
}

function getSeverityStats(anomalies: any[]) {
  const stats = { critical: 0, high: 0, medium: 0, low: 0 };
  anomalies.forEach((anomaly) => {
    stats[anomaly.severity as keyof typeof stats]++;
  });
  return stats;
}

function getAverageScore(anomalies: any[]) {
  if (anomalies.length === 0) return 0;
  const sum = anomalies.reduce((acc, a) => acc + a.score, 0);
  return (sum / anomalies.length) * 100;
}

function getActiveEntities(anomalies: any[]) {
  return new Set(anomalies.map((a) => a.entityId)).size;
}

function getEntityTypeIcon(type: 'user' | 'host' | 'ip') {
  switch (type) {
    case 'user':
      return '👤';
    case 'host':
      return '💻';
    case 'ip':
      return '🌐';
  }
}

// ============================================================================
// Component
// ============================================================================

export function UEBAWidget() {
  const [activeTab, setActiveTab] = useState('overview');
  const { alerts, entityRisks, loading } = useUEBAStore();

  // Use store data instead of mock data
  const anomalies = alerts;
  const risks = entityRisks;
  const severityStats = getSeverityStats(anomalies);

  // ECharts option for anomaly type distribution (donut chart)
  const anomalyTypeOption = {
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
        name: 'Anomaly Type',
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
            fontSize: 12,
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
        data: getAnomalyTypeDistribution(anomalies).map((item, index) => ({
          ...item,
          itemStyle: {
            color: [
              '#ff2d55',
              '#ff6b35',
              '#ffc107',
              '#17c3b2',
              '#7b61ff',
              '#5cc05c',
            ][index % 6],
          },
        })),
      },
    ],
  };

  // ECharts option for timeline (line chart)
  const timelineOption = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'hsl(222 47% 8%)',
      borderColor: 'hsl(222 30% 18%)',
      textStyle: {
        color: 'hsl(180 100% 97%)',
        fontFamily: 'JetBrains Mono',
      },
    },
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      top: '10%',
      containLabel: true,
    },
    xAxis: {
      type: 'category',
      data: mockTimelineData.map((d) => d.hour),
      axisLine: {
        lineStyle: {
          color: 'hsl(222 30% 18%)',
        },
      },
      axisLabel: {
        color: 'hsl(215 20% 65%)',
        fontFamily: 'JetBrains Mono',
        fontSize: 10,
      },
    },
    yAxis: {
      type: 'value',
      axisLine: {
        lineStyle: {
          color: 'hsl(222 30% 18%)',
        },
      },
      axisLabel: {
        color: 'hsl(215 20% 65%)',
        fontFamily: 'JetBrains Mono',
      },
      splitLine: {
        lineStyle: {
          color: 'hsl(222 30% 12%)',
        },
      },
    },
    series: [
      {
        data: mockTimelineData.map((d) => d.count),
        type: 'line',
        smooth: true,
        areaStyle: {
          color: {
            type: 'linear',
            x: 0,
            y: 0,
            x2: 0,
            y2: 1,
            colorStops: [
              {
                offset: 0,
                color: 'rgba(123, 97, 255, 0.3)',
              },
              {
                offset: 1,
                color: 'rgba(123, 97, 255, 0)',
              },
            ],
          },
        },
        lineStyle: {
          color: '#7b61ff',
          width: 2,
        },
        itemStyle: {
          color: '#7b61ff',
        },
      },
    ],
  };

  return (
    <Card className="h-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-primary" />
            <CardTitle>UEBA Analytics</CardTitle>
          </div>
          <Badge variant="outline" className="text-xs">
            ML-Powered
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="entities">Entities</TabsTrigger>
            <TabsTrigger value="timeline">Timeline</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview" className="space-y-4">
            {/* Top Stats Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <div className="flex items-center gap-2 mb-1">
                  <Activity className="w-4 h-4 text-primary" />
                  <span className="text-xs text-muted-foreground">
                    총 탐지
                  </span>
                </div>
                <p className="text-2xl font-bold">{anomalies.length}</p>
              </div>

              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <div className="flex items-center gap-2 mb-1">
                  <AlertTriangle className="w-4 h-4 text-threat-critical" />
                  <span className="text-xs text-muted-foreground">
                    Critical
                  </span>
                </div>
                <p className="text-2xl font-bold text-threat-critical">
                  {severityStats.critical}
                </p>
              </div>

              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <div className="flex items-center gap-2 mb-1">
                  <TrendingUp className="w-4 h-4 text-warning" />
                  <span className="text-xs text-muted-foreground">
                    평균 점수
                  </span>
                </div>
                <p className="text-2xl font-bold">
                  {getAverageScore(anomalies).toFixed(0)}
                  <span className="text-sm text-muted-foreground ml-1">%</span>
                </p>
              </div>

              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <div className="flex items-center gap-2 mb-1">
                  <Users className="w-4 h-4 text-success" />
                  <span className="text-xs text-muted-foreground">
                    활성 Entity
                  </span>
                </div>
                <p className="text-2xl font-bold">{getActiveEntities(anomalies)}</p>
              </div>
            </div>

            {/* Anomaly Type Distribution Chart */}
            <div>
              <h4 className="text-sm font-medium mb-2">이상 유형별 분포</h4>
              <ReactECharts
                option={anomalyTypeOption}
                style={{ height: '200px' }}
                notMerge={true}
              />
            </div>

            {/* Recent Anomalies List */}
            <div>
              <h4 className="text-sm font-medium mb-2">최근 탐지 이벤트</h4>
              <ScrollArea className="h-[240px]">
                <div className="space-y-2">
                  {anomalies.slice(0, 5).map((anomaly) => (
                    <div
                      key={anomaly.id}
                      className="p-3 rounded-lg border border-border bg-card/50 hover:bg-card hover:border-primary/30 transition-all duration-200 group"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge variant={anomaly.severity as any}>
                              {anomaly.severity.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {anomaly.id}
                            </span>
                          </div>
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-sm">
                              {getEntityTypeIcon(anomaly.entityType)}
                            </span>
                            <span className="text-sm font-medium truncate">
                              {anomaly.entityId}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            {ANOMALY_TYPES[anomaly.anomalyType] ||
                              anomaly.anomalyType}
                          </p>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          <div className="flex items-center gap-1">
                            <span className="text-xs text-muted-foreground">
                              Score:
                            </span>
                            <span
                              className="text-sm font-bold"
                              style={{
                                color:
                                  SEVERITY_COLORS[
                                    anomaly.severity as keyof typeof SEVERITY_COLORS
                                  ],
                              }}
                            >
                              {(anomaly.score * 100).toFixed(0)}
                            </span>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {formatRelativeTime(new Date(anomaly.detectedAt))}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>

          {/* Entities Tab */}
          <TabsContent value="entities" className="space-y-4">
            <div>
              <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-threat-critical" />
                위험 점수 Top Entities
              </h4>
              <ScrollArea className="h-[520px]">
                <div className="space-y-2">
                  {risks.slice(0, 10).map((entity, index) => (
                    <div
                      key={entity.entityId}
                      className="p-3 rounded-lg border border-border bg-card/50 hover:bg-card hover:border-primary/30 transition-all duration-200"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-2">
                          <div className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/10 text-primary text-xs font-bold">
                            {index + 1}
                          </div>
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-sm">
                                {getEntityTypeIcon(entity.entityType)}
                              </span>
                              <span className="text-sm font-medium">
                                {entity.entityId}
                              </span>
                            </div>
                            <div className="flex items-center gap-3 text-xs text-muted-foreground">
                              <span>탐지: {entity.anomalyCount}</span>
                              {entity.criticalCount > 0 && (
                                <span className="text-threat-critical">
                                  Critical: {entity.criticalCount}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex flex-col items-end gap-1">
                          <div className="flex items-center gap-1">
                            <ArrowUpRight className="w-3 h-3 text-threat-critical" />
                            <span
                              className="text-lg font-bold"
                              style={{
                                color:
                                  entity.riskScore >= 0.8
                                    ? SEVERITY_COLORS.critical
                                    : entity.riskScore >= 0.6
                                    ? SEVERITY_COLORS.high
                                    : entity.riskScore >= 0.4
                                    ? SEVERITY_COLORS.medium
                                    : SEVERITY_COLORS.low,
                              }}
                            >
                              {(entity.riskScore * 100).toFixed(0)}
                            </span>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {formatRelativeTime(new Date(entity.lastDetectedAt))}
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </div>
          </TabsContent>

          {/* Timeline Tab */}
          <TabsContent value="timeline" className="space-y-4">
            <div>
              <h4 className="text-sm font-medium mb-2 flex items-center gap-2">
                <Clock className="w-4 h-4 text-primary" />
                24시간 탐지 현황
              </h4>
              <ReactECharts
                option={timelineOption}
                style={{ height: '400px' }}
                notMerge={true}
              />
            </div>

            {/* Hourly Stats */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <p className="text-xs text-muted-foreground mb-1">최대 탐지</p>
                <p className="text-xl font-bold">
                  {Math.max(...mockTimelineData.map((d) => d.count))}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <p className="text-xs text-muted-foreground mb-1">평균 탐지</p>
                <p className="text-xl font-bold">
                  {(
                    mockTimelineData.reduce((acc, d) => acc + d.count, 0) /
                    mockTimelineData.length
                  ).toFixed(1)}
                </p>
              </div>
              <div className="p-3 rounded-lg bg-muted/30 border border-border">
                <p className="text-xs text-muted-foreground mb-1">총 탐지</p>
                <p className="text-xl font-bold">
                  {mockTimelineData.reduce((acc, d) => acc + d.count, 0)}
                </p>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
