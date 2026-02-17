/**
 * GroupStatistics Component
 * Displays statistics for grouped alert events
 */

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Globe,
  User,
  Clock,
  Activity,
  TrendingUp,
  Target
} from 'lucide-react';
import { type GroupStatistics as GroupStatsType } from '../utils/groupStats';
import { formatFullTimestamp } from '../utils/groupStats';

interface GroupStatisticsProps {
  statistics: GroupStatsType;
  className?: string;
}

export function GroupStatistics({ statistics, className }: GroupStatisticsProps) {
  return (
    <div className={className}>
      <ScrollArea className="h-[400px]">
        <div className="space-y-4 pr-4">
          {/* Overview */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Activity className="w-4 h-4 text-primary" />
                Overview
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-3 gap-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-primary">
                    {statistics.totalEvents}
                  </p>
                  <p className="text-xs text-muted-foreground">Total Events</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-neon-cyan">
                    {statistics.uniqueSourceIPs.length}
                  </p>
                  <p className="text-xs text-muted-foreground">Unique Sources</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-neon-orange">
                    {statistics.uniqueUsers.length}
                  </p>
                  <p className="text-xs text-muted-foreground">Unique Users</p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Peak Time */}
          {statistics.peakTime && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-neon-orange" />
                  Peak Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium">
                      {formatFullTimestamp(statistics.peakTime.start)}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      5-minute window with highest activity
                    </p>
                  </div>
                  <Badge variant="warning" className="text-lg px-3 py-1">
                    {statistics.peakTime.count} events
                  </Badge>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Source IPs */}
          {statistics.uniqueSourceIPs.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Globe className="w-4 h-4 text-neon-cyan" />
                  Source IPs ({statistics.uniqueSourceIPs.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {statistics.uniqueSourceIPs.slice(0, 10).map(({ ip, count }) => (
                    <div
                      key={ip}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="font-mono text-muted-foreground">{ip}</span>
                      <Badge variant="outline" className="text-xs">
                        {count} events
                      </Badge>
                    </div>
                  ))}
                  {statistics.uniqueSourceIPs.length > 10 && (
                    <p className="text-xs text-muted-foreground text-center pt-2">
                      +{statistics.uniqueSourceIPs.length - 10} more IPs
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Destination IPs */}
          {statistics.uniqueDestinationIPs.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Target className="w-4 h-4 text-threat-high" />
                  Destination IPs ({statistics.uniqueDestinationIPs.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {statistics.uniqueDestinationIPs.slice(0, 10).map(({ ip, count }) => (
                    <div
                      key={ip}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="font-mono text-muted-foreground">{ip}</span>
                      <Badge variant="outline" className="text-xs">
                        {count} events
                      </Badge>
                    </div>
                  ))}
                  {statistics.uniqueDestinationIPs.length > 10 && (
                    <p className="text-xs text-muted-foreground text-center pt-2">
                      +{statistics.uniqueDestinationIPs.length - 10} more IPs
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Users */}
          {statistics.uniqueUsers.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <User className="w-4 h-4 text-neon-blue" />
                  Users ({statistics.uniqueUsers.length})
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {statistics.uniqueUsers.slice(0, 10).map(({ user, count }) => (
                    <div
                      key={user}
                      className="flex items-center justify-between text-sm"
                    >
                      <span className="font-medium">{user}</span>
                      <Badge variant="outline" className="text-xs">
                        {count} events
                      </Badge>
                    </div>
                  ))}
                  {statistics.uniqueUsers.length > 10 && (
                    <p className="text-xs text-muted-foreground text-center pt-2">
                      +{statistics.uniqueUsers.length - 10} more users
                    </p>
                  )}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Time Distribution */}
          {statistics.timeDistribution.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Clock className="w-4 h-4 text-muted-foreground" />
                  Time Distribution
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {statistics.timeDistribution.map(({ hour, count }) => {
                    const maxCount = Math.max(
                      ...statistics.timeDistribution.map((t) => t.count)
                    );
                    const percentage = (count / maxCount) * 100;
                    const hourFormatted = new Date(hour).toLocaleTimeString('en-US', {
                      hour: '2-digit',
                      minute: '2-digit',
                      hour12: false,
                    });

                    return (
                      <div key={hour} className="space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-muted-foreground">{hourFormatted}</span>
                          <span className="font-medium">{count}</span>
                        </div>
                        <div className="h-2 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-primary transition-all"
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Actions */}
          {statistics.uniqueActions.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Actions</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {statistics.uniqueActions.map(({ action, count }) => (
                    <Badge key={action} variant="secondary">
                      {action} ({count})
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Statuses */}
          {statistics.uniqueStatuses.length > 0 && (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">Status Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {statistics.uniqueStatuses.map(({ status, count }) => {
                    const variant =
                      status.toLowerCase() === 'failure' ||
                      status.toLowerCase() === 'failed'
                        ? 'destructive'
                        : status.toLowerCase() === 'success'
                        ? 'success'
                        : 'outline';
                    return (
                      <Badge key={status} variant={variant as any}>
                        {status} ({count})
                      </Badge>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
