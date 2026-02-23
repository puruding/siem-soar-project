import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ChevronRight, ExternalLink, Loader2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { formatRelativeTime } from '@/lib/utils';
import { useTopAlerts } from '../hooks/useDashboardData';

export function TopAlerts() {
  const { topAlerts, isLoading, error } = useTopAlerts({ limit: 5 });

  return (
    <Card className="h-full">
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Top Priority Alerts</CardTitle>
        <Link to="/alerts">
          <Button variant="ghost" size="sm" className="text-primary">
            View All
            <ExternalLink className="w-4 h-4 ml-1" />
          </Button>
        </Link>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[400px] pr-4">
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <div className="flex items-center justify-center h-32 text-muted-foreground">
              Failed to load alerts
            </div>
          ) : topAlerts.length === 0 ? (
            <div className="flex items-center justify-center h-32 text-muted-foreground">
              No alerts found
            </div>
          ) : (
            <div className="space-y-3">
              {topAlerts.map((alert) => (
                <Link
                  key={alert.id}
                  to={`/alerts/${alert.id}`}
                  className="block p-4 rounded-lg border border-border bg-card/50 hover:bg-card hover:border-primary/30 transition-all duration-200 group"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge
                          variant={
                            alert.severity.toLowerCase() as
                              | 'critical'
                              | 'high'
                              | 'medium'
                              | 'low'
                          }
                        >
                          {alert.severity.toUpperCase()}
                        </Badge>
                        <span className="text-xs text-muted-foreground">
                          {alert.id}
                        </span>
                        {alert.count > 1 && (
                          <Badge variant="secondary" className="text-xs">
                            ×{alert.count}
                          </Badge>
                        )}
                      </div>
                      <h4 className="font-medium text-sm truncate group-hover:text-primary transition-colors">
                        {alert.name}
                      </h4>
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      <span className="text-xs text-muted-foreground whitespace-nowrap">
                        {formatRelativeTime(new Date(alert.lastSeen))}
                      </span>
                      <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                    </div>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
