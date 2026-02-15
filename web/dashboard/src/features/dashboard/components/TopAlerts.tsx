import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { ChevronRight, ExternalLink } from 'lucide-react';
import { Link } from 'react-router-dom';
import { formatRelativeTime } from '@/lib/utils';

const alerts = [
  {
    id: 'ALT-2024-001',
    title: 'Ransomware Detection - LockBit 3.0',
    severity: 'critical',
    source: 'EDR',
    timestamp: new Date(Date.now() - 1000 * 60 * 2),
    target: 'DESKTOP-A1B2C3',
  },
  {
    id: 'ALT-2024-002',
    title: 'Suspicious PowerShell Execution',
    severity: 'high',
    source: 'SIEM',
    timestamp: new Date(Date.now() - 1000 * 60 * 15),
    target: 'SERVER-WEB-01',
  },
  {
    id: 'ALT-2024-003',
    title: 'Brute Force Attack Detected',
    severity: 'high',
    source: 'Firewall',
    timestamp: new Date(Date.now() - 1000 * 60 * 32),
    target: '192.168.1.100',
  },
  {
    id: 'ALT-2024-004',
    title: 'Data Exfiltration Attempt',
    severity: 'critical',
    source: 'DLP',
    timestamp: new Date(Date.now() - 1000 * 60 * 45),
    target: 'user@company.com',
  },
  {
    id: 'ALT-2024-005',
    title: 'Unauthorized API Access',
    severity: 'medium',
    source: 'API Gateway',
    timestamp: new Date(Date.now() - 1000 * 60 * 58),
    target: '/api/admin/users',
  },
];

export function TopAlerts() {
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
          <div className="space-y-3">
            {alerts.map((alert) => (
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
                          alert.severity as
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
                    </div>
                    <h4 className="font-medium text-sm truncate group-hover:text-primary transition-colors">
                      {alert.title}
                    </h4>
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>Source: {alert.source}</span>
                      <span>Target: {alert.target}</span>
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-2">
                    <span className="text-xs text-muted-foreground whitespace-nowrap">
                      {formatRelativeTime(alert.timestamp)}
                    </span>
                    <ChevronRight className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}
