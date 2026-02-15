import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ExternalLink, MoreHorizontal } from 'lucide-react';
import { Link } from 'react-router-dom';
import { formatRelativeTime, cn } from '@/lib/utils';

const cases = [
  {
    id: 'CASE-2024-001',
    title: 'Ransomware Incident - Finance Dept',
    status: 'in-progress',
    severity: 'critical',
    assignee: { name: 'John Doe', initials: 'JD' },
    alerts: 5,
    created: new Date(Date.now() - 1000 * 60 * 60 * 2),
  },
  {
    id: 'CASE-2024-002',
    title: 'Phishing Campaign Investigation',
    status: 'open',
    severity: 'high',
    assignee: { name: 'Jane Smith', initials: 'JS' },
    alerts: 12,
    created: new Date(Date.now() - 1000 * 60 * 60 * 5),
  },
  {
    id: 'CASE-2024-003',
    title: 'Unauthorized Access - Admin Portal',
    status: 'in-progress',
    severity: 'high',
    assignee: { name: 'Mike Johnson', initials: 'MJ' },
    alerts: 3,
    created: new Date(Date.now() - 1000 * 60 * 60 * 8),
  },
  {
    id: 'CASE-2024-004',
    title: 'Data Exfiltration - Cloud Storage',
    status: 'pending',
    severity: 'critical',
    assignee: null,
    alerts: 8,
    created: new Date(Date.now() - 1000 * 60 * 60 * 12),
  },
  {
    id: 'CASE-2024-005',
    title: 'Malware on Endpoint',
    status: 'resolved',
    severity: 'medium',
    assignee: { name: 'Sarah Wilson', initials: 'SW' },
    alerts: 2,
    created: new Date(Date.now() - 1000 * 60 * 60 * 24),
  },
];

const statusStyles: Record<string, string> = {
  open: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  'in-progress': 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  pending: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

export function RecentCases() {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle>Recent Cases</CardTitle>
        <Link to="/cases">
          <Button variant="ghost" size="sm" className="text-primary">
            View All
            <ExternalLink className="w-4 h-4 ml-1" />
          </Button>
        </Link>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[120px]">Case ID</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Assignee</TableHead>
              <TableHead className="text-center">Alerts</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-[50px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cases.map((caseItem) => (
              <TableRow key={caseItem.id} className="group">
                <TableCell className="font-mono text-sm text-primary">
                  <Link
                    to={`/cases/${caseItem.id}`}
                    className="hover:underline"
                  >
                    {caseItem.id}
                  </Link>
                </TableCell>
                <TableCell className="max-w-[300px] truncate">
                  {caseItem.title}
                </TableCell>
                <TableCell>
                  <Badge
                    variant="outline"
                    className={cn(
                      'capitalize',
                      statusStyles[caseItem.status]
                    )}
                  >
                    {caseItem.status.replace('-', ' ')}
                  </Badge>
                </TableCell>
                <TableCell>
                  <Badge
                    variant={
                      caseItem.severity as
                        | 'critical'
                        | 'high'
                        | 'medium'
                        | 'low'
                    }
                  >
                    {caseItem.severity}
                  </Badge>
                </TableCell>
                <TableCell>
                  {caseItem.assignee ? (
                    <div className="flex items-center gap-2">
                      <Avatar className="w-6 h-6">
                        <AvatarFallback className="text-2xs bg-primary/20 text-primary">
                          {caseItem.assignee.initials}
                        </AvatarFallback>
                      </Avatar>
                      <span className="text-sm">{caseItem.assignee.name}</span>
                    </div>
                  ) : (
                    <span className="text-muted-foreground text-sm">
                      Unassigned
                    </span>
                  )}
                </TableCell>
                <TableCell className="text-center font-mono">
                  {caseItem.alerts}
                </TableCell>
                <TableCell className="text-muted-foreground text-sm">
                  {formatRelativeTime(caseItem.created)}
                </TableCell>
                <TableCell>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="opacity-0 group-hover:opacity-100"
                  >
                    <MoreHorizontal className="w-4 h-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
