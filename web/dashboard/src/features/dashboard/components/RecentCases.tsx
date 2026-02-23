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
import { ExternalLink, MoreHorizontal, Loader2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { formatRelativeTime, cn } from '@/lib/utils';
import { useRecentCases } from '../hooks/useDashboardData';

const statusStyles: Record<string, string> = {
  open: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  investigating: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  'in-progress': 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  pending: 'bg-yellow-500/20 text-yellow-500 border-yellow-500/50',
  resolved: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  closed: 'bg-muted text-muted-foreground border-border',
};

// Get initials from name
function getInitials(name: string): string {
  if (!name) return '??';
  const parts = name.split(' ').filter(p => p.length > 0);
  if (parts.length >= 2 && parts[0]?.[0] && parts[1]?.[0]) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return name.substring(0, 2).toUpperCase();
}

export function RecentCases() {
  const { recentCases, isLoading, error } = useRecentCases({ limit: 5 });

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
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            Failed to load cases
          </div>
        ) : recentCases.length === 0 ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            No cases found
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[120px]">Case ID</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Assignee</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-[50px]"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {recentCases.map((caseItem) => (
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
                        statusStyles[caseItem.status] || statusStyles['open']
                      )}
                    >
                      {caseItem.status.replace('-', ' ')}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={
                        caseItem.severity.toLowerCase() as
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
                            {getInitials(caseItem.assignee)}
                          </AvatarFallback>
                        </Avatar>
                        <span className="text-sm">{caseItem.assignee}</span>
                      </div>
                    ) : (
                      <span className="text-muted-foreground text-sm">
                        Unassigned
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-muted-foreground text-sm">
                    {formatRelativeTime(new Date(caseItem.createdAt))}
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
        )}
      </CardContent>
    </Card>
  );
}
