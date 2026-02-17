/**
 * Group Statistics Utility Functions
 * Calculates statistics for grouped alert events
 */

export interface RelatedEvent {
  id: string;
  timestamp: string;
  sourceIp?: string;
  destinationIp?: string;
  user?: string;
  action?: string;
  status?: string;
  message?: string;
  fields?: Record<string, unknown>;
}

export interface IpCount {
  ip: string;
  count: number;
}

export interface UserCount {
  user: string;
  count: number;
}

export interface TimeDistributionEntry {
  hour: string;
  count: number;
}

export interface PeakTime {
  start: string;
  end: string;
  count: number;
}

export interface GroupStatistics {
  uniqueSourceIPs: IpCount[];
  uniqueDestinationIPs: IpCount[];
  uniqueUsers: UserCount[];
  timeDistribution: TimeDistributionEntry[];
  peakTime: PeakTime | null;
  totalEvents: number;
  uniqueActions: { action: string; count: number }[];
  uniqueStatuses: { status: string; count: number }[];
}

/**
 * Count occurrences and return sorted array by count (descending)
 */
function countOccurrences<T extends string | undefined>(
  values: T[]
): { value: string; count: number }[] {
  const counts = new Map<string, number>();

  values.forEach((val) => {
    if (val) {
      counts.set(val, (counts.get(val) || 0) + 1);
    }
  });

  return Array.from(counts.entries())
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count);
}

/**
 * Calculate time distribution by hour
 */
function calculateTimeDistribution(events: RelatedEvent[]): TimeDistributionEntry[] {
  const hourCounts = new Map<string, number>();

  events.forEach((event) => {
    const date = new Date(event.timestamp);
    const hour = date.toISOString().slice(0, 13) + ':00'; // YYYY-MM-DDTHH:00
    hourCounts.set(hour, (hourCounts.get(hour) || 0) + 1);
  });

  return Array.from(hourCounts.entries())
    .map(([hour, count]) => ({ hour, count }))
    .sort((a, b) => a.hour.localeCompare(b.hour));
}

/**
 * Find peak time window (5-minute intervals)
 */
function findPeakTime(events: RelatedEvent[]): PeakTime | null {
  if (events.length === 0) return null;

  // Group by 5-minute intervals
  const intervalCounts = new Map<string, { events: RelatedEvent[]; count: number }>();

  events.forEach((event) => {
    const date = new Date(event.timestamp);
    const minutes = Math.floor(date.getMinutes() / 5) * 5;
    const interval = new Date(date);
    interval.setMinutes(minutes, 0, 0);
    const key = interval.toISOString();

    if (!intervalCounts.has(key)) {
      intervalCounts.set(key, { events: [], count: 0 });
    }
    const entry = intervalCounts.get(key)!;
    entry.events.push(event);
    entry.count++;
  });

  // Find the interval with the most events
  let maxInterval: { start: string; end: string; count: number } | null = null;

  intervalCounts.forEach((entry, key) => {
    if (!maxInterval || entry.count > maxInterval.count) {
      const start = new Date(key);
      const end = new Date(start.getTime() + 5 * 60 * 1000);
      maxInterval = {
        start: start.toISOString(),
        end: end.toISOString(),
        count: entry.count,
      };
    }
  });

  return maxInterval;
}

/**
 * Calculate comprehensive group statistics from related events
 */
export function calculateGroupStatistics(events: RelatedEvent[]): GroupStatistics {
  const sourceIPs = countOccurrences(events.map((e) => e.sourceIp));
  const destinationIPs = countOccurrences(events.map((e) => e.destinationIp));
  const users = countOccurrences(events.map((e) => e.user));
  const actions = countOccurrences(events.map((e) => e.action));
  const statuses = countOccurrences(events.map((e) => e.status));

  return {
    uniqueSourceIPs: sourceIPs.map(({ value, count }) => ({ ip: value, count })),
    uniqueDestinationIPs: destinationIPs.map(({ value, count }) => ({ ip: value, count })),
    uniqueUsers: users.map(({ value, count }) => ({ user: value, count })),
    timeDistribution: calculateTimeDistribution(events),
    peakTime: findPeakTime(events),
    totalEvents: events.length,
    uniqueActions: actions.map(({ value, count }) => ({ action: value, count })),
    uniqueStatuses: statuses.map(({ value, count }) => ({ status: value, count })),
  };
}

/**
 * Format duration between two timestamps
 */
export function formatDurationBetween(start: string, end: string): string {
  const startDate = new Date(start);
  const endDate = new Date(end);
  const diffMs = endDate.getTime() - startDate.getTime();

  if (diffMs < 0) return '0s';

  const seconds = Math.floor(diffMs / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  if (days > 0) {
    return `${days}d ${hours % 24}h ${minutes % 60}m`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes % 60}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

/**
 * Format timestamp for display in event timeline
 */
export function formatEventTime(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

/**
 * Format full timestamp with date
 */
export function formatFullTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}
