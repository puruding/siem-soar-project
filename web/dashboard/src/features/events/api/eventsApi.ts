import type { EventLog } from '../types';

interface EventsQueryParams {
  assetId?: string;
  startDate?: Date | null;
  endDate?: Date | null;
  page?: number;
  pageSize?: number;
}

interface EventsResponse {
  data: EventLog[];
  total: number;
}

// Map severity from API to EventLog format
function mapSeverity(severity: string): EventLog['security_severity'] {
  const upper = severity?.toUpperCase() || '';
  switch (upper) {
    case 'CRITICAL':
      return 'CRITICAL';
    case 'HIGH':
      return 'HIGH';
    case 'MEDIUM':
      return 'MEDIUM';
    case 'LOW':
      return 'LOW';
    case 'INFO':
    case 'INFORMATIONAL':
      return 'INFORMATIONAL';
    default:
      return 'UNKNOWN';
  }
}

// Format date to yyyy-mm-dd HH:mm:ss
export function formatEventTime(date: Date | string | null | undefined): string {
  if (!date) return '-';
  const d = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(d.getTime())) return '-';

  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export async function fetchEvents(params: EventsQueryParams): Promise<EventsResponse> {
  const { assetId, startDate, endDate, page = 1, pageSize = 10 } = params;

  // Build query parameters
  const queryParams = new URLSearchParams();
  queryParams.set('limit', pageSize.toString());
  queryParams.set('offset', ((page - 1) * pageSize).toString());

  if (assetId && assetId !== 'all') {
    queryParams.set('source', assetId);
  }

  if (startDate) {
    queryParams.set('start_time', startDate.toISOString());
  }

  if (endDate) {
    queryParams.set('end_time', endDate.toISOString());
  }

  try {
    const response = await fetch(`/api/v1/events?${queryParams.toString()}`);

    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }

    const json = await response.json();
    const apiEvents = json.events || [];
    const total = json.total || 0;

    // Map API response to EventLog interface
    const events: EventLog[] = apiEvents.map((event: Record<string, unknown>) => ({
      id: event.id as string,
      tenant_id: (event.tenant_id as string) || 'default',
      timestamp: new Date(event.event_time as string),
      vendor_name: (event.source as string) || '',
      product_name: (event.source_type as string) || '',
      principal_ip: (event.source_ip as string) || '',
      target_ip: (event.dest_ip as string) || '',
      principal_hostname: (event.hostname as string) || '',
      principal_user_id: (event.user as string) || '',
      security_severity: mapSeverity(event.severity as string),
      security_threat_name: (event.message as string) || '',
      mitre_tactics: [],
      mitre_techniques: [],
      raw_log: (event.raw_log as string) || '',
    }));

    return { data: events, total };
  } catch (error) {
    console.error('Failed to fetch events:', error);
    return { data: [], total: 0 };
  }
}

// Fetch available assets for dropdown
export async function fetchAssets(): Promise<{ id: string; name: string }[]> {
  try {
    const response = await fetch('/api/v1/assets');
    if (!response.ok) {
      throw new Error(`API error: ${response.status}`);
    }
    const assets = await response.json();
    return [
      { id: 'all', name: '전체 자산' },
      ...assets.map((asset: Record<string, unknown>) => ({
        id: asset.hostname || asset.id,
        name: asset.name || asset.hostname,
      })),
    ];
  } catch (error) {
    console.error('Failed to fetch assets:', error);
    return [
      { id: 'all', name: '전체 자산' },
    ];
  }
}
