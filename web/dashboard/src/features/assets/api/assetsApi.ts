import type { Asset } from '../types';

interface AssetsQueryParams {
  search?: string;
  type?: string;
  criticality?: string;
  status?: string;
}

export async function fetchAssets(params: AssetsQueryParams = {}): Promise<Asset[]> {
  const queryParams = new URLSearchParams();

  if (params.search) queryParams.append('search', params.search);
  if (params.type && params.type !== 'all') queryParams.append('asset_type', params.type);
  if (params.criticality && params.criticality !== 'all') queryParams.append('criticality', params.criticality);
  if (params.status && params.status !== 'all') queryParams.append('status', params.status);

  const url = `/api/v1/assets${queryParams.toString() ? '?' + queryParams.toString() : ''}`;

  try {
    const response = await fetch(url);

    if (!response.ok) {
      throw new Error('Failed to fetch assets');
    }

    const data = await response.json();

    // Map API response to frontend Asset type
    return data.map((item: any) => ({
      id: item.id,
      name: item.display_name || item.asset_id,
      hostname: item.hostname || '',
      ipAddresses: item.ip_addresses || [],
      type: mapAssetType(item.asset_type),
      osType: mapOsType(item.os_family),
      osVersion: item.os_name || '',
      owner: item.owner || '',
      department: item.department || '',
      location: item.location || '',
      tags: item.tags || [],
      criticality: item.criticality?.toLowerCase() || 'medium',
      status: item.status?.toLowerCase() || 'active',
      lastSeen: item.last_seen_at ? new Date(item.last_seen_at) : undefined,
      createdAt: item.created_at ? new Date(item.created_at) : new Date(),
      updatedAt: item.created_at ? new Date(item.created_at) : new Date(),
      // Product/data_source relationship
      dataSourceId: item.data_source_id || undefined,
      productName: item.product_name || undefined,
      vendorName: item.vendor_name || undefined,
      parserType: item.parser_type || undefined,
    }));
  } catch (error) {
    console.error('Failed to fetch assets:', error);
    return [];
  }
}

function mapAssetType(type: string): Asset['type'] {
  const typeMap: Record<string, Asset['type']> = {
    'server': 'server',
    'workstation': 'workstation',
    'firewall': 'network_device',
    'switch': 'network_device',
    'router': 'network_device',
    'proxy': 'network_device',
    'sensor': 'other',
    'container': 'container',
    'cloud': 'cloud_instance',
    'iot': 'iot',
  };
  return typeMap[type] || 'other';
}

function mapOsType(osFamily: string | null): Asset['osType'] | undefined {
  if (!osFamily) return undefined;
  const osMap: Record<string, Asset['osType']> = {
    'windows': 'windows',
    'linux': 'linux',
    'macos': 'macos',
    'ios': 'ios',
    'android': 'android',
  };
  return osMap[osFamily.toLowerCase()] || 'other';
}

export async function fetchAsset(assetId: string): Promise<Asset | null> {
  try {
    const response = await fetch(`/api/v1/assets/${assetId}`);

    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error('Failed to fetch asset');
    }

    const item = await response.json();

    return {
      id: item.id,
      name: item.display_name || item.asset_id,
      hostname: item.hostname || '',
      ipAddresses: item.ip_addresses || [],
      type: mapAssetType(item.asset_type),
      osType: mapOsType(item.os_family),
      osVersion: item.os_name || '',
      owner: item.owner || '',
      department: item.department || '',
      location: item.location || '',
      tags: item.tags || [],
      criticality: item.criticality?.toLowerCase() || 'medium',
      status: item.status?.toLowerCase() || 'active',
      lastSeen: item.last_seen_at ? new Date(item.last_seen_at) : undefined,
      createdAt: item.created_at ? new Date(item.created_at) : new Date(),
      updatedAt: item.created_at ? new Date(item.created_at) : new Date(),
      // Product/data_source relationship
      dataSourceId: item.data_source_id || undefined,
      productName: item.product_name || undefined,
      vendorName: item.vendor_name || undefined,
      parserType: item.parser_type || undefined,
    };
  } catch (error) {
    console.error('Failed to fetch asset:', error);
    return null;
  }
}
