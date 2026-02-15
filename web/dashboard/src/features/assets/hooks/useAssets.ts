import { useState, useMemo, useCallback } from 'react';
import type { Asset, AssetTreeNode, AssetFilters, AssetGroup } from '../types';

// Mock hierarchical data
const mockGroups: AssetGroup[] = [
  { id: 'dc1', name: 'Data Center 1', assetCount: 12 },
  { id: 'cloud', name: 'Cloud', assetCount: 10 },
  { id: 'remote', name: 'Remote Offices', assetCount: 8 },
];

const mockAssets: Asset[] = [
  // Data Center 1 - Servers
  {
    id: 'asset-001',
    name: 'Production DB Server',
    hostname: 'db-prod-01',
    ipAddresses: ['10.0.1.10'],
    macAddresses: ['00:1A:2B:3C:4D:01'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Ubuntu 22.04 LTS',
    owner: 'Database Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack A1',
    tags: ['production', 'database', 'critical-data'],
    criticality: 'critical',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 5),
    createdAt: new Date('2023-01-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 30),
  },
  {
    id: 'asset-002',
    name: 'Web Server 01',
    hostname: 'web-01',
    ipAddresses: ['10.0.1.20'],
    macAddresses: ['00:1A:2B:3C:4D:02'],
    type: 'server',
    osType: 'linux',
    osVersion: 'CentOS 8',
    owner: 'Web Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack A2',
    tags: ['production', 'web', 'nginx'],
    criticality: 'high',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 2),
    createdAt: new Date('2023-02-10'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60),
  },
  {
    id: 'asset-003',
    name: 'Web Server 02',
    hostname: 'web-02',
    ipAddresses: ['10.0.1.21'],
    macAddresses: ['00:1A:2B:3C:4D:03'],
    type: 'server',
    osType: 'linux',
    osVersion: 'CentOS 8',
    owner: 'Web Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack A2',
    tags: ['production', 'web', 'nginx'],
    criticality: 'high',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 3),
    createdAt: new Date('2023-02-10'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 45),
  },
  {
    id: 'asset-004',
    name: 'Core Switch',
    hostname: 'sw-core-01',
    ipAddresses: ['10.0.1.1'],
    macAddresses: ['00:1A:2B:3C:4D:04'],
    type: 'network_device',
    owner: 'Network Team',
    department: 'IT Operations',
    location: 'Data Center 1 - Rack B1',
    tags: ['network', 'core', 'cisco'],
    criticality: 'critical',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2022-06-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 10),
  },
  {
    id: 'asset-005',
    name: 'Backup Server',
    hostname: 'backup-01',
    ipAddresses: ['10.0.1.50'],
    macAddresses: ['00:1A:2B:3C:4D:05'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Debian 11',
    owner: 'IT Operations',
    department: 'IT Operations',
    location: 'Data Center 1 - Rack C1',
    tags: ['backup', 'storage'],
    criticality: 'high',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 15),
    createdAt: new Date('2023-03-20'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 120),
  },
  // Data Center 1 - More servers
  {
    id: 'asset-006',
    name: 'API Gateway',
    hostname: 'api-gw-01',
    ipAddresses: ['10.0.1.30'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Ubuntu 22.04',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack A3',
    tags: ['api', 'gateway', 'kong'],
    criticality: 'critical',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 4),
    createdAt: new Date('2023-04-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 20),
  },
  {
    id: 'asset-007',
    name: 'Cache Server',
    hostname: 'cache-01',
    ipAddresses: ['10.0.1.40'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Ubuntu 20.04',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack A3',
    tags: ['cache', 'redis'],
    criticality: 'medium',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 6),
    createdAt: new Date('2023-04-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 35),
  },
  {
    id: 'asset-008',
    name: 'Firewall Primary',
    hostname: 'fw-primary',
    ipAddresses: ['10.0.0.1'],
    type: 'network_device',
    owner: 'Security Team',
    department: 'Security',
    location: 'Data Center 1 - Rack B1',
    tags: ['firewall', 'security', 'palo-alto'],
    criticality: 'critical',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 30),
    createdAt: new Date('2022-01-10'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 5),
  },
  {
    id: 'asset-009',
    name: 'Log Aggregator',
    hostname: 'log-agg-01',
    ipAddresses: ['10.0.1.60'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Rocky Linux 9',
    owner: 'Security Team',
    department: 'Security',
    location: 'Data Center 1 - Rack C2',
    tags: ['logging', 'elk', 'siem'],
    criticality: 'high',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 2),
    createdAt: new Date('2023-05-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 15),
  },
  {
    id: 'asset-010',
    name: 'CI/CD Server',
    hostname: 'cicd-01',
    ipAddresses: ['10.0.1.70'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Ubuntu 22.04',
    owner: 'DevOps Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack D1',
    tags: ['cicd', 'jenkins', 'devops'],
    criticality: 'medium',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 8),
    createdAt: new Date('2023-06-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 45),
  },
  {
    id: 'asset-011',
    name: 'Legacy App Server',
    hostname: 'legacy-app-01',
    ipAddresses: ['10.0.1.80'],
    type: 'server',
    osType: 'windows',
    osVersion: 'Windows Server 2016',
    owner: 'Legacy Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack D2',
    tags: ['legacy', 'windows'],
    criticality: 'low',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 30),
    createdAt: new Date('2020-01-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60 * 24),
  },
  {
    id: 'asset-012',
    name: 'Monitoring Server',
    hostname: 'mon-01',
    ipAddresses: ['10.0.1.90'],
    type: 'server',
    osType: 'linux',
    osVersion: 'Ubuntu 22.04',
    owner: 'SRE Team',
    department: 'Engineering',
    location: 'Data Center 1 - Rack C2',
    tags: ['monitoring', 'prometheus', 'grafana'],
    criticality: 'high',
    status: 'active',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2023-03-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 10),
  },
  // Cloud assets
  {
    id: 'asset-013',
    name: 'K8s Worker Node 1',
    hostname: 'k8s-worker-01',
    ipAddresses: ['10.100.1.10'],
    type: 'cloud_instance',
    osType: 'linux',
    osVersion: 'Amazon Linux 2',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['kubernetes', 'aws', 'production'],
    criticality: 'critical',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2023-07-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 5),
  },
  {
    id: 'asset-014',
    name: 'K8s Worker Node 2',
    hostname: 'k8s-worker-02',
    ipAddresses: ['10.100.1.11'],
    type: 'cloud_instance',
    osType: 'linux',
    osVersion: 'Amazon Linux 2',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['kubernetes', 'aws', 'production'],
    criticality: 'critical',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2023-07-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 5),
  },
  {
    id: 'asset-015',
    name: 'K8s Worker Node 3',
    hostname: 'k8s-worker-03',
    ipAddresses: ['10.100.1.12'],
    type: 'cloud_instance',
    osType: 'linux',
    osVersion: 'Amazon Linux 2',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['kubernetes', 'aws', 'production'],
    criticality: 'critical',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 2),
    createdAt: new Date('2023-07-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 8),
  },
  {
    id: 'asset-016',
    name: 'Staging Container',
    hostname: 'stg-app-container',
    ipAddresses: ['10.100.2.10'],
    type: 'container',
    osType: 'linux',
    osVersion: 'Alpine 3.18',
    owner: 'QA Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['staging', 'container', 'docker'],
    criticality: 'low',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 10),
    createdAt: new Date('2023-08-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 30),
  },
  {
    id: 'asset-017',
    name: 'Dev Container Pool',
    hostname: 'dev-containers',
    ipAddresses: ['10.100.3.0/24'],
    type: 'container',
    osType: 'linux',
    osVersion: 'Various',
    owner: 'Engineering',
    department: 'Engineering',
    location: 'AWS us-west-2',
    tags: ['development', 'container'],
    criticality: 'low',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 5),
    createdAt: new Date('2023-06-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 20),
  },
  {
    id: 'asset-018',
    name: 'RDS Primary',
    hostname: 'rds-primary.us-east-1',
    ipAddresses: ['10.100.4.10'],
    type: 'cloud_instance',
    owner: 'Database Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['database', 'rds', 'postgresql'],
    criticality: 'critical',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 30),
    createdAt: new Date('2023-02-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 2),
  },
  {
    id: 'asset-019',
    name: 'RDS Replica',
    hostname: 'rds-replica.us-east-1',
    ipAddresses: ['10.100.4.11'],
    type: 'cloud_instance',
    owner: 'Database Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['database', 'rds', 'postgresql', 'replica'],
    criticality: 'high',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 45),
    createdAt: new Date('2023-02-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 3),
  },
  {
    id: 'asset-020',
    name: 'S3 Gateway',
    hostname: 's3-gw-vpc-endpoint',
    ipAddresses: ['10.100.0.5'],
    type: 'cloud_instance',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'AWS us-east-1',
    tags: ['s3', 'gateway', 'storage'],
    criticality: 'medium',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2023-01-20'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 15),
  },
  {
    id: 'asset-021',
    name: 'Lambda Functions Pool',
    hostname: 'lambda-prod-pool',
    ipAddresses: [],
    type: 'cloud_instance',
    owner: 'Platform Team',
    department: 'Engineering',
    location: 'AWS Multi-Region',
    tags: ['serverless', 'lambda', 'functions'],
    criticality: 'medium',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2023-05-10'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 5),
  },
  {
    id: 'asset-022',
    name: 'CloudFront CDN',
    hostname: 'cdn.company.com',
    ipAddresses: [],
    type: 'cloud_instance',
    owner: 'Web Team',
    department: 'Engineering',
    location: 'AWS Global Edge',
    tags: ['cdn', 'cloudfront', 'edge'],
    criticality: 'high',
    status: 'active',
    parentId: 'cloud',
    lastSeen: new Date(Date.now() - 1000 * 30),
    createdAt: new Date('2022-12-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 10),
  },
  // Remote Offices
  {
    id: 'asset-023',
    name: 'NYC Office Workstation 1',
    hostname: 'NYC-WS-001',
    ipAddresses: ['192.168.10.101'],
    macAddresses: ['00:1A:2B:3C:5D:01'],
    type: 'workstation',
    osType: 'windows',
    osVersion: 'Windows 11 Pro',
    owner: 'John Smith',
    department: 'Sales',
    location: 'NYC Office - Floor 3',
    tags: ['workstation', 'nyc', 'sales'],
    criticality: 'low',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 15),
    createdAt: new Date('2023-09-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60),
  },
  {
    id: 'asset-024',
    name: 'NYC Office Workstation 2',
    hostname: 'NYC-WS-002',
    ipAddresses: ['192.168.10.102'],
    macAddresses: ['00:1A:2B:3C:5D:02'],
    type: 'workstation',
    osType: 'macos',
    osVersion: 'macOS Sonoma',
    owner: 'Jane Doe',
    department: 'Marketing',
    location: 'NYC Office - Floor 2',
    tags: ['workstation', 'nyc', 'marketing'],
    criticality: 'low',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 20),
    createdAt: new Date('2023-09-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 120),
  },
  {
    id: 'asset-025',
    name: 'NYC Office Router',
    hostname: 'NYC-RTR-01',
    ipAddresses: ['192.168.10.1'],
    macAddresses: ['00:1A:2B:3C:5D:FF'],
    type: 'network_device',
    owner: 'IT Operations',
    department: 'IT',
    location: 'NYC Office - Server Room',
    tags: ['router', 'nyc', 'network'],
    criticality: 'high',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 1),
    createdAt: new Date('2022-03-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 30),
  },
  {
    id: 'asset-026',
    name: 'LA Office Workstation 1',
    hostname: 'LA-WS-001',
    ipAddresses: ['192.168.20.101'],
    type: 'workstation',
    osType: 'windows',
    osVersion: 'Windows 11 Pro',
    owner: 'Bob Wilson',
    department: 'Engineering',
    location: 'LA Office',
    tags: ['workstation', 'la', 'engineering'],
    criticality: 'medium',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 45),
    createdAt: new Date('2023-10-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 90),
  },
  {
    id: 'asset-027',
    name: 'LA Office Router',
    hostname: 'LA-RTR-01',
    ipAddresses: ['192.168.20.1'],
    type: 'network_device',
    owner: 'IT Operations',
    department: 'IT',
    location: 'LA Office',
    tags: ['router', 'la', 'network'],
    criticality: 'high',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 2),
    createdAt: new Date('2022-08-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 15),
  },
  {
    id: 'asset-028',
    name: 'Smart Thermostat',
    hostname: 'iot-thermo-01',
    ipAddresses: ['192.168.10.200'],
    type: 'iot',
    owner: 'Facilities',
    department: 'Operations',
    location: 'NYC Office - Floor 1',
    tags: ['iot', 'hvac', 'facilities'],
    criticality: 'low',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 5),
    createdAt: new Date('2023-11-01'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 60),
  },
  {
    id: 'asset-029',
    name: 'Conference Room Display',
    hostname: 'iot-display-01',
    ipAddresses: ['192.168.10.201'],
    type: 'iot',
    osType: 'android',
    osVersion: 'Android 12',
    owner: 'Facilities',
    department: 'Operations',
    location: 'NYC Office - Conference Room A',
    tags: ['iot', 'display', 'conference'],
    criticality: 'low',
    status: 'active',
    parentId: 'remote',
    lastSeen: new Date(Date.now() - 1000 * 60 * 10),
    createdAt: new Date('2023-11-15'),
    updatedAt: new Date(Date.now() - 1000 * 60 * 120),
  },
  {
    id: 'asset-030',
    name: 'Decommissioned Server',
    hostname: 'old-srv-01',
    ipAddresses: ['10.0.99.10'],
    type: 'server',
    osType: 'linux',
    osVersion: 'CentOS 7',
    owner: 'IT Operations',
    department: 'IT',
    location: 'Data Center 1 - Decom Rack',
    tags: ['decommissioned', 'legacy'],
    criticality: 'low',
    status: 'decommissioned',
    parentId: 'dc1',
    lastSeen: new Date(Date.now() - 1000 * 60 * 60 * 24 * 30),
    createdAt: new Date('2019-05-01'),
    updatedAt: new Date('2024-01-15'),
  },
];

export function useAssets() {
  const [assets, setAssets] = useState<Asset[]>(mockAssets);
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());

  const addAsset = useCallback((asset: Omit<Asset, 'id' | 'createdAt' | 'updatedAt'>) => {
    const newAsset: Asset = {
      ...asset,
      id: `asset-${Date.now()}`,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    setAssets(prev => [...prev, newAsset]);
    return newAsset;
  }, []);

  const updateAsset = useCallback((id: string, updates: Partial<Asset>) => {
    setAssets(prev => prev.map(asset =>
      asset.id === id
        ? { ...asset, ...updates, updatedAt: new Date() }
        : asset
    ));
  }, []);

  const deleteAsset = useCallback((id: string) => {
    setAssets(prev => prev.filter(asset => asset.id !== id));
    setSelectedAssets(prev => {
      const newSet = new Set(prev);
      newSet.delete(id);
      return newSet;
    });
  }, []);

  const deleteAssets = useCallback((ids: string[]) => {
    setAssets(prev => prev.filter(asset => !ids.includes(asset.id)));
    setSelectedAssets(new Set());
  }, []);

  const moveAssetsToGroup = useCallback((assetIds: string[], groupId: string) => {
    setAssets(prev => prev.map(asset =>
      assetIds.includes(asset.id)
        ? { ...asset, parentId: groupId, updatedAt: new Date() }
        : asset
    ));
  }, []);

  const updateAssetsCriticality = useCallback((assetIds: string[], criticality: Asset['criticality']) => {
    setAssets(prev => prev.map(asset =>
      assetIds.includes(asset.id)
        ? { ...asset, criticality, updatedAt: new Date() }
        : asset
    ));
  }, []);

  const addTagToAssets = useCallback((assetIds: string[], tag: string) => {
    setAssets(prev => prev.map(asset =>
      assetIds.includes(asset.id) && !asset.tags.includes(tag)
        ? { ...asset, tags: [...asset.tags, tag], updatedAt: new Date() }
        : asset
    ));
  }, []);

  const toggleAssetSelection = useCallback((id: string) => {
    setSelectedAssets(prev => {
      const newSet = new Set(prev);
      if (newSet.has(id)) {
        newSet.delete(id);
      } else {
        newSet.add(id);
      }
      return newSet;
    });
  }, []);

  const selectAllAssets = useCallback((ids: string[]) => {
    setSelectedAssets(new Set(ids));
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedAssets(new Set());
  }, []);

  return {
    assets,
    groups: mockGroups,
    selectedAssets,
    addAsset,
    updateAsset,
    deleteAsset,
    deleteAssets,
    moveAssetsToGroup,
    updateAssetsCriticality,
    addTagToAssets,
    toggleAssetSelection,
    selectAllAssets,
    clearSelection,
  };
}

export function useFilteredAssets(assets: Asset[], filters: AssetFilters) {
  return useMemo(() => {
    return assets.filter(asset => {
      // Search filter
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        const matchesSearch =
          asset.name.toLowerCase().includes(searchLower) ||
          asset.hostname.toLowerCase().includes(searchLower) ||
          asset.ipAddresses.some(ip => ip.includes(searchLower)) ||
          asset.tags.some(tag => tag.toLowerCase().includes(searchLower));
        if (!matchesSearch) return false;
      }

      // Type filter
      if (filters.type !== 'all' && asset.type !== filters.type) {
        return false;
      }

      // Criticality filter
      if (filters.criticality !== 'all' && asset.criticality !== filters.criticality) {
        return false;
      }

      // Status filter
      if (filters.status !== 'all' && asset.status !== filters.status) {
        return false;
      }

      return true;
    });
  }, [assets, filters]);
}

export function useAssetTree(assets: Asset[], groups: AssetGroup[]): AssetTreeNode[] {
  return useMemo(() => {
    const tree: AssetTreeNode[] = groups.map(group => {
      const groupAssets = assets.filter(a => a.parentId === group.id);
      return {
        id: group.id,
        name: group.name,
        type: 'group' as const,
        assetCount: groupAssets.length,
        children: groupAssets.map(asset => ({
          id: asset.id,
          name: asset.name,
          type: asset.type,
          assetCount: 0,
          children: [],
          asset,
        })),
      };
    });

    // Add ungrouped assets
    const ungroupedAssets = assets.filter(a => !a.parentId || !groups.some(g => g.id === a.parentId));
    if (ungroupedAssets.length > 0) {
      tree.push({
        id: 'ungrouped',
        name: 'Ungrouped',
        type: 'group',
        assetCount: ungroupedAssets.length,
        children: ungroupedAssets.map(asset => ({
          id: asset.id,
          name: asset.name,
          type: asset.type,
          assetCount: 0,
          children: [],
          asset,
        })),
      });
    }

    return tree;
  }, [assets, groups]);
}
