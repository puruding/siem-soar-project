export interface Asset {
  id: string;
  name: string;
  hostname: string;
  ipAddresses: string[];
  macAddresses?: string[];
  type: 'server' | 'workstation' | 'network_device' | 'container' | 'cloud_instance' | 'iot' | 'other';
  osType?: 'windows' | 'linux' | 'macos' | 'ios' | 'android' | 'other';
  osVersion?: string;
  owner?: string;
  department?: string;
  location?: string;
  tags: string[];
  criticality: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'inactive' | 'decommissioned';
  parentId?: string;
  children?: Asset[];
  lastSeen?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface AssetGroup {
  id: string;
  name: string;
  description?: string;
  parentId?: string;
  assetCount: number;
}

export interface AssetTreeNode {
  id: string;
  name: string;
  type: 'group' | Asset['type'];
  children: AssetTreeNode[];
  assetCount: number;
  asset?: Asset;
  isExpanded?: boolean;
}

export interface AssetFilters {
  search: string;
  type: Asset['type'] | 'all';
  criticality: Asset['criticality'] | 'all';
  status: Asset['status'] | 'all';
}

export type ViewMode = 'tree' | 'grid';

export interface ImportField {
  sourceColumn: string;
  targetField: keyof Asset | '';
  preview: string[];
}

export interface ImportPreview {
  headers: string[];
  rows: string[][];
  totalRows: number;
  mapping: ImportField[];
}
