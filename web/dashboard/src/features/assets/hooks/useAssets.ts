import { useState, useEffect, useMemo, useCallback } from 'react';
import type { Asset, AssetTreeNode, AssetFilters, AssetGroup } from '../types';
import { fetchAssets } from '../api/assetsApi';

// Mock hierarchical data
const mockGroups: AssetGroup[] = [
  { id: 'dc1', name: 'Data Center 1', assetCount: 12 },
  { id: 'cloud', name: 'Cloud', assetCount: 10 },
  { id: 'remote', name: 'Remote Offices', assetCount: 8 },
];

export function useAssets() {
  const [assets, setAssets] = useState<Asset[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedAssets, setSelectedAssets] = useState<Set<string>>(new Set());

  useEffect(() => {
    const loadAssets = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await fetchAssets();
        setAssets(data);
      } catch (err) {
        setError('자산 목록을 불러오는데 실패했습니다.');
      } finally {
        setIsLoading(false);
      }
    };
    loadAssets();
  }, []);

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
    isLoading,
    error,
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
