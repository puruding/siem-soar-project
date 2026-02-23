import { useState, useEffect, useMemo, useCallback } from 'react';
import type { Product, Vendor, ProductCategory, ProductStatus } from '../types';
import { fetchProducts, fetchProduct, type ApiProduct } from '../api/productsApi';

// Map API source_type to ProductCategory
function mapSourceTypeToCategory(sourceType: string): ProductCategory {
  const lower = sourceType.toLowerCase();
  if (lower.includes('firewall') || lower.includes('fw')) return 'firewall';
  if (lower.includes('edr') || lower.includes('endpoint')) return 'edr';
  if (lower.includes('siem')) return 'siem';
  if (lower.includes('iam') || lower.includes('identity')) return 'iam';
  if (lower.includes('dlp')) return 'dlp';
  if (lower.includes('ndr') || lower.includes('network')) return 'ndr';
  return 'custom';
}

// Map API status to ProductStatus
function mapStatus(status: string): ProductStatus {
  const lower = status.toLowerCase();
  if (lower === 'active') return 'active';
  if (lower === 'inactive') return 'inactive';
  if (lower === 'deprecated') return 'deprecated';
  return 'inactive';
}

// Convert API product to frontend Product type
function mapApiProductToProduct(apiProduct: ApiProduct): Product {
  const vendorName = apiProduct.vendor ?? 'Unknown';
  const vendor: Vendor = {
    id: vendorName.toLowerCase().replace(/\s+/g, '-'),
    name: vendorName,
    logoUrl: undefined,
  };

  return {
    id: apiProduct.id,
    name: apiProduct.name,
    vendorId: vendor.id,
    vendor,
    version: apiProduct.version ?? '1.0.0',
    category: mapSourceTypeToCategory(apiProduct.source_type),
    status: mapStatus(apiProduct.status),
    logFormats: apiProduct.parser_type ? [apiProduct.parser_type] : [],
    parserIds: [],
    description: apiProduct.product ? `${vendorName} ${apiProduct.product}` : undefined,
    createdAt: new Date(),
    updatedAt: new Date(),
    // Parser info
    parserType: apiProduct.parser_type ?? undefined,
    parserConfig: apiProduct.parser_config ?? undefined,
    fieldMapping: apiProduct.field_mapping ?? undefined,
  };
}

export interface UseProductsResult {
  products: Product[];
  isLoading: boolean;
  error: Error | null;
  refetch: () => void;
}

export interface UseVendorsResult {
  vendors: Vendor[];
  isLoading: boolean;
  error: Error | null;
}

export interface ProductFilters {
  search: string;
  vendorId: string;
  category: string;
  status: string;
}

export function useProducts(filters?: ProductFilters): UseProductsResult {
  const [allProducts, setAllProducts] = useState<Product[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [fetchTrigger, setFetchTrigger] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    fetchProducts()
      .then((data) => {
        if (!cancelled) {
          setAllProducts(data.map(mapApiProductToProduct));
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error('Failed to fetch products'));
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [fetchTrigger]);

  const filteredProducts = useMemo(() => {
    if (!filters) return allProducts;

    return allProducts.filter((product) => {
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        const matchesSearch =
          product.name.toLowerCase().includes(searchLower) ||
          product.id.toLowerCase().includes(searchLower) ||
          product.vendor.name.toLowerCase().includes(searchLower) ||
          product.description?.toLowerCase().includes(searchLower);
        if (!matchesSearch) return false;
      }

      if (filters.vendorId && filters.vendorId !== 'all') {
        if (product.vendorId !== filters.vendorId) return false;
      }

      if (filters.category && filters.category !== 'all') {
        if (product.category !== filters.category) return false;
      }

      if (filters.status && filters.status !== 'all') {
        if (product.status !== filters.status) return false;
      }

      return true;
    });
  }, [allProducts, filters]);

  const refetch = useCallback(() => {
    setFetchTrigger((n) => n + 1);
  }, []);

  return {
    products: filteredProducts,
    isLoading,
    error,
    refetch,
  };
}

export function useVendors(): UseVendorsResult {
  const [vendors, setVendors] = useState<Vendor[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);

    fetchProducts()
      .then((data) => {
        if (!cancelled) {
          const vendorMap = new Map<string, Vendor>();
          data.forEach((p) => {
            const vendorName = p.vendor ?? 'Unknown';
            const vendorId = vendorName.toLowerCase().replace(/\s+/g, '-');
            if (!vendorMap.has(vendorId)) {
              vendorMap.set(vendorId, { id: vendorId, name: vendorName, logoUrl: undefined });
            }
          });
          setVendors(Array.from(vendorMap.values()));
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error('Failed to fetch vendors'));
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return {
    vendors,
    isLoading,
    error,
  };
}

export function useProduct(productId: string): {
  product: Product | undefined;
  isLoading: boolean;
  error: Error | null;
} {
  const [product, setProduct] = useState<Product | undefined>(undefined);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    if (!productId) {
      setIsLoading(false);
      return;
    }

    let cancelled = false;
    setIsLoading(true);
    setError(null);

    fetchProduct(productId)
      .then((data) => {
        if (!cancelled) {
          setProduct(mapApiProductToProduct(data));
          setIsLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err : new Error('Failed to fetch product'));
          setIsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [productId]);

  return {
    product,
    isLoading,
    error,
  };
}

// Category display utilities
export const categoryLabels: Record<ProductCategory, string> = {
  siem: 'SIEM',
  edr: 'EDR',
  firewall: 'Firewall',
  iam: 'IAM',
  dlp: 'DLP',
  ndr: 'NDR',
  custom: 'Custom',
};

export const categoryColors: Record<ProductCategory, string> = {
  siem: 'bg-neon-cyan/20 text-neon-cyan border-neon-cyan/50',
  edr: 'bg-neon-pink/20 text-neon-pink border-neon-pink/50',
  firewall: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  iam: 'bg-neon-blue/20 text-neon-blue border-neon-blue/50',
  dlp: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  ndr: 'bg-purple-500/20 text-purple-400 border-purple-500/50',
  custom: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
};

export const statusLabels: Record<ProductStatus, string> = {
  active: 'Active',
  inactive: 'Inactive',
  deprecated: 'Deprecated',
};

export const statusColors: Record<ProductStatus, string> = {
  active: 'bg-neon-green/20 text-neon-green border-neon-green/50',
  inactive: 'bg-neon-orange/20 text-neon-orange border-neon-orange/50',
  deprecated: 'bg-gray-500/20 text-gray-400 border-gray-500/50',
};
