import { useState, useMemo } from 'react';
import type { Product, Vendor, ProductCategory, ProductStatus } from '../types';

// Mock vendors data - using a map for type-safe lookups
const vendorSplunk: Vendor = { id: 'v1', name: 'Splunk', logoUrl: '/vendors/splunk.svg' };
const vendorCrowdStrike: Vendor = { id: 'v2', name: 'CrowdStrike', logoUrl: '/vendors/crowdstrike.svg' };
const vendorPaloAlto: Vendor = { id: 'v3', name: 'Palo Alto Networks', logoUrl: '/vendors/paloalto.svg' };
const vendorMicrosoft: Vendor = { id: 'v4', name: 'Microsoft', logoUrl: '/vendors/microsoft.svg' };
const vendorElastic: Vendor = { id: 'v5', name: 'Elastic', logoUrl: '/vendors/elastic.svg' };
const vendorOkta: Vendor = { id: 'v6', name: 'Okta', logoUrl: '/vendors/okta.svg' };
const vendorFortinet: Vendor = { id: 'v7', name: 'Fortinet', logoUrl: '/vendors/fortinet.svg' };
const vendorDarktrace: Vendor = { id: 'v8', name: 'Darktrace', logoUrl: '/vendors/darktrace.svg' };
const vendorSymantec: Vendor = { id: 'v9', name: 'Symantec', logoUrl: '/vendors/symantec.svg' };
const vendorCustom: Vendor = { id: 'v10', name: 'Custom', logoUrl: undefined };

const mockVendors: Vendor[] = [
  vendorSplunk,
  vendorCrowdStrike,
  vendorPaloAlto,
  vendorMicrosoft,
  vendorElastic,
  vendorOkta,
  vendorFortinet,
  vendorDarktrace,
  vendorSymantec,
  vendorCustom,
];

// Mock products data
const mockProducts: Product[] = [
  {
    id: 'prod-001',
    name: 'Splunk Enterprise',
    vendorId: 'v1',
    vendor: vendorSplunk,
    version: '9.1.2',
    category: 'siem',
    status: 'active',
    logFormats: ['JSON', 'Syslog', 'CEF'],
    parserIds: ['parser-001', 'parser-007'],
    description: 'Enterprise SIEM platform for security monitoring and analytics.',
    createdAt: new Date('2024-01-15'),
    updatedAt: new Date('2024-02-10'),
  },
  {
    id: 'prod-002',
    name: 'CrowdStrike Falcon',
    vendorId: 'v2',
    vendor: vendorCrowdStrike,
    version: '6.45.0',
    category: 'edr',
    status: 'active',
    logFormats: ['JSON', 'CEF'],
    parserIds: ['parser-009'],
    description: 'Cloud-native endpoint detection and response platform.',
    createdAt: new Date('2024-01-20'),
    updatedAt: new Date('2024-02-08'),
  },
  {
    id: 'prod-003',
    name: 'Palo Alto Cortex XDR',
    vendorId: 'v3',
    vendor: vendorPaloAlto,
    version: '3.7.1',
    category: 'edr',
    status: 'active',
    logFormats: ['JSON', 'LEEF'],
    parserIds: ['parser-004'],
    description: 'Extended detection and response platform.',
    createdAt: new Date('2024-01-25'),
    updatedAt: new Date('2024-02-05'),
  },
  {
    id: 'prod-004',
    name: 'Microsoft Sentinel',
    vendorId: 'v4',
    vendor: vendorMicrosoft,
    version: '2024.1',
    category: 'siem',
    status: 'active',
    logFormats: ['JSON', 'CEF', 'Syslog'],
    parserIds: ['parser-003'],
    description: 'Cloud-native SIEM and SOAR solution.',
    createdAt: new Date('2024-02-01'),
    updatedAt: new Date('2024-02-12'),
  },
  {
    id: 'prod-005',
    name: 'Elastic Security',
    vendorId: 'v5',
    vendor: vendorElastic,
    version: '8.12.0',
    category: 'siem',
    status: 'active',
    logFormats: ['JSON', 'ECS'],
    parserIds: ['parser-002'],
    description: 'Open SIEM solution built on Elasticsearch.',
    createdAt: new Date('2024-01-18'),
    updatedAt: new Date('2024-02-09'),
  },
  {
    id: 'prod-006',
    name: 'Okta Identity Cloud',
    vendorId: 'v6',
    vendor: vendorOkta,
    version: '2024.01',
    category: 'iam',
    status: 'active',
    logFormats: ['JSON'],
    parserIds: ['parser-010'],
    description: 'Identity and access management platform.',
    createdAt: new Date('2024-01-10'),
    updatedAt: new Date('2024-02-01'),
  },
  {
    id: 'prod-007',
    name: 'FortiGate NGFW',
    vendorId: 'v7',
    vendor: vendorFortinet,
    version: '7.4.2',
    category: 'firewall',
    status: 'active',
    logFormats: ['Syslog', 'CEF'],
    parserIds: ['parser-007'],
    description: 'Next-generation firewall with advanced threat protection.',
    createdAt: new Date('2024-01-05'),
    updatedAt: new Date('2024-02-03'),
  },
  {
    id: 'prod-008',
    name: 'Palo Alto NGFW',
    vendorId: 'v3',
    vendor: vendorPaloAlto,
    version: '11.1.0',
    category: 'firewall',
    status: 'active',
    logFormats: ['Syslog', 'LEEF', 'CEF'],
    parserIds: ['parser-004'],
    description: 'Enterprise next-generation firewall.',
    createdAt: new Date('2024-01-08'),
    updatedAt: new Date('2024-02-07'),
  },
  {
    id: 'prod-009',
    name: 'Darktrace Enterprise',
    vendorId: 'v8',
    vendor: vendorDarktrace,
    version: '6.1',
    category: 'ndr',
    status: 'active',
    logFormats: ['JSON'],
    parserIds: ['parser-002'],
    description: 'AI-powered network detection and response.',
    createdAt: new Date('2024-02-05'),
    updatedAt: new Date('2024-02-11'),
  },
  {
    id: 'prod-010',
    name: 'Symantec DLP',
    vendorId: 'v9',
    vendor: vendorSymantec,
    version: '15.8',
    category: 'dlp',
    status: 'inactive',
    logFormats: ['Syslog', 'CEF'],
    parserIds: ['parser-003'],
    description: 'Enterprise data loss prevention solution.',
    createdAt: new Date('2023-12-01'),
    updatedAt: new Date('2024-01-15'),
  },
  {
    id: 'prod-011',
    name: 'Microsoft Defender for Endpoint',
    vendorId: 'v4',
    vendor: vendorMicrosoft,
    version: '4.18',
    category: 'edr',
    status: 'active',
    logFormats: ['JSON', 'CEF'],
    parserIds: ['parser-003', 'parser-009'],
    description: 'Enterprise endpoint security platform.',
    createdAt: new Date('2024-01-22'),
    updatedAt: new Date('2024-02-10'),
  },
  {
    id: 'prod-012',
    name: 'Custom Log Collector',
    vendorId: 'v10',
    vendor: vendorCustom,
    version: '1.0.0',
    category: 'custom',
    status: 'deprecated',
    logFormats: ['JSON', 'CSV'],
    parserIds: ['parser-008'],
    description: 'Custom internal log collection tool.',
    createdAt: new Date('2023-06-01'),
    updatedAt: new Date('2023-12-15'),
  },
];

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
  const [isLoading] = useState(false);
  const [error] = useState<Error | null>(null);

  const filteredProducts = useMemo(() => {
    if (!filters) return mockProducts;

    return mockProducts.filter((product) => {
      // Search filter
      if (filters.search) {
        const searchLower = filters.search.toLowerCase();
        const matchesSearch =
          product.name.toLowerCase().includes(searchLower) ||
          product.id.toLowerCase().includes(searchLower) ||
          product.vendor.name.toLowerCase().includes(searchLower) ||
          product.description?.toLowerCase().includes(searchLower);
        if (!matchesSearch) return false;
      }

      // Vendor filter
      if (filters.vendorId && filters.vendorId !== 'all') {
        if (product.vendorId !== filters.vendorId) return false;
      }

      // Category filter
      if (filters.category && filters.category !== 'all') {
        if (product.category !== filters.category) return false;
      }

      // Status filter
      if (filters.status && filters.status !== 'all') {
        if (product.status !== filters.status) return false;
      }

      return true;
    });
  }, [filters]);

  const refetch = () => {
    // In a real implementation, this would trigger a re-fetch
    console.log('Refetching products...');
  };

  return {
    products: filteredProducts,
    isLoading,
    error,
    refetch,
  };
}

export function useVendors(): UseVendorsResult {
  const [isLoading] = useState(false);
  const [error] = useState<Error | null>(null);

  return {
    vendors: mockVendors,
    isLoading,
    error,
  };
}

export function useProduct(productId: string): {
  product: Product | undefined;
  isLoading: boolean;
  error: Error | null;
} {
  const [isLoading] = useState(false);
  const [error] = useState<Error | null>(null);

  const product = mockProducts.find((p) => p.id === productId);

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
