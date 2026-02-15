export interface Vendor {
  id: string;
  name: string;
  logoUrl?: string;
}

export interface Product {
  id: string;
  name: string;
  vendorId: string;
  vendor: Vendor;
  version: string;
  category: 'siem' | 'edr' | 'firewall' | 'iam' | 'dlp' | 'ndr' | 'custom';
  status: 'active' | 'inactive' | 'deprecated';
  logFormats: string[];
  parserIds: string[];
  description?: string;
  createdAt: Date;
  updatedAt: Date;
}

export type ProductCategory = Product['category'];
export type ProductStatus = Product['status'];

export interface ProductFormData {
  name: string;
  vendorId: string;
  version: string;
  category: ProductCategory;
  status: ProductStatus;
  logFormats: string[];
  description?: string;
}
