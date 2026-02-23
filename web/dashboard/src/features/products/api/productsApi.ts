const BASE_URL = '/api/v1/products';

export interface ApiProduct {
  id: string;
  name: string;
  vendor: string | null;
  product: string | null;
  version: string | null;
  source_type: string;
  status: string;
  // Parser info (embedded in data_sources)
  parser_type: string | null;
  parser_config: Record<string, unknown> | null;
  field_mapping: Record<string, unknown> | null;
}

export interface ProductsQueryParams {
  source_type?: string;
  status?: string;
  search?: string;
}

export async function fetchProducts(params?: ProductsQueryParams): Promise<ApiProduct[]> {
  const url = new URL(BASE_URL, window.location.origin);
  if (params?.source_type && params.source_type !== 'all') {
    url.searchParams.set('source_type', params.source_type);
  }
  if (params?.status && params.status !== 'all') {
    url.searchParams.set('status', params.status);
  }
  if (params?.search) {
    url.searchParams.set('search', params.search);
  }

  const response = await fetch(url.toString());
  if (!response.ok) {
    throw new Error(`Failed to fetch products: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiProduct[]>;
}

export async function fetchProduct(productId: string): Promise<ApiProduct> {
  const response = await fetch(`${BASE_URL}/${productId}`);
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Product not found');
    }
    throw new Error(`Failed to fetch product: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiProduct>;
}

export interface ProductUpdatePayload {
  vendor?: string;
  product?: string;
  version?: string;
  source_type?: string;
  status?: string;
  parser_type?: string | null;
  parser_config?: Record<string, unknown> | null;
}

export async function updateProduct(
  productId: string,
  updates: ProductUpdatePayload,
): Promise<ApiProduct> {
  const response = await fetch(`${BASE_URL}/${productId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Product not found');
    }
    throw new Error(`Failed to update product: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiProduct>;
}
