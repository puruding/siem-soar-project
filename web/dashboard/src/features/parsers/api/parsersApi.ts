const BASE_URL = '/api/v1/parsers';

export interface ApiParser {
  id: string;
  data_source_id: string;
  name: string;
  parser_type: string;
  pattern: string | null;
  parser_config: Record<string, unknown> | null;
  field_mapping: Record<string, unknown> | null;
  sample_logs: string[] | null;
  status: string;
  version: number;
  created_at: string | null;
  updated_at: string | null;
  product_name: string | null;
  vendor_name: string | null;
}

export interface ParsersQueryParams {
  data_source_id?: string;
  parser_type?: string;
  status?: string;
  search?: string;
}

export async function fetchParsers(params?: ParsersQueryParams): Promise<ApiParser[]> {
  const url = new URL(BASE_URL, window.location.origin);
  if (params?.data_source_id) {
    url.searchParams.set('data_source_id', params.data_source_id);
  }
  if (params?.parser_type && params.parser_type !== 'all') {
    url.searchParams.set('parser_type', params.parser_type);
  }
  if (params?.status && params.status !== 'all') {
    url.searchParams.set('status', params.status);
  }
  if (params?.search) {
    url.searchParams.set('search', params.search);
  }

  const response = await fetch(url.toString());
  if (!response.ok) {
    throw new Error(`Failed to fetch parsers: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiParser[]>;
}

export async function fetchParser(parserId: string): Promise<ApiParser> {
  const response = await fetch(`${BASE_URL}/${parserId}`);
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Parser not found');
    }
    throw new Error(`Failed to fetch parser: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiParser>;
}

export type ParserCreatePayload = Omit<ApiParser, 'id' | 'version' | 'created_at' | 'updated_at' | 'product_name' | 'vendor_name'>;

export async function createParser(parser: ParserCreatePayload): Promise<ApiParser> {
  const response = await fetch(BASE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(parser),
  });
  if (!response.ok) {
    throw new Error(`Failed to create parser: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiParser>;
}

export type ParserUpdatePayload = Partial<Pick<ApiParser, 'name' | 'parser_type' | 'pattern' | 'parser_config' | 'field_mapping' | 'sample_logs' | 'status'>>;

export async function updateParser(parserId: string, updates: ParserUpdatePayload): Promise<ApiParser> {
  const response = await fetch(`${BASE_URL}/${parserId}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(updates),
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Parser not found');
    }
    throw new Error(`Failed to update parser: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiParser>;
}

export async function deleteParser(parserId: string): Promise<void> {
  const response = await fetch(`${BASE_URL}/${parserId}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Parser not found');
    }
    throw new Error(`Failed to delete parser: ${response.status} ${response.statusText}`);
  }
}

export async function fetchProductParsers(productId: string): Promise<ApiParser[]> {
  const response = await fetch(`/api/v1/products/${productId}/parsers`);
  if (!response.ok) {
    throw new Error(`Failed to fetch product parsers: ${response.status} ${response.statusText}`);
  }
  return response.json() as Promise<ApiParser[]>;
}
