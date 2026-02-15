// Components
export { ProductList } from './components/ProductList';
export { ProductDetail } from './components/ProductDetail';
export { ProductForm } from './components/ProductForm';
export { VendorFilter } from './components/VendorFilter';

// Hooks
export {
  useProducts,
  useVendors,
  useProduct,
  categoryLabels,
  categoryColors,
  statusLabels,
  statusColors,
} from './hooks/useProducts';

// Types
export type {
  Product,
  Vendor,
  ProductCategory,
  ProductStatus,
  ProductFormData,
} from './types';
