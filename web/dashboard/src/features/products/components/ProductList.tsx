import { useState } from 'react';
import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Search,
  Filter,
  RefreshCw,
  Plus,
  ChevronRight,
  Building2,
  Trash2,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import type { Product, ProductFormData } from '../types';
import {
  useProducts,
  useVendors,
  categoryLabels,
  categoryColors,
  statusLabels,
  statusColors,
  type ProductFilters,
} from '../hooks/useProducts';
import { ProductDetail } from './ProductDetail';
import { ProductForm } from './ProductForm';
import { VendorFilter } from './VendorFilter';

export function ProductList() {
  // Filter state
  const [filters, setFilters] = useState<ProductFilters>({
    search: '',
    vendorId: 'all',
    category: 'all',
    status: 'all',
  });

  // Selection state
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);
  const [selectedProducts, setSelectedProducts] = useState<Set<string>>(new Set());

  // Form dialog state
  const [isFormOpen, setIsFormOpen] = useState(false);
  const [editingProduct, setEditingProduct] = useState<Product | null>(null);

  // Data hooks
  const { products, isLoading, refetch } = useProducts(filters);
  const { vendors } = useVendors();

  const toggleProductSelection = (productId: string) => {
    const newSelection = new Set(selectedProducts);
    if (newSelection.has(productId)) {
      newSelection.delete(productId);
    } else {
      newSelection.add(productId);
    }
    setSelectedProducts(newSelection);
  };

  const selectAll = () => {
    if (selectedProducts.size === products.length) {
      setSelectedProducts(new Set());
    } else {
      setSelectedProducts(new Set(products.map((p) => p.id)));
    }
  };

  const handleCreateProduct = () => {
    setEditingProduct(null);
    setIsFormOpen(true);
  };

  const handleEditProduct = (product: Product) => {
    setEditingProduct(product);
    setIsFormOpen(true);
  };

  const handleDeleteProduct = (product: Product) => {
    // In a real implementation, this would call an API
    console.log('Deleting product:', product.id);
    setSelectedProduct(null);
  };

  const handleBulkDelete = () => {
    // In a real implementation, this would call an API
    console.log('Deleting products:', Array.from(selectedProducts));
    setSelectedProducts(new Set());
  };

  const handleFormSubmit = (data: ProductFormData) => {
    if (editingProduct) {
      // Update existing product
      console.log('Updating product:', editingProduct.id, data);
    } else {
      // Create new product
      console.log('Creating product:', data);
    }
    refetch();
  };

  const getVendorLogo = (vendorId: string) => {
    const vendor = vendors.find((v) => v.id === vendorId);
    if (vendor?.logoUrl) {
      return (
        <img
          src={vendor.logoUrl}
          alt={vendor.name}
          className="w-8 h-8 object-contain rounded"
          onError={(e) => {
            e.currentTarget.style.display = 'none';
          }}
        />
      );
    }
    return (
      <div className="w-8 h-8 bg-muted/50 rounded flex items-center justify-center">
        <Building2 className="w-4 h-4 text-muted-foreground" />
      </div>
    );
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-display font-bold tracking-tight">
            Products
          </h1>
          <p className="text-muted-foreground">
            Manage security products and integrations
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={refetch} disabled={isLoading}>
            <RefreshCw className={cn('w-4 h-4 mr-2', isLoading && 'animate-spin')} />
            Refresh
          </Button>
          <Button size="sm" onClick={handleCreateProduct}>
            <Plus className="w-4 h-4 mr-2" />
            Create Product
          </Button>
        </div>
      </div>

      <div className="flex gap-6">
        {/* Main content */}
        <div className="flex-1">
          <Card>
            <CardHeader className="pb-4">
              {/* Filters */}
              <div className="flex items-center gap-4 flex-wrap">
                <div className="relative flex-1 min-w-[200px] max-w-sm">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                  <Input
                    placeholder="Search products..."
                    value={filters.search}
                    onChange={(e) => setFilters((prev) => ({ ...prev, search: e.target.value }))}
                    className="pl-10"
                  />
                </div>
                <VendorFilter
                  value={filters.vendorId}
                  onValueChange={(value) => setFilters((prev) => ({ ...prev, vendorId: value }))}
                />
                <Select
                  value={filters.category}
                  onValueChange={(value) => setFilters((prev) => ({ ...prev, category: value }))}
                >
                  <SelectTrigger className="w-[140px]">
                    <SelectValue placeholder="Category" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Categories</SelectItem>
                    <SelectItem value="siem">SIEM</SelectItem>
                    <SelectItem value="edr">EDR</SelectItem>
                    <SelectItem value="firewall">Firewall</SelectItem>
                    <SelectItem value="iam">IAM</SelectItem>
                    <SelectItem value="dlp">DLP</SelectItem>
                    <SelectItem value="ndr">NDR</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
                <Select
                  value={filters.status}
                  onValueChange={(value) => setFilters((prev) => ({ ...prev, status: value }))}
                >
                  <SelectTrigger className="w-[130px]">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="inactive">Inactive</SelectItem>
                    <SelectItem value="deprecated">Deprecated</SelectItem>
                  </SelectContent>
                </Select>
                <Button variant="outline" size="icon">
                  <Filter className="w-4 h-4" />
                </Button>
              </div>

              {/* Bulk actions */}
              {selectedProducts.size > 0 && (
                <div className="flex items-center gap-4 pt-4 border-t border-border mt-4">
                  <span className="text-sm text-muted-foreground">
                    {selectedProducts.size} selected
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="text-red-400 hover:text-red-300 hover:bg-red-400/10"
                    onClick={handleBulkDelete}
                  >
                    <Trash2 className="w-4 h-4 mr-2" />
                    Delete Selected
                  </Button>
                </div>
              )}
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[calc(100vh-320px)]">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-[40px]">
                        <input
                          type="checkbox"
                          checked={
                            selectedProducts.size === products.length &&
                            products.length > 0
                          }
                          onChange={selectAll}
                          className="rounded border-border"
                        />
                      </TableHead>
                      <TableHead className="w-[50px]"></TableHead>
                      <TableHead>Product</TableHead>
                      <TableHead>Vendor</TableHead>
                      <TableHead>Category</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Log Formats</TableHead>
                      <TableHead className="w-[40px]"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {products.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={8} className="text-center py-8">
                          <p className="text-muted-foreground">No products found</p>
                          <Button
                            variant="link"
                            className="mt-2"
                            onClick={handleCreateProduct}
                          >
                            Create your first product
                          </Button>
                        </TableCell>
                      </TableRow>
                    ) : (
                      products.map((product) => (
                        <TableRow
                          key={product.id}
                          className={cn(
                            'cursor-pointer',
                            selectedProduct?.id === product.id && 'bg-primary/5'
                          )}
                          onClick={() => setSelectedProduct(product)}
                        >
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={selectedProducts.has(product.id)}
                              onChange={() => toggleProductSelection(product.id)}
                              className="rounded border-border"
                            />
                          </TableCell>
                          <TableCell>
                            {getVendorLogo(product.vendorId)}
                          </TableCell>
                          <TableCell>
                            <div>
                              <p className="font-medium">{product.name}</p>
                              <p className="text-xs text-muted-foreground font-mono">
                                {product.id}
                              </p>
                            </div>
                          </TableCell>
                          <TableCell className="text-sm">
                            {product.vendor.name}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={cn(
                                'capitalize text-xs',
                                categoryColors[product.category]
                              )}
                            >
                              {categoryLabels[product.category]}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={cn(
                                'capitalize text-xs',
                                statusColors[product.status]
                              )}
                            >
                              {statusLabels[product.status]}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1 max-w-[200px]">
                              {product.logFormats.slice(0, 3).map((format) => (
                                <Badge
                                  key={format}
                                  variant="outline"
                                  className="text-2xs bg-muted/50"
                                >
                                  {format}
                                </Badge>
                              ))}
                              {product.logFormats.length > 3 && (
                                <Badge
                                  variant="outline"
                                  className="text-2xs bg-muted/50"
                                >
                                  +{product.logFormats.length - 3}
                                </Badge>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <ChevronRight className="w-4 h-4 text-muted-foreground" />
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </ScrollArea>
            </CardContent>
          </Card>
        </div>

        {/* Detail panel */}
        {selectedProduct && (
          <ProductDetail
            product={selectedProduct}
            onClose={() => setSelectedProduct(null)}
            onEdit={handleEditProduct}
            onDelete={handleDeleteProduct}
          />
        )}
      </div>

      {/* Create/Edit Form Dialog */}
      <ProductForm
        open={isFormOpen}
        onOpenChange={setIsFormOpen}
        product={editingProduct}
        onSubmit={handleFormSubmit}
      />
    </div>
  );
}
