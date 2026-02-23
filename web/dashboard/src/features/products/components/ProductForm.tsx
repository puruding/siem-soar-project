import { useState, useEffect } from 'react';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { cn } from '@/lib/utils';
import type { Product, ProductFormData, ProductCategory, ProductStatus } from '../types';
import { useVendors, categoryLabels, categoryColors, statusLabels, statusColors } from '../hooks/useProducts';

interface ProductFormProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  product?: Product | null;
  onSubmit: (data: ProductFormData) => void;
}

const initialFormData: ProductFormData = {
  name: '',
  vendorId: '',
  version: '',
  category: 'siem',
  status: 'active',
  description: '',
};

const categoryOptions: ProductCategory[] = ['siem', 'edr', 'firewall', 'iam', 'dlp', 'ndr', 'custom'];
const statusOptions: ProductStatus[] = ['active', 'inactive', 'deprecated'];

export function ProductForm({ open, onOpenChange, product, onSubmit }: ProductFormProps) {
  const { vendors } = useVendors();
  const [formData, setFormData] = useState<ProductFormData>(initialFormData);
  const [errors, setErrors] = useState<Partial<Record<keyof ProductFormData, string>>>({});

  const isEditMode = !!product;

  useEffect(() => {
    if (product) {
      setFormData({
        name: product.name,
        vendorId: product.vendorId,
        version: product.version,
        category: product.category,
        status: product.status,
        description: product.description || '',
      });
    } else {
      setFormData(initialFormData);
    }
    setErrors({});
  }, [product, open]);

  const validateForm = (): boolean => {
    const newErrors: Partial<Record<keyof ProductFormData, string>> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Product name is required';
    }

    if (!formData.vendorId) {
      newErrors.vendorId = 'Vendor is required';
    }

    if (!formData.version.trim()) {
      newErrors.version = 'Version is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (validateForm()) {
      onSubmit(formData);
      onOpenChange(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditMode ? 'Edit Product' : 'Create Product'}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Product Name */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Product Name *</label>
            <Input
              value={formData.name}
              onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
              placeholder="e.g., Splunk Enterprise"
              error={!!errors.name}
            />
            {errors.name && (
              <p className="text-xs text-red-400">{errors.name}</p>
            )}
          </div>

          {/* Vendor */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Vendor *</label>
            <Select
              value={formData.vendorId}
              onValueChange={(value) => setFormData((prev) => ({ ...prev, vendorId: value }))}
            >
              <SelectTrigger className={cn(errors.vendorId && 'border-red-400')}>
                <SelectValue placeholder="Select vendor" />
              </SelectTrigger>
              <SelectContent>
                {vendors.map((vendor) => (
                  <SelectItem key={vendor.id} value={vendor.id}>
                    {vendor.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {errors.vendorId && (
              <p className="text-xs text-red-400">{errors.vendorId}</p>
            )}
          </div>

          {/* Version */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Version *</label>
            <Input
              value={formData.version}
              onChange={(e) => setFormData((prev) => ({ ...prev, version: e.target.value }))}
              placeholder="e.g., 9.1.2"
              error={!!errors.version}
            />
            {errors.version && (
              <p className="text-xs text-red-400">{errors.version}</p>
            )}
          </div>

          {/* Category and Status */}
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-sm font-medium">Category</label>
              <Select
                value={formData.category}
                onValueChange={(value: ProductCategory) => setFormData((prev) => ({ ...prev, category: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {categoryOptions.map((category) => (
                    <SelectItem key={category} value={category}>
                      <Badge
                        variant="outline"
                        className={cn('text-xs', categoryColors[category])}
                      >
                        {categoryLabels[category]}
                      </Badge>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium">Status</label>
              <Select
                value={formData.status}
                onValueChange={(value: ProductStatus) => setFormData((prev) => ({ ...prev, status: value }))}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {statusOptions.map((status) => (
                    <SelectItem key={status} value={status}>
                      <Badge
                        variant="outline"
                        className={cn('text-xs', statusColors[status])}
                      >
                        {statusLabels[status]}
                      </Badge>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Description */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Description</label>
            <Textarea
              value={formData.description}
              onChange={(e) => setFormData((prev) => ({ ...prev, description: e.target.value }))}
              placeholder="Enter product description..."
              rows={3}
            />
          </div>

          {/* Parsers note (edit mode only) */}
          {isEditMode && (
            <div className="text-sm text-muted-foreground bg-muted/30 p-3 rounded-md">
              <p>Parsers are managed separately in the product detail view.</p>
            </div>
          )}

          <DialogFooter className="pt-4">
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit">
              {isEditMode ? 'Save Changes' : 'Create Product'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
