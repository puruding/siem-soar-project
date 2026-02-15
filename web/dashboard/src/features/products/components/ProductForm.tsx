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
import { X } from 'lucide-react';
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
  logFormats: [],
  description: '',
};

const categoryOptions: ProductCategory[] = ['siem', 'edr', 'firewall', 'iam', 'dlp', 'ndr', 'custom'];
const statusOptions: ProductStatus[] = ['active', 'inactive', 'deprecated'];
const commonLogFormats = ['JSON', 'Syslog', 'CEF', 'LEEF', 'CSV', 'XML', 'ECS'];

export function ProductForm({ open, onOpenChange, product, onSubmit }: ProductFormProps) {
  const { vendors } = useVendors();
  const [formData, setFormData] = useState<ProductFormData>(initialFormData);
  const [newLogFormat, setNewLogFormat] = useState('');
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
        logFormats: [...product.logFormats],
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

    if (formData.logFormats.length === 0) {
      newErrors.logFormats = 'At least one log format is required';
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

  const addLogFormat = (format: string) => {
    const trimmedFormat = format.trim().toUpperCase();
    if (trimmedFormat && !formData.logFormats.includes(trimmedFormat)) {
      setFormData((prev) => ({
        ...prev,
        logFormats: [...prev.logFormats, trimmedFormat],
      }));
      setNewLogFormat('');
    }
  };

  const removeLogFormat = (format: string) => {
    setFormData((prev) => ({
      ...prev,
      logFormats: prev.logFormats.filter((f) => f !== format),
    }));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      addLogFormat(newLogFormat);
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

          {/* Log Formats */}
          <div className="space-y-2">
            <label className="text-sm font-medium">Log Formats *</label>
            <div className="flex flex-wrap gap-2 mb-2">
              {formData.logFormats.map((format) => (
                <Badge
                  key={format}
                  variant="outline"
                  className="bg-primary/10 text-primary border-primary/30 pr-1"
                >
                  {format}
                  <button
                    type="button"
                    onClick={() => removeLogFormat(format)}
                    className="ml-1 hover:bg-primary/20 rounded p-0.5"
                  >
                    <X className="w-3 h-3" />
                  </button>
                </Badge>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                value={newLogFormat}
                onChange={(e) => setNewLogFormat(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Add log format..."
                className="flex-1"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => addLogFormat(newLogFormat)}
                disabled={!newLogFormat.trim()}
              >
                Add
              </Button>
            </div>
            <div className="flex flex-wrap gap-1 mt-2">
              <span className="text-xs text-muted-foreground mr-1">Quick add:</span>
              {commonLogFormats
                .filter((f) => !formData.logFormats.includes(f))
                .slice(0, 5)
                .map((format) => (
                  <button
                    key={format}
                    type="button"
                    onClick={() => addLogFormat(format)}
                    className="text-xs text-primary hover:underline"
                  >
                    +{format}
                  </button>
                ))}
            </div>
            {errors.logFormats && (
              <p className="text-xs text-red-400">{errors.logFormats}</p>
            )}
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
