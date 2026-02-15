import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { useVendors } from '../hooks/useProducts';
import { Building2 } from 'lucide-react';

interface VendorFilterProps {
  value: string;
  onValueChange: (value: string) => void;
}

export function VendorFilter({ value, onValueChange }: VendorFilterProps) {
  const { vendors, isLoading } = useVendors();

  return (
    <Select value={value} onValueChange={onValueChange} disabled={isLoading}>
      <SelectTrigger className="w-[180px]">
        <SelectValue placeholder="Vendor" />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value="all">
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-muted-foreground" />
            <span>All Vendors</span>
          </div>
        </SelectItem>
        {vendors.map((vendor) => (
          <SelectItem key={vendor.id} value={vendor.id}>
            <div className="flex items-center gap-2">
              {vendor.logoUrl ? (
                <img
                  src={vendor.logoUrl}
                  alt={vendor.name}
                  className="w-4 h-4 object-contain"
                  onError={(e) => {
                    // Fallback to icon if image fails to load
                    e.currentTarget.style.display = 'none';
                  }}
                />
              ) : (
                <Building2 className="w-4 h-4 text-muted-foreground" />
              )}
              <span>{vendor.name}</span>
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
