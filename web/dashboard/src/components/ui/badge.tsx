import * as React from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const badgeVariants = cva(
  'inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2',
  {
    variants: {
      variant: {
        default:
          'border-transparent bg-primary text-primary-foreground',
        secondary:
          'border-transparent bg-secondary text-secondary-foreground',
        destructive:
          'border-transparent bg-destructive text-destructive-foreground',
        outline: 'text-foreground',
        critical:
          'border-threat-critical/50 bg-threat-critical/20 text-threat-critical',
        high: 'border-threat-high/50 bg-threat-high/20 text-threat-high',
        medium:
          'border-threat-medium/50 bg-threat-medium/20 text-threat-medium',
        low: 'border-threat-low/50 bg-threat-low/20 text-threat-low',
        info: 'border-threat-info/50 bg-threat-info/20 text-threat-info',
        success:
          'border-neon-green/50 bg-neon-green/20 text-neon-green',
        warning:
          'border-neon-orange/50 bg-neon-orange/20 text-neon-orange',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  }
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
