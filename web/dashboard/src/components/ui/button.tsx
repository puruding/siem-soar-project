import * as React from 'react';
import { Slot } from '@radix-ui/react-slot';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded text-sm font-medium transition-all duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00A4A6] focus-visible:ring-offset-2 focus-visible:ring-offset-[#171D21] disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        default:
          'bg-[#00A4A6] text-white hover:bg-[#008B8D] active:bg-[#007577]',
        destructive:
          'bg-[#DC4E41] text-white hover:bg-[#C23B31] active:bg-[#A82921]',
        outline:
          'border border-[#2D3339] bg-transparent text-[#FFFFFF] hover:bg-[#1F2527] hover:border-[#00A4A6] hover:text-[#00A4A6]',
        secondary:
          'bg-[#1F2527] text-[#FFFFFF] border border-[#2D3339] hover:bg-[#2D3339]',
        ghost: 'text-[#9BA7B4] hover:bg-[#1F2527] hover:text-[#FFFFFF]',
        link: 'text-[#00A4A6] underline-offset-4 hover:underline',
      },
      size: {
        default: 'h-9 px-4 py-2',
        sm: 'h-8 rounded px-3 text-xs',
        lg: 'h-10 rounded px-6',
        icon: 'h-9 w-9',
      },
    },
    defaultVariants: {
      variant: 'default',
      size: 'default',
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : 'button';
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button, buttonVariants };
