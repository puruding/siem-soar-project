import * as React from 'react';
import { cn } from '@/lib/utils';

export interface InputProps
  extends React.InputHTMLAttributes<HTMLInputElement> {
  error?: boolean;
}

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ className, type, error, ...props }, ref) => {
    return (
      <input
        type={type}
        className={cn(
          'flex h-9 w-full rounded border bg-[#1F2527] px-3 py-2 text-sm text-[#FFFFFF]',
          'ring-offset-[#171D21] transition-all duration-150',
          'file:border-0 file:bg-transparent file:text-sm file:font-medium file:text-[#FFFFFF]',
          'placeholder:text-[#9BA7B4]',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-2',
          'disabled:cursor-not-allowed disabled:opacity-50',
          error
            ? 'border-[#DC4E41] focus-visible:ring-[#DC4E41]'
            : 'border-[#2D3339] hover:border-[#00A4A6]/50 focus-visible:border-[#00A4A6] focus-visible:ring-[#00A4A6]',
          className
        )}
        ref={ref}
        {...props}
      />
    );
  }
);
Input.displayName = 'Input';

export { Input };
