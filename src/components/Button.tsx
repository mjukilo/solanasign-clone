import { ButtonHTMLAttributes } from 'react';
import { clsx } from 'clsx';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary';
}

export const Button = ({ variant = 'secondary', className, ...props }: ButtonProps) => {
  return (
    <button
      className={clsx(
        'w-full px-6 py-3.5 rounded-xl text-sm font-medium transition-all duration-200',
        'disabled:opacity-50 disabled:cursor-not-allowed',
        'transform active:scale-[0.98]',
        variant === 'primary' 
          ? 'text-white shadow-lg shadow-purple-600/20' 
          : 'text-white',
        className
      )}
      {...props}
    />
  );
};