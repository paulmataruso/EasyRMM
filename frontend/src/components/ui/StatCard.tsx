import type { ReactNode } from 'react';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: ReactNode;
  color: string;
  change?: string;
}

export function StatCard({ label, value, icon, color, change }: StatCardProps) {
  return (
    <div
      className="glass rounded-xl p-5 flex items-start gap-4"
      style={{ border: '1px solid var(--color-border)' }}
    >
      <div
        className="w-11 h-11 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: `${color}15`, color }}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
          {label}
        </p>
        <p className="text-2xl font-bold mt-0.5" style={{ color: 'var(--color-text-primary)' }}>
          {value}
        </p>
        {change && (
          <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
            {change}
          </p>
        )}
      </div>
    </div>
  );
}
