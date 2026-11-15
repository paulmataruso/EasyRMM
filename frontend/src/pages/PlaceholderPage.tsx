import { Construction } from 'lucide-react';

interface PlaceholderPageProps {
  name: string;
}

export function PlaceholderPage({ name }: PlaceholderPageProps) {
  return (
    <div className="flex flex-col items-center justify-center py-24">
      <Construction size={48} className="mb-4" style={{ color: 'var(--color-text-muted)' }} />
      <h2 className="text-lg font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
        {name}
      </h2>
      <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
        This section is under development
      </p>
    </div>
  );
}
