import { Search, Bell } from 'lucide-react';

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export function Header({ title, subtitle }: HeaderProps) {
  return (
    <header
      className="flex items-center justify-between px-8 py-5 border-b"
      style={{ borderColor: 'var(--color-border)' }}
    >
      <div>
        <h2 className="text-xl font-semibold" style={{ color: 'var(--color-text-primary)' }}>
          {title}
        </h2>
        {subtitle && (
          <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
            {subtitle}
          </p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {/* Search */}
        <div className="relative">
          <Search
            size={16}
            className="absolute left-3 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--color-text-muted)' }}
          />
          <input
            type="text"
            placeholder="Search devices, scripts..."
            className="pl-9 pr-4 py-2 text-sm rounded-lg w-64 focus:outline-none focus:ring-2"
            style={{
              background: 'var(--color-bg-tertiary)',
              color: 'var(--color-text-primary)',
              border: '1px solid var(--color-border)',
              '--tw-ring-color': 'var(--color-border-focus)',
            } as React.CSSProperties}
          />
        </div>

        {/* Notifications */}
        <button
          className="relative p-2.5 rounded-lg transition-colors duration-150"
          style={{
            background: 'var(--color-bg-tertiary)',
            border: '1px solid var(--color-border)',
            color: 'var(--color-text-secondary)',
          }}
        >
          <Bell size={18} />
          <span
            className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full"
            style={{ background: 'var(--color-status-alert)' }}
          />
        </button>
      </div>
    </header>
  );
}
