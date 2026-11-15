import {
  LayoutDashboard,
  Building2,
  Monitor,
  ScrollText,
  Play,
  Package,
  Activity,
  Bell,
  FileBarChart,
  Settings,
  Shield,
  LogOut,
} from 'lucide-react';

interface NavItem {
  label: string;
  icon: React.ElementType;
  path: string;
}

const navItems: NavItem[] = [
  { label: 'Dashboard', icon: LayoutDashboard, path: '/' },
  { label: 'Organizations', icon: Building2, path: '/organizations' },
  { label: 'Devices', icon: Monitor, path: '/devices' },
  { label: 'Scripts', icon: ScrollText, path: '/scripts' },
  { label: 'Jobs', icon: Play, path: '/jobs' },
  { label: 'Software', icon: Package, path: '/software' },
  { label: 'Monitoring', icon: Activity, path: '/monitoring' },
  { label: 'Alerts', icon: Bell, path: '/alerts' },
  { label: 'Reports', icon: FileBarChart, path: '/reports' },
  { label: 'Settings', icon: Settings, path: '/settings' },
];

interface SidebarProps {
  currentPath: string;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  user?: { display_name: string; role: string } | null;
}

export function Sidebar({ currentPath, onNavigate, onLogout, user }: SidebarProps) {
  return (
    <aside
      className="flex flex-col w-64 shrink-0 h-screen sticky top-0 border-r"
      style={{
        background: 'var(--color-bg-secondary)',
        borderColor: 'var(--color-border)',
      }}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-5 py-5">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
        >
          <Shield size={20} className="text-white" />
        </div>
        <div>
          <h1 className="text-base font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            EasyRMM
          </h1>
          <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
            Remote Management
          </p>
        </div>
      </div>

      {/* Divider */}
      <div className="mx-4 mb-2" style={{ borderTop: '1px solid var(--color-border)' }} />

      {/* Navigation */}
      <nav className="flex-1 px-3 space-y-0.5 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = currentPath === item.path ||
            (item.path !== '/' && currentPath.startsWith(item.path));
          return (
            <button
              key={item.path}
              onClick={() => onNavigate(item.path)}
              className="w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150"
              style={{
                color: isActive ? 'var(--color-text-accent)' : 'var(--color-text-secondary)',
                background: isActive ? 'rgba(6, 182, 212, 0.1)' : 'transparent',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'var(--color-bg-hover)';
                  e.currentTarget.style.color = 'var(--color-text-primary)';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.background = 'transparent';
                  e.currentTarget.style.color = 'var(--color-text-secondary)';
                }
              }}
            >
              <item.icon size={18} />
              {item.label}
              {isActive && (
                <div
                  className="ml-auto w-1.5 h-1.5 rounded-full"
                  style={{ background: 'var(--color-accent)' }}
                />
              )}
            </button>
          );
        })}
      </nav>

      {/* User section */}
      <div className="p-3">
        <div
          className="rounded-lg p-3"
          style={{ background: 'var(--color-bg-tertiary)' }}
        >
          <div className="flex items-center gap-3">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold"
              style={{
                background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))',
                color: 'white',
              }}
            >
              {user?.display_name?.charAt(0)?.toUpperCase() || 'A'}
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text-primary)' }}>
                {user?.display_name || 'Admin'}
              </p>
              <p className="text-xs truncate" style={{ color: 'var(--color-text-muted)' }}>
                {user?.role?.replace('_', ' ') || 'Super Admin'}
              </p>
            </div>
            <button
              onClick={onLogout}
              className="p-1.5 rounded-md transition-colors duration-150"
              style={{ color: 'var(--color-text-muted)' }}
              onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--color-status-alert)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--color-text-muted)'; }}
              title="Sign out"
            >
              <LogOut size={16} />
            </button>
          </div>
        </div>
      </div>
    </aside>
  );
}
