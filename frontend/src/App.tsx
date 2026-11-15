import { useState, useCallback } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { AuthProvider, useAuth } from './hooks/useAuth';
import { AppLayout } from './components/layout/AppLayout';
import { LoginPage } from './components/auth/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { DevicesPage } from './pages/DevicesPage';
import { DeviceDetailPage } from './pages/DeviceDetailPage';
import { OrganizationsPage } from './pages/OrganizationsPage';
import { EnrollPage } from './pages/EnrollPage';
import { PlaceholderPage } from './pages/PlaceholderPage';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
});

const pageTitles: Record<string, { title: string; subtitle?: string }> = {
  '/': { title: 'Dashboard', subtitle: 'System overview and device health' },
  '/organizations': { title: 'Organizations', subtitle: 'Manage tenants and sites' },
  '/devices': { title: 'Devices', subtitle: 'Monitor and manage enrolled endpoints' },
  '/scripts': { title: 'Scripts', subtitle: 'Script library and execution' },
  '/jobs': { title: 'Jobs', subtitle: 'Job history and scheduling' },
  '/software': { title: 'Software', subtitle: 'Software inventory and patch management' },
  '/monitoring': { title: 'Monitoring', subtitle: 'Performance metrics and thresholds' },
  '/alerts': { title: 'Alerts', subtitle: 'Active alerts and notification rules' },
  '/reports': { title: 'Reports', subtitle: 'Compliance and operational reports' },
  '/settings': { title: 'Settings', subtitle: 'System configuration' },
  '/settings/enrollment': { title: 'Enrollment Tokens', subtitle: 'Manage device enrollment' },
};

function AppContent() {
  const { user, loading, logout } = useAuth();
  const [currentPath, setCurrentPath] = useState('/');

  const navigate = useCallback((path: string) => {
    setCurrentPath(path);
    window.history.pushState(null, '', path);
  }, []);

  if (loading) {
    return (
      <div
        className="min-h-screen flex items-center justify-center"
        style={{ background: 'var(--color-bg-primary)' }}
      >
        <div
          className="w-8 h-8 border-2 rounded-full animate-spin"
          style={{ borderColor: 'var(--color-border)', borderTopColor: 'var(--color-accent)' }}
        />
      </div>
    );
  }

  if (!user) {
    return <LoginPage />;
  }

  const deviceDetailMatch = currentPath.match(/^\/devices\/([a-f0-9-]+)$/);
  const pageInfo = pageTitles[deviceDetailMatch ? '/devices' : currentPath] || { title: 'Not Found' };

  function renderPage() {
    if (deviceDetailMatch) {
      return <DeviceDetailPage deviceId={deviceDetailMatch[1]} onBack={() => navigate('/devices')} />;
    }
    switch (currentPath) {
      case '/':
        return <DashboardPage />;
      case '/devices':
        return <DevicesPage onSelectDevice={(id) => navigate(`/devices/${id}`)} />;
      case '/organizations':
        return <OrganizationsPage />;
      case '/scripts':
        return <PlaceholderPage name="Scripts" />;
      case '/jobs':
        return <PlaceholderPage name="Jobs" />;
      case '/software':
        return <PlaceholderPage name="Software" />;
      case '/monitoring':
        return <PlaceholderPage name="Monitoring" />;
      case '/alerts':
        return <PlaceholderPage name="Alerts" />;
      case '/reports':
        return <PlaceholderPage name="Reports" />;
      case '/settings':
        return <EnrollPage />;
      case '/settings/enrollment':
        return <EnrollPage />;
      default:
        return <PlaceholderPage name="Page Not Found" />;
    }
  }

  return (
    <AppLayout
      title={pageInfo.title}
      subtitle={pageInfo.subtitle}
      currentPath={currentPath}
      onNavigate={navigate}
      onLogout={logout}
      user={user}
    >
      {renderPage()}
    </AppLayout>
  );
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </QueryClientProvider>
  );
}
