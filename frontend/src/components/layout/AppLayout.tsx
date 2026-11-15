import { ReactNode } from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface AppLayoutProps {
  children: ReactNode;
  title: string;
  subtitle?: string;
  currentPath: string;
  onNavigate: (path: string) => void;
  onLogout: () => void;
  user?: { display_name: string; role: string } | null;
}

export function AppLayout({
  children,
  title,
  subtitle,
  currentPath,
  onNavigate,
  onLogout,
  user,
}: AppLayoutProps) {
  return (
    <div className="flex min-h-screen" style={{ background: 'var(--color-bg-primary)' }}>
      <Sidebar
        currentPath={currentPath}
        onNavigate={onNavigate}
        onLogout={onLogout}
        user={user}
      />
      <div className="flex-1 flex flex-col min-w-0">
        <Header title={title} subtitle={subtitle} />
        <main className="flex-1 p-8">
          {children}
        </main>
      </div>
    </div>
  );
}
