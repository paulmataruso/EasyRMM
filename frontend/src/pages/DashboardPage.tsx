import { useEffect, useState } from 'react';
import { Monitor, Wifi, WifiOff, AlertTriangle, Clock, Play, XCircle } from 'lucide-react';
import { api } from '../lib/api';
import { StatCard } from '../components/ui/StatCard';
import type { DeviceStats, AuditLog } from '../types';

export function DashboardPage() {
  const [stats, setStats] = useState<DeviceStats | null>(null);
  const [recentActivity, setRecentActivity] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [s, a] = await Promise.all([
          api.get<DeviceStats>('/dashboard/stats'),
          api.get<{ logs: AuditLog[] }>('/audit-logs?limit=10'),
        ]);
        setStats(s);
        setRecentActivity(a.logs || []);
      } catch {
        // will show zeroes
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const totalDevices = stats ? stats.online + stats.offline + stats.alert + stats.pending : 0;

  return (
    <div className="space-y-8">
      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          label="Total Devices"
          value={loading ? '—' : totalDevices}
          icon={<Monitor size={22} />}
          color="var(--color-accent)"
        />
        <StatCard
          label="Online"
          value={loading ? '—' : stats?.online ?? 0}
          icon={<Wifi size={22} />}
          color="var(--color-status-online)"
        />
        <StatCard
          label="Offline"
          value={loading ? '—' : stats?.offline ?? 0}
          icon={<WifiOff size={22} />}
          color="var(--color-text-muted)"
        />
        <StatCard
          label="Alerts"
          value={loading ? '—' : stats?.alert ?? 0}
          icon={<AlertTriangle size={22} />}
          color="var(--color-status-alert)"
        />
      </div>

      {/* Two Column Layout */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Recent Activity */}
        <div
          className="glass rounded-xl"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              Recent Activity
            </h3>
          </div>
          <div className="p-5 space-y-3">
            {loading ? (
              <ActivitySkeleton />
            ) : recentActivity.length === 0 ? (
              <p className="text-sm py-8 text-center" style={{ color: 'var(--color-text-muted)' }}>
                No recent activity
              </p>
            ) : (
              recentActivity.map((log) => (
                <ActivityRow key={log.id} log={log} />
              ))
            )}
          </div>
        </div>

        {/* Quick Actions / Status */}
        <div
          className="glass rounded-xl"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div className="px-5 py-4 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              System Status
            </h3>
          </div>
          <div className="p-5 space-y-4">
            <StatusRow label="API Server" status="healthy" />
            <StatusRow label="MeshCentral" status="healthy" />
            <StatusRow label="Database" status="healthy" />
            <StatusRow label="Agent WebSocket" status="healthy" />
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityRow({ log }: { log: AuditLog }) {
  const iconMap: Record<string, React.ReactNode> = {
    login: <Play size={14} />,
    logout: <XCircle size={14} />,
  };

  return (
    <div className="flex items-center gap-3">
      <div
        className="w-8 h-8 rounded-full flex items-center justify-center shrink-0"
        style={{ background: 'var(--color-bg-tertiary)', color: 'var(--color-text-muted)' }}
      >
        {iconMap[log.action] || <Clock size={14} />}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm truncate" style={{ color: 'var(--color-text-primary)' }}>
          {log.action.replace(/_/g, ' ')}
          {log.resource_type ? ` — ${log.resource_type}` : ''}
        </p>
        <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
          {new Date(log.created_at).toLocaleString()}
        </p>
      </div>
    </div>
  );
}

function StatusRow({ label, status }: { label: string; status: 'healthy' | 'degraded' | 'down' }) {
  const colors: Record<string, string> = {
    healthy: 'var(--color-status-online)',
    degraded: 'var(--color-status-warning)',
    down: 'var(--color-status-alert)',
  };
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>{label}</span>
      <div className="flex items-center gap-2">
        <div className="w-2 h-2 rounded-full" style={{ background: colors[status] }} />
        <span className="text-xs capitalize" style={{ color: colors[status] }}>{status}</span>
      </div>
    </div>
  );
}

function ActivitySkeleton() {
  return (
    <div className="space-y-3">
      {[1, 2, 3].map((i) => (
        <div key={i} className="flex items-center gap-3 animate-pulse">
          <div className="w-8 h-8 rounded-full" style={{ background: 'var(--color-bg-tertiary)' }} />
          <div className="flex-1 space-y-1.5">
            <div className="h-3 rounded w-3/4" style={{ background: 'var(--color-bg-tertiary)' }} />
            <div className="h-2.5 rounded w-1/3" style={{ background: 'var(--color-bg-tertiary)' }} />
          </div>
        </div>
      ))}
    </div>
  );
}
