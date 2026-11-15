import { useEffect, useState } from 'react';
import { Bell, CheckCircle, AlertTriangle, Info, XCircle } from 'lucide-react';
import { api } from '../lib/api';
import type { Alert } from '../types';

export function AlertsPage() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<'all' | 'active' | 'acknowledged' | 'resolved'>('active');

  useEffect(() => { loadAlerts(); }, [filter]);

  async function loadAlerts() {
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: '50' });
      if (filter !== 'all') params.set('status', filter);
      const res = await api.get<{ alerts: Alert[] }>(`/alerts?${params}`);
      setAlerts(res.alerts || []);
    } catch {
      setAlerts([]);
    } finally {
      setLoading(false);
    }
  }

  async function acknowledgeAlert(id: string) {
    try {
      await api.post(`/alerts/${id}/acknowledge`);
      loadAlerts();
    } catch {}
  }

  async function resolveAlert(id: string) {
    try {
      await api.post(`/alerts/${id}/resolve`);
      loadAlerts();
    } catch {}
  }

  const severityColors: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
    critical: { bg: 'rgba(239,68,68,0.1)', text: 'var(--color-status-alert)', icon: <XCircle size={16} /> },
    warning: { bg: 'rgba(245,158,11,0.1)', text: 'var(--color-status-warning)', icon: <AlertTriangle size={16} /> },
    info: { bg: 'rgba(6,182,212,0.1)', text: 'var(--color-accent)', icon: <Info size={16} /> },
  };

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex items-center gap-2">
        {(['all', 'active', 'acknowledged', 'resolved'] as const).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className="px-3 py-1.5 rounded-lg text-xs font-medium capitalize transition-colors"
            style={{
              background: filter === f ? 'rgba(6,182,212,0.15)' : 'var(--color-bg-tertiary)',
              color: filter === f ? 'var(--color-text-accent)' : 'var(--color-text-secondary)',
              border: `1px solid ${filter === f ? 'rgba(6,182,212,0.3)' : 'var(--color-border)'}`,
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Alert List */}
      <div className="space-y-3">
        {loading ? (
          <div className="glass rounded-xl p-8 text-center" style={{ border: '1px solid var(--color-border)' }}>
            <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading alerts...</p>
          </div>
        ) : alerts.length === 0 ? (
          <div className="glass rounded-xl p-12 text-center" style={{ border: '1px solid var(--color-border)' }}>
            <Bell size={40} className="mx-auto mb-3" style={{ color: 'var(--color-text-muted)' }} />
            <p style={{ color: 'var(--color-text-secondary)' }}>No {filter !== 'all' ? filter : ''} alerts</p>
          </div>
        ) : (
          alerts.map((alert) => {
            const sev = severityColors[alert.severity] || severityColors.info;
            return (
              <div
                key={alert.id}
                className="glass rounded-xl p-4 flex items-start gap-4"
                style={{ border: '1px solid var(--color-border)' }}
              >
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: sev.bg, color: sev.text }}
                >
                  {sev.icon}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium" style={{ color: 'var(--color-text-primary)' }}>
                      {alert.message}
                    </span>
                    <span
                      className="px-1.5 py-0.5 text-[10px] rounded capitalize"
                      style={{ background: sev.bg, color: sev.text }}
                    >
                      {alert.severity}
                    </span>
                    <span
                      className="px-1.5 py-0.5 text-[10px] rounded capitalize"
                      style={{
                        background: alert.status === 'active' ? 'rgba(239,68,68,0.1)' : 'var(--color-bg-tertiary)',
                        color: alert.status === 'active' ? 'var(--color-status-alert)' : 'var(--color-text-muted)',
                      }}
                    >
                      {alert.status}
                    </span>
                  </div>
                  <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>
                    Metric: {alert.metric} · {new Date(alert.created_at).toLocaleString()}
                  </p>
                </div>
                {alert.status === 'active' && (
                  <div className="flex items-center gap-1">
                    <button
                      onClick={() => acknowledgeAlert(alert.id)}
                      className="p-1.5 rounded text-xs"
                      style={{ color: 'var(--color-status-warning)' }}
                      title="Acknowledge"
                    >
                      <AlertTriangle size={14} />
                    </button>
                    <button
                      onClick={() => resolveAlert(alert.id)}
                      className="p-1.5 rounded text-xs"
                      style={{ color: 'var(--color-status-online)' }}
                      title="Resolve"
                    >
                      <CheckCircle size={14} />
                    </button>
                  </div>
                )}
                {alert.status === 'acknowledged' && (
                  <button
                    onClick={() => resolveAlert(alert.id)}
                    className="p-1.5 rounded text-xs"
                    style={{ color: 'var(--color-status-online)' }}
                    title="Resolve"
                  >
                    <CheckCircle size={14} />
                  </button>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
