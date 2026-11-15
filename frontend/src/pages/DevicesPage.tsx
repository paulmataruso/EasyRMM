import { useEffect, useState } from 'react';
import { Monitor, Wifi, WifiOff, AlertTriangle, Search, RefreshCw } from 'lucide-react';
import { api } from '../lib/api';
import type { Device, DeviceListResponse } from '../types';

export function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');

  useEffect(() => {
    loadDevices();
  }, [statusFilter]);

  async function loadDevices() {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (statusFilter) params.set('status', statusFilter);
      if (search) params.set('search', search);
      params.set('limit', '50');
      const res = await api.get<DeviceListResponse>(`/devices?${params}`);
      setDevices(res.devices || []);
      setTotal(res.total || 0);
    } catch {
      setDevices([]);
    } finally {
      setLoading(false);
    }
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    loadDevices();
  }

  const statusIcon: Record<string, React.ReactNode> = {
    online: <Wifi size={14} style={{ color: 'var(--color-status-online)' }} />,
    offline: <WifiOff size={14} style={{ color: 'var(--color-text-muted)' }} />,
    alert: <AlertTriangle size={14} style={{ color: 'var(--color-status-alert)' }} />,
    pending: <Monitor size={14} style={{ color: 'var(--color-status-warning)' }} />,
  };

  return (
    <div className="space-y-6">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <form onSubmit={handleSearch} className="relative flex-1 max-w-sm">
          <Search
            size={16}
            className="absolute left-3 top-1/2 -translate-y-1/2"
            style={{ color: 'var(--color-text-muted)' }}
          />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search devices..."
            className="w-full pl-9 pr-4 py-2 text-sm rounded-lg focus:outline-none focus:ring-2"
            style={{
              background: 'var(--color-bg-tertiary)',
              color: 'var(--color-text-primary)',
              border: '1px solid var(--color-border)',
              '--tw-ring-color': 'var(--color-border-focus)',
            } as React.CSSProperties}
          />
        </form>

        <div className="flex items-center gap-2">
          {['', 'online', 'offline', 'alert'].map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className="px-3 py-1.5 rounded-lg text-xs font-medium transition-colors"
              style={{
                background: statusFilter === s ? 'rgba(6, 182, 212, 0.15)' : 'var(--color-bg-tertiary)',
                color: statusFilter === s ? 'var(--color-text-accent)' : 'var(--color-text-secondary)',
                border: `1px solid ${statusFilter === s ? 'rgba(6, 182, 212, 0.3)' : 'var(--color-border)'}`,
              }}
            >
              {s || 'All'}
            </button>
          ))}
          <button
            onClick={loadDevices}
            className="p-2 rounded-lg transition-colors"
            style={{
              background: 'var(--color-bg-tertiary)',
              border: '1px solid var(--color-border)',
              color: 'var(--color-text-secondary)',
            }}
            title="Refresh"
          >
            <RefreshCw size={16} />
          </button>
        </div>
      </div>

      {/* Table */}
      <div
        className="glass rounded-xl overflow-hidden"
        style={{ border: '1px solid var(--color-border)' }}
      >
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--color-bg-tertiary)' }}>
              {['Status', 'Hostname', 'OS', 'IP / Agent', 'Last Seen'].map((h) => (
                <th
                  key={h}
                  className="text-left px-5 py-3 font-medium text-xs uppercase tracking-wider"
                  style={{ color: 'var(--color-text-muted)' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <TableSkeleton />
            ) : devices.length === 0 ? (
              <tr>
                <td
                  colSpan={5}
                  className="text-center py-12"
                  style={{ color: 'var(--color-text-muted)' }}
                >
                  {total === 0 ? 'No devices enrolled yet' : 'No devices match filters'}
                </td>
              </tr>
            ) : (
              devices.map((d) => (
                <tr
                  key={d.id}
                  className="border-t cursor-pointer transition-colors"
                  style={{ borderColor: 'var(--color-border)' }}
                  onMouseEnter={(e) => { e.currentTarget.style.background = 'var(--color-bg-hover)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                >
                  <td className="px-5 py-3">
                    <div className="flex items-center gap-2">
                      {statusIcon[d.status] || statusIcon.pending}
                      <span className="capitalize" style={{ color: 'var(--color-text-secondary)' }}>
                        {d.status}
                      </span>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span className="font-medium" style={{ color: 'var(--color-text-primary)' }}>
                      {d.display_name || d.hostname}
                    </span>
                  </td>
                  <td className="px-5 py-3" style={{ color: 'var(--color-text-secondary)' }}>
                    {d.os_name || d.os_type}
                    {d.os_version ? ` ${d.os_version}` : ''}
                  </td>
                  <td className="px-5 py-3 font-mono text-xs" style={{ color: 'var(--color-text-muted)' }}>
                    {d.agent_id?.slice(0, 12)}...
                  </td>
                  <td className="px-5 py-3" style={{ color: 'var(--color-text-muted)' }}>
                    {d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : 'Never'}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
        {total > 0 && (
          <div
            className="px-5 py-3 text-xs border-t"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}
          >
            Showing {devices.length} of {total} devices
          </div>
        )}
      </div>
    </div>
  );
}

function TableSkeleton() {
  return (
    <>
      {[1, 2, 3, 4, 5].map((i) => (
        <tr key={i} className="border-t animate-pulse" style={{ borderColor: 'var(--color-border)' }}>
          {[1, 2, 3, 4, 5].map((j) => (
            <td key={j} className="px-5 py-3">
              <div className="h-3 rounded w-20" style={{ background: 'var(--color-bg-tertiary)' }} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
