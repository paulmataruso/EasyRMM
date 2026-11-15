import { useEffect, useState } from 'react';
import {
  ArrowLeft, Monitor, Terminal, FolderOpen, Info,
  Wifi, WifiOff, AlertTriangle, Cpu, HardDrive, Clock, Loader2,
} from 'lucide-react';
import { api } from '../lib/api';
import type { Device } from '../types';

interface DeviceDetailPageProps {
  deviceId: string;
  onBack: () => void;
}

type Tab = 'overview' | 'remote-desktop' | 'terminal' | 'file-manager';

interface RemoteAccessToken {
  url: string;
  token: string;
  node_id: string;
  expires_at: string;
}

export function DeviceDetailPage({ deviceId, onBack }: DeviceDetailPageProps) {
  const [device, setDevice] = useState<Device | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<Tab>('overview');
  const [remoteAccess, setRemoteAccess] = useState<RemoteAccessToken | null>(null);
  const [remoteLoading, setRemoteLoading] = useState(false);

  useEffect(() => {
    api.get<Device>(`/devices/${deviceId}`)
      .then(setDevice)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [deviceId]);

  async function loadRemoteAccess() {
    if (remoteAccess) return;
    setRemoteLoading(true);
    try {
      const token = await api.get<RemoteAccessToken>(`/devices/${deviceId}/remote-access`);
      setRemoteAccess(token);
    } catch {
      // show error in UI
    } finally {
      setRemoteLoading(false);
    }
  }

  function handleTabChange(tab: Tab) {
    setActiveTab(tab);
    if (tab !== 'overview' && !remoteAccess) {
      loadRemoteAccess();
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <Loader2 size={24} className="animate-spin" style={{ color: 'var(--color-accent)' }} />
      </div>
    );
  }

  if (!device) {
    return (
      <div className="text-center py-24" style={{ color: 'var(--color-text-muted)' }}>
        Device not found
      </div>
    );
  }

  const statusColors: Record<string, string> = {
    online: 'var(--color-status-online)',
    offline: 'var(--color-text-muted)',
    alert: 'var(--color-status-alert)',
    pending: 'var(--color-status-warning)',
  };

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: 'overview', label: 'Overview', icon: <Info size={16} /> },
    { key: 'remote-desktop', label: 'Remote Desktop', icon: <Monitor size={16} /> },
    { key: 'terminal', label: 'Terminal', icon: <Terminal size={16} /> },
    { key: 'file-manager', label: 'Files', icon: <FolderOpen size={16} /> },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <button
          onClick={onBack}
          className="p-2 rounded-lg transition-colors"
          style={{ background: 'var(--color-bg-tertiary)', color: 'var(--color-text-secondary)' }}
        >
          <ArrowLeft size={18} />
        </button>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ background: statusColors[device.status] }} />
            <h2 className="text-lg font-semibold" style={{ color: 'var(--color-text-primary)' }}>
              {device.display_name || device.hostname}
            </h2>
          </div>
          <span
            className="px-2 py-0.5 text-xs font-medium rounded capitalize"
            style={{
              background: `${statusColors[device.status]}20`,
              color: statusColors[device.status],
            }}
          >
            {device.status}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 p-1 rounded-lg" style={{ background: 'var(--color-bg-tertiary)' }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => handleTabChange(tab.key)}
            className="flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all"
            style={{
              background: activeTab === tab.key ? 'var(--color-bg-secondary)' : 'transparent',
              color: activeTab === tab.key ? 'var(--color-text-accent)' : 'var(--color-text-secondary)',
              boxShadow: activeTab === tab.key ? '0 1px 3px rgba(0,0,0,0.3)' : 'none',
            }}
          >
            {tab.icon}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && <OverviewTab device={device} />}
      {activeTab === 'remote-desktop' && (
        <RemoteAccessFrame
          remoteAccess={remoteAccess}
          loading={remoteLoading}
          type="desktop"
          device={device}
        />
      )}
      {activeTab === 'terminal' && (
        <RemoteAccessFrame
          remoteAccess={remoteAccess}
          loading={remoteLoading}
          type="terminal"
          device={device}
        />
      )}
      {activeTab === 'file-manager' && (
        <RemoteAccessFrame
          remoteAccess={remoteAccess}
          loading={remoteLoading}
          type="files"
          device={device}
        />
      )}
    </div>
  );
}

function OverviewTab({ device }: { device: Device }) {
  const infoSections = [
    {
      title: 'System',
      icon: <Cpu size={16} />,
      items: [
        { label: 'OS', value: `${device.os_name || device.os_type} ${device.os_version || ''}`.trim() },
        { label: 'Architecture', value: device.arch || '—' },
        { label: 'CPU', value: device.cpu_model || '—' },
        { label: 'CPU Cores', value: device.cpu_cores?.toString() || '—' },
        { label: 'Memory', value: device.total_memory_mb ? `${Math.round(device.total_memory_mb / 1024)} GB` : '—' },
      ],
    },
    {
      title: 'Hardware',
      icon: <HardDrive size={16} />,
      items: [
        { label: 'Manufacturer', value: device.manufacturer || '—' },
        { label: 'Model', value: device.model || '—' },
        { label: 'Serial Number', value: device.serial_number || '—' },
      ],
    },
    {
      title: 'Agent',
      icon: <Clock size={16} />,
      items: [
        { label: 'Agent ID', value: device.agent_id },
        { label: 'Agent Version', value: device.agent_version || '—' },
        { label: 'Last Seen', value: device.last_seen_at ? new Date(device.last_seen_at).toLocaleString() : 'Never' },
        { label: 'Enrolled', value: device.enrolled_at ? new Date(device.enrolled_at).toLocaleString() : '—' },
      ],
    },
  ];

  return (
    <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
      {infoSections.map((section) => (
        <div
          key={section.title}
          className="glass rounded-xl"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div
            className="flex items-center gap-2 px-5 py-3 border-b"
            style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-primary)' }}
          >
            {section.icon}
            <h3 className="text-sm font-semibold">{section.title}</h3>
          </div>
          <div className="p-5 space-y-3">
            {section.items.map((item) => (
              <div key={item.label} className="flex justify-between text-sm">
                <span style={{ color: 'var(--color-text-secondary)' }}>{item.label}</span>
                <span className="font-mono text-xs" style={{ color: 'var(--color-text-primary)' }}>
                  {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Tags */}
      {device.tags && device.tags.length > 0 && (
        <div
          className="glass rounded-xl"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div
            className="px-5 py-3 border-b"
            style={{ borderColor: 'var(--color-border)' }}
          >
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Tags</h3>
          </div>
          <div className="p-5 flex flex-wrap gap-2">
            {device.tags.map((tag) => (
              <span
                key={tag}
                className="px-3 py-1 rounded-full text-xs font-medium"
                style={{
                  background: 'rgba(6, 182, 212, 0.1)',
                  color: 'var(--color-text-accent)',
                  border: '1px solid rgba(6, 182, 212, 0.2)',
                }}
              >
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function RemoteAccessFrame({
  remoteAccess,
  loading,
  type,
  device,
}: {
  remoteAccess: RemoteAccessToken | null;
  loading: boolean;
  type: 'desktop' | 'terminal' | 'files';
  device: Device;
}) {
  if (loading) {
    return (
      <div
        className="glass rounded-xl flex items-center justify-center"
        style={{ border: '1px solid var(--color-border)', height: 'calc(100vh - 320px)', minHeight: '400px' }}
      >
        <div className="text-center">
          <Loader2 size={32} className="animate-spin mx-auto mb-3" style={{ color: 'var(--color-accent)' }} />
          <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>
            Establishing remote connection...
          </p>
        </div>
      </div>
    );
  }

  if (!remoteAccess) {
    return (
      <div
        className="glass rounded-xl flex items-center justify-center"
        style={{ border: '1px solid var(--color-border)', height: 'calc(100vh - 320px)', minHeight: '400px' }}
      >
        <div className="text-center">
          {device.status === 'offline' ? (
            <>
              <WifiOff size={40} className="mx-auto mb-3" style={{ color: 'var(--color-text-muted)' }} />
              <p style={{ color: 'var(--color-text-secondary)' }}>Device is offline</p>
              <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
                Remote access requires the device to be online
              </p>
            </>
          ) : (
            <>
              <AlertTriangle size={40} className="mx-auto mb-3" style={{ color: 'var(--color-status-warning)' }} />
              <p style={{ color: 'var(--color-text-secondary)' }}>Could not establish connection</p>
              <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
                The device may not have MeshCentral agent installed
              </p>
            </>
          )}
        </div>
      </div>
    );
  }

  const viewMap: Record<string, string> = {
    desktop: '&viewmode=11',
    terminal: '&viewmode=12',
    files: '&viewmode=13',
  };

  const iframeURL = remoteAccess.url + (viewMap[type] || '');

  const iconMap: Record<string, React.ReactNode> = {
    desktop: <Monitor size={14} />,
    terminal: <Terminal size={14} />,
    files: <FolderOpen size={14} />,
  };

  const labelMap: Record<string, string> = {
    desktop: 'Remote Desktop',
    terminal: 'Terminal',
    files: 'File Manager',
  };

  return (
    <div
      className="glass rounded-xl overflow-hidden"
      style={{ border: '1px solid var(--color-border)' }}
    >
      <div
        className="flex items-center justify-between px-4 py-2 border-b"
        style={{ borderColor: 'var(--color-border)', background: 'var(--color-bg-tertiary)' }}
      >
        <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--color-text-secondary)' }}>
          {iconMap[type]}
          <span>{labelMap[type]}</span>
          <span style={{ color: 'var(--color-text-muted)' }}>—</span>
          <Wifi size={12} style={{ color: 'var(--color-status-online)' }} />
          <span style={{ color: 'var(--color-status-online)' }}>Connected</span>
        </div>
        <a
          href={iframeURL}
          target="_blank"
          rel="noopener noreferrer"
          className="text-xs px-2 py-1 rounded"
          style={{ color: 'var(--color-text-accent)' }}
        >
          Open in new tab
        </a>
      </div>
      <iframe
        src={iframeURL}
        title={`${labelMap[type]} - ${device.display_name || device.hostname}`}
        className="w-full"
        style={{
          height: 'calc(100vh - 360px)',
          minHeight: '400px',
          border: 'none',
          background: '#000',
        }}
        allow="clipboard-read; clipboard-write"
        sandbox="allow-same-origin allow-scripts allow-popups allow-forms"
      />
    </div>
  );
}
