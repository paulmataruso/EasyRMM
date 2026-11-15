import { useEffect, useState } from 'react';
import { Key, Plus, Copy, Check, Trash2, Loader2, Terminal as TermIcon } from 'lucide-react';
import { api } from '../lib/api';

interface EnrollmentToken {
  id: string;
  organization_id: string;
  name: string;
  token_hash: string;
  token_plain?: string;
  max_uses: number;
  use_count: number;
  expires_at: string;
  is_active: boolean;
  created_at: string;
}

export function EnrollPage() {
  const [tokens, setTokens] = useState<EnrollmentToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [orgId, setOrgId] = useState('');
  const [maxUses, setMaxUses] = useState('0');
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  useEffect(() => { loadTokens(); }, []);

  async function loadTokens() {
    try {
      const res = await api.get<{ tokens: EnrollmentToken[] }>('/enrollment-tokens');
      setTokens(res.tokens || []);
    } catch {
      setTokens([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      const res = await api.post<EnrollmentToken & { token_plain: string }>('/enrollment-tokens', {
        name,
        organization_id: orgId,
        max_uses: parseInt(maxUses) || 0,
      });
      setNewToken(res.token_plain);
      setShowCreate(false);
      setName('');
      loadTokens();
    } catch {
      // TODO: error handling
    } finally {
      setCreating(false);
    }
  }

  async function revokeToken(id: string) {
    try {
      await api.delete(`/enrollment-tokens/${id}`);
      loadTokens();
    } catch {}
  }

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  }

  return (
    <div className="space-y-6">
      {/* New token alert */}
      {newToken && (
        <div
          className="rounded-xl p-5"
          style={{
            background: 'rgba(6, 182, 212, 0.08)',
            border: '1px solid rgba(6, 182, 212, 0.2)',
          }}
        >
          <h3 className="text-sm font-semibold mb-2" style={{ color: 'var(--color-text-accent)' }}>
            Enrollment Token Created
          </h3>
          <p className="text-xs mb-3" style={{ color: 'var(--color-text-secondary)' }}>
            Copy this token now — it cannot be shown again.
          </p>
          <div className="flex items-center gap-2">
            <code
              className="flex-1 px-4 py-2 rounded-lg font-mono text-sm select-all"
              style={{
                background: 'var(--color-bg-primary)',
                color: 'var(--color-text-primary)',
                border: '1px solid var(--color-border)',
              }}
            >
              {newToken}
            </code>
            <button
              onClick={() => copyToClipboard(newToken, 'new')}
              className="px-3 py-2 rounded-lg text-sm flex items-center gap-1"
              style={{
                background: 'var(--color-bg-tertiary)',
                color: copiedId === 'new' ? 'var(--color-status-online)' : 'var(--color-text-secondary)',
              }}
            >
              {copiedId === 'new' ? <Check size={14} /> : <Copy size={14} />}
              {copiedId === 'new' ? 'Copied' : 'Copy'}
            </button>
          </div>

          <div className="mt-4 p-3 rounded-lg" style={{ background: 'var(--color-bg-primary)' }}>
            <p className="text-xs font-medium mb-2" style={{ color: 'var(--color-text-secondary)' }}>
              <TermIcon size={12} className="inline mr-1" />
              Install command:
            </p>
            <code className="text-xs font-mono block" style={{ color: 'var(--color-text-muted)' }}>
              {`# Windows (PowerShell as Admin)\nirex (irm ${window.location.origin}/scripts/install-windows.ps1) -ServerURL ${window.location.origin} -EnrollmentToken ${newToken} -MeshID <mesh-group-id>`}
            </code>
            <code className="text-xs font-mono block mt-2" style={{ color: 'var(--color-text-muted)' }}>
              {`# Linux\ncurl -fsSL ${window.location.origin}/scripts/install-linux.sh | sudo bash -s -- --server ${window.location.origin} --token ${newToken} --meshid <mesh-group-id>`}
            </code>
          </div>

          <button
            onClick={() => setNewToken(null)}
            className="mt-3 text-xs"
            style={{ color: 'var(--color-text-muted)' }}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div />
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
          style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
        >
          <Plus size={16} />
          Create Token
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="glass rounded-xl p-5 space-y-4"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                style={{
                  background: 'var(--color-bg-tertiary)',
                  color: 'var(--color-text-primary)',
                  border: '1px solid var(--color-border)',
                  '--tw-ring-color': 'var(--color-border-focus)',
                } as React.CSSProperties}
                placeholder="Office workstations"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                Organization ID
              </label>
              <input
                type="text"
                value={orgId}
                onChange={(e) => setOrgId(e.target.value)}
                required
                className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                style={{
                  background: 'var(--color-bg-tertiary)',
                  color: 'var(--color-text-primary)',
                  border: '1px solid var(--color-border)',
                  '--tw-ring-color': 'var(--color-border-focus)',
                } as React.CSSProperties}
                placeholder="UUID"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                Max Uses (0 = unlimited)
              </label>
              <input
                type="number"
                value={maxUses}
                onChange={(e) => setMaxUses(e.target.value)}
                min="0"
                className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                style={{
                  background: 'var(--color-bg-tertiary)',
                  color: 'var(--color-text-primary)',
                  border: '1px solid var(--color-border)',
                  '--tw-ring-color': 'var(--color-border-focus)',
                } as React.CSSProperties}
              />
            </div>
          </div>
          <div className="flex justify-end gap-3">
            <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--color-text-secondary)' }}>Cancel</button>
            <button
              type="submit"
              disabled={creating}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50"
              style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
            >
              {creating && <Loader2 size={14} className="animate-spin" />}
              Create
            </button>
          </div>
        </form>
      )}

      {/* Token List */}
      <div className="glass rounded-xl overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
        <table className="w-full text-sm">
          <thead>
            <tr style={{ background: 'var(--color-bg-tertiary)' }}>
              {['Name', 'Uses', 'Status', 'Created', 'Actions'].map((h) => (
                <th key={h} className="text-left px-5 py-3 font-medium text-xs uppercase tracking-wider" style={{ color: 'var(--color-text-muted)' }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={5} className="text-center py-8" style={{ color: 'var(--color-text-muted)' }}>Loading...</td></tr>
            ) : tokens.length === 0 ? (
              <tr><td colSpan={5} className="text-center py-12">
                <Key size={32} className="mx-auto mb-2" style={{ color: 'var(--color-text-muted)' }} />
                <p style={{ color: 'var(--color-text-secondary)' }}>No enrollment tokens</p>
                <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>Create a token to start enrolling devices</p>
              </td></tr>
            ) : (
              tokens.map((t) => (
                <tr key={t.id} className="border-t" style={{ borderColor: 'var(--color-border)' }}>
                  <td className="px-5 py-3 font-medium" style={{ color: 'var(--color-text-primary)' }}>{t.name}</td>
                  <td className="px-5 py-3" style={{ color: 'var(--color-text-secondary)' }}>
                    {t.use_count}{t.max_uses > 0 ? ` / ${t.max_uses}` : ' / ∞'}
                  </td>
                  <td className="px-5 py-3">
                    <span
                      className="px-2 py-0.5 text-xs rounded"
                      style={{
                        background: t.is_active ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)',
                        color: t.is_active ? 'var(--color-status-online)' : 'var(--color-status-alert)',
                      }}
                    >
                      {t.is_active ? 'Active' : 'Revoked'}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs" style={{ color: 'var(--color-text-muted)' }}>
                    {new Date(t.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-5 py-3">
                    {t.is_active && (
                      <button
                        onClick={() => revokeToken(t.id)}
                        className="p-1.5 rounded transition-colors"
                        style={{ color: 'var(--color-text-muted)' }}
                        title="Revoke token"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
