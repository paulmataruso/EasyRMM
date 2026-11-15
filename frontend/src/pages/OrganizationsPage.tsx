import { useEffect, useState } from 'react';
import { Building2, Plus, Loader2 } from 'lucide-react';
import { api } from '../lib/api';
import type { Organization } from '../types';

export function OrganizationsPage() {
  const [orgs, setOrgs] = useState<Organization[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');

  useEffect(() => {
    loadOrgs();
  }, []);

  async function loadOrgs() {
    try {
      const res = await api.get<{ organizations: Organization[] }>('/organizations');
      setOrgs(res.organizations || []);
    } catch {
      setOrgs([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post('/organizations', { name, slug: slug || name.toLowerCase().replace(/\s+/g, '-') });
      setShowCreate(false);
      setName('');
      setSlug('');
      loadOrgs();
    } catch {
      // TODO: error display
    } finally {
      setCreating(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div />
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white transition-opacity"
          style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
        >
          <Plus size={16} />
          New Organization
        </button>
      </div>

      {showCreate && (
        <form
          onSubmit={handleCreate}
          className="glass rounded-xl p-5 space-y-4"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                placeholder="Acme Corp"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                Slug
              </label>
              <input
                type="text"
                value={slug}
                onChange={(e) => setSlug(e.target.value)}
                className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                style={{
                  background: 'var(--color-bg-tertiary)',
                  color: 'var(--color-text-primary)',
                  border: '1px solid var(--color-border)',
                  '--tw-ring-color': 'var(--color-border-focus)',
                } as React.CSSProperties}
                placeholder="acme-corp (auto-generated if empty)"
              />
            </div>
          </div>
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={() => setShowCreate(false)}
              className="px-4 py-2 rounded-lg text-sm"
              style={{ color: 'var(--color-text-secondary)' }}
            >
              Cancel
            </button>
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

      {/* Org Grid */}
      {loading ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="glass rounded-xl p-5 animate-pulse"
              style={{ border: '1px solid var(--color-border)' }}
            >
              <div className="h-4 rounded w-1/2 mb-3" style={{ background: 'var(--color-bg-tertiary)' }} />
              <div className="h-3 rounded w-1/3" style={{ background: 'var(--color-bg-tertiary)' }} />
            </div>
          ))}
        </div>
      ) : orgs.length === 0 ? (
        <div
          className="glass rounded-xl p-12 text-center"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <Building2 size={40} className="mx-auto mb-3" style={{ color: 'var(--color-text-muted)' }} />
          <p style={{ color: 'var(--color-text-secondary)' }}>No organizations yet</p>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
            Create your first organization to start managing devices
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {orgs.map((org) => (
            <div
              key={org.id}
              className="glass rounded-xl p-5 cursor-pointer transition-all"
              style={{ border: '1px solid var(--color-border)' }}
              onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'var(--color-border-focus)'; }}
              onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'var(--color-border)'; }}
            >
              <div className="flex items-center gap-3 mb-3">
                <div
                  className="w-10 h-10 rounded-lg flex items-center justify-center"
                  style={{ background: 'rgba(6, 182, 212, 0.1)', color: 'var(--color-accent)' }}
                >
                  <Building2 size={20} />
                </div>
                <div>
                  <h3 className="font-semibold" style={{ color: 'var(--color-text-primary)' }}>
                    {org.name}
                  </h3>
                  <p className="text-xs font-mono" style={{ color: 'var(--color-text-muted)' }}>
                    {org.slug}
                  </p>
                </div>
              </div>
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                Created {new Date(org.created_at).toLocaleDateString()}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
