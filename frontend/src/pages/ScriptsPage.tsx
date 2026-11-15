import { useEffect, useState } from 'react';
import { ScrollText, Plus, Play, Trash2, Loader2, Code } from 'lucide-react';
import { api } from '../lib/api';

interface Script {
  id: string;
  organization_id?: string;
  name: string;
  description: string;
  shell: string;
  os_type: string;
  content: string;
  timeout_seconds: number;
  category: string;
  is_builtin: boolean;
  created_at: string;
}

export function ScriptsPage() {
  const [scripts, setScripts] = useState<Script[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [selectedScript, setSelectedScript] = useState<Script | null>(null);

  const [form, setForm] = useState({
    name: '',
    description: '',
    shell: 'powershell',
    os_type: 'windows',
    content: '',
    timeout_seconds: 300,
    category: 'general',
    organization_id: '',
  });

  useEffect(() => { loadScripts(); }, []);

  async function loadScripts() {
    try {
      const res = await api.get<{ scripts: Script[] }>('/scripts?organization_id=00000000-0000-0000-0000-000000000000');
      setScripts(res.scripts || []);
    } catch {
      setScripts([]);
    } finally {
      setLoading(false);
    }
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post('/scripts', form);
      setShowCreate(false);
      setForm({ name: '', description: '', shell: 'powershell', os_type: 'windows', content: '', timeout_seconds: 300, category: 'general', organization_id: '' });
      loadScripts();
    } catch {} finally {
      setCreating(false);
    }
  }

  async function deleteScript(id: string) {
    try {
      await api.delete(`/scripts/${id}`);
      if (selectedScript?.id === id) setSelectedScript(null);
      loadScripts();
    } catch {}
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div />
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white"
          style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
        >
          <Plus size={16} />
          New Script
        </button>
      </div>

      {/* Create Form */}
      {showCreate && (
        <form onSubmit={handleCreate} className="glass rounded-xl p-5 space-y-4" style={{ border: '1px solid var(--color-border)' }}>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <InputField label="Name" value={form.name} onChange={(v) => setForm({ ...form, name: v })} required placeholder="Disk Cleanup" />
            <SelectField label="Shell" value={form.shell} onChange={(v) => setForm({ ...form, shell: v })} options={['powershell', 'cmd', 'bash', 'sh', 'python']} />
            <SelectField label="OS" value={form.os_type} onChange={(v) => setForm({ ...form, os_type: v })} options={['windows', 'linux', 'any']} />
          </div>
          <InputField label="Description" value={form.description} onChange={(v) => setForm({ ...form, description: v })} placeholder="Cleans up temp files..." />
          <div>
            <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>Script Content</label>
            <textarea
              value={form.content}
              onChange={(e) => setForm({ ...form, content: e.target.value })}
              required
              rows={10}
              className="w-full px-4 py-2.5 rounded-lg text-sm font-mono focus:outline-none focus:ring-2"
              style={{
                background: 'var(--color-bg-primary)',
                color: 'var(--color-text-primary)',
                border: '1px solid var(--color-border)',
                '--tw-ring-color': 'var(--color-border-focus)',
              } as React.CSSProperties}
              placeholder="# Enter script content..."
            />
          </div>
          <div className="flex justify-end gap-3">
            <button type="button" onClick={() => setShowCreate(false)} className="px-4 py-2 rounded-lg text-sm" style={{ color: 'var(--color-text-secondary)' }}>Cancel</button>
            <button type="submit" disabled={creating} className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium text-white disabled:opacity-50" style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}>
              {creating && <Loader2 size={14} className="animate-spin" />}
              Create Script
            </button>
          </div>
        </form>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Script List */}
        <div className="xl:col-span-1 glass rounded-xl overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
          <div className="px-5 py-3 border-b" style={{ borderColor: 'var(--color-border)' }}>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>Script Library</h3>
          </div>
          <div className="divide-y" style={{ '--tw-divide-opacity': '1', borderColor: 'var(--color-border)' } as React.CSSProperties}>
            {loading ? (
              <div className="p-5 text-center text-sm" style={{ color: 'var(--color-text-muted)' }}>Loading...</div>
            ) : scripts.length === 0 ? (
              <div className="p-8 text-center">
                <ScrollText size={32} className="mx-auto mb-2" style={{ color: 'var(--color-text-muted)' }} />
                <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>No scripts yet</p>
              </div>
            ) : (
              scripts.map((sc) => (
                <button
                  key={sc.id}
                  onClick={() => setSelectedScript(sc)}
                  className="w-full text-left px-4 py-3 transition-colors"
                  style={{
                    background: selectedScript?.id === sc.id ? 'rgba(6,182,212,0.08)' : 'transparent',
                    borderLeft: selectedScript?.id === sc.id ? '2px solid var(--color-accent)' : '2px solid transparent',
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate" style={{ color: 'var(--color-text-primary)' }}>{sc.name}</p>
                      <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>{sc.shell} · {sc.os_type}</p>
                    </div>
                    {sc.is_builtin && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded" style={{ background: 'rgba(6,182,212,0.1)', color: 'var(--color-text-accent)' }}>Built-in</span>
                    )}
                  </div>
                </button>
              ))
            )}
          </div>
        </div>

        {/* Script Detail / Editor */}
        <div className="xl:col-span-2 glass rounded-xl" style={{ border: '1px solid var(--color-border)' }}>
          {selectedScript ? (
            <>
              <div className="flex items-center justify-between px-5 py-3 border-b" style={{ borderColor: 'var(--color-border)' }}>
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>{selectedScript.name}</h3>
                  <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>{selectedScript.description}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-medium" style={{ background: 'rgba(6,182,212,0.1)', color: 'var(--color-text-accent)' }}>
                    <Play size={12} /> Run
                  </button>
                  {!selectedScript.is_builtin && (
                    <button onClick={() => deleteScript(selectedScript.id)} className="p-1.5 rounded" style={{ color: 'var(--color-text-muted)' }}>
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              </div>
              <div className="p-5">
                <pre
                  className="text-xs font-mono p-4 rounded-lg overflow-auto"
                  style={{
                    background: 'var(--color-bg-primary)',
                    color: 'var(--color-text-primary)',
                    border: '1px solid var(--color-border)',
                    maxHeight: '500px',
                  }}
                >
                  {selectedScript.content}
                </pre>
                <div className="flex items-center gap-4 mt-4 text-xs" style={{ color: 'var(--color-text-muted)' }}>
                  <span>Shell: {selectedScript.shell}</span>
                  <span>OS: {selectedScript.os_type}</span>
                  <span>Timeout: {selectedScript.timeout_seconds}s</span>
                  {selectedScript.category && <span>Category: {selectedScript.category}</span>}
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center py-24">
              <Code size={40} style={{ color: 'var(--color-text-muted)' }} />
              <p className="text-sm mt-3" style={{ color: 'var(--color-text-secondary)' }}>Select a script to view</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function InputField({ label, value, onChange, required, placeholder }: {
  label: string; value: string; onChange: (v: string) => void; required?: boolean; placeholder?: string;
}) {
  return (
    <div>
      <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        required={required}
        placeholder={placeholder}
        className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
        style={{
          background: 'var(--color-bg-tertiary)',
          color: 'var(--color-text-primary)',
          border: '1px solid var(--color-border)',
          '--tw-ring-color': 'var(--color-border-focus)',
        } as React.CSSProperties}
      />
    </div>
  );
}

function SelectField({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void; options: string[];
}) {
  return (
    <div>
      <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>{label}</label>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
        style={{
          background: 'var(--color-bg-tertiary)',
          color: 'var(--color-text-primary)',
          border: '1px solid var(--color-border)',
          '--tw-ring-color': 'var(--color-border-focus)',
        } as React.CSSProperties}
      >
        {options.map((o) => <option key={o} value={o}>{o}</option>)}
      </select>
    </div>
  );
}
