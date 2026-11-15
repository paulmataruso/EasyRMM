import { useState, type FormEvent } from 'react';
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react';
import { useAuth } from '../../hooks/useAuth';

export function LoginPage() {
  const { login, verifyMFA, error } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  async function handleLogin(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const res = await login(username, password);
      if (res.mfa_required) setMfaRequired(true);
    } catch {
      // error is set in auth context
    } finally {
      setSubmitting(false);
    }
  }

  async function handleMFA(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await verifyMFA(mfaCode);
    } catch {
      // error is set in auth context
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: 'var(--color-bg-primary)' }}
    >
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div
            className="w-14 h-14 rounded-2xl flex items-center justify-center mb-4"
            style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
          >
            <Shield size={28} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold" style={{ color: 'var(--color-text-primary)' }}>
            EasyRMM
          </h1>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
            Remote Monitoring &amp; Management
          </p>
        </div>

        {/* Card */}
        <div
          className="glass rounded-2xl p-8"
          style={{ border: '1px solid var(--color-border)' }}
        >
          <h2 className="text-lg font-semibold mb-1" style={{ color: 'var(--color-text-primary)' }}>
            {mfaRequired ? 'Two-Factor Authentication' : 'Sign in'}
          </h2>
          <p className="text-sm mb-6" style={{ color: 'var(--color-text-secondary)' }}>
            {mfaRequired
              ? 'Enter the code from your authenticator app'
              : 'Enter your credentials to continue'}
          </p>

          {error && (
            <div
              className="rounded-lg px-4 py-3 text-sm mb-4"
              style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.2)',
                color: 'var(--color-status-alert)',
              }}
            >
              {error}
            </div>
          )}

          {!mfaRequired ? (
            <form onSubmit={handleLogin} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoFocus
                  autoComplete="username"
                  className="w-full px-4 py-2.5 rounded-lg text-sm focus:outline-none focus:ring-2"
                  style={{
                    background: 'var(--color-bg-tertiary)',
                    color: 'var(--color-text-primary)',
                    border: '1px solid var(--color-border)',
                    '--tw-ring-color': 'var(--color-border-focus)',
                  } as React.CSSProperties}
                  placeholder="admin"
                />
              </div>

              <div>
                <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    autoComplete="current-password"
                    className="w-full px-4 py-2.5 pr-11 rounded-lg text-sm focus:outline-none focus:ring-2"
                    style={{
                      background: 'var(--color-bg-tertiary)',
                      color: 'var(--color-text-primary)',
                      border: '1px solid var(--color-border)',
                      '--tw-ring-color': 'var(--color-border-focus)',
                    } as React.CSSProperties}
                    placeholder="••••••••••••"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2"
                    style={{ color: 'var(--color-text-muted)' }}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              <button
                type="submit"
                disabled={submitting}
                className="w-full py-2.5 rounded-lg text-sm font-medium text-white transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
                style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
              >
                {submitting ? <Loader2 size={16} className="animate-spin" /> : null}
                Sign in
              </button>
            </form>
          ) : (
            <form onSubmit={handleMFA} className="space-y-4">
              <div>
                <label className="block text-sm font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  Authentication Code
                </label>
                <input
                  type="text"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  required
                  autoFocus
                  inputMode="numeric"
                  className="w-full px-4 py-2.5 rounded-lg text-sm text-center tracking-[0.3em] font-mono focus:outline-none focus:ring-2"
                  style={{
                    background: 'var(--color-bg-tertiary)',
                    color: 'var(--color-text-primary)',
                    border: '1px solid var(--color-border)',
                    '--tw-ring-color': 'var(--color-border-focus)',
                  } as React.CSSProperties}
                  placeholder="000000"
                />
              </div>

              <button
                type="submit"
                disabled={submitting || mfaCode.length !== 6}
                className="w-full py-2.5 rounded-lg text-sm font-medium text-white transition-opacity disabled:opacity-50 flex items-center justify-center gap-2"
                style={{ background: 'linear-gradient(135deg, var(--color-accent), var(--color-accent-blue))' }}
              >
                {submitting ? <Loader2 size={16} className="animate-spin" /> : null}
                Verify
              </button>

              <button
                type="button"
                onClick={() => { setMfaRequired(false); setMfaCode(''); }}
                className="w-full py-2 text-sm"
                style={{ color: 'var(--color-text-secondary)' }}
              >
                Back to login
              </button>
            </form>
          )}
        </div>

        <p className="text-center text-xs mt-6" style={{ color: 'var(--color-text-muted)' }}>
          EasyRMM &mdash; Open Source Remote Monitoring &amp; Management
        </p>
      </div>
    </div>
  );
}
