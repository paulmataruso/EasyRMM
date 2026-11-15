import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import { api, ApiError } from '../lib/api';
import type { User } from '../types';

interface AuthState {
  user: User | null;
  loading: boolean;
  error: string | null;
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<{ mfa_required?: boolean }>;
  verifyMFA: (code: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({
    user: null,
    loading: true,
    error: null,
  });

  const refresh = useCallback(async () => {
    try {
      const user = await api.get<User>('/auth/me');
      setState({ user, loading: false, error: null });
    } catch {
      setState({ user: null, loading: false, error: null });
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const login = useCallback(async (username: string, password: string) => {
    setState((s) => ({ ...s, error: null }));
    try {
      const res = await api.post<{ user?: User; mfa_required?: boolean }>('/auth/login', {
        username,
        password,
      });
      if (res.mfa_required) {
        return { mfa_required: true };
      }
      if (res.user) {
        setState({ user: res.user, loading: false, error: null });
      }
      return {};
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Login failed';
      setState((s) => ({ ...s, error: message }));
      throw err;
    }
  }, []);

  const verifyMFA = useCallback(async (code: string) => {
    try {
      const res = await api.post<{ user: User }>('/auth/mfa/verify', { code });
      setState({ user: res.user, loading: false, error: null });
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'MFA verification failed';
      setState((s) => ({ ...s, error: message }));
      throw err;
    }
  }, []);

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      setState({ user: null, loading: false, error: null });
    }
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, verifyMFA, logout, refresh }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
