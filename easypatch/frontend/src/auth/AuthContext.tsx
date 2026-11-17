import { createContext, useCallback, useContext, useEffect, useMemo, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { ApiError, request, setAuthErrorListener } from '../api/client';
import { ME_KEY } from '../api/hooks';
import type { CurrentUserDto, UserRole } from '../api/types';

/** Where the signed-in user is in the login pipeline. */
export type AuthStage = 'loading' | 'anonymous' | 'mfa' | 'mfa-setup' | 'password-change' | 'ready' | 'error';

interface MeResult {
  user: CurrentUserDto | null;
  /** Stage forced by a 403 from /auth/me, when the server reports it that way. */
  forcedStage?: AuthStage;
}

interface AuthContextValue {
  stage: AuthStage;
  user: CurrentUserDto | null;
  role: UserRole | null;
  isSuperAdmin: boolean;
  /** Admin or SuperAdmin: may perform operational writes. */
  canOperate: boolean;
  /** SuperAdmin, or a user without organization restrictions (can see and assign MSP-wide tags). */
  isUnrestricted: boolean;
  refresh: () => Promise<void>;
  setUser: (user: CurrentUserDto | null) => void;
  error: unknown;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function fetchMe(signal: AbortSignal): Promise<MeResult> {
  try {
    const user = await request<CurrentUserDto>('GET', '/auth/me', { signal, silentAuth: true });
    return { user };
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 401) return { user: null };
      if (e.status === 403) {
        if (e.code === 'mfa_required') return { user: null, forcedStage: 'mfa' };
        if (e.code === 'mfa_setup_required') return { user: null, forcedStage: 'mfa-setup' };
        if (e.code === 'password_change_required') return { user: null, forcedStage: 'password-change' };
      }
    }
    throw e;
  }
}

export function stageFor(user: CurrentUserDto | null): AuthStage {
  if (!user) return 'anonymous';
  if (user.mfaEnabled && !user.mfaCompleted) return 'mfa';
  if (user.mfaSetupRequired) return 'mfa-setup';
  if (user.mustChangePassword) return 'password-change';
  return 'ready';
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const me = useQuery<MeResult>({
    queryKey: ME_KEY,
    queryFn: ({ signal }) => fetchMe(signal),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
    retry: (count, error) => !(error instanceof ApiError && error.status > 0 && error.status < 500) && count < 2,
  });

  // Any API call that comes back 401 (or an auth-stage 403) re-evaluates the session.
  useEffect(() => {
    setAuthErrorListener((error) => {
      if (error.status === 401) {
        client.setQueryData<MeResult>(ME_KEY, { user: null });
      } else {
        void client.invalidateQueries({ queryKey: ME_KEY });
      }
    });
    return () => setAuthErrorListener(null);
  }, [client]);

  const refresh = useCallback(async () => {
    await client.invalidateQueries({ queryKey: ME_KEY });
    await client.refetchQueries({ queryKey: ME_KEY });
  }, [client]);

  const setUser = useCallback(
    (user: CurrentUserDto | null) => {
      client.setQueryData<MeResult>(ME_KEY, { user });
      if (!user) {
        // Drop every cached resource when the session ends.
        client.removeQueries({ predicate: (q) => q.queryKey[0] !== ME_KEY[0] });
      }
    },
    [client],
  );

  const value = useMemo<AuthContextValue>(() => {
    const data = me.data;
    let stage: AuthStage;
    if (me.isPending) stage = 'loading';
    else if (me.isError && !data) stage = 'error';
    else stage = data?.forcedStage ?? stageFor(data?.user ?? null);
    const user = data?.user ?? null;
    const role = user?.role ?? null;
    return {
      stage,
      user,
      role,
      isSuperAdmin: role === 'SuperAdmin',
      canOperate: role === 'SuperAdmin' || role === 'Admin',
      isUnrestricted: role === 'SuperAdmin' || (user !== null && user.organizationIds.length === 0),
      refresh,
      setUser,
      error: me.error,
    };
  }, [me.data, me.isPending, me.isError, me.error, refresh, setUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
}
