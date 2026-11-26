import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient, type QueryKey } from "@tanstack/react-query";
import { ApiError, request, setAuthErrorListener, setCsrfToken } from "../api/client";
import type { Permission, SessionView, SetupStatus } from "../api/types";

/** Where the browser is in the sign-in pipeline. */
export type AuthStage = "loading" | "error" | "setup" | "anonymous" | "mfa" | "mfa-setup" | "ready";

/** The organization, and optionally the site in it, a permission is checked at. */
export interface PermissionScope {
  organizationId: string;
  siteId?: string;
}

export const SESSION_KEY: QueryKey = ["auth", "session"];

interface SessionResult {
  setupRequired: boolean;
  session: SessionView | null;
}

interface AuthContextValue {
  stage: AuthStage;
  session: SessionView | null;
  /** True after the server ended the session (expiry, revocation), so sign-in can say why. */
  sessionEnded: boolean;
  isSuperAdmin: boolean;
  /** Whether the user holds the permission in at least one scope. */
  can: (permission: Permission) => boolean;
  /**
   * Whether the user holds the permission at an organization or site: platform-wide, over the whole organization, or
   * (for a site) at that site. Pass `siteId` with its `organizationId`; without `siteId` it is the organization level.
   */
  canAt: (permission: Permission, scope: PermissionScope) => boolean;
  /** Whether the user holds the permission platform-wide. */
  canGlobal: (permission: Permission) => boolean;
  refresh: () => Promise<void>;
  /** Applies a session view the server just returned (sign-in, MFA). */
  applySession: (view: SessionView | null) => void;
  signOut: () => Promise<void>;
  /**
   * While one-time recovery codes are on screen the enrollment page must stay put, even if a
   * background refresh already sees the session as fully signed in.
   */
  showingRecoveryCodes: boolean;
  setShowingRecoveryCodes: (value: boolean) => void;
  /** The administrator email from a setup that just finished, so sign-in can welcome them and pre-fill it. */
  setupEmail: string | null;
  /**
   * Records a finished setup, then re-reads the server state. The route guard moves the browser from
   * /setup to /login on its own; the email travels here rather than in a navigate() that races the guard.
   */
  completeSetup: (email: string) => Promise<void>;
  error: unknown;
}

const AuthContext = createContext<AuthContextValue | null>(null);

async function fetchSession(signal: AbortSignal): Promise<SessionResult> {
  const setup = await request<SetupStatus>("GET", "/setup", { signal, silentAuth: true });
  if (setup.required) return { setupRequired: true, session: null };
  try {
    const session = await request<SessionView>("GET", "/auth/session", { signal, silentAuth: true });
    setCsrfToken(session.csrfToken);
    return { setupRequired: false, session };
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) {
      setCsrfToken(null);
      return { setupRequired: false, session: null };
    }
    throw e;
  }
}

export function stageFor(result: SessionResult | undefined): AuthStage {
  if (!result) return "loading";
  if (result.setupRequired) return "setup";
  switch (result.session?.state) {
    case undefined:
      return "anonymous";
    case "mfa_required":
      return "mfa";
    case "mfa_enrollment":
      return "mfa-setup";
    default:
      return "ready";
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const [sessionEnded, setSessionEnded] = useState(false);
  const [showingRecoveryCodes, setShowingRecoveryCodes] = useState(false);
  const [setupEmail, setSetupEmail] = useState<string | null>(null);
  const query = useQuery<SessionResult>({
    queryKey: SESSION_KEY,
    queryFn: ({ signal }) => fetchSession(signal),
    staleTime: 60_000,
    refetchInterval: 5 * 60_000,
    retry: (count, error) => !(error instanceof ApiError && error.status > 0 && error.status < 500) && count < 2,
  });

  const dropCache = useCallback(() => {
    client.removeQueries({ predicate: (q) => q.queryKey[0] !== SESSION_KEY[0] });
  }, [client]);

  // Any API call that reports the session gone (or back at its second factor) re-evaluates the session.
  useEffect(() => {
    setAuthErrorListener((error) => {
      if (error.status === 401) {
        setCsrfToken(null);
        setSessionEnded(true);
        client.setQueryData<SessionResult>(SESSION_KEY, { setupRequired: false, session: null });
        dropCache();
      } else {
        void client.invalidateQueries({ queryKey: SESSION_KEY });
      }
    });
    return () => setAuthErrorListener(null);
  }, [client, dropCache]);

  const refresh = useCallback(async () => {
    await client.invalidateQueries({ queryKey: SESSION_KEY });
    await client.refetchQueries({ queryKey: SESSION_KEY });
  }, [client]);

  const applySession = useCallback(
    (view: SessionView | null) => {
      setCsrfToken(view?.csrfToken ?? null);
      if (view) {
        setSessionEnded(false);
        setSetupEmail(null);
      }
      client.setQueryData<SessionResult>(SESSION_KEY, { setupRequired: false, session: view });
      if (!view) dropCache();
    },
    [client, dropCache],
  );

  const completeSetup = useCallback(
    async (email: string) => {
      setSetupEmail(email);
      await refresh();
    },
    [refresh],
  );

  const signOut = useCallback(async () => {
    try {
      await request("POST", "/auth/logout", { silentAuth: true });
    } catch {
      // The session is discarded locally either way.
    }
    applySession(null);
  }, [applySession]);

  const value = useMemo<AuthContextValue>(() => {
    const data = query.data;
    const stage: AuthStage = query.isPending ? "loading" : query.isError && !data ? "error" : stageFor(data);
    const session = data?.session ?? null;
    const permissions = new Set(session?.state === "active" ? session.permissions : []);
    const global = new Set(session?.state === "active" ? (session.globalPermissions ?? []) : []);
    // A server that does not send scopes (older than this field) leaves the any-scope answer.
    const scoped = session?.state === "active" ? session.scopedPermissions : undefined;
    return {
      stage,
      session,
      sessionEnded,
      isSuperAdmin: session?.state === "active" && session.isSuperAdmin,
      can: (p) => permissions.has(p),
      canAt: (p, scope) => {
        if (global.has(p)) return true;
        if (!scoped) return permissions.has(p);
        const where = scoped[p];
        if (!where) return false;
        return where.organizations.includes(scope.organizationId) || (!!scope.siteId && where.sites.includes(scope.siteId));
      },
      canGlobal: (p) => global.has(p),
      refresh,
      applySession,
      signOut,
      showingRecoveryCodes,
      setShowingRecoveryCodes,
      setupEmail,
      completeSetup,
      error: query.error,
    };
  }, [query.data, query.isPending, query.isError, query.error, sessionEnded, showingRecoveryCodes, setupEmail, refresh, applySession, signOut, completeSetup]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
}
