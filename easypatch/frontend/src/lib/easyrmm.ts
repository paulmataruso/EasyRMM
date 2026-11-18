// Signing in through EasyRMM, which owns EasyPatch (EasyRMM's ADR-0036; integration plan 6.1, 6.2 and 6.4).
//
// * An account managed by EasyRMM sees the EasyRMM | EasyPatch switch. It links to EasyRMM's /go/from-easypatch/…, which
//   opens EasyRMM's page for what this page shows.
// * Its sessions last at most an hour. The browser remembers (localStorage) that it signs in through EasyRMM, so when the
//   session ends the sign-in page starts EasyRMM's sign-in by itself instead of asking.
// * Someone arriving from EasyRMM (`from=easyrmm`) is sent on to EasyRMM's sign-in the same way.
// * Either happens at most once per tab (sessionStorage) until a sign-in succeeds, so neither a refusal nor Back can loop.

/** Remembers, in this browser, that the last account signed in here signs in through EasyRMM. */
export const MEMORY_KEY = 'easypatch.signInThroughEasyRmm';
/** Set when the sign-in page starts EasyRMM's sign-in by itself; cleared once someone is signed in. */
export const STARTED_KEY = 'easypatch.easyRmmSignInStarted';

/** The two stores, injectable for tests. */
export interface Stores {
  local: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null;
  session: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> | null;
}

function browserStores(): Stores {
  const get = (name: 'localStorage' | 'sessionStorage') => {
    try {
      return window[name];
    } catch {
      return null; // blocked storage
    }
  };
  return { local: get('localStorage'), session: get('sessionStorage') };
}

function read(store: Stores['local'], key: string): string | null {
  try {
    return store?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

function write(store: Stores['local'], key: string, value: string | null): void {
  try {
    if (value === null) store?.removeItem(key);
    else store?.setItem(key, value);
  } catch {
    // Storage unavailable: the sign-in page then simply asks.
  }
}

/** Called whenever the signed-in account is known: remembers whether it signs in through EasyRMM, and ends the once-per-tab guard. */
export function signedIn(managedByEasyRmm: boolean, stores: Stores = browserStores()): void {
  write(stores.local, MEMORY_KEY, managedByEasyRmm ? '1' : null);
  write(stores.session, STARTED_KEY, null);
}

/** Signing out: the next sign-in page asks again. */
export function signedOut(stores: Stores = browserStores()): void {
  write(stores.local, MEMORY_KEY, null);
}

/** Whether `returnTo` (a path with a query) carries `from=easyrmm`, added by EasyRMM's links into EasyPatch. */
export function cameFromEasyRmm(returnTo: string): boolean {
  return new URL(returnTo, 'https://easypatch.invalid').searchParams.get('from') === 'easyrmm';
}

/** `returnTo` without EasyRMM's `from` marker. */
export function withoutFrom(returnTo: string): string {
  const url = new URL(returnTo, 'https://easypatch.invalid');
  if (!url.searchParams.has('from')) return returnTo;
  url.searchParams.delete('from');
  return `${url.pathname}${url.search}${url.hash}`;
}

/**
 * Whether the sign-in page should start EasyRMM's sign-in by itself: the visitor came from EasyRMM or last signed in here through
 * it, the page is not showing a sign-in error, and it has not already done so in this tab since the last successful sign-in.
 */
export function shouldStartByItself(returnTo: string, ssoError: string | null, stores: Stores = browserStores()): boolean {
  if (ssoError) return false;
  if (read(stores.session, STARTED_KEY)) return false;
  return cameFromEasyRmm(returnTo) || read(stores.local, MEMORY_KEY) === '1';
}

/** Records that the sign-in page started EasyRMM's sign-in in this tab. */
export function startingByItself(stores: Stores = browserStores()): void {
  write(stores.session, STARTED_KEY, String(Date.now()));
}

/** EasyRMM's address with no trailing slash, or null unless it is an http(s) URL without credentials, query or fragment. */
export function easyRmmBase(value: string | null | undefined): string | null {
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password || url.search || url.hash) return null;
  return `${url.origin}${url.pathname}`.replace(/\/+$/, '');
}

export interface EasyRmmTarget {
  href: string;
  /** The link's accessible name and tooltip. */
  label: string;
}

const ID = '[0-9a-fA-F-]{36}';
const LINKED: { pattern: RegExp; kind: 'endpoints' | 'organizations' | 'jobs'; label: string }[] = [
  { pattern: new RegExp(`^/endpoints/(${ID})/?$`), kind: 'endpoints', label: 'Open this endpoint in EasyRMM' },
  { pattern: new RegExp(`^/organizations/(${ID})/?$`), kind: 'organizations', label: 'Open this organization in EasyRMM' },
  { pattern: new RegExp(`^/jobs/(${ID})/?$`), kind: 'jobs', label: 'Open this job in EasyRMM' },
];

/**
 * EasyRMM's page for the EasyPatch page at `pathname`. EasyRMM resolves an endpoint, organization or job through
 * /go/from-easypatch (and says so when it does not link one); patching lists open EasyRMM's Patching page.
 */
export function easyRmmTarget(base: string, pathname: string): EasyRmmTarget {
  for (const { pattern, kind, label } of LINKED) {
    const match = pattern.exec(pathname);
    if (match) return { href: `${base}/go/from-easypatch/${kind}/${match[1].toLowerCase()}`, label };
  }
  if (pathname === '/organizations' || pathname.startsWith('/organizations/')) return { href: `${base}/organizations`, label: 'Open EasyRMM' };
  if (/^\/(endpoints|jobs|updates|approvals)(\/|$)/.test(pathname)) return { href: `${base}/patching`, label: 'Open EasyRMM' };
  return { href: `${base}/`, label: 'Open EasyRMM' };
}
