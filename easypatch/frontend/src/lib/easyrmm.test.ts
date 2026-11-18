import { describe, expect, it } from 'vitest';
import {
  cameFromEasyRmm,
  easyRmmBase,
  easyRmmTarget,
  MEMORY_KEY,
  shouldStartByItself,
  signedIn,
  signedOut,
  startingByItself,
  STARTED_KEY,
  withoutFrom,
  type Stores,
} from './easyrmm';

function memoryStore() {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (k: string) => values.get(k) ?? null,
    setItem: (k: string, v: string) => void values.set(k, v),
    removeItem: (k: string) => void values.delete(k),
  };
}

function stores() {
  const local = memoryStore();
  const session = memoryStore();
  return { local, session, stores: { local, session } satisfies Stores };
}

const ID = '0199a3b4-5c6d-7e8f-9a0b-1c2d3e4f5a6b';

describe('easyRmmTarget', () => {
  const base = 'https://rmm.example.com';
  it.each([
    [`/endpoints/${ID}`, `/go/from-easypatch/endpoints/${ID}`, 'Open this endpoint in EasyRMM'],
    [`/organizations/${ID}`, `/go/from-easypatch/organizations/${ID}`, 'Open this organization in EasyRMM'],
    [`/jobs/${ID.toUpperCase()}`, `/go/from-easypatch/jobs/${ID}`, 'Open this job in EasyRMM'],
    ['/organizations', '/organizations', 'Open EasyRMM'],
    ['/endpoints', '/patching', 'Open EasyRMM'],
    ['/updates/KB5040442', '/patching', 'Open EasyRMM'],
    ['/approvals', '/patching', 'Open EasyRMM'],
    ['/jobs', '/patching', 'Open EasyRMM'],
    ['/', '/', 'Open EasyRMM'],
    ['/settings', '/', 'Open EasyRMM'],
    ['/endpoints/not-an-id', '/patching', 'Open EasyRMM'],
    [`/endpoints/${ID}/../../admin`, '/patching', 'Open EasyRMM'],
  ])('%s → %s', (path, href, label) => {
    expect(easyRmmTarget(base, path)).toEqual({ href: base + href, label });
  });
});

describe('easyRmmBase', () => {
  it.each([
    ['https://rmm.example.com', 'https://rmm.example.com'],
    ['https://rmm.example.com/', 'https://rmm.example.com'],
    ['https://example.com/rmm/', 'https://example.com/rmm'],
    ['http://rmm.lab.test:8080', 'http://rmm.lab.test:8080'],
    ['javascript:alert(1)', null],
    ['https://user:pw@rmm.example.com', null],
    ['https://rmm.example.com/?x=1', null],
    ['not a url', null],
    [null, null],
  ])('%s → %s', (value, base) => {
    expect(easyRmmBase(value)).toBe(base);
  });
});

describe('from=easyrmm', () => {
  it('is recognised and removed from the return path', () => {
    expect(cameFromEasyRmm(`/endpoints/${ID}?tab=updates&from=easyrmm`)).toBe(true);
    expect(cameFromEasyRmm('/endpoints?from=elsewhere')).toBe(false);
    expect(withoutFrom(`/endpoints/${ID}?tab=updates&from=easyrmm`)).toBe(`/endpoints/${ID}?tab=updates`);
    expect(withoutFrom('/?from=easyrmm')).toBe('/');
    expect(withoutFrom('/jobs?status=failed')).toBe('/jobs?status=failed');
  });
});

describe('starting EasyRMM sign-in by itself', () => {
  it('happens when coming from EasyRMM, once per tab until someone signs in', () => {
    const { session, stores: s } = stores();
    expect(shouldStartByItself('/endpoints?from=easyrmm', null, s)).toBe(true);
    expect(shouldStartByItself('/endpoints', null, s)).toBe(false);
    startingByItself(s);
    expect(session.values.has(STARTED_KEY)).toBe(true);
    // Refused at EasyRMM, or Back from it: the sign-in page asks.
    expect(shouldStartByItself('/endpoints?from=easyrmm', null, s)).toBe(false);
    signedIn(true, s);
    expect(shouldStartByItself('/endpoints?from=easyrmm', null, s)).toBe(true);
  });

  it('renews the session of an account managed by EasyRMM until sign-out', () => {
    const { local, stores: s } = stores();
    signedIn(true, s);
    expect(local.values.get(MEMORY_KEY)).toBe('1');
    expect(shouldStartByItself('/jobs', null, s)).toBe(true);
    expect(shouldStartByItself('/jobs', 'easyrmm_no_access', s)).toBe(false);
    signedOut(s);
    expect(shouldStartByItself('/jobs', null, s)).toBe(false);
  });

  it('forgets EasyRMM when another account signs in here', () => {
    const { stores: s } = stores();
    signedIn(true, s);
    signedIn(false, s);
    expect(shouldStartByItself('/', null, s)).toBe(false);
  });

  it('asks when storage is blocked', () => {
    const blocked = {
      getItem: () => {
        throw new Error('blocked');
      },
      setItem: () => {
        throw new Error('blocked');
      },
      removeItem: () => {
        throw new Error('blocked');
      },
    };
    const s: Stores = { local: blocked, session: blocked };
    signedIn(true, s);
    startingByItself(s);
    expect(shouldStartByItself('/', null, s)).toBe(false);
    expect(shouldStartByItself('/?from=easyrmm', null, { local: null, session: null })).toBe(true);
  });
});
