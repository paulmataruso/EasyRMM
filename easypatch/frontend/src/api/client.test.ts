import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api, buildQuery, problemMessage, setAuthErrorListener } from './client';
import { toPage } from './hooks';
import { jobIdOf } from '../components/InstallDialog';
import { resolveInherited, validatePolicy } from '../components/PolicyEditor';
import { passwordProblem, safeReturnTo } from '../pages/auth/AuthPages';
import type { PolicyDto, PolicyRequest } from './types';

function json(status: number, body: unknown, type = 'application/json'): Response {
  return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'content-type': type } });
}

describe('buildQuery', () => {
  it('skips empty values and repeats keys for arrays', () => {
    expect(buildQuery({ a: 'x', b: undefined, c: null, d: '', e: 0, f: false, g: ['1', '2'] })).toBe('?a=x&e=0&f=false&g=1&g=2');
    expect(buildQuery({})).toBe('');
    expect(buildQuery()).toBe('');
  });
  it('encodes values', () => {
    expect(buildQuery({ search: 'a b&c' })).toBe('?search=a+b%26c');
  });
});

describe('problem details', () => {
  it('prefers detail, then the first validation error, then title', () => {
    expect(problemMessage(400, { detail: 'Nope', title: 'Bad' })).toBe('Nope');
    expect(problemMessage(400, { errors: { name: ['Name is required.'] }, title: 'Validation' })).toBe('Name is required.');
    expect(problemMessage(409, { title: 'Conflict' })).toBe('Conflict');
    expect(problemMessage(503, {})).toMatch(/server/i);
  });
  it('exposes code, correlation id and extensions', () => {
    const e = new ApiError(409, { code: 'duplicate_job', correlationId: 'abc', existingJobId: 'job-1' });
    expect(e.code).toBe('duplicate_job');
    expect(e.correlationId).toBe('abc');
    expect(e.extension<string>('existingJobId')).toBe('job-1');
  });
});

describe('request', () => {
  const fetchMock = vi.fn<typeof fetch>();
  let cookie = 'XSRF-TOKEN=tok%3D1';

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubGlobal('document', {
      get cookie() {
        return cookie;
      },
    });
    cookie = 'XSRF-TOKEN=tok%3D1';
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    setAuthErrorListener(null);
  });

  it('sends same-origin requests with the XSRF header only on unsafe methods', async () => {
    fetchMock.mockResolvedValueOnce(json(200, { ok: true })).mockResolvedValueOnce(json(204, null));
    await api.get('/endpoints', { page: 2 });
    await api.post('/endpoints/1/scan');
    const [getUrl, getInit] = fetchMock.mock.calls[0];
    expect(getUrl).toBe('/api/v1/endpoints?page=2');
    expect(getInit?.credentials).toBe('same-origin');
    expect((getInit?.headers as Record<string, string>)['X-XSRF-TOKEN']).toBeUndefined();
    const [postUrl, postInit] = fetchMock.mock.calls[1];
    expect(postUrl).toBe('/api/v1/endpoints/1/scan');
    expect((postInit?.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('tok=1');
    expect(postInit?.body).toBe('{}');
  });

  it('refreshes the XSRF cookie via /auth/me and retries once on csrf_failed', async () => {
    fetchMock
      .mockResolvedValueOnce(json(403, { code: 'csrf_failed' }, 'application/problem+json'))
      .mockImplementationOnce(async () => {
        cookie = 'XSRF-TOKEN=fresh';
        return json(200, {});
      })
      .mockResolvedValueOnce(json(200, { id: 'x' }));
    await expect(api.put<{ id: string }>('/settings', { a: 1 })).resolves.toEqual({ id: 'x' });
    expect(fetchMock.mock.calls.map((c) => [c[0], c[1]?.method])).toEqual([
      ['/api/v1/settings', 'PUT'],
      ['/api/v1/auth/me', 'GET'],
      ['/api/v1/settings', 'PUT'],
    ]);
    expect((fetchMock.mock.calls[2][1]?.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('fresh');
  });

  it('notifies the auth listener on 401 and auth-stage 403s, not on plain 403s', async () => {
    const listener = vi.fn();
    setAuthErrorListener(listener);
    fetchMock
      .mockResolvedValueOnce(json(401, { code: 'unauthenticated' }, 'application/problem+json'))
      .mockResolvedValueOnce(json(403, { code: 'mfa_required' }, 'application/problem+json'))
      .mockResolvedValueOnce(json(403, { code: 'forbidden' }, 'application/problem+json'));
    await expect(api.get('/a')).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
    await expect(api.get('/b')).rejects.toMatchObject({ status: 403, code: 'mfa_required' });
    await expect(api.get('/c')).rejects.toMatchObject({ status: 403, code: 'forbidden' });
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it('maps network failures to status 0', async () => {
    fetchMock.mockRejectedValueOnce(new TypeError('Failed to fetch'));
    await expect(api.get('/x')).rejects.toMatchObject({ status: 0 });
  });
});

describe('helpers', () => {
  it('normalizes plain arrays and paged envelopes', () => {
    expect(toPage([1, 2])).toEqual({ items: [1, 2], page: 1, pageSize: 2, totalCount: 2 });
    expect(toPage({ items: [1], page: 3, pageSize: 1, totalCount: 9 }).page).toBe(3);
    expect(toPage(undefined).items).toEqual([]);
  });
  it('finds the job id in job creation responses', () => {
    expect(jobIdOf({ id: 'a' })).toBe('a');
    expect(jobIdOf({ summary: { id: 'b' } })).toBe('b');
    expect(jobIdOf(null)).toBeNull();
  });
  it('only allows same-site return paths', () => {
    expect(safeReturnTo('/endpoints?x=1')).toBe('/endpoints?x=1');
    for (const bad of [null, '', 'https://evil.example', '//evil.example', '/\\evil.example', '/login']) expect(safeReturnTo(bad)).toBe('/');
  });
  it('mirrors the password policy', () => {
    expect(passwordProblem('short', 'short')).toMatch(/12/);
    expect(passwordProblem('aaaaaaaaaaaa', 'aaaaaaaaaaaa')).toMatch(/different/);
    expect(passwordProblem('alice-is-great-2026', 'alice-is-great-2026', 'Alice')).toMatch(/username/);
    expect(passwordProblem('correct horse battery', 'correct horse batter')).toMatch(/match/);
    expect(passwordProblem('correct horse battery', 'correct horse battery', 'bob')).toBeNull();
  });
});

describe('policy editor rules', () => {
  const global: PolicyDto = {
    id: 'g',
    scope: 'Global',
    organizationId: null,
    siteId: null,
    updatedAt: null,
    checkInIntervalSeconds: 60,
    scanIntervalMinutes: 240,
    inventoryIntervalMinutes: 1440,
    jitterPercent: 10,
    allowedCategories: ['Security', 'Critical'],
    includeOptional: false,
    excludedKbs: ['KB1'],
    acceptEulas: true,
    autoInstallEnabled: false,
    maintenanceDays: null,
    maintenanceStart: null,
    maintenanceDurationMinutes: null,
    scanStaleAfterHours: 48,
    maxConcurrentInstallsPerSite: 10,
    endpointId: null,
    trayIconEnabled: true,
    installNotificationsEnabled: true,
    agentAutoUpdateEnabled: true,
    installDelayDays: 0,
    securityInstallDelayDays: 0,
    knownExploitedSkipsDelay: true,
    applicationUpdates: null,
    preDownloadHours: 0,
    restartSchedule: null,
    windowsUpdate: {
      automaticUpdates: { managed: true, value: { mode: 'AutoDownloadNotifyInstall', scheduledInstallDay: 0, scheduledInstallHour: 3 } },
      featureUpdates: null,
      qualityUpdates: { managed: true, value: { deferDays: 7, disablePause: false } },
      restartBehavior: null,
    },
  };
  const org: PolicyDto = {
    ...global,
    id: 'o',
    scope: 'Organization',
    organizationId: 'org',
    checkInIntervalSeconds: null,
    scanIntervalMinutes: null,
    inventoryIntervalMinutes: null,
    jitterPercent: null,
    allowedCategories: null,
    includeOptional: null,
    acceptEulas: null,
    autoInstallEnabled: true,
    excludedKbs: ['kb2'],
    maintenanceDays: [6],
    maintenanceStart: '01:00',
    maintenanceDurationMinutes: 120,
    scanStaleAfterHours: null,
    maxConcurrentInstallsPerSite: 3,
    trayIconEnabled: false,
    installNotificationsEnabled: null,
    agentAutoUpdateEnabled: false,
    installDelayDays: 14,
    securityInstallDelayDays: null,
    restartSchedule: { enabled: true, days: [6], time: '04:00', condition: 'OnlyIfPending', mode: 'Countdown', countdownMinutes: 10, deadlineMinutes: 240, expiryMinutes: 120 },
    windowsUpdate: {
      automaticUpdates: { managed: false, value: null },
      featureUpdates: { managed: true, value: { deferDays: 90, targetProductVersion: 'Windows 11', targetReleaseVersion: '24H2' } },
      qualityUpdates: null,
      restartBehavior: null,
    },
  };

  it('resolves inherited values layer by layer and unions exclusions', () => {
    const r = resolveInherited([global, org]);
    expect(r.checkInIntervalSeconds).toBe(60);
    expect(r.autoInstallEnabled).toBe(true);
    expect(r.maxConcurrentInstallsPerSite).toBe(3);
    expect(r.maintenanceDays).toEqual([6]);
    expect(r.maintenanceStart).toBe('01:00');
    expect(r.excludedKbs.sort()).toEqual(['KB1', 'KB2']);
    expect(r.trayIconEnabled).toBe(false);
    expect(r.installNotificationsEnabled).toBe(true);
    expect(r.agentAutoUpdateEnabled).toBe(false);
    expect(r.restartSchedule?.mode).toBe('Countdown');
    expect(r.installDelayDays).toBe(14);
    expect(r.securityInstallDelayDays).toBe(0);
  });

  it('merges Windows Update settings group by group', () => {
    const wu = resolveInherited([global, org]).windowsUpdate!;
    // The organization explicitly stops managing Automatic Updates...
    expect(wu.automaticUpdates).toEqual({ managed: false, value: null });
    // ...adds feature updates, and inherits the global quality updates.
    expect(wu.featureUpdates?.value?.targetReleaseVersion).toBe('24H2');
    expect(wu.qualityUpdates?.value?.deferDays).toBe(7);
    expect(wu.restartBehavior).toBeNull();
  });

  it('validates restart schedules and Windows Update settings like the server', () => {
    const base: PolicyRequest = { ...global };
    const schedule = org.restartSchedule!;
    expect(validatePolicy({ ...base, restartSchedule: { ...schedule, days: [] } }, true)).toMatch(/at least one day/);
    expect(validatePolicy({ ...base, restartSchedule: { ...schedule, expiryMinutes: 5 } }, true)).toMatch(/15 minutes to 24 hours/);
    expect(validatePolicy({ ...base, restartSchedule: { ...schedule, enabled: false, days: [] } }, true)).toBeNull();
    const pin = (version: string | null) => ({
      ...base,
      windowsUpdate: { ...base.windowsUpdate!, featureUpdates: { managed: true, value: { deferDays: null, targetProductVersion: 'Windows 11', targetReleaseVersion: version } } },
    });
    expect(validatePolicy(pin('24H2'), true)).toBeNull();
    expect(validatePolicy(pin('2024'), true)).toMatch(/24H2/);
    expect(validatePolicy(pin(null), true)).toMatch(/both/);
    const hours = (start: number, end: number) => ({
      ...base,
      windowsUpdate: { ...base.windowsUpdate!, restartBehavior: { managed: true, value: { noAutoRestartWithSignedInUsers: true, activeHoursStart: start, activeHoursEnd: end } } },
    });
    expect(validatePolicy(hours(8, 18), true)).toBeNull();
    expect(validatePolicy(hours(22, 6), true)).toBeNull();
    expect(validatePolicy(hours(6, 1), true)).toMatch(/1 to 18 hours/);
    expect(validatePolicy({ ...base, windowsUpdate: { ...base.windowsUpdate!, qualityUpdates: { managed: true, value: null } } }, true)).toMatch(/choose the settings/);
  });

  it('validates ranges like the server', () => {
    const base: PolicyRequest = { ...global };
    expect(validatePolicy(base, true)).toBeNull();
    expect(validatePolicy({ ...base, checkInIntervalSeconds: 14 }, true)).toMatch(/between 15 and 3600/);
    expect(validatePolicy({ ...base, jitterPercent: 51 }, true)).toMatch(/between 0 and 50/);
    expect(validatePolicy({ ...base, allowedCategories: [] }, true)).toMatch(/at least one/);
    expect(validatePolicy({ ...base, maintenanceDays: [1], maintenanceStart: '25:00', maintenanceDurationMinutes: 60 }, true)).toMatch(/start/);
    expect(validatePolicy({ ...base, maintenanceDays: [1], maintenanceStart: '02:00', maintenanceDurationMinutes: 10 }, true)).toMatch(/duration/);
    expect(validatePolicy({ ...base, checkInIntervalSeconds: null }, true)).toMatch(/required/);
    expect(validatePolicy({ ...base, checkInIntervalSeconds: null }, false)).toBeNull();
    expect(validatePolicy({ ...base, securityInstallDelayDays: 91 }, true)).toMatch(/security updates must be between 0 and 90/);
    expect(validatePolicy({ ...base, installDelayDays: 365, securityInstallDelayDays: null }, true)).toBeNull();
  });
});
