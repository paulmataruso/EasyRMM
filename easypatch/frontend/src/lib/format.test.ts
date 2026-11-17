import { describe, expect, it } from 'vitest';
import {
  dayBoundary,
  describeAgentPackage,
  describeKeyProtection,
  describeSkipReason,
  describeUserAgent,
  formatBytes,
  formatDate,
  formatDays,
  formatDuration,
  formatPackageFormat,
  formatPercent,
  formatRelative,
  formatVersionChange,
  humanize,
  isLinux,
  isMacOS,
  isValidTime,
  isWindows,
  jobItemPercent,
  MACOS_EXPERIMENTAL,
  normalizeKb,
  osDetails,
  platformName,
  truncate,
} from './format';
import { aggregateTrend } from './trend';

describe('normalizeKb', () => {
  it('accepts KB numbers with or without the prefix, any case, surrounding spaces', () => {
    expect(normalizeKb('KB5030219')).toBe('KB5030219');
    expect(normalizeKb('kb5030219')).toBe('KB5030219');
    expect(normalizeKb(' 5030219 ')).toBe('KB5030219');
    expect(normalizeKb('1')).toBe('KB1');
  });
  it('rejects anything else', () => {
    expect(normalizeKb('')).toBeNull();
    expect(normalizeKb('KB')).toBeNull();
    expect(normalizeKb('KB12345678901')).toBeNull();
    expect(normalizeKb('KB50-30219')).toBeNull();
    expect(normalizeKb('Q5030219')).toBeNull();
  });
});

describe('isValidTime', () => {
  it('accepts 24 h HH:mm', () => {
    expect(isValidTime('00:00')).toBe(true);
    expect(isValidTime('02:30')).toBe(true);
    expect(isValidTime('23:59')).toBe(true);
  });
  it('rejects malformed times', () => {
    for (const v of ['24:00', '2:30', '02:60', '0230', '', '02:30:00']) expect(isValidTime(v)).toBe(false);
  });
});

describe('formatting', () => {
  it('formats bytes', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(null)).toBe('—');
  });
  it('formats percentages and durations', () => {
    expect(formatPercent(87.4)).toBe('87%');
    expect(formatPercent(null)).toBe('—');
    expect(formatDuration(180)).toBe('3 h');
    expect(formatDuration(90)).toBe('1 h 30 min');
    expect(formatDuration(45)).toBe('45 min');
    expect(formatDuration(1440)).toBe('1 day');
    expect(formatDuration(10080)).toBe('7 days');
    expect(formatDuration(1500)).toBe('25 h');
  });
  it('humanizes enum values', () => {
    expect(humanize('WaitingForReboot')).toBe('Waiting for restart');
    expect(humanize('DotNet')).toBe('.NET');
    expect(humanize('ServicingStack')).toBe('Servicing stack');
    expect(humanize('AppleSoftwareUpdate')).toBe('Apple software update');
    expect(humanize(null)).toBe('—');
  });
  it('formats maintenance days', () => {
    expect(formatDays([0, 6])).toContain('Sun');
    expect(formatDays([])).toBe('No days');
  });
  it('keeps date-only values on their calendar day in every time zone', () => {
    expect(formatDate('2026-11-13')).toMatch(/13/);
  });
  it('formats relative times', () => {
    const now = Date.parse('2026-11-13T12:00:00Z');
    expect(formatRelative('2026-11-13T11:55:00Z', now)).toMatch(/5/);
    expect(formatRelative('2026-11-13T11:59:50Z', now)).toBe('just now');
    expect(formatRelative(null, now)).toBe('never');
  });
  it('truncates with an ellipsis', () => {
    expect(truncate('abcdef', 4)).toBe('abc…');
    expect(truncate('abc', 4)).toBe('abc');
  });
  it('explains skip reasons', () => {
    expect(describeSkipReason('CategoryNotAllowed')).toBe('Category not allowed by policy');
    expect(describeSkipReason('SomethingNew')).toBe('SomethingNew');
    expect(describeSkipReason(null)).toBe('');
  });
  it('describes user agents', () => {
    expect(describeUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36 Edg/141.0')).toBe(
      'Edge on Windows',
    );
    expect(describeUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 15_1) Gecko/20100101 Firefox/144.0')).toBe('Firefox on macOS');
    expect(describeUserAgent(null)).toBe('Unknown device');
  });
});

describe('dayBoundary', () => {
  it('covers the whole local day', () => {
    const start = new Date(dayBoundary('2026-11-13', false)!);
    const end = new Date(dayBoundary('2026-11-13', true)!);
    expect(start.getHours()).toBe(0);
    expect(start.getDate()).toBe(13);
    expect(end.getHours()).toBe(23);
    expect(end.getMilliseconds()).toBe(999);
    expect(end.getTime() - start.getTime()).toBeGreaterThan(22 * 3600_000);
  });
  it('ignores empty or malformed input', () => {
    expect(dayBoundary('', true)).toBeUndefined();
    expect(dayBoundary('garbage', false)).toBeUndefined();
  });
});

describe('aggregateTrend', () => {
  const point = (date: string, total: number, compliant: number) => ({
    date,
    totalEndpoints: total,
    compliant,
    missingUpdates: total - compliant,
    failedUpdates: 0,
    rebootRequired: 0,
    scanStale: 0,
    neverScanned: 0,
    offline: 0,
    missingRequiredUpdates: 0,
    compliancePercent: total ? (compliant / total) * 100 : 0,
  });
  it('merges per-organization points by date and recomputes the percentage', () => {
    const out = aggregateTrend([point('2026-11-02', 10, 10), point('2026-11-01', 4, 1), point('2026-11-02', 30, 10)]);
    expect(out.map((p) => p.date)).toEqual(['2026-11-01', '2026-11-02']);
    expect(out[1].totalEndpoints).toBe(40);
    expect(out[1].compliant).toBe(20);
    expect(out[1].compliancePercent).toBe(50);
  });
});

describe('platforms', () => {
  it('treats only "Linux" (any case) as Linux', () => {
    expect(isLinux('Linux')).toBe(true);
    expect(isLinux('linux')).toBe(true);
    expect(isLinux('Windows')).toBe(false);
    expect(isLinux(null)).toBe(false);
    expect(isLinux(undefined)).toBe(false);
    expect(isLinux('macOS')).toBe(false);
  });
  it('tells macOS apart, so it is never shown as Windows', () => {
    expect(isMacOS('macOS')).toBe(true);
    expect(isMacOS('macos')).toBe(true);
    expect(isMacOS('Linux')).toBe(false);
    expect(isMacOS(null)).toBe(false);
    expect(isWindows('macOS')).toBe(false);
    expect(isWindows('Linux')).toBe(false);
    expect(isWindows('Windows')).toBe(true);
    // Agents before 1.3.0 did not report a platform; they only ran on Windows.
    expect(isWindows(null)).toBe(true);
    expect(platformName('macOS')).toBe('macOS');
    expect(platformName('Linux')).toBe('Linux');
    expect(platformName(undefined)).toBe('Windows');
    expect(MACOS_EXPERIMENTAL).toBe('Experimental: the macOS agent is in development and not for production use.');
  });
  it('describes the OS version: build on Windows, kernel on Linux, version and build on macOS', () => {
    expect(osDetails({ platform: 'Windows', operatingSystem: 'Windows 11 Pro', osVersion: '23H2', osBuild: '22631.4317' })).toEqual(['23H2', 'build 22631.4317']);
    expect(osDetails({ platform: 'Windows', operatingSystem: null, osVersion: null, osBuild: null })).toEqual([]);
    // VERSION_ID is dropped when PRETTY_NAME already contains it.
    expect(osDetails({ platform: 'Linux', operatingSystem: 'Ubuntu 24.04.1 LTS', osVersion: '24.04', osBuild: '6.8.0-45-generic' })).toEqual([
      'kernel 6.8.0-45-generic',
    ]);
    expect(osDetails({ platform: 'Linux', operatingSystem: 'Rocky Linux', osVersion: '9.4', osBuild: '5.14.0-427.el9.x86_64' })).toEqual([
      '9.4',
      'kernel 5.14.0-427.el9.x86_64',
    ]);
    // The macOS version is dropped when the OS name already contains it; the build is the Apple build, not the kernel.
    expect(osDetails({ platform: 'macOS', operatingSystem: 'macOS Sequoia 15.7.2', osVersion: '15.7.2', osBuild: '24G325' })).toEqual(['build 24G325']);
    expect(osDetails({ platform: 'macOS', operatingSystem: 'macOS Sequoia', osVersion: '15.7.2', osBuild: '24G325' })).toEqual(['15.7.2', 'build 24G325']);
  });
  it('describes key protection', () => {
    expect(describeKeyProtection('systemd-creds-host')).toBe('systemd-creds (host key)');
    expect(describeKeyProtection('file-permissions')).toBe('File permissions only');
    expect(describeKeyProtection(null)).toBe('—');
    expect(describeKeyProtection('something-new')).toBe('something-new');
  });
  it('formats package versions and formats', () => {
    expect(formatVersionChange('3.0.13-0ubuntu3.1', '3.0.13-0ubuntu3.4')).toBe('3.0.13-0ubuntu3.1 → 3.0.13-0ubuntu3.4');
    expect(formatVersionChange(null, '1.2-3')).toBe('1.2-3');
    expect(formatVersionChange(null, null)).toBe('—');
    expect(formatPackageFormat('deb')).toBe('DEB');
    expect(formatPackageFormat('pkg')).toBe('macOS package (.pkg)');
    expect(formatPackageFormat(null)).toBe('—');
    expect(describeAgentPackage('msi')).toBe('MSI package');
    expect(describeAgentPackage('rpm')).toBe('RPM package');
    expect(describeAgentPackage('pkg')).toBe('macOS package (.pkg)');
    expect(describeAgentPackage(null)).toBe('package');
  });
});

describe('jobItemPercent', () => {
  it('shows the percentage of the phase the update is in', () => {
    expect(jobItemPercent({ status: 'Downloading', downloadPercent: 42, installPercent: null })).toBe(42);
    expect(jobItemPercent({ status: 'Installing', downloadPercent: 100, installPercent: 7 })).toBe(7);
  });

  it('shows nothing when the agent reported no percentage or the update is not in progress', () => {
    expect(jobItemPercent({ status: 'Installing', downloadPercent: 100, installPercent: null })).toBeNull();
    expect(jobItemPercent({ status: 'Succeeded', downloadPercent: 100, installPercent: 100 })).toBeNull();
    expect(jobItemPercent({ status: 'Downloading' })).toBeNull();
  });

  it('keeps the value between 0 and 100', () => {
    expect(jobItemPercent({ status: 'Downloading', downloadPercent: 140 })).toBe(100);
  });
});
