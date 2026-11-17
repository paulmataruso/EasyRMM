import type { ApplicationUpdateSettings } from '../api/types';

/** Same rule as the server and the agent (ApplicationIds.IsValid): a winget package ID such as Mozilla.Firefox. */
const APP_ID = /^[A-Za-z0-9][A-Za-z0-9_+-]*(\.[A-Za-z0-9_+-]+)+$/;

export const MAX_APPROVED_APPS = 100;

export function isValidAppId(id: string): boolean {
  return id.length >= 3 && id.length <= 128 && APP_ID.test(id);
}

/** Splits pasted text (commas, spaces or new lines) into package IDs; IDs already in `existing` are skipped. */
export function parseAppIds(text: string, existing: readonly string[] = []): { ids: string[]; invalid: string[] } {
  const seen = new Set(existing.map((id) => id.toLowerCase()));
  const ids: string[] = [];
  const invalid: string[] = [];
  for (const token of text.split(/[\s,;]+/)) {
    if (!token) continue;
    if (!isValidAppId(token)) {
      invalid.push(token);
      continue;
    }
    const key = token.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    ids.push(token);
  }
  return { ids, invalid };
}

/** Common machine-wide applications in the winget community repository. */
export const SUGGESTED_APPS: readonly { id: string; name: string }[] = [
  { id: 'Mozilla.Firefox', name: 'Firefox' },
  { id: '7zip.7zip', name: '7-Zip' },
  { id: 'Notepad++.Notepad++', name: 'Notepad++' },
  { id: 'VideoLAN.VLC', name: 'VLC' },
  { id: 'Adobe.Acrobat.Reader.64-bit', name: 'Acrobat Reader (64-bit)' },
  { id: 'Zoom.Zoom', name: 'Zoom' },
  { id: 'PuTTY.PuTTY', name: 'PuTTY' },
  { id: 'WinSCP.WinSCP', name: 'WinSCP' },
];

export function describeApplicationUpdates(settings: ApplicationUpdateSettings | null | undefined): string {
  if (!settings || !settings.enabled) return 'Off';
  const n = settings.approvedApps.length;
  if (n === 0) return 'On, but no applications are approved';
  return `On for ${n} application${n === 1 ? '' : 's'}: ${settings.approvedApps.slice(0, 5).join(', ')}${n > 5 ? ', …' : ''}`;
}
