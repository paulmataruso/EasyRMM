let cached: string[] | null = null;

/** IANA time zone names supported by this browser (used for suggestions; the server validates). */
export function timeZones(): string[] {
  if (cached) return cached;
  try {
    const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
    cached = intl.supportedValuesOf ? ['UTC', ...intl.supportedValuesOf('timeZone').filter((z) => z !== 'UTC')] : ['UTC'];
  } catch {
    cached = ['UTC'];
  }
  return cached;
}

export function browserTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC';
  } catch {
    return 'UTC';
  }
}
