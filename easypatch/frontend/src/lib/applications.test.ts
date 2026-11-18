import { describe, expect, it } from 'vitest';
import { describeApplicationUpdates, isValidAppId, parseAppIds } from './applications';

describe('winget package IDs', () => {
  it('accepts plain package IDs only', () => {
    for (const id of ['Mozilla.Firefox', '7zip.7zip', 'Notepad++.Notepad++', 'Adobe.Acrobat.Reader.64-bit']) expect(isValidAppId(id)).toBe(true);
    for (const id of ['Firefox', 'Mozilla.Firefox;calc', '-Mozilla.Firefox', 'Mozilla..Firefox', 'Mozilla.Firefox --force', '9NBLGGH4NNS1']) {
      expect(isValidAppId(id)).toBe(false);
    }
  });

  it('splits pasted lists and skips duplicates ignoring case', () => {
    expect(parseAppIds('Mozilla.Firefox, 7zip.7zip\nmozilla.firefox  VideoLAN.VLC', ['videolan.vlc'])).toEqual({
      ids: ['Mozilla.Firefox', '7zip.7zip'],
      invalid: [],
    });
    expect(parseAppIds('Mozilla.Firefox calc.exe&').invalid).toEqual(['calc.exe&']);
  });

  it('describes the setting', () => {
    expect(describeApplicationUpdates(null)).toBe('Off');
    expect(describeApplicationUpdates({ enabled: true, approvedApps: [] })).toBe('On, but no applications are approved');
    expect(describeApplicationUpdates({ enabled: true, approvedApps: ['Mozilla.Firefox'] })).toBe('On for 1 application: Mozilla.Firefox');
  });
});
