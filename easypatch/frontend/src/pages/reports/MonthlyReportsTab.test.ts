import { describe, expect, it } from 'vitest';
import { monthLabel, parseRecipients } from './MonthlyReportsTab';

describe('monthly reports helpers', () => {
  it('parses recipient lists and drops duplicates case-insensitively', () => {
    expect(parseRecipients('it@example.com\nIT@example.com, owner@example.com;  \n')).toEqual(['it@example.com', 'owner@example.com']);
    expect(parseRecipients('   ')).toEqual([]);
  });

  it('labels a month without shifting across time zones', () => {
    const expected = new Date(2026, 9, 1).toLocaleDateString(undefined, { month: 'long', year: 'numeric' });
    expect(monthLabel('2026-10-01')).toBe(expected);
    expect(monthLabel('2026-10-31')).toBe(expected);
  });
});
