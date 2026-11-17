import { describe, expect, it } from 'vitest';
import { legacyAgentsTarget } from './DeployPage';

describe('legacyAgentsTarget', () => {
  it('sends the old pending approvals tab to its own page and keeps its filters', () => {
    expect(legacyAgentsTarget('?tab=approvals')).toBe('/approvals');
    expect(legacyAgentsTarget('?tab=approvals&status=all')).toBe('/approvals?status=all');
  });

  it('sends everything else to Deploy unchanged', () => {
    expect(legacyAgentsTarget('')).toBe('/deploy');
    expect(legacyAgentsTarget('?tab=codes&organizationId=abc&create=1')).toBe('/deploy?tab=codes&organizationId=abc&create=1');
    expect(legacyAgentsTarget('?tab=packages')).toBe('/deploy?tab=packages');
  });
});
