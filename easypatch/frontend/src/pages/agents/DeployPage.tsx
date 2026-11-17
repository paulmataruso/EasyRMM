import { Navigate, useLocation } from 'react-router';
import { useAuth } from '../../auth/AuthContext';
import { PageHeader, Tabs } from '../../components/ui';
import { useUrlState } from '../../lib/urlState';
import { DeploymentCodesTab } from './DeploymentCodesTab';
import { PackagesTab } from './PackagesTab';
import { TokensTab } from './TokensTab';

export function DeployPage() {
  const url = useUrlState();
  const { canOperate } = useAuth();
  const tab = url.get('tab', 'tokens');
  return (
    <>
      <PageHeader
        title="Deploy"
        subtitle={
          canOperate
            ? 'Deploy the EasyPatch agent with enrollment tokens (msiexec on Windows, easypatch-agent enroll on Linux and the experimental macOS agent) or tokenless deployment codes (RMM scripts with approval).'
            : 'Enrollment tokens, deployment codes and agent packages.'
        }
      />
      <Tabs
        active={tab}
        onChange={(t) => url.set({ tab: t === 'tokens' ? null : t, create: null })}
        tabs={[
          { id: 'tokens', label: 'Enrollment tokens' },
          { id: 'codes', label: 'Deployment codes' },
          { id: 'packages', label: 'Agent packages' },
        ]}
      />
      {tab === 'tokens' && <TokensTab />}
      {tab === 'codes' && <DeploymentCodesTab />}
      {tab === 'packages' && <PackagesTab />}
    </>
  );
}

/** Where an old Agent Management address (/agents?tab=…) now lives: pending approvals at /approvals, the rest at /deploy. */
export function legacyAgentsTarget(search: string): string {
  const params = new URLSearchParams(search);
  if (params.get('tab') !== 'approvals') {
    return `/deploy${search}`;
  }

  params.delete('tab');
  const rest = params.toString();
  return `/approvals${rest ? `?${rest}` : ''}`;
}

export function LegacyAgentsRedirect() {
  const { search } = useLocation();
  return <Navigate to={legacyAgentsTarget(search)} replace />;
}
