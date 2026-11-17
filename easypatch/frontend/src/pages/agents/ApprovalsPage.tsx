import { PageHeader } from '../../components/ui';
import { ApprovalsTab } from './ApprovalsTab';

export function ApprovalsPage() {
  return (
    <>
      <PageHeader
        title="Pending Approvals"
        subtitle="Computers installed with a deployment code wait here. Compare the key fingerprint with the one the install script printed, then approve or reject them."
      />
      <ApprovalsTab />
    </>
  );
}
