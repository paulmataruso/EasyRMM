import { useApi } from "../../api/hooks";
import type { PatchReportsMail } from "../../api/types";
import { Alert } from "../../components/ui";

/**
 * Why the patching engine emails no reports, where reports are emailed: while a Microsoft 365
 * application signs in to EasyRMM's mail server, the engine is given none (ADR-0053). Nothing
 * otherwise, and nothing while the answer is loading or failed: the send itself says why it fails.
 */
export function ReportMailAlert({ className }: { className?: string }) {
  const mail = useApi<PatchReportsMail>("/patching/reports/mail");
  if (!mail.data?.withheld) return null;
  return (
    <Alert tone="warn" title="Reports are not emailed: the patching engine has no mail server" className={className}>
      {mail.data.withheld}
    </Alert>
  );
}
