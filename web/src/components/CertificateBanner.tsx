import { Link } from "react-router";
import { useApi } from "../api/hooks";
import type { TlsOverview } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { Alert } from "./ui";

/**
 * A banner across every console origin, the IP console included, for super administrators when a name's certificate is
 * missing or failing (ADR-0055): when the DNS name's certificate is gone, the IP console is often the only way in.
 */
export function CertificateBanner() {
  const { canGlobal } = useAuth();
  const allowed = canGlobal("settings.manage");
  const q = useApi<TlsOverview>(allowed ? "/settings/certificates" : null, undefined, { refetchInterval: 60_000, staleTime: 30_000 });
  const bad = (q.data?.status?.names ?? []).filter((n) => n.alert !== "none");
  if (!allowed || bad.length === 0) return null;
  const critical = bad.some((n) => n.alert === "critical");
  return (
    <div className="px-4 pt-3 sm:px-6 lg:px-8" data-testid="certificate-banner">
      <Alert tone={critical ? "danger" : "warn"}>
        {bad.length === 1 ? `The certificate for ${bad[0]!.name} needs attention.` : `${bad.length} certificates need attention: ${bad.map((n) => n.name).join(", ")}.`}{" "}
        <Link to="/settings?tab=certificates" className="underline">
          Open Settings → Certificates
        </Link>
      </Alert>
    </div>
  );
}
