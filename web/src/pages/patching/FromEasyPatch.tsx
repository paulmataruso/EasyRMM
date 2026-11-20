import { Navigate, useParams } from "react-router";
import { useApi } from "../../api/hooks";
import type { EasyPatchLanding } from "../../api/types";
import { ErrorState, PageHeader, Spinner } from "../../components/ui";

/**
 * A link from the patching engine: /go/from-easypatch/endpoints/:id, organizations/:id,
 * jobs/:id or alerts/:id (an organization's alerts), in the engine's ids, as its alert messages carry them. The
 * server says which page that is here; when nothing matches, Patching opens with a notice.
 * The console asks with its own request, so EasyRMM's session cookie (SameSite=Strict) comes along even though the
 * link was followed from another site.
 */
export function FromEasyPatchPage() {
  const { kind = "", id = "" } = useParams();
  const landing = useApi<EasyPatchLanding>(`/patching/from-easypatch/${encodeURIComponent(kind)}/${encodeURIComponent(id)}`, undefined, { staleTime: 0 });
  if (landing.isPending) return <Spinner label="Opening…" />;
  if (landing.isError) {
    return (
      <>
        <PageHeader title="Link from the patching engine" />
        <ErrorState error={landing.error} onRetry={() => void landing.refetch()} />
      </>
    );
  }
  const { path, notice } = landing.data;
  return <Navigate to={path} replace state={notice ? { notice } : undefined} />;
}
