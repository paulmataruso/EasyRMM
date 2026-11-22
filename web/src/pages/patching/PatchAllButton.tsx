import { useState } from "react";
import { Download, Zap } from "lucide-react";
import { useAuth } from "../../auth/AuthContext";
import { Button } from "../../components/ui";
import { InstallDialog } from "./PatchDialogs";
import { scopeLabel, usePatchScope } from "./scopeParts";

/**
 * Patch all on an organization's page, or Update all now on a site's: an install on every device there, for those who
 * may patch there. Nothing for anyone else, or while the organization is not linked to the patching engine.
 */
export function PatchAllButton({ organizationId, siteId, preset }: { organizationId: string; siteId?: string; preset?: "update-now" }) {
  const { can } = useAuth();
  const scope = usePatchScope(can("patch.manage") ? { organizationId, siteId } : null);
  const [open, setOpen] = useState(false);
  const s = scope.data;
  if (!s?.canManage) return null;
  const updateNow = preset === "update-now";
  return (
    <>
      <Button icon={updateNow ? <Zap className="size-4" aria-hidden /> : <Download className="size-4" aria-hidden />} onClick={() => setOpen(true)}>
        {updateNow ? "Update all now…" : "Patch all…"}
      </Button>
      <InstallDialog
        open={open}
        onClose={() => setOpen(false)}
        scope={{ organizationId, siteId, label: scopeLabel(s.organizationName, s.siteName) }}
        preset={preset}
      />
    </>
  );
}
