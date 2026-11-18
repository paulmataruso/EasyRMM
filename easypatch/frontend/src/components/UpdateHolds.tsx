import { useEffect, useState } from 'react';
import { PauseCircle, PlayCircle } from 'lucide-react';
import { api } from '../api/client';
import { useApiMutation } from '../api/hooks';
import type { CreateUpdateHoldRequest, UpdateHoldDto } from '../api/types';
import { useAuth } from '../auth/AuthContext';
import { formatDateTime } from '../lib/format';
import { Dialog } from './Dialog';
import { OrganizationSelect } from './Filters';
import { useToast } from './Toast';
import { Alert, Button, InlineError, TextField } from './ui';

const INVALIDATE = ['/updates', '/update-holds', '/endpoints', '/alerts'];

function scopeText(hold: UpdateHoldDto): string {
  return hold.organizationId ? `for ${hold.organizationName ?? 'one organization'}` : 'for every organization';
}

/** Active holds of an update, each with a release button when the administrator may release it. */
export function UpdateHoldBanner({ holds }: { holds: UpdateHoldDto[] }) {
  const toast = useToast();
  const release = useApiMutation((hold: UpdateHoldDto) => api.post<UpdateHoldDto>(`/update-holds/${hold.id}/release`, {}), {
    invalidate: INVALIDATE,
    onSuccess: (hold) => toast.success(`Hold released ${scopeText(hold)}. Scheduled installations include the update again.`),
  });
  if (holds.length === 0) return null;
  return (
    <div className="mb-5 flex flex-col gap-3">
      {holds.map((hold) => (
        <Alert key={hold.id} tone="warn" title={`On hold ${scopeText(hold)}`}>
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <p>{hold.reason}</p>
              <p className="mt-1 text-xs">
                {hold.source === 'Automatic' ? 'Held automatically by the rollout guard' : `Held by ${hold.createdBy}`} on {formatDateTime(hold.createdAt)}.
                EasyPatch does not install it automatically (maintenance windows and Install all missing). Selecting it on an endpoint still installs it.
              </p>
            </div>
            {hold.canRelease && (
              <Button
                size="sm"
                icon={<PlayCircle className="size-4" aria-hidden />}
                loading={release.isPending && release.variables?.id === hold.id}
                onClick={() => release.mutate(hold)}
              >
                Release hold
              </Button>
            )}
          </div>
        </Alert>
      ))}
      <InlineError error={release.error} />
    </div>
  );
}

/** Puts an update on hold for one organization, or for every organization (super administrators). */
export function HoldUpdateDialog({ open, onClose, guid, title, defaultOrganizationId }: {
  open: boolean;
  onClose: () => void;
  guid: string;
  title: string;
  defaultOrganizationId: string;
}) {
  const { isSuperAdmin } = useAuth();
  const toast = useToast();
  const [org, setOrg] = useState(defaultOrganizationId);
  const [reason, setReason] = useState('');
  const hold = useApiMutation((req: CreateUpdateHoldRequest) => api.post<UpdateHoldDto>(`/updates/${guid}/holds`, req), {
    invalidate: INVALIDATE,
    onSuccess: (h) => {
      toast.success(`Update held ${scopeText(h)}.`);
      onClose();
    },
  });
  const reset = hold.reset;
  useEffect(() => {
    if (open) {
      setOrg(defaultOrganizationId);
      setReason('');
      reset();
    }
  }, [open, defaultOrganizationId, reset]);
  const needsOrg = !org && !isSuperAdmin;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Put this update on hold"
      description={title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            icon={<PauseCircle className="size-4" aria-hidden />}
            loading={hold.isPending}
            disabled={!reason.trim() || needsOrg}
            onClick={() => hold.mutate({ organizationId: org || null, reason: reason.trim() })}
          >
            Hold update
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>
          While the update is on hold, EasyPatch leaves it out of scheduled installations and Install all missing, including jobs already queued. It can still be
          installed by selecting it on an endpoint. Release the hold on this page.
        </p>
        <OrganizationSelect value={org} onChange={setOrg} allLabel={isSuperAdmin ? 'Every organization' : 'Choose an organization'} />
        {needsOrg && <Alert tone="info">Only super administrators can hold an update for every organization.</Alert>}
        <TextField label="Reason" required value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} placeholder="e.g. breaks printing" />
        <InlineError error={hold.error} />
      </div>
    </Dialog>
  );
}
