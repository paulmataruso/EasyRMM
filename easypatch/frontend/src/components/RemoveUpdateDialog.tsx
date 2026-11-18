import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Undo2 } from 'lucide-react';
import { api } from '../api/client';
import { useApiMutation } from '../api/hooks';
import type { BulkResultDto } from '../api/types';
import { useAuth } from '../auth/AuthContext';
import { Dialog } from './Dialog';
import { OrganizationSelect, SiteSelect } from './Filters';
import { jobIdOf } from './InstallDialog';
import { useToast } from './Toast';
import { Alert, Button, Checkbox, InlineError, TextField } from './ui';

export interface RemovableUpdate {
  updateGuid: string;
  title: string;
}

/** What removing an update does, shared by the endpoint and fleet dialogs. */
function RemovalExplanation() {
  return (
    <Alert tone="info" title="How the update is removed">
      The agent uses Windows Update’s own uninstall when the update supports it, otherwise DISM removes the update’s package (the way
      Microsoft documents for cumulative updates). It never restarts the endpoint: when Windows needs a restart to finish, the job says so. Windows
      does not allow some updates to be removed, such as servicing stack updates and most definition updates; the job then fails and nothing changes.
    </Alert>
  );
}

function BlockFields({ block, onBlock, reason, onReason, fleet }: {
  block: boolean;
  onBlock: (value: boolean) => void;
  reason: string;
  onReason: (value: string) => void;
  fleet: boolean;
}) {
  return (
    <>
      <Checkbox
        label={fleet ? 'Exclude it on these endpoints' : 'Exclude it on this endpoint'}
        hint="EasyPatch then does not install it again (automatically or with Install all missing). Windows Update itself can still offer it if the endpoint also updates outside EasyPatch."
        checked={block}
        onChange={(e) => onBlock(e.target.checked)}
      />
      {block && (
        <TextField label="Reason (optional)" value={reason} onChange={(e) => onReason(e.target.value)} maxLength={500} placeholder="e.g. breaks printing" />
      )}
    </>
  );
}

/** Removes one installed Windows update from one endpoint. */
export function RemoveUpdateDialog({ endpointId, hostname, update, onClose }: {
  endpointId: string;
  hostname: string;
  update: RemovableUpdate | null;
  onClose: () => void;
}) {
  const toast = useToast();
  const [block, setBlock] = useState(true);
  const [reason, setReason] = useState('');
  const remove = useApiMutation(
    (vars: { guid: string; block: boolean; reason: string | null }) =>
      api.post<unknown>(`/endpoints/${endpointId}/updates/${vars.guid}/uninstall`, { block: vars.block, reason: vars.reason }),
    {
      invalidate: [`/endpoints/${endpointId}`, '/jobs', '/updates'],
      onSuccess: (result) => {
        const jobId = jobIdOf(result);
        toast.success(
          <span>
            Removal queued for {hostname}.{' '}
            {jobId && (
              <Link to={`/jobs/${jobId}`} className="text-accent hover:underline">
                View job
              </Link>
            )}
          </span>,
        );
        onClose();
      },
    },
  );
  const reset = remove.reset;
  useEffect(() => {
    if (update) {
      setBlock(true);
      setReason('');
      reset();
    }
  }, [update, reset]);

  return (
    <Dialog
      open={update !== null}
      onClose={onClose}
      title="Remove this update?"
      description={update?.title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="danger"
            icon={<Undo2 className="size-4" aria-hidden />}
            loading={remove.isPending}
            onClick={() => update && remove.mutate({ guid: update.updateGuid, block, reason: block ? reason.trim() || null : null })}
          >
            Remove update
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>
          Removes this update from <strong>{hostname}</strong>. A scan afterwards shows what Windows reports; until the endpoint restarts, the update can still
          appear as installed.
        </p>
        <RemovalExplanation />
        <BlockFields block={block} onBlock={setBlock} reason={reason} onReason={setReason} fleet={false} />
        <InlineError error={remove.error} />
      </div>
    </Dialog>
  );
}

/** Removes one installed Windows update from every endpoint in scope that reports it installed. */
export function FleetRemoveUpdateDialog({ open, onClose, guid, title, defaultOrganizationId, defaultSiteId, onDone }: {
  open: boolean;
  onClose: () => void;
  guid: string;
  title: string;
  defaultOrganizationId: string;
  defaultSiteId: string;
  onDone: (result: BulkResultDto) => void;
}) {
  const [org, setOrg] = useState(defaultOrganizationId);
  const [site, setSite] = useState(defaultSiteId);
  const { isSuperAdmin } = useAuth();
  const [block, setBlock] = useState(true);
  const [hold, setHold] = useState(false);
  const [reason, setReason] = useState('');
  const remove = useApiMutation(
    () =>
      api.post<BulkResultDto>(`/updates/${guid}/uninstall`, {
        organizationId: org || null,
        siteId: site || null,
        block,
        reason: block || hold ? reason.trim() || null : null,
        hold: hold && (!!org || isSuperAdmin),
      }),
    { invalidate: ['/updates', '/update-holds', '/jobs', '/endpoints', '/dashboard'], onSuccess: onDone },
  );
  const reset = remove.reset;
  useEffect(() => {
    if (open) {
      setOrg(defaultOrganizationId);
      setSite(defaultSiteId);
      setBlock(true);
      setHold(false);
      setReason('');
      reset();
    }
  }, [open, defaultOrganizationId, defaultSiteId, reset]);
  const holdAllowed = !!org || isSuperAdmin;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="Remove this update from endpoints"
      description={title}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(undefined)} icon={<Undo2 className="size-4" aria-hidden />}>
            Queue removals
          </Button>
        </>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <p>Creates a removal job on every endpoint, within the scope below, that reports this update as installed or waiting for a restart.</p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <OrganizationSelect value={org} onChange={(v) => { setOrg(v); setSite(''); }} />
          <SiteSelect organizationId={org} value={site} onChange={setSite} />
        </div>
        {!org && <Alert tone="warn">No organization selected: every endpoint you can access that has this update is included.</Alert>}
        <RemovalExplanation />
        <BlockFields block={block} onBlock={setBlock} reason={reason} onReason={setReason} fleet />
        <Checkbox
          label={org ? 'Also put it on hold for this organization' : 'Also put it on hold for every organization'}
          hint={
            holdAllowed
              ? 'Other endpoints then do not install it automatically either, until the hold is released on this page.'
              : 'Choose an organization: only super administrators can hold an update for every organization.'
          }
          checked={hold && holdAllowed}
          disabled={!holdAllowed}
          onChange={(e) => setHold(e.target.checked)}
        />
        {hold && holdAllowed && !block && (
          <TextField label="Reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} placeholder="e.g. breaks printing" />
        )}
        <InlineError error={remove.error} />
      </div>
    </Dialog>
  );
}
