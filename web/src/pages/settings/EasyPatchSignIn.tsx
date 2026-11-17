import { useState, type ReactNode } from "react";
import { KeyRound } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { EasyPatchSignIn as Settings, EasyPatchSignInSecret } from "../../api/types";
import { CodeBlock, CopyButton, OneTimeNotice } from "../../components/Copy";
import { ConfirmDialog, Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Alert, Button, Card, ErrorState, InlineError, KeyValueList, Mono, Spinner } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";

const KEYS = ["/settings/easypatch/sign-in", "/audit"];

function When({ at, by }: { at: string; by?: string }) {
  return (
    <span>
      <span title={formatDateTime(at)}>{formatRelative(at)}</span>
      {by && <span className="text-muted"> by {by}</span>}
    </span>
  );
}

function Copyable({ value }: { value: string }) {
  return (
    <span className="flex flex-wrap items-center gap-2">
      <Mono className="break-all">{value}</Mono>
      <CopyButton text={value} />
    </span>
  );
}

/**
 * Sign-in to EasyPatch through EasyRMM (ADR-0036): EasyRMM is EasyPatch's OpenID provider, with EasyPatch its only
 * client. A super administrator sets the client up here and copies its details into EasyPatch.
 */
export function EasyPatchSignIn() {
  const toast = useToast();
  const settings = useApi<Settings>("/settings/easypatch/sign-in");
  const [secret, setSecret] = useState<EasyPatchSignInSecret | null>(null);
  const [rotating, setRotating] = useState(false);
  const [removing, setRemoving] = useState(false);
  const create = useApiMutation(() => api.post<EasyPatchSignInSecret>("/settings/easypatch/sign-in"), { invalidate: KEYS, onSuccess: setSecret });
  const rotate = useApiMutation(() => api.post<EasyPatchSignInSecret>("/settings/easypatch/sign-in/rotate"), {
    invalidate: KEYS,
    onSuccess: (s) => {
      setRotating(false);
      setSecret(s);
    },
  });
  const remove = useApiMutation(() => api.del("/settings/easypatch/sign-in"), {
    invalidate: KEYS,
    onSuccess: () => {
      setRemoving(false);
      toast.success("Sign-in through EasyRMM is off. People sign in to EasyPatch on their own again.");
    },
  });

  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  const s = settings.data;
  const client = s.client;

  let body: ReactNode;
  if (client) {
    const moved = s.redirectUri && s.redirectUri !== client.redirectUri;
    const items: [string, ReactNode][] = [
      ["Issuer", <Copyable key="i" value={s.issuer} />],
      ["Client ID", <Copyable key="c" value={client.clientId} />],
      [
        "Redirect URI",
        <Mono key="r" className="break-all">
          {client.redirectUri}
        </Mono>,
      ],
      ["Set up", <When key="w" at={client.createdAt} by={client.createdBy} />],
    ];
    if (client.rotatedAt) items.push(["Secret replaced", <When key="r2" at={client.rotatedAt} by={client.rotatedBy} />]);
    body = (
      <div className="flex flex-col gap-4">
        <KeyValueList items={items} />
        {moved && (
          <Alert tone="warn" title="EasyPatch's address changed">
            EasyRMM sends people back only to the redirect URI above, but EasyPatch now answers at <Mono className="break-all">{s.redirectUri}</Mono>. Turn
            sign-in off and set it up again, then enter the new details in EasyPatch.
          </Alert>
        )}
        <InlineError error={rotate.error ?? remove.error} />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <p className="text-xs text-muted">The secret is stored only as a hash. Replacing it stops the old one at once.</p>
          <div className="flex gap-2">
            <Button variant="danger-ghost" onClick={() => setRemoving(true)}>
              Turn off
            </Button>
            <Button onClick={() => setRotating(true)}>Replace secret…</Button>
          </div>
        </div>
      </div>
    );
  } else if (!s.available) {
    body = <p className="text-sm text-muted">{s.reason}</p>;
  } else {
    body = (
      <div className="flex flex-col gap-4">
        <InlineError error={create.error} />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <p className="text-xs text-muted">EasyRMM creates EasyPatch's client ID and secret. You enter them in EasyPatch.</p>
          <Button variant="primary" icon={<KeyRound className="size-3.5" aria-hidden />} loading={create.isPending} onClick={() => create.mutate()}>
            Set up sign-in
          </Button>
        </div>
      </div>
    );
  }

  return (
    <Card title="Sign-in">
      <div className="flex flex-col gap-4">
        <p className="max-w-[75ch] text-sm text-muted">
          People signed in to EasyRMM with a second factor open EasyPatch without signing in again. Their EasyPatch role follows their EasyRMM roles: super
          administrators are SuperAdmins; organization administrators are Admins of their linked organizations; technicians and viewers can look there but not
          change anything. Anyone without a role in a linked organization cannot sign in this way.
        </p>
        {body}
      </div>

      <Dialog open={secret !== null} onClose={() => setSecret(null)} title="Enter these in EasyPatch" size="lg" dismissible={false}>
        {secret && (
          <div className="flex flex-col gap-3.5">
            <OneTimeNotice title="Copy the client secret now. It is shown only once.">
              In EasyPatch, open Settings → Single sign-on, add a provider, tick <span className="font-medium text-fg">This provider is EasyRMM</span>, and
              enter the issuer, client ID and secret. EasyPatch finds the rest itself.
            </OneTimeNotice>
            <KeyValueList
              items={[
                ["Issuer", <Copyable key="i" value={secret.issuer} />],
                ["Client ID", <Copyable key="c" value={secret.clientId} />],
              ]}
            />
            <div>
              <p className="mb-1.5 text-sm font-medium text-fg">Client secret</p>
              <CodeBlock code={secret.clientSecret} />
            </div>
            <div className="flex justify-end">
              <Button variant="primary" onClick={() => setSecret(null)}>
                Done
              </Button>
            </div>
          </div>
        )}
      </Dialog>
      <ConfirmDialog
        open={rotating}
        onClose={() => setRotating(false)}
        onConfirm={() => rotate.mutate()}
        loading={rotate.isPending}
        error={rotate.error}
        title="Replace the client secret?"
        confirmLabel="Replace"
      >
        The current secret stops working at once: nobody can sign in to EasyPatch through EasyRMM until you enter the new one in EasyPatch.
      </ConfirmDialog>
      <ConfirmDialog
        open={removing}
        onClose={() => setRemoving(false)}
        onConfirm={() => remove.mutate()}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title="Turn off sign-in through EasyRMM?"
        confirmLabel="Turn off"
      >
        EasyPatch can no longer sign anyone in through EasyRMM. People already signed in to EasyPatch stay signed in until their session ends, at most an hour.
      </ConfirmDialog>
    </Card>
  );
}
