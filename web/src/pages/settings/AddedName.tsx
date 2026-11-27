import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type {
  TlsAddedName,
  TlsAddedNameState,
  TlsNameCheck,
} from "../../api/types";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Badge,
  Button,
  Card,
  InlineError,
  TextField,
} from "../../components/ui";
import { formatRelative } from "../../lib/format";

const PATH = "/settings/certificates/added-name";

const STATE_LABEL: Record<TlsAddedNameState, string> = {
  pending: "Waiting for certificates",
  trusted: "Trusted",
  untrusted: "Not trusted (agent route only)",
};

const STATE_TONE: Record<TlsAddedNameState, "warn" | "ok" | "danger"> = {
  pending: "warn",
  trusted: "ok",
  untrusted: "danger",
};

interface Status {
  eligible: boolean;
  pair?: TlsAddedName;
}

/**
 * Adding a name to an installation set up on an IP address (ADR-0055, 5b3). The operator types the console's name, the
 * page checks that both names point at this server, then Let's Encrypt certificates are obtained and agents are asked to
 * verify the authority's second certificate for the names. Nothing is shown on installs that already have a DNS name.
 */
export function AddedName() {
  const q = useApi<Status>(PATH, undefined, { refetchInterval: 10_000 });
  const pair = q.data?.pair;
  const host =
    typeof window === "undefined" ? "" : window.location.hostname.toLowerCase();
  const onName =
    pair !== undefined && (host === pair.console || host === pair.mesh);

  // A signed-in person who loaded the console through the name is proof that it reaches this server.
  useEffect(() => {
    if (onName) void api.post(`${PATH}/browser-confirm`).catch(() => undefined);
  }, [onName]);

  if (q.isPending || q.isError || q.data === undefined) return null;
  if (pair) return <Pair pair={pair} />;
  if (!q.data.eligible) return null;
  return <Add />;
}

function Add() {
  const toast = useToast();
  const [consoleName, setConsole] = useState("");
  const [meshName, setMesh] = useState("");
  const [meshEdited, setMeshEdited] = useState(false);
  const [checks, setChecks] = useState<TlsNameCheck[] | null>(null);
  const [confirm, setConfirm] = useState(false);
  const body = { console: consoleName.trim(), mesh: meshName.trim() };
  const check = useApiMutation(
    () => api.post<{ checks: TlsNameCheck[] }>(`${PATH}/check`, body),
    { onSuccess: (r) => setChecks(r.checks) },
  );
  const add = useApiMutation(() => api.post(PATH, body), {
    invalidate: [PATH, "/settings/certificates", "/audit"],
    onSuccess: () => {
      setConfirm(false);
      toast.success("The name was added. Certificates are being obtained.");
    },
  });
  const allPoint =
    checks !== null && checks.length > 0 && checks.every((c) => c.points);
  const reset = () => setChecks(null);

  return (
    <Card title="Add a name">
      <div className="flex flex-col gap-3 text-sm">
        <p>
          This installation is reached by an IP address, so browsers warn about
          its certificate. Add a DNS name to get a Let&apos;s Encrypt
          certificate browsers trust. Agents already installed keep working
          through the IP address.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <TextField
            label="Console name"
            placeholder="rmm.example.com"
            value={consoleName}
            onChange={(e) => {
              setConsole(e.target.value);
              if (!meshEdited)
                setMesh(
                  e.target.value.trim() === ""
                    ? ""
                    : `mesh.${e.target.value.trim()}`,
                );
              reset();
            }}
          />
          <TextField
            label="Remote-access name"
            hint="On the same site as the console's name."
            value={meshName}
            onChange={(e) => {
              setMesh(e.target.value);
              setMeshEdited(true);
              reset();
            }}
          />
        </div>
        <p className="text-muted">
          Create an A (and AAAA) record for each name with this server&apos;s
          public address, then check them.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            disabled={consoleName.trim() === "" || check.isPending}
            onClick={() => check.mutate(undefined)}
          >
            Check the names
          </Button>
          <Button
            variant="primary"
            disabled={!allPoint || add.isPending}
            onClick={() => setConfirm(true)}
          >
            Agree and get certificates…
          </Button>
        </div>
        {checks && (
          <ul className="flex flex-col gap-1">
            {checks.map((c) => (
              <li key={c.name} className="flex flex-wrap items-center gap-2">
                <Badge tone={c.points ? "ok" : "danger"}>
                  {c.points ? "Points here" : "Not ready"}
                </Badge>
                <strong>{c.name}</strong>
                {c.addresses.length > 0 && (
                  <span className="text-muted">{c.addresses.join(", ")}</span>
                )}
                {c.error && <span className="text-muted">{c.error}</span>}
              </li>
            ))}
          </ul>
        )}
        <InlineError error={check.error ?? add.error} />
      </div>
      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => add.mutate(undefined)}
        title={`Add ${body.console} and ${body.mesh}?`}
        confirmLabel="Agree and get certificates"
        loading={add.isPending}
        error={add.error}
      >
        <p>
          By continuing you agree to Let&apos;s Encrypt&apos;s subscriber
          agreement. Certificates are obtained for both names; until they are in
          hand nothing changes. The names serve agents with this server&apos;s
          own authority until then. You will be asked to confirm it is you.
        </p>
      </ConfirmDialog>
    </Card>
  );
}

function Pair({ pair }: { pair: TlsAddedName }) {
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  const remove = useApiMutation(() => api.del(PATH), {
    invalidate: [PATH, "/settings/certificates", "/audit"],
    onSuccess: () => {
      setConfirm(false);
      toast.success("The name pair was removed.");
    },
  });
  const resend = useApiMutation(() => api.post(`${PATH}/resend`), {
    onSuccess: () => toast.success("Agents were asked again."),
  });
  const names = [pair.console, pair.mesh];
  return (
    <Card title={`Added name: ${pair.console}`}>
      <div className="flex flex-col gap-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={STATE_TONE[pair.state]}>{STATE_LABEL[pair.state]}</Badge>
          <span className="text-muted">
            Added {formatRelative(pair.addedAt)}
          </span>
        </div>
        <ul className="flex flex-col gap-1">
          {names.map((n) => (
            <li key={n} className="flex flex-wrap items-center gap-2">
              <Badge tone={pair.held[n] ? "ok" : "warn"}>
                {pair.held[n]
                  ? "Certificate in hand"
                  : "Waiting for the certificate"}
              </Badge>
              <strong>{n}</strong>
            </li>
          ))}
        </ul>
        <div>
          <Badge tone={pair.reachable ? "ok" : "danger"}>
            {pair.reachable ? "Reachable" : "Not reached"}
          </Badge>{" "}
          <span className="text-muted">
            Server fetch:{" "}
            {pair.lastFetchOkAt
              ? `succeeded ${formatRelative(pair.lastFetchOkAt)}`
              : "no success yet"}
            . Browser:{" "}
            {pair.lastBrowserOkAt
              ? formatRelative(pair.lastBrowserOkAt)
              : "none yet"}
            .
          </span>
        </div>
        {pair.lastFetchError && (
          <Alert tone="warn">
            The last fetch through the name failed: {pair.lastFetchError}
          </Alert>
        )}
        <p>
          Agents asked to verify the authority&apos;s certificate for the names:{" "}
          {pair.agentsPassed} of {pair.agentsAsked} have.
        </p>
        <div className="flex flex-wrap gap-2">
          <Button
            variant="secondary"
            disabled={resend.isPending}
            onClick={() => resend.mutate(undefined)}
          >
            Ask agents again
          </Button>
          <Button variant="danger-ghost" onClick={() => setConfirm(true)}>
            Remove name…
          </Button>
        </div>
        <InlineError error={resend.error} />
      </div>
      <ConfirmDialog
        open={confirm}
        onClose={() => setConfirm(false)}
        onConfirm={() => remove.mutate(undefined)}
        title={`Remove ${pair.console}?`}
        confirmLabel="Remove name"
        loading={remove.isPending}
        error={remove.error}
      >
        <p>
          The console, links and sign-in return to the IP address. The names
          keep serving the agent API with the authority&apos;s certificate, so
          agents enrolled through them keep working. You will be asked to
          confirm it is you.
        </p>
      </ConfirmDialog>
    </Card>
  );
}
