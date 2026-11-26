// A device's BitLocker recovery-key escrow, volume by volume (ADR-0081). It shows where each volume's recovery key
// stands and why. The key itself is never in this list: a person with the read permission reveals it on request, once
// (RevealRecoveryKey), and the approvers of a two-person organization decide the requests here.
import { useAuth } from "../../auth/AuthContext";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type {
  DeviceEscrow,
  EscrowState,
  KeystoreSummary,
  RecoveryKeyRequest,
} from "../../api/types";
import {
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  InlineError,
  Mono,
  Spinner,
  TableWrap,
} from "../../components/ui";
import { formatRelative } from "../../lib/format";
import { EnableBitLocker } from "./EnableBitLocker";
import { RevealRecoveryKey } from "./RevealRecoveryKey";

export const ESCROW_STATE_TEXT: Record<
  EscrowState,
  {
    label: string;
    tone: "ok" | "warn" | "danger" | "neutral" | "info";
    help: string;
  }
> = {
  verified: {
    label: "Verified",
    tone: "ok",
    help: "The keystore opened the sealed key and it matches what the device holds.",
  },
  pending: {
    label: "Pending",
    tone: "info",
    help: "Stored, waiting for the keystore to check it.",
  },
  missing: {
    label: "Missing",
    tone: "warn",
    help: "No recovery key is escrowed for this volume yet.",
  },
  stale: {
    label: "Stale",
    tone: "danger",
    help: "The sealed key did not match. The agent sends it again.",
  },
  conflict: {
    label: "Conflict",
    tone: "danger",
    help: "A different key arrived for a protector that already has a verified one. The verified one is kept.",
  },
  cannot_escrow: {
    label: "Cannot escrow",
    tone: "warn",
    help: "Only a passphrase unlocks this volume, so the agent cannot add a key slot of its own. Nothing was changed on it.",
  },
  escrow_off: {
    label: "Escrow off",
    tone: "neutral",
    help: "LUKS escrow is off for this organization. Turn it on in the organization's Recovery keys tab.",
  },
  not_encrypted: {
    label: "Not encrypted",
    tone: "warn",
    help: "BitLocker is not on this volume. Turning it on escrows and verifies the recovery key before encryption starts.",
  },
  managed_elsewhere: {
    label: "Managed elsewhere",
    tone: "neutral",
    help: "Clevis or the distribution's own scheme manages how this volume unlocks. EasyRMM does not rewrite it.",
  },
};

/** Why escrow is not running, in words, or null while the keystore is ready. */
export function keystoreNotice(k: KeystoreSummary): string | null {
  switch (k.state) {
    case "uninitialised":
      return "The keystore is not initialised, so recovery-key escrow is off. Run easyrmm-keystore init at the host.";
    case "sealed":
      return `The keystore is sealed${k.detail ? ` (${k.detail})` : ""}. Keys already escrowed stay safe; new ones wait until it is unsealed at the host.`;
    case "unavailable":
      return "The keystore cannot be reached, so escrow waits.";
    default:
      return k.recoveryVerified
        ? null
        : "The keystore's recovery has not been verified, so it wraps nothing yet. Run easyrmm-keystore verify-recovery.";
  }
}

/** The requests a second person may decide for this device. */
function Approvals({ deviceId }: { deviceId: string }) {
  const q = useApi<{ requests: RecoveryKeyRequest[] }>(
    "/keystore/requests",
    undefined,
    { refetchInterval: 15_000, staleTime: 5_000 },
  );
  const decide = useApiMutation(
    (v: { id: string; approve: boolean }) =>
      api.post<RecoveryKeyRequest>(
        `/keystore/requests/${v.id}/${v.approve ? "approve" : "deny"}`,
      ),
    {
      invalidate: ["/keystore/requests"],
    },
  );
  const open = (q.data?.requests ?? []).filter(
    (r) => r.deviceId === deviceId && r.canDecide,
  );
  if (open.length === 0) return null;
  return (
    <div className="flex flex-col gap-2 border-t border-line p-4">
      <h3 className="text-sm font-medium text-fg">Waiting for your decision</h3>
      <InlineError error={decide.error} />
      <ul className="flex flex-col gap-2">
        {open.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-3 text-sm">
            <span>
              <strong className="font-medium">{r.requester}</strong> asks for
              the key of <Mono>{r.volume}</Mono>: “{r.reason}”
              {r.ticket ? ` (${r.ticket})` : ""}
            </span>
            <span className="ml-auto flex gap-2">
              <Button
                size="sm"
                variant="secondary"
                loading={decide.isPending}
                onClick={() => decide.mutate({ id: r.id, approve: false })}
              >
                Refuse
              </Button>
              <Button
                size="sm"
                loading={decide.isPending}
                onClick={() => decide.mutate({ id: r.id, approve: true })}
              >
                Approve
              </Button>
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function RecoveryKeysCard({
  deviceId,
  deviceName = "",
  hideWhenEmpty = false,
}: {
  deviceId: string;
  /** The computer's name, which turning BitLocker on asks to have typed. */
  deviceName?: string;
  /** Linux computers mostly have no LUKS volume: the card shows only when one was reported. */
  hideWhenEmpty?: boolean;
}) {
  const { can } = useAuth();
  const q = useApi<DeviceEscrow>(`/devices/${deviceId}/escrow`, undefined, {
    refetchInterval: 60_000,
    staleTime: 15_000,
  });
  if (q.isPending) return <Spinner />;
  if (q.isError)
    return (
      <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
    );
  const e = q.data;
  if (!e.applicable || (hideWhenEmpty && e.volumes.length === 0)) return null;
  const notice = keystoreNotice(e.keystore);
  return (
    <Card title="Disk recovery keys" padded={false}>
      <div className="flex flex-col gap-3 p-4">
        {notice && <Alert tone="info">{notice}</Alert>}
        {e.keystore.fileMode && (
          <Alert tone="warn" title="Keystore protection: file (stand-in)">
            The keystore’s key is in a file on the host; a copy of the host’s
            disk opens it.
          </Alert>
        )}
        <p className="text-xs text-muted">
          The agent seals each recovery key to your organization’s key before it
          leaves the device. The server stores it and has the keystore check it;
          it cannot open it.{" "}
          {e.canRead
            ? "You may reveal a key: it asks for your second factor and a reason, is shown once, and your administrators are told."
            : "Reading a key needs the Recovery Key Reader add-on."}
          {e.canRead && e.twoPerson
            ? " Your organization asks for a second person to approve each read."
            : ""}
        </p>
        <p className="text-xs text-muted">
          Anyone who can run scripts or open a terminal on an online device can
          read its BitLocker key there without the keystore; the keystore
          protects the keys of devices that are offline, lost or dead.
        </p>
        {e.volumes.some((v) => v.kind === "luks") && (
          <p className="text-xs text-muted">
            On Linux the agent adds a key slot of its own to a LUKS volume it
            can unlock by itself (a key file in /etc/crypttab or a TPM2 token)
            and escrows that passphrase. A volume only a passphrase unlocks
            cannot be escrowed this way.
          </p>
        )}
      </div>
      {e.volumes.length === 0 ? (
        <div className="border-t border-line">
          <EmptyState title="No encrypted volumes reported" compact>
            Volumes appear once the agent has the organization’s key and finds
            BitLocker (Windows) or LUKS (Linux) on a disk.
          </EmptyState>
        </div>
      ) : (
        <TableWrap>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-y border-line text-left text-xs text-muted">
                <th className="px-4 py-2 font-medium">Volume</th>
                <th className="px-4 py-2 font-medium">Recovery key</th>
                <th className="px-4 py-2 font-medium">Protectors</th>
              </tr>
            </thead>
            <tbody>
              {e.volumes.map((v) => {
                const t = ESCROW_STATE_TEXT[v.state];
                return (
                  <tr key={v.id} className="border-b border-line last:border-0">
                    <td className="px-4 py-2 align-top">
                      <span className="font-medium text-fg">
                        {v.mount || "Volume"}
                      </span>
                      <span className="ml-2 text-xs text-muted">
                        {v.kind === "luks" ? `LUKS (${v.status})` : v.status}
                      </span>
                    </td>
                    <td className="px-4 py-2 align-top">
                      <Badge tone={t.tone} title={t.help}>
                        {t.label}
                      </Badge>
                      {v.reason && (
                        <p className="mt-1 max-w-xs text-xs text-muted">
                          {v.reason}
                        </p>
                      )}
                      {v.state === "not_encrypted" && e.canEnable && deviceName && (
                        <span className="ml-2">
                          <EnableBitLocker
                            deviceId={deviceId}
                            deviceName={deviceName}
                            volume={v.id}
                            mount={v.mount}
                            onDone={() => void q.refetch()}
                          />
                        </span>
                      )}
                      {v.protectors.length === 0 && !v.reason && v.state !== "not_encrypted" && (
                        <span className="ml-2 text-xs text-muted">
                          {v.kind === "luks"
                            ? "No key slot of EasyRMM's yet"
                            : "No recovery password protector"}
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 align-top">
                      <ul className="flex flex-col gap-1">
                        {v.protectors.map((p) => (
                          <li
                            key={p.id}
                            className="flex flex-wrap items-center gap-2"
                          >
                            <Mono>{p.id}</Mono>
                            <Badge
                              tone={ESCROW_STATE_TEXT[p.state].tone}
                              title={ESCROW_STATE_TEXT[p.state].help}
                            >
                              {ESCROW_STATE_TEXT[p.state].label}
                            </Badge>
                            {p.verifiedAt && (
                              <span className="text-xs text-muted">
                                verified {formatRelative(p.verifiedAt)}
                              </span>
                            )}
                            {p.rotationDue && (
                              <Badge
                                tone="info"
                                title="This key was read. The agent adds a new one, escrows and verifies it, and only then removes this one."
                              >
                                Will be replaced
                              </Badge>
                            )}
                            {e.canRead && p.state === "verified" && (
                              <RevealRecoveryKey
                                deviceId={deviceId}
                                volume={v.id}
                                protector={p.id}
                                mount={v.mount}
                              />
                            )}
                          </li>
                        ))}
                      </ul>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </TableWrap>
      )}
      {can("device.recovery_key.approve") && <Approvals deviceId={deviceId} />}
    </Card>
  );
}
