import { useState, type ReactNode } from "react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Device, EnrollmentTokenInput, NewEnrollmentToken, TlsTrust, TlsTrustCheck } from "../../api/types";
import { Alert, Button, Card, InlineError, Mono } from "../../components/ui";
import { formatDateTime, formatRelative } from "../../lib/format";
import { InstallSteps, type Platform } from "./AddDevicesPage";

// What a device's agent really trusts (ADR-0055, slice 5b1). The server asks the agent to verify the certificate chains a name
// is served with, on the computer itself, and keeps the answers. Nothing here changes a name or a certificate. A device that
// cannot verify the chain its name falls back to is shown as unprotected; one that is cut off is offered a reinstall through
// a remote session, which checks no certificate chain.

const SCOPES: Record<TlsTrustCheck["scope"], string> = { agent: "EasyRMM agent", easypatch: "EasyPatch agent" };
const PURPOSES: Record<TlsTrustCheck["purpose"], string> = {
  served: "The certificate served now",
  fallback: "The certificate this name falls back to",
  target: "The certificate this name is moving to",
};
const TRUSTS: Record<NonNullable<TlsTrust["trusts"]>, string> = {
  system: "the computer's root certificates",
  "ca-file": "the server's certificate authority only",
  "system+ca-file": "the computer's root certificates and the server's certificate authority",
};

/** What a check's state says, in words. */
export function checkResult(c: Pick<TlsTrustCheck, "state" | "error">): string {
  switch (c.state) {
    case "passed":
      return "Verified";
    case "failed":
      return c.error ? `Cannot verify: ${c.error}` : "Cannot verify";
    default:
      return "Not reported yet";
  }
}

/** True when there is something to show: a result, a refusal, or a reinstall to offer. */
export function hasTrustToShow(t: TlsTrust | undefined): t is TlsTrust {
  return Boolean(t && (t.checks.length > 0 || t.refused || t.reinstall));
}

/** The command's operating system: Windows unless the device runs Linux. */
export function platformOf(device: Pick<Device, "platform">): Platform {
  return device.platform === "linux" ? "linux" : "windows";
}

/** The trust of a device's agent, from what it verified. Shows nothing for a device that has not been asked. */
export function AgentTrustCard({ device, terminal }: { device: Device; terminal: ReactNode }) {
  const trust = useApi<TlsTrust>(device.agent ? `/devices/${device.id}/tls-trust` : null, undefined, { refetchInterval: 30_000 });
  const t = trust.data;
  if (!hasTrustToShow(t)) return null;
  return (
    <Card title="Certificate trust" className="mb-5">
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          The EasyRMM agent was asked to verify the certificates this server uses, on the computer itself.
          {t.trusts && <> It trusts {TRUSTS[t.trusts]}.</>}
          {t.widened && <> A move widened its trust.</>}
        </p>
        {t.unprotected && (
          <Alert tone="warn" title="Unprotected">
            This device cannot verify the certificate its name falls back to. If the name fell back to it, the device would be cut off.
          </Alert>
        )}
        {t.refused && <Alert tone="warn" title="The agent refused the last instruction">{t.refused}</Alert>}
        {t.checks.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted">
                <tr>
                  <th className="py-1 pr-3 font-medium">Whose trust</th>
                  <th className="py-1 pr-3 font-medium">Certificate</th>
                  <th className="py-1 pr-3 font-medium">Result</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {t.checks.map((c) => (
                  <tr key={`${c.scope}/${c.host}/${c.purpose}`}>
                    <td className="py-1.5 pr-3 align-top">
                      {SCOPES[c.scope]}
                      {c.standIn && (
                        <span className="block text-xs text-muted" title="The EasyRMM agent read the computer's certificate bundle for it; the EasyPatch agent may read another.">
                          Checked by the EasyRMM agent
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 align-top">
                      {PURPOSES[c.purpose]} for <Mono>{c.host}</Mono>
                    </td>
                    <td className="py-1.5 pr-3 align-top">
                      <span className={c.state === "failed" ? "text-danger" : c.state === "passed" ? "text-ok" : "text-muted"}>{checkResult(c)}</span>
                      {c.checkedAt && (
                        <span className="block text-xs text-muted" title={formatDateTime(c.checkedAt)}>
                          {formatRelative(c.checkedAt)}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {t.reinstall && <ReinstallThroughRemoteSession device={device} trust={t} terminal={terminal} />}
      </div>
    </Card>
  );
}

/**
 * Reinstall through a remote session (ADR-0055): a terminal through MeshAgent, which checks no TLS chain and stays connected,
 * with the install command and the fix for what the agent reported. The command needs a deployment token: one use, one day.
 */
function ReinstallThroughRemoteSession({ device, trust, terminal }: { device: Device; trust: TlsTrust; terminal: ReactNode }) {
  const [created, setCreated] = useState<NewEnrollmentToken | null>(null);
  const create = useApiMutation(
    () => api.post<NewEnrollmentToken>(`/sites/${trust.siteId}/enrollment-tokens`, { name: `Reinstall ${device.name}`, deviceGroupId: null, expiresInDays: 1, maxUses: 1 } satisfies EnrollmentTokenInput),
    { invalidate: ["/enrollment-tokens", "/audit"], onSuccess: setCreated },
  );
  return (
    <section className="rounded-md border border-line p-3" aria-label="Reinstall through a remote session">
      <h3 className="text-sm font-semibold text-fg">Reinstall through a remote session</h3>
      <p className="mt-1 text-sm text-muted">{trust.reinstall?.reason}</p>
      <p className="mt-1 text-sm text-fg">{trust.reinstall?.fix}</p>
      <ol className="mt-3 flex list-decimal flex-col gap-3 pl-5 text-sm">
        <li>
          <span className="block">Open a terminal on the device through MeshAgent. It does not check the server&apos;s certificate, so it works while the agent cannot connect.</span>
          <div className="mt-1.5">
            {trust.canTerminal && device.canTerminal ? terminal : <span className="text-muted">A terminal is not available on this device now: remote access is not connected, or you may not open one.</span>}
          </div>
        </li>
        <li>
          <span className="block">Run the install command in it. The deployment token is for this one install and expires in a day.</span>
          <div className="mt-1.5">
            {created ? (
              <InstallSteps
                secret={created.secret}
                serverUrl={created.serverUrl}
                initialPlatform={platformOf(device)}
                onDone={() => setCreated(null)}
                notice={<>One use, valid for a day, for {created.token.siteName}. Revoke it under Deployment tokens if it is not used.</>}
                details={[
                  ["Token", created.token.name],
                  ["Site", `${created.token.organizationName} / ${created.token.siteName}`],
                  ["Expires", formatDateTime(created.token.expiresAt)],
                ]}
              />
            ) : (
              <>
                <Button onClick={() => create.mutate(undefined)} loading={create.isPending}>
                  Create install command
                </Button>
                {create.isError && <InlineError error={create.error} />}
              </>
            )}
          </div>
        </li>
      </ol>
    </section>
  );
}
