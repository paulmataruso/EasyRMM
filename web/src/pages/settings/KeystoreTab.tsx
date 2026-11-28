import { useState } from "react";
import { useApi, useApiMutation } from "../../api/hooks";
import { api } from "../../api/client";
import type { KeystoreInitResponse, KeystoreStatus } from "../../api/types";
import { KeystoreAlerts } from "../../components/KeystoreAlerts";
import { keystoreNotice } from "../devices/DeviceRecoveryKeys";
import {
  Alert,
  Badge,
  Button,
  Card,
  ErrorState,
  Spinner,
  TableWrap,
  TextField,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";

const STATE_TONE = {
  unsealed: "ok",
  sealed: "danger",
  unavailable: "danger",
  uninitialised: "warn",
} as const;

function InitWizard({ onDone }: { onDone: () => void }) {
  const [step, setStep] = useState<"passphrase" | "recovery" | "verify">("passphrase");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [initResult, setInitResult] = useState<KeystoreInitResponse | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [error, setError] = useState("");

  const initMut = useApiMutation(
    (vars: { mode: string; passphrase: string }) =>
      api.post<KeystoreInitResponse>("/keystore/init", vars),
    { invalidate: ["/keystore"] },
  );

  const verifyMut = useApiMutation(
    (vars: { bundle: string; code: string }) =>
      api.post<{ version: number }>("/keystore/verify-recovery", vars),
    {
      invalidate: ["/keystore"],
      onSuccess: () => onDone(),
    },
  );

  const handleInit = async () => {
    setError("");
    if (passphrase.length < 16) {
      setError("The passphrase must be at least 16 characters.");
      return;
    }
    if (passphrase !== confirm) {
      setError("The two passphrases do not match.");
      return;
    }
    try {
      const result = await initMut.mutateAsync({ mode: "passphrase", passphrase });
      setInitResult(result);
      setStep("recovery");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Init failed.");
    }
  };

  const handleVerify = async () => {
    setError("");
    if (!initResult) return;
    try {
      await verifyMut.mutateAsync({ bundle: initResult.bundlePath, code: verifyCode });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Verification failed.");
    }
  };

  if (step === "passphrase") {
    return (
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted">
          The keystore protects recovery keys. Choose a passphrase that unseals it
          after each restart. It must be at least 16 characters.
        </p>
        {error && <Alert tone="danger">{error}</Alert>}
        <TextField
          type="password"
          label="Passphrase"
          value={passphrase}
          onChange={(e) => setPassphrase(e.target.value)}
          autoComplete="new-password"
        />
        <TextField
          type="password"
          label="Confirm passphrase"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
        />
        <div>
          <Button onClick={handleInit} disabled={initMut.isPending}>
            {initMut.isPending ? "Initialising…" : "Initialise keystore"}
          </Button>
        </div>
      </div>
    );
  }

  if (step === "recovery") {
    return (
      <div className="flex flex-col gap-4">
        <Alert tone="warn">
          Copy this recovery code now. It is shown once and kept nowhere. Without it
          and the bundle the keystore cannot be restored.
        </Alert>
        <div className="rounded border border-line bg-surface-sunken p-4 font-mono text-lg select-all break-all">
          {initResult?.recoveryCode}
        </div>
        <p className="text-sm text-muted">
          Bundle path: <code className="text-xs">{initResult?.bundlePath}</code>
        </p>
        <div>
          <Button onClick={() => setStep("verify")}>
            I have copied the recovery code
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted">
        Type the recovery code to prove you have it.
      </p>
      {error && <Alert tone="danger">{error}</Alert>}
      <TextField
        label="Recovery code"
        value={verifyCode}
        onChange={(e) => setVerifyCode(e.target.value)}
        autoComplete="off"
      />
      <div>
        <Button onClick={handleVerify} disabled={verifyMut.isPending}>
          {verifyMut.isPending ? "Verifying…" : "Verify recovery code"}
        </Button>
      </div>
    </div>
  );
}

function UnsealForm({ onDone }: { onDone: () => void }) {
  const [passphrase, setPassphrase] = useState("");
  const [error, setError] = useState("");
  const unseal = useApiMutation(
    (vars: { passphrase: string }) => api.post("/keystore/unseal", vars),
    {
      invalidate: ["/keystore"],
      onSuccess: () => onDone(),
    },
  );

  const handleUnseal = async () => {
    setError("");
    try {
      await unseal.mutateAsync({ passphrase });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unseal failed.");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted">
        The keystore is sealed. Enter the passphrase to unseal it.
      </p>
      {error && <Alert tone="danger">{error}</Alert>}
      <TextField
        type="password"
        label="Passphrase"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
        autoComplete="current-password"
      />
      <div>
        <Button onClick={handleUnseal} disabled={unseal.isPending}>
          {unseal.isPending ? "Unsealing…" : "Unseal"}
        </Button>
      </div>
    </div>
  );
}

export function KeystoreTab() {
  const q = useApi<KeystoreStatus>("/keystore", undefined, {
    refetchInterval: 30_000,
    staleTime: 10_000,
  });
  const notice = q.data
    ? keystoreNotice({
        state: q.data.state,
        recoveryVerified: q.data.recoveryVerified,
        detail: q.data.detail,
        fileMode: q.data.mode === "file",
      })
    : null;
  return (
    <div className="flex flex-col gap-4">
      <Card title="Keystore">
        {q.isPending ? (
          <Spinner />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} compact />
        ) : q.data.state === "uninitialised" ? (
          <InitWizard onDone={() => void q.refetch()} />
        ) : q.data.state === "sealed" ? (
          <UnsealForm onDone={() => void q.refetch()} />
        ) : (
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Badge tone={STATE_TONE[q.data.state]}>{q.data.state}</Badge>
              {q.data.mode && (
                <span className="text-muted">protected by {q.data.mode}</span>
              )}
              {q.data.detail && (
                <span className="text-muted">({q.data.detail})</span>
              )}
            </div>
            {notice && <Alert tone="warn">{notice}</Alert>}
            {q.data.versions.length > 0 && (
              <TableWrap>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-xs text-muted">
                      <th className="px-3 py-2 font-medium">Version</th>
                      <th className="px-3 py-2 font-medium">Made</th>
                      <th className="px-3 py-2 font-medium">Recovery</th>
                      <th className="px-3 py-2 font-medium">In use</th>
                      <th className="px-3 py-2 font-medium">Keys it wraps</th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.versions.map((v) => (
                      <tr key={v.version} className="border-b border-line last:border-0">
                        <td className="px-3 py-2">
                          v{v.version}
                          {v.version === q.data.primary && (
                            <span className="ml-2 text-xs text-muted">primary</span>
                          )}
                        </td>
                        <td className="px-3 py-2">{formatDateTime(v.createdAt)}</td>
                        <td className="px-3 py-2">
                          {v.recoveryVerifiedAt ? (
                            <Badge tone="ok">
                              verified {formatDateTime(v.recoveryVerifiedAt)}
                            </Badge>
                          ) : (
                            <Badge tone="warn">not verified</Badge>
                          )}
                        </td>
                        <td className="px-3 py-2">{v.open ? "yes" : "no"}</td>
                        <td className="px-3 py-2">
                          {q.data.kekUsage?.find((u) => u.version === v.version)?.keys ?? 0}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            )}
          </div>
        )}
      </Card>
      <Card title="Keystore alerts">
        <KeystoreAlerts canResolve />
      </Card>
    </div>
  );
}
