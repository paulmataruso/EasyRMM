import { useState } from "react";
import { Plus, RefreshCw, Trash2 } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import { useToast } from "../../components/Toast";
import {
  Alert,
  Badge,
  Button,
  Card,
  ErrorState,
  InlineError,
  SelectField,
  Spinner,
  TableWrap,
  TextField,
} from "../../components/ui";
import { formatDateTime } from "../../lib/format";

interface DNSCredential {
  id: string;
  provider: "rfc2136" | "cloudflare";
  zone: string;
  overrideDomain: string;
  serverAddr?: string;
  testedAt?: string;
  testOk: boolean;
  createdAt: string;
  updatedAt: string;
}

type TestReason = "ok" | "refused" | "timed_out" | "not_authorized" | "zone_not_found" | "unknown";

const TEST_LABEL: Record<TestReason, string> = {
  ok: "Passed",
  refused: "Refused by the server",
  timed_out: "Timed out",
  not_authorized: "Not authorized (check the TSIG key)",
  zone_not_found: "Zone not found",
  unknown: "Failed",
};

const base = "/settings/certificates/dns";

export function DNSProviders() {
  const q = useApi<{ credentials: DNSCredential[] }>(base, undefined, { refetchInterval: 30_000 });
  const [adding, setAdding] = useState(false);

  if (q.isPending) return <Spinner />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;

  return (
    <Card
      title="DNS-01 Providers"
      actions={
        <Button variant="secondary" onClick={() => setAdding(!adding)}>
          <Plus className="size-4" aria-hidden /> {adding ? "Cancel" : "Add provider"}
        </Button>
      }
    >
      <p className="mb-3 text-sm text-muted">
        For servers Let's Encrypt cannot reach on port 80 or 443 (internal networks, a VPN). Credentials
        are tested when saved and never shown again.
      </p>
      <Alert tone="info" className="mb-4">
        <strong>Delegation:</strong> if the zone is only reachable inside your network, create a CNAME{" "}
        <code>_acme-challenge.rmm.example.com</code> pointing to a name in a public zone, and enter
        that public zone as the override domain.
      </Alert>

      {adding && <AddForm onDone={() => { setAdding(false); void q.refetch(); }} />}

      {q.data.credentials.length === 0 && !adding && (
        <p className="text-sm text-muted">No DNS providers configured.</p>
      )}

      {q.data.credentials.length > 0 && (
        <TableWrap>
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className="text-left">Provider</th>
                <th className="text-left">Zone</th>
                <th className="text-left">Override</th>
                <th className="text-left">Test</th>
                <th className="text-left">Last tested</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {q.data.credentials.map((c) => (
                <CredRow key={c.id} c={c} onDelete={() => void q.refetch()} />
              ))}
            </tbody>
          </table>
        </TableWrap>
      )}
    </Card>
  );
}

function CredRow({ c, onDelete }: { c: DNSCredential; onDelete: () => void }) {
  const toast = useToast();
  const retest = useApiMutation(() => api.post<{ testResult: TestReason }>(`${base}/${c.id}/test`), {
    invalidate: [base],
    onSuccess: (r) => toast.success(`Test: ${TEST_LABEL[r.testResult]}`),
  });
  const remove = useApiMutation(() => api.del(`${base}/${c.id}`), {
    onSuccess: () => { toast.success("DNS provider removed."); onDelete(); },
  });

  return (
    <tr>
      <td>{c.provider === "rfc2136" ? "RFC 2136" : "Cloudflare"}</td>
      <td className="font-mono text-xs">{c.zone}</td>
      <td className="font-mono text-xs">{c.overrideDomain || "—"}</td>
      <td>
        <Badge tone={c.testOk ? "ok" : "danger"}>{c.testOk ? "OK" : "Failed"}</Badge>
      </td>
      <td className="text-muted">{c.testedAt ? formatDateTime(c.testedAt) : "never"}</td>
      <td className="flex gap-2 justify-end">
        <Button variant="ghost" size="sm" onClick={() => retest.mutate(undefined)} disabled={retest.isPending}>
          <RefreshCw className="size-3.5" aria-hidden /> Test
        </Button>
        <Button variant="ghost" size="sm" onClick={() => remove.mutate(undefined)} disabled={remove.isPending}>
          <Trash2 className="size-3.5 text-danger" aria-hidden /> Remove
        </Button>
        <InlineError error={retest.error ?? remove.error} />
      </td>
    </tr>
  );
}

function AddForm({ onDone }: { onDone: () => void }) {
  const toast = useToast();
  const [provider, setProvider] = useState<"rfc2136" | "cloudflare">("rfc2136");
  const [zone, setZone] = useState("");
  const [overrideDomain, setOverrideDomain] = useState("");
  const [server, setServer] = useState("");
  const [keyName, setKeyName] = useState("");
  const [keySecret, setKeySecret] = useState("");
  const [algorithm, setAlgorithm] = useState("hmac-sha256");
  const [apiToken, setApiToken] = useState("");

  const save = useApiMutation(
    () => {
      const body: Record<string, unknown> = { provider, overrideDomain };
      if (provider === "rfc2136") {
        body.rfc2136 = { server, zone, keyName, keySecret, algorithm };
      } else {
        body.cloudflare = { zone, apiToken };
      }
      return api.post<{ credential: DNSCredential; testResult: TestReason }>(base, body);
    },
    {
      onSuccess: (r) => {
        toast.success(`Provider saved. Test: ${TEST_LABEL[r.testResult]}`);
        onDone();
      },
    },
  );

  return (
    <div className="mb-4 rounded border p-4 space-y-3">
      <div className="flex flex-wrap gap-4 items-end">
        <SelectField label="Provider" value={provider} onChange={(e) => setProvider(e.target.value as "rfc2136" | "cloudflare")}>
          <option value="rfc2136">RFC 2136 (BIND, Knot, PowerDNS)</option>
          <option value="cloudflare">Cloudflare</option>
        </SelectField>
        <TextField label="Zone" value={zone} onChange={(e) => setZone(e.target.value)} placeholder="example.com" />
        <TextField label="Override domain (delegation)" value={overrideDomain} onChange={(e) => setOverrideDomain(e.target.value)} placeholder="optional" />
      </div>

      {provider === "rfc2136" && (
        <div className="flex flex-wrap gap-4 items-end">
          <TextField label="Server" value={server} onChange={(e) => setServer(e.target.value)} placeholder="ns1.example.com or 10.0.0.53" />
          <TextField label="TSIG key name" value={keyName} onChange={(e) => setKeyName(e.target.value)} placeholder="acme-update." />
          <TextField label="TSIG key (base64)" value={keySecret} onChange={(e) => setKeySecret(e.target.value)} type="password" />
          <SelectField label="Algorithm" value={algorithm} onChange={(e) => setAlgorithm(e.target.value)}>
            <option value="hmac-sha256">HMAC-SHA256</option>
            <option value="hmac-sha384">HMAC-SHA384</option>
            <option value="hmac-sha512">HMAC-SHA512</option>
          </SelectField>
        </div>
      )}

      {provider === "cloudflare" && (
        <div className="flex flex-wrap gap-4 items-end">
          <TextField label="API token" value={apiToken} onChange={(e) => setApiToken(e.target.value)} type="password" />
        </div>
      )}

      <div className="flex gap-2">
        <Button onClick={() => save.mutate(undefined)} disabled={save.isPending || !zone}>
          {save.isPending ? "Saving…" : "Save and test"}
        </Button>
        <Button variant="secondary" onClick={onDone}>
          Cancel
        </Button>
      </div>
      <InlineError error={save.error} />
      {!overrideDomain && provider === "cloudflare" && (
        <p className="text-xs text-muted">
          Without delegation, EasyRMM holds write access to the whole zone. Scope the token to this zone
          only, or use delegation.
        </p>
      )}
    </div>
  );
}
