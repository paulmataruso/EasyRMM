import { useState } from "react";
import { Lock, Pencil, Plus, Trash2 } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { SsoProvider, SsoProviderInput, SsoSettings } from "../../api/types";
import { CopyButton } from "../../components/Copy";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Badge, Button, Card, Dot, EmptyState, ErrorState, InlineError, Mono, Spinner, TableWrap, TextField, TextareaField } from "../../components/ui";

const KEYS = ["/settings/sso", "/auth/sso", "/audit"];

/** Platform settings: the identity providers people can sign in through (ADR-0034). */
export function SingleSignOnTab() {
  const settings = useApi<SsoSettings>("/settings/sso");
  const [editing, setEditing] = useState<SsoProvider | "new" | null>(null);
  const [deleting, setDeleting] = useState<SsoProvider | null>(null);
  const toast = useToast();
  const remove = useApiMutation((p: SsoProvider) => api.del(`/settings/sso/providers/${p.id}`), {
    invalidate: KEYS,
    onSuccess: (_, p) => {
      setDeleting(null);
      if (editing !== "new" && editing?.id === p.id) setEditing(null);
      toast.success(`${p.name} removed. Its links to EasyRMM accounts are forgotten.`);
    },
  });

  if (settings.isPending) return <Spinner />;
  if (settings.isError) return <ErrorState error={settings.error} onRetry={() => void settings.refetch()} />;
  const { redirectUri, providers } = settings.data;

  return (
    <div className="flex flex-col gap-5">
      <Card title="Redirect URI">
        <div className="flex flex-col gap-2.5">
          <p className="text-sm text-muted">
            Register EasyRMM with your identity provider (Microsoft Entra ID, Google Workspace, Okta, Keycloak and others) as a web application using OpenID
            Connect, with this redirect URI. It is the same for every provider.
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <Mono className="break-all">{redirectUri}</Mono>
            <CopyButton text={redirectUri} />
          </div>
        </div>
      </Card>

      {editing && (
        <ProviderForm
          key={editing === "new" ? "new" : editing.id}
          provider={editing === "new" ? null : editing}
          onDone={() => setEditing(null)}
        />
      )}

      <Card
        title="Providers"
        padded={false}
        actions={
          editing === null && (
            <Button size="sm" variant="primary" icon={<Plus className="size-3.5" aria-hidden />} onClick={() => setEditing("new")}>
              Add provider
            </Button>
          )
        }
      >
        <InlineError error={remove.error} />
        {providers.length === 0 ? (
          <EmptyState title="No single sign-on yet" compact>
            People sign in with their EasyRMM password. Add a provider to offer “Sign in with …” on the sign-in page.
          </EmptyState>
        ) : (
          <TableWrap className="rounded-none border-0">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Provider</th>
                  <th className="hidden md:table-cell">Email domains</th>
                  <th className="hidden lg:table-cell">Second factor</th>
                  <th>State</th>
                  <th>
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {providers.map((p) => (
                  <tr key={p.id}>
                    <td>
                      <p className="font-medium">{p.name}</p>
                      <p className="max-w-md truncate text-xs text-muted" title={p.issuer}>
                        {p.issuer}
                      </p>
                    </td>
                    <td className="hidden md:table-cell">{p.allowedDomains.join(", ")}</td>
                    <td className="hidden text-muted lg:table-cell">{p.trustMfa ? "The provider's" : "EasyRMM's"}</td>
                    <td>
                      <Badge tone={p.enabled ? "ok" : "neutral"} icon={<Dot tone={p.enabled ? "ok" : "neutral"} />}>
                        {p.enabled ? "On" : "Off"}
                      </Badge>
                    </td>
                    <td className="text-right whitespace-nowrap">
                      {p.managed ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-muted" title="Set in the server's configuration (deploy/.env), not here">
                          <Lock className="size-3.5" aria-hidden />
                          Set by the deployment
                        </span>
                      ) : (
                        <>
                          <Button size="sm" variant="ghost" icon={<Pencil className="size-3.5" aria-hidden />} onClick={() => setEditing(p)} aria-label={`Edit ${p.name}`}>
                            Edit
                          </Button>
                          <Button
                            size="sm"
                            variant="danger-ghost"
                            icon={<Trash2 className="size-3.5" aria-hidden />}
                            onClick={() => setDeleting(p)}
                            aria-label={`Remove ${p.name}`}
                          >
                            Remove
                          </Button>
                        </>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <ConfirmDialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        onConfirm={() => deleting && remove.mutate(deleting)}
        loading={remove.isPending}
        error={remove.error}
        tone="danger"
        title={`Remove ${deleting?.name ?? ""}?`}
        confirmLabel="Remove"
      >
        Nobody can sign in through it any more, and its links to EasyRMM accounts are forgotten. People already signed in stay signed in until their session
        ends. Their EasyRMM accounts and passwords are not affected.
      </ConfirmDialog>
    </div>
  );
}

function ProviderForm({ provider, onDone }: { provider: SsoProvider | null; onDone: () => void }) {
  const toast = useToast();
  const [form, setForm] = useState({
    name: provider?.name ?? "",
    issuer: provider?.issuer ?? "",
    clientId: provider?.clientId ?? "",
    clientSecret: "",
    domains: provider?.allowedDomains.join("\n") ?? "",
    trustEmail: provider?.trustEmail ?? false,
    trustMfa: provider?.trustMfa ?? false,
    enabled: provider?.enabled ?? true,
  });
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));
  const save = useApiMutation(
    (body: SsoProviderInput) =>
      provider ? api.put<SsoProvider>(`/settings/sso/providers/${provider.id}`, body) : api.post<SsoProvider>("/settings/sso/providers", body),
    {
      invalidate: KEYS,
      onSuccess: (p) => {
        toast.success(provider ? `${p.name} saved.` : `${p.name} added. ${p.enabled ? "The sign-in page offers it now." : "Turn it on to offer it."}`);
        onDone();
      },
    },
  );
  const err = (f: string) => fieldError(save.error, f);

  return (
    <Card title={provider ? `Edit ${provider.name}` : "Add a provider"}>
      <form
        className="space-y-4"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({
            name: form.name.trim(),
            issuer: form.issuer.trim(),
            clientId: form.clientId.trim(),
            clientSecret: form.clientSecret.trim(),
            allowedDomains: form.domains
              .split(/[\s,;]+/)
              .map((d) => d.trim())
              .filter(Boolean),
            trustEmail: form.trustEmail,
            trustMfa: form.trustMfa,
            enabled: form.enabled,
          });
        }}
      >
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <TextField
            label="Name"
            hint="The sign-in button says “Sign in with” this name."
            placeholder="Microsoft"
            value={form.name}
            onChange={(e) => set("name", e.target.value)}
            error={err("name")}
            maxLength={64}
            required
            autoFocus
          />
          <TextField
            label="Issuer URL"
            hint="For Entra ID, https://login.microsoftonline.com/<tenant ID>/v2.0, with your tenant's ID; for Google, https://accounts.google.com."
            placeholder="https://login.microsoftonline.com/…/v2.0"
            value={form.issuer}
            onChange={(e) => set("issuer", e.target.value)}
            error={err("issuer")}
            autoComplete="off"
            spellCheck={false}
            inputMode="url"
            required
          />
          <TextField
            label="Client ID"
            hint="The application (client) ID the provider gave EasyRMM."
            value={form.clientId}
            onChange={(e) => set("clientId", e.target.value)}
            error={err("clientId")}
            autoComplete="off"
            spellCheck={false}
            required
          />
          <TextField
            label="Client secret"
            type="password"
            hint={provider ? "A secret is stored, encrypted. Paste a new one to replace it." : "Stored encrypted and never shown again."}
            placeholder={provider ? "Stored" : undefined}
            value={form.clientSecret}
            onChange={(e) => set("clientSecret", e.target.value)}
            error={err("clientSecret")}
            autoComplete="new-password"
            spellCheck={false}
            required={!provider}
          />
        </div>
        <TextareaField
          label="Email domains"
          hint="People whose EasyRMM address is in one of these domains can link their account the first time they sign in this way. One per line."
          placeholder="example.com"
          value={form.domains}
          onChange={(e) => set("domains", e.target.value)}
          error={err("allowedDomains")}
          rows={2}
          spellCheck={false}
        />
        <fieldset className="space-y-3">
          <legend className="sr-only">Options</legend>
          <label className="flex items-start gap-2.5 text-sm">
            <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} className="mt-0.5 size-4 accent-accent" />
            <span>
              <span className="font-medium">Offer it on the sign-in page</span>
              <span className="block text-muted">Off stops new sign-ins through it and keeps the settings and links.</span>
            </span>
          </label>
          <label className="flex items-start gap-2.5 text-sm">
            <input type="checkbox" checked={form.trustEmail} onChange={(e) => set("trustEmail", e.target.checked)} className="mt-0.5 size-4 accent-accent" />
            <span>
              <span className="font-medium">Its email addresses belong to my organization</span>
              <span className="block text-muted">
                For providers that do not say whether an address is verified, such as Microsoft Entra ID. Use it only with an issuer for your own tenant,
                never a shared one such as “common”.
              </span>
            </span>
          </label>
          <label className="flex items-start gap-2.5 text-sm">
            <input type="checkbox" checked={form.trustMfa} onChange={(e) => set("trustMfa", e.target.checked)} className="mt-0.5 size-4 accent-accent" />
            <span>
              <span className="font-medium">It requires multi-factor authentication</span>
              <span className="block text-muted">
                People who sign in through it skip EasyRMM's own second factor. EasyRMM cannot check this: turn it on only if the provider enforces MFA for
                everyone in these domains.
              </span>
            </span>
          </label>
        </fieldset>
        <InlineError error={save.error} fields={["name", "issuer", "clientId", "clientSecret", "allowedDomains"]} />
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-line pt-4">
          <p className="text-xs text-muted">EasyRMM reads the provider's OpenID configuration before saving.</p>
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={onDone} disabled={save.isPending}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" loading={save.isPending}>
              {provider ? "Save" : "Add provider"}
            </Button>
          </div>
        </div>
      </form>
    </Card>
  );
}
