import { useEffect, useState, type FormEvent } from "react";
import { Check, Copy, LifeBuoy, Plus, X } from "lucide-react";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useOrganizations } from "../../api/hooks";
import type { NewQuickAssistLink, QuickAssistLink, QuickAssistSession } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { Dialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { Button, Card, EmptyState, ErrorState, Field, InlineError, PageHeader, SelectField, Spinner, Tabs, TableWrap, TextField } from "../../components/ui";
import { formatDateTime, formatRelative, plural } from "../../lib/format";
import { useUrlState } from "../../lib/urlState";

type View = "requests" | "active" | "links" | "ended";
const VIEWS: View[] = ["requests", "active", "links", "ended"];

const END_REASON: Record<string, string> = {
  technician: "Ended by the technician",
  user: "Ended by the user",
  not_accepted: "Not accepted in time",
  declined: "Declined",
  code_failed: "The code was typed wrong three times",
  evicted: "Made room for a newer request",
  link_revoked: "The link was revoked",
  max_length: "Reached its maximum length",
  lost: "The computer stopped answering",
};

const CLEANUP: Record<QuickAssistSession["cleanup"], string> = {
  none: "Not reported yet",
  verified: "Cleaned up, verified",
  residue: "Something was left behind",
  unconfirmed: "Not confirmed by the computer",
};

/**
 * Quick Assist (ADR-0080): links a technician gives a user, the requests waiting for the technician to accept by typing
 * the code the user reads out, the sessions running, and the ones that ended.
 */
export function QuickAssistPage() {
  const { can } = useAuth();
  const url = useUrlState();
  const orgs = useOrganizations();
  const requested = url.get("view");
  const view: View = VIEWS.includes(requested as View) ? (requested as View) : "requests";
  const list = orgs.data?.items ?? [];
  const org = url.get("organizationId") || list[0]?.id || "";
  const [made, setMade] = useState<NewQuickAssistLink | null>(null);

  return (
    <>
      <PageHeader
        title="Quick Assist"
        subtitle="Help a person whose computer is not enrolled: they open a link, read you a code, and you accept the request here. Nothing is installed, and the program removes itself when the session ends."
        actions={
          <>
            {list.length > 1 && (
              <SelectField label="Organization" value={org} onChange={(e) => url.set({ organizationId: e.target.value })}>
                {list.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </SelectField>
            )}
            {org && <NewLinkButtons org={org} onMade={setMade} />}
          </>
        }
      />
      {made && <MadeDialog made={made} onClose={() => setMade(null)} />}
      {!can("quickassist.view") ? (
        <EmptyState title="Not available to your role" icon={<LifeBuoy className="size-8" aria-hidden />}>
          Quick Assist needs the permission to view it.
        </EmptyState>
      ) : orgs.isLoading ? (
        <Spinner />
      ) : !org ? (
        <EmptyState title="No organization yet" icon={<LifeBuoy className="size-8" aria-hidden />}>
          Quick Assist links belong to an organization. Add one first.
        </EmptyState>
      ) : (
        <>
          <Tabs
            active={view}
            onChange={(v) => url.set({ view: v === "requests" ? null : v })}
            tabs={[
              { id: "requests", label: "Requests" },
              { id: "active", label: "Active" },
              { id: "links", label: "Links" },
              { id: "ended", label: "Ended" },
            ]}
          />
          {view === "links" ? <Links org={org} /> : <Sessions org={org} view={view} />}
        </>
      )}
    </>
  );
}

function Sessions({ org, view }: { org: string; view: Exclude<View, "links"> }) {
  const states = view === "requests" ? "requested" : view === "active" ? "active" : "declined,ended,lost";
  const q = useApi<{ sessions: QuickAssistSession[] }>(`/organizations/${org}/quickassist/sessions`, { state: states }, { refetchInterval: view === "ended" ? 30_000 : 3_000 });
  const [accepting, setAccepting] = useState<QuickAssistSession | null>(null);
  const toast = useToast();
  const inval = ["/organizations", "/quickassist"];
  const decline = useApiMutation((s: QuickAssistSession) => api.post(`/quickassist/sessions/${s.id}/decline`), { invalidate: inval, onSuccess: () => toast.success("Request declined.") });
  const end = useApiMutation((s: QuickAssistSession) => api.post(`/quickassist/sessions/${s.id}/end`), { invalidate: inval, onSuccess: () => toast.success("Session ended. The program is removing itself.") });
  const takeover = useApiMutation((s: QuickAssistSession) => api.post(`/quickassist/sessions/${s.id}/takeover`), { invalidate: inval, onSuccess: () => toast.success("You hold this session now.") });
  const install = useApiMutation((s: QuickAssistSession) => api.post(`/quickassist/sessions/${s.id}/install`), {
    invalidate: inval,
    onSuccess: () => toast.success("Asked. The user is shown a question on their screen and nothing is installed unless they agree."),
  });
  const { can, session } = useAuth();

  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const rows = q.data?.sessions ?? [];
  if (rows.length === 0) {
    return (
      <EmptyState title={view === "requests" ? "No requests waiting" : view === "active" ? "No sessions running" : "Nothing has ended yet"} icon={<LifeBuoy className="size-8" aria-hidden />}>
        {view === "requests" ? "When a user opens a link and allows the session, it appears here within seconds." : "Sessions appear here while they last."}
      </EmptyState>
    );
  }
  return (
    <Card padded={false} title={plural(rows.length, view === "requests" ? "request" : "session")}>
      <TableWrap>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-xs text-muted">
              <th className="px-4 py-2">Computer</th>
              <th className="px-4 py-2">Link</th>
              <th className="px-4 py-2">{view === "ended" ? "Ended" : "Asked"}</th>
              <th className="px-4 py-2">Details</th>
              <th className="px-4 py-2" />
            </tr>
          </thead>
          <tbody>
            {rows.map((s) => (
              <tr key={s.id} className="border-t border-border">
                <td className="px-4 py-2 font-medium">{s.deviceName || "Unknown"}</td>
                <td className="px-4 py-2">{s.linkName || "Unnamed link"}</td>
                <td className="px-4 py-2" title={formatDateTime(s.endedAt ?? s.requestedAt)}>
                  {formatRelative(s.endedAt ?? s.requestedAt)}
                </td>
                <td className="px-4 py-2 text-muted">
                  {view === "ended" ? (
                    <>
                      {END_REASON[s.endReason] ?? s.state}. {CLEANUP[s.cleanup]}.
                    </>
                  ) : (
                    <>
                      {s.elevated ? "Full access" : "Not elevated: screen and inventory only"}
                      {s.disconnected ? ". Disconnected." : ""}
                      {s.acceptedBy && s.acceptedBy === session?.user.id ? ". You hold it." : s.acceptedBy ? ". Held by another technician." : ""}
                    </>
                  )}
                </td>
                <td className="px-4 py-2 text-right whitespace-nowrap">
                  {view === "requests" && can("quickassist.session") && (
                    <>
                      <Button size="sm" onClick={() => setAccepting(s)}>
                        <Check className="size-4" aria-hidden /> Accept
                      </Button>{" "}
                      <Button size="sm" variant="secondary" onClick={() => decline.mutate(s)}>
                        <X className="size-4" aria-hidden /> Decline
                      </Button>
                    </>
                  )}
                  {view === "active" && (
                    <>
                      {s.deviceId && (
                        <a className="mr-2 text-accent hover:underline" href={`/devices/${s.deviceId}`}>
                          Open
                        </a>
                      )}
                      {s.acceptedBy !== session?.user.id && can("quickassist.session.takeover") && (
                        <Button size="sm" variant="secondary" onClick={() => takeover.mutate(s)}>
                          Take over
                        </Button>
                      )}{" "}
                      {can("quickassist.install") && s.elevated && (
                        <>
                          <Button size="sm" variant="secondary" onClick={() => install.mutate(s)}>
                            Install agent
                          </Button>{" "}
                        </>
                      )}
                      <Button size="sm" variant="danger" onClick={() => end.mutate(s)}>
                        End session
                      </Button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
      {accepting && <AcceptDialog session={accepting} onClose={() => setAccepting(null)} />}
    </Card>
  );
}

/** The technician types the code the user reads out; the console never shows it. */
function AcceptDialog({ session, onClose }: { session: QuickAssistSession; onClose: () => void }) {
  const [code, setCode] = useState("");
  const toast = useToast();
  const accept = useApiMutation((c: string) => api.post(`/quickassist/sessions/${session.id}/accept`, { code: c }), {
    invalidate: ["/organizations", "/quickassist"],
    onSuccess: () => {
      toast.success(`${session.deviceName || "The computer"} is in Active.`);
      onClose();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    accept.mutate(code);
  };
  return (
    <Dialog open onClose={onClose} title={`Accept ${session.deviceName || "this request"}`} description="Ask the user for the six-digit code on their screen and type it here. Three wrong tries close the request.">
      <form onSubmit={submit} className="space-y-3">
        <Field label="Code from the user's screen" error={accept.error ? fieldError(accept.error, "code") ?? accept.error.message : null}>
          <input
            autoFocus
            inputMode="numeric"
            autoComplete="off"
            maxLength={6}
            aria-label="Code from the user's screen"
            className="w-40 rounded-md border border-border bg-surface px-3 py-2 font-mono text-lg tracking-widest"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={code.length !== 6 || accept.isPending}>
            Accept
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function Links({ org }: { org: string }) {
  const { can } = useAuth();
  const q = useApi<{ links: QuickAssistLink[] }>(`/organizations/${org}/quickassist/links`);
  const mode = useApi<{ mode: "own_test" | "open" }>("/quickassist/settings");
  const toast = useToast();
  const inval = ["/organizations", "/quickassist"];
  const revoke = useApiMutation((l: QuickAssistLink) => api.post(`/quickassist/links/${l.id}/revoke`), { invalidate: inval, onSuccess: () => toast.success("Link revoked.") });
  const pause = useApiMutation((l: QuickAssistLink) => api.post(`/quickassist/links/${l.id}/pause`, { paused: !l.paused }), { invalidate: inval });
  if (q.isLoading) return <Spinner />;
  if (q.error) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const links = q.data?.links ?? [];
  return (
    <>
      {mode.data?.mode === "own_test" && (
        <p className="mb-3 rounded-md bg-hover px-3 py-2 text-sm text-muted">
          Until the program is signed, only one-time test links can be made, and only the person who made a link can accept a session from it.
        </p>
      )}
      <Card
        padded={false}
        title={plural(links.length, "link")}
      >
        {links.length === 0 ? (
          <EmptyState title="No links yet" icon={<LifeBuoy className="size-8" aria-hidden />} compact>
            Make a one-time link, send it to the user, and stay on the phone.
          </EmptyState>
        ) : (
          <TableWrap>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-muted">
                  <th className="px-4 py-2">Name</th>
                  <th className="px-4 py-2">Kind</th>
                  <th className="px-4 py-2">State</th>
                  <th className="px-4 py-2">Made</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {links.map((l) => (
                  <tr key={l.id} className="border-t border-border">
                    <td className="px-4 py-2 font-medium">{l.name || "Unnamed link"}</td>
                    <td className="px-4 py-2">{l.kind === "one_time" ? "One-time" : "Permanent"}{l.test ? " (test)" : ""}</td>
                    <td className="px-4 py-2">{l.paused ? "Paused" : l.state === "active" ? "Active" : l.state === "used" ? "Used" : l.state === "expired" ? "Expired" : "Revoked"}</td>
                    <td className="px-4 py-2" title={formatDateTime(l.createdAt)}>
                      {formatRelative(l.createdAt)}
                    </td>
                    <td className="px-4 py-2 text-right whitespace-nowrap">
                      {l.kind === "permanent" && l.state === "active" && can("quickassist.link.permanent") && (
                        <Button size="sm" variant="secondary" onClick={() => pause.mutate(l)}>
                          {l.paused ? "Resume" : "Pause"}
                        </Button>
                      )}{" "}
                      {(l.state === "active" || l.state === "used") && (
                        <Button size="sm" variant="secondary" onClick={() => revoke.mutate(l)}>
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>
    </>
  );
}

/**
 * One click makes a link (no name asked for: the server names it) and shows it. A permanent link, only while the link
 * mode is open and for those who may make one, has its own button; the server asks for the second factor.
 */
function NewLinkButtons({ org, onMade }: { org: string; onMade: (m: NewQuickAssistLink) => void }) {
  const { can } = useAuth();
  const mode = useApi<{ mode: "own_test" | "open" }>("/quickassist/settings");
  const make = useApiMutation((kind: "one_time" | "permanent") => api.post<NewQuickAssistLink>(`/organizations/${org}/quickassist/links`, { kind }), {
    invalidate: ["/quickassist", "/organizations"],
    onSuccess: onMade,
  });
  const toast = useToast();
  useEffect(() => {
    if (make.error) toast.error(make.error instanceof Error ? make.error.message : "The link could not be made.");
  }, [make.error]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!can("quickassist.link.create")) return null;
  return (
    <>
      <Button onClick={() => make.mutate("one_time")} disabled={make.isPending}>
        <Plus className="size-4" aria-hidden /> New link
      </Button>
      {mode.data?.mode === "open" && can("quickassist.link.permanent") && (
        <Button variant="secondary" onClick={() => make.mutate("permanent")} disabled={make.isPending}>
          New permanent link
        </Button>
      )}
    </>
  );
}

function MadeDialog({ made, onClose }: { made: NewQuickAssistLink; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const full = `${window.location.origin}${made.path}`;
  useEffect(() => setCopied(false), [full]);
  return (
    <Dialog open onClose={onClose} title="Send this link to the user" description="It is shown once. Stay on the phone: they will read you a six-digit code." size="lg">
      <div className="space-y-3">
        <p className="text-sm text-muted">{made.link.expiresAt ? `Works once, until ${formatDateTime(made.link.expiresAt)}.` : "A permanent link: it does not expire."}</p>
        <input readOnly aria-label="Link" className="w-full rounded-md border border-border bg-surface px-3 py-2 font-mono text-sm" value={full} onFocus={(e) => e.currentTarget.select()} />
        <div className="flex justify-end gap-2">
          <Button
            variant="secondary"
            onClick={() => {
              void navigator.clipboard?.writeText(full).then(() => setCopied(true));
            }}
          >
            <Copy className="size-4" aria-hidden /> {copied ? "Copied" : "Copy"}
          </Button>
          <Button onClick={onClose}>Done</Button>
        </div>
      </div>
    </Dialog>
  );
}
