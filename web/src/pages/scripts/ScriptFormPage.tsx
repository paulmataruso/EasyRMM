import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { api, fieldError } from "../../api/client";
import { useApi, useApiMutation, useOrganizations, useSites } from "../../api/hooks";
import type { Script, ScriptInput, ScriptLevel, Shell } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { useToast } from "../../components/Toast";
import {
  Alert,
  buttonClasses,
  Button,
  Card,
  ErrorState,
  Field,
  InlineError,
  KeyValueList,
  PageHeader,
  Select,
  SelectField,
  Spinner,
  Textarea,
  TextareaField,
  TextField,
} from "../../components/ui";
import { SelfPatchingWarning, TimeoutField } from "./parts";
import { formatBytes, LIMITS, PLATFORM_NAMES, scriptScope, SHELL_NAMES, SHELL_PLATFORM, SHELLS, utf8Length } from "./scriptText";

const FIELDS = ["name", "description", "shell", "body", "timeoutSeconds", "organizationId", "siteId"];

/** /scripts/new and /scripts/:id/edit. */
export function ScriptFormPage() {
  const { id } = useParams();
  return id ? <EditScript id={id} /> : <ScriptForm />;
}

function EditScript({ id }: { id: string }) {
  const script = useApi<Script>(`/scripts/${id}`);
  if (script.isPending) return <Spinner />;
  if (script.isError) return <ErrorState error={script.error} onRetry={() => void script.refetch()} />;
  if (!script.data.canEdit) {
    return (
      <>
        <PageHeader title={script.data.name} breadcrumb={<Breadcrumb script={script.data} />} />
        <Alert tone="info" title="You can run this script but not change it">
          Changing a script takes the Site Administrator role or higher where it runs ({scriptScope(script.data)}).
        </Alert>
      </>
    );
  }
  return <ScriptForm key={script.data.id} script={script.data} />;
}

function Breadcrumb({ script }: { script?: Script }) {
  return (
    <>
      <Link to="/scripts" className="hover:text-fg">
        Scripts
      </Link>
      {script && (
        <>
          <span className="mx-1.5" aria-hidden>
            /
          </span>
          <Link to={`/scripts/${script.id}`} className="hover:text-fg">
            {script.name}
          </Link>
        </>
      )}
    </>
  );
}

function ScriptForm({ script }: { script?: Script }) {
  const { session } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const orgs = useOrganizations();
  const levelId = useId();
  const bodyId = useId();
  const superAdmin = session?.isSuperAdmin === true;

  const [level, setLevel] = useState<ScriptLevel>(superAdmin ? "shared" : "organization");
  const [organizationId, setOrganizationId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [name, setName] = useState(script?.name ?? "");
  const [description, setDescription] = useState(script?.description ?? "");
  const [shell, setShell] = useState<Shell>(script?.shell ?? "powershell");
  const [body, setBody] = useState(script?.body ?? "");
  const [timeoutSeconds, setTimeoutSeconds] = useState(script?.timeoutSeconds ?? LIMITS.defaultTimeout);
  const sites = useSites(level === "site" && organizationId ? organizationId : null);

  const dirty = script
    ? name !== script.name || description !== script.description || shell !== script.shell || body !== (script.body ?? "") || timeoutSeconds !== script.timeoutSeconds
    : name !== "" || description !== "" || body !== "";
  useEffect(() => {
    if (!dirty) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  // Organizations and sites where the caller may write scripts: site.manage and script.manage go together, and
  // organization administrators hold both for the whole organization.
  const writableOrgs = orgs.items.filter((o) => level === "site" || o.canManage);
  const writableSites = sites.items.filter((s) => s.canManage);
  const noOrgLevel = !orgs.isPending && !orgs.items.some((o) => o.canManage);

  const save = useApiMutation(
    (input: ScriptInput) =>
      script
        ? api.patch<Script>(`/scripts/${script.id}`, {
            name: input.name,
            description: input.description,
            shell: input.shell,
            body: input.body,
            timeoutSeconds: input.timeoutSeconds,
          })
        : api.post<Script>("/scripts", input),
    {
      invalidate: ["/scripts"],
      onSuccess: (saved) => {
        toast.success(script ? `Saved ${saved.name}.` : `Added ${saved.name} to the library.`);
        navigate(`/scripts/${saved.id}`);
      },
    },
  );

  const bytes = utf8Length(body);
  const tooBig = bytes > LIMITS.body;
  const [missing, setMissing] = useState<Record<string, string>>({});
  /** A field's own complaint goes once it is edited. */
  const edited = (field: string) =>
    setMissing((m) => {
      if (!(field in m)) return m;
      const { [field]: _gone, ...rest } = m;
      return rest;
    });

  function submit(e: FormEvent) {
    e.preventDefault();
    const m: Record<string, string> = {};
    if (!name.trim()) m.name = "Enter a name.";
    if (!body.trim()) m.body = "Enter the script.";
    if (!script && level !== "shared" && !organizationId) m.organizationId = "Choose an organization.";
    if (!script && level === "site" && !siteId) m.siteId = "Choose a site.";
    if (timeoutSeconds < LIMITS.minTimeout || timeoutSeconds > LIMITS.maxTimeout) m.timeoutSeconds = "Use a timeout from 1 second to 4 hours.";
    setMissing(m);
    if (Object.keys(m).length > 0 || tooBig) return;
    save.mutate({
      organizationId: level === "shared" ? null : organizationId,
      siteId: level === "site" ? siteId : null,
      name,
      description,
      shell,
      body,
      timeoutSeconds,
    });
  }

  const err = (field: string) => missing[field] ?? fieldError(save.error, field);

  return (
    <>
      <PageHeader
        breadcrumb={<Breadcrumb script={script} />}
        title={script ? `Edit ${script.name}` : "New script"}
        subtitle={script ? "Jobs already started keep the version they ran." : "Add a script to the library, then run it on devices."}
      />
      <form onSubmit={submit} noValidate className="flex flex-col gap-5">
        <Card title="Details">
          <div className="grid grid-cols-1 gap-3.5 md:grid-cols-2">
            <TextField
              label="Name"
              required
              value={name}
              maxLength={LIMITS.name}
              onChange={(e) => {
                setName(e.target.value);
                edited("name");
              }}
              error={err("name")}
              autoFocus={!script}
              className="md:col-span-2"
            />
            <TextareaField
              label="Description"
              value={description}
              maxLength={LIMITS.description}
              onChange={(e) => setDescription(e.target.value)}
              error={err("description")}
              hint="What it does and what arguments it takes. Shown in the library and when running it."
              rows={2}
              className="md:col-span-2"
            />
            {script ? (
              <div className="md:col-span-2">
                <KeyValueList narrow items={[["Runs in", <span key="r">{scriptScope(script)}</span>]]} />
                <p className="mt-1 text-xs text-subtle">Set when the script was added.</p>
              </div>
            ) : (
              <>
                <Field label="Runs in" htmlFor={levelId} hint={LEVEL_HINTS[level]}>
                  <Select
                    id={levelId}
                    value={level}
                    onChange={(e) => {
                      setLevel(e.target.value as ScriptLevel);
                      setOrganizationId("");
                      setSiteId("");
                    }}
                  >
                    {superAdmin && <option value="shared">All organizations (shared)</option>}
                    <option value="organization" disabled={noOrgLevel}>
                      One organization
                    </option>
                    <option value="site">One site</option>
                  </Select>
                </Field>
                {level !== "shared" ? (
                  <div className="flex flex-wrap gap-3">
                    <SelectField
                      label="Organization"
                      required
                      value={organizationId}
                      onChange={(e) => {
                        setOrganizationId(e.target.value);
                        setSiteId("");
                        edited("organizationId");
                      }}
                      error={err("organizationId")}
                      disabled={orgs.isPending}
                      className="min-w-44 flex-1"
                    >
                      <option value="">Choose…</option>
                      {writableOrgs.map((o) => (
                        <option key={o.id} value={o.id}>
                          {o.name}
                        </option>
                      ))}
                    </SelectField>
                    {level === "site" && (
                      <SelectField
                        label="Site"
                        required
                        value={siteId}
                        onChange={(e) => {
                          setSiteId(e.target.value);
                          edited("siteId");
                        }}
                        error={err("siteId")}
                        disabled={!organizationId || sites.isPending}
                        className="min-w-44 flex-1"
                      >
                        <option value="">{organizationId && !sites.isPending && writableSites.length === 0 ? "No sites you manage" : "Choose…"}</option>
                        {writableSites.map((s) => (
                          <option key={s.id} value={s.id}>
                            {s.name}
                          </option>
                        ))}
                      </SelectField>
                    )}
                  </div>
                ) : (
                  <div className="hidden md:block" />
                )}
              </>
            )}
            <SelectField label="Shell" value={shell} onChange={(e) => setShell(e.target.value as Shell)} error={err("shell")} hint={`Runs on ${PLATFORM_NAMES[SHELL_PLATFORM[shell]]} devices.`}>
              {SHELLS.map((s) => (
                <option key={s} value={s}>
                  {SHELL_NAMES[s]}
                </option>
              ))}
            </SelectField>
            <TimeoutField
              label="Timeout"
              value={timeoutSeconds}
              onChange={(v) => {
                setTimeoutSeconds(v);
                edited("timeoutSeconds");
              }}
              error={err("timeoutSeconds")}
              hint="Stopped if still running after this. Up to 4 hours; each run can override it."
            />
          </div>
        </Card>

        <Card title="Script">
          <Field
            label="Body"
            htmlFor={bodyId}
            required
            error={err("body") ?? (tooBig ? `The script is ${formatBytes(bytes)}; the limit is 64 KiB.` : null)}
            hint={`${formatBytes(bytes)} of 64 KiB.`}
          >
            <Textarea
              id={bodyId}
              value={body}
              onChange={(e) => {
                setBody(e.target.value);
                edited("body");
              }}
              rows={20}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              wrap="off"
              aria-invalid={err("body") || tooBig ? true : undefined}
              aria-describedby={`${bodyId}-how`}
              className="font-mono text-xs leading-relaxed"
              placeholder={PLACEHOLDERS[shell]}
            />
          </Field>
          <p id={`${bodyId}-how`} className="mt-2 text-xs text-muted">
            {HOW_IT_RUNS[shell]}
          </p>
          <SelfPatchingWarning shell={shell} body={body} className="mt-3" />
        </Card>

        <InlineError error={save.error} fields={FIELDS} />
        <div className="flex justify-end gap-2">
          <Link to={script ? `/scripts/${script.id}` : "/scripts"} className={buttonClasses("secondary")}>
            Cancel
          </Link>
          <Button type="submit" variant="primary" loading={save.isPending}>
            {script ? "Save changes" : "Add script"}
          </Button>
        </div>
      </form>
    </>
  );
}

const LEVEL_HINTS: Record<ScriptLevel, string> = {
  shared: "Every organization's technicians can run it.",
  organization: "Runs on devices in one organization and its sites.",
  site: "Runs on devices in one site only.",
};

const TEMP_FOLDER = "in a new temporary folder that is removed afterwards";

const HOW_IT_RUNS: Record<Shell, ReactNode> = {
  powershell: (
    <>
      The agent runs the script with Windows PowerShell 5.1 as Local System, {TEMP_FOLDER}, without a profile and with the execution policy bypassed. Arguments
      arrive in <code className="font-mono">$args</code> or a <code className="font-mono">param()</code> block; <code className="font-mono">exit</code> sets the
      exit code.
    </>
  ),
  cmd: (
    <>
      The agent runs the script as a batch file with cmd.exe as Local System, {TEMP_FOLDER}. Arguments arrive as <code className="font-mono">%1</code>,{" "}
      <code className="font-mono">%2</code> and so on, and cannot contain %, double quotes or line breaks; <code className="font-mono">exit /b</code> sets the
      exit code.
    </>
  ),
  bash: <LinuxHow shell="bash" />,
  sh: <LinuxHow shell="sh" />,
  python3: <LinuxHow shell="python3" />,
};

function LinuxHow({ shell }: { shell: Shell }) {
  return (
    <>
      The agent runs the script with {SHELL_NAMES[shell]} as its own user (root on a standard install), {TEMP_FOLDER}. A{" "}
      <code className="font-mono">#!</code> line is ignored. Arguments arrive as {shell === "python3" ? "sys.argv[1:]" : "$1, $2 and so on"}.
    </>
  );
}

const PLACEHOLDERS: Record<Shell, string> = {
  powershell: "Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' |\n  Select-Object DeviceID, @{ n = 'FreeGB'; e = { [math]::Round($_.FreeSpace / 1GB, 1) } }",
  cmd: "@echo off\nsysteminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\"",
  bash: 'set -euo pipefail\necho "Disk usage on $(hostname):"\ndf -h /',
  sh: "set -eu\nuptime",
  python3: "import platform\nprint(platform.platform())",
};
