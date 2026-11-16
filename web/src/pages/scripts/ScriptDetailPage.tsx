import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { Pencil, Play, Trash2 } from "lucide-react";
import { api } from "../../api/client";
import { useApi, useApiMutation } from "../../api/hooks";
import type { Script } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { ConfirmDialog } from "../../components/Dialog";
import { useToast } from "../../components/Toast";
import { buttonClasses, Button, Card, ErrorState, KeyValueList, Mono, PageHeader, Spinner } from "../../components/ui";
import { formatDateTime } from "../../lib/format";
import { JobsTable } from "../jobs/JobsPage";
import { CodeView } from "./parts";
import { RunScriptDialog } from "./RunScriptDialog";
import { formatBytes, formatSeconds, scriptScope, SHELL_NAMES } from "./scriptText";

export function ScriptDetailPage() {
  const { id = "" } = useParams();
  const { can } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const script = useApi<Script>(`/scripts/${id}`);
  const [running, setRunning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const remove = useApiMutation(() => api.del(`/scripts/${id}`), {
    invalidate: ["/scripts"],
    onSuccess: () => {
      toast.success(`Deleted ${script.data?.name ?? "the script"}. Jobs that ran it keep their copy.`);
      navigate("/scripts", { replace: true });
    },
  });

  if (script.isPending) return <Spinner />;
  if (script.isError) return <ErrorState error={script.error} onRetry={() => void script.refetch()} />;
  const s = script.data;

  return (
    <>
      <PageHeader
        breadcrumb={
          <Link to="/scripts" className="hover:text-fg">
            Scripts
          </Link>
        }
        title={s.name}
        subtitle={s.description || `${SHELL_NAMES[s.shell] ?? s.shell} script · ${scriptScope(s)}`}
        actions={
          <>
            {s.canEdit && (
              <Button variant="danger-ghost" icon={<Trash2 className="size-4" aria-hidden />} onClick={() => setDeleting(true)}>
                Delete
              </Button>
            )}
            {s.canEdit && (
              <Link to={`/scripts/${s.id}/edit`} className={buttonClasses("secondary")}>
                <Pencil className="size-4" aria-hidden />
                Edit
              </Link>
            )}
            {s.canRun && (
              <Button variant="primary" icon={<Play className="size-4" aria-hidden />} onClick={() => setRunning(true)}>
                Run
              </Button>
            )}
          </>
        }
      />

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-3">
        <Card title="Script" className="min-w-0 xl:col-span-2">
          <CodeView code={s.body ?? ""} label={`${s.name} script`} />
        </Card>
        <Card title="Details">
          <KeyValueList
            narrow
            items={[
              ["Runs in", scriptScope(s)],
              ["Shell", SHELL_NAMES[s.shell] ?? s.shell],
              ["Timeout", formatSeconds(s.timeoutSeconds)],
              ["Size", formatBytes(s.size)],
              ["SHA-256", <Mono key="h">{s.sha256}</Mono>],
              ["Updated", formatDateTime(s.updatedAt)],
              ["Added", formatDateTime(s.createdAt)],
            ]}
          />
        </Card>
      </div>

      {can("job.view") && (
        <section className="mt-5">
          <h2 className="mb-2 text-sm font-semibold">Recent jobs</h2>
          <JobsTable params={{ scriptId: s.id }} empty="This script has not run yet." />
        </section>
      )}

      <RunScriptDialog open={running} onClose={() => setRunning(false)} script={s} />
      <ConfirmDialog
        open={deleting}
        onClose={() => setDeleting(false)}
        onConfirm={() => remove.mutate()}
        title={`Delete ${s.name}?`}
        confirmLabel="Delete script"
        tone="danger"
        loading={remove.isPending}
        error={remove.error}
        confirmText={s.name}
      >
        It leaves the library at once. Jobs that already ran it keep their own copy and results; runs still waiting for a device go ahead.
      </ConfirmDialog>
    </>
  );
}
