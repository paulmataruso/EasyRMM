import { useMemo, useState } from "react";
import { Alert, Badge, Card, TextField } from "../../../../../components/ui";
import type { GpoReport, ReportConfig, SettingNode } from "./types";

/** Keeps the nodes whose own text, or a descendant's, holds the term. */
export function filterNodes(nodes: SettingNode[], term: string): SettingNode[] {
  const t = term.trim().toLowerCase();
  if (!t) return nodes;
  const out: SettingNode[] = [];
  for (const n of nodes) {
    const own = `${n.label} ${n.value ?? ""} ${n.state ?? ""}`.toLowerCase().includes(t);
    const kids = n.children ? filterNodes(n.children, t) : [];
    if (own) out.push(n);
    else if (kids.length > 0) out.push({ ...n, children: kids });
  }
  return out;
}

const STATE_TONE: Record<string, "ok" | "warn" | "neutral"> = { Enabled: "ok", Disabled: "warn" };

function Node({ node, depth }: { node: SettingNode; depth: number }) {
  const kids = node.children ?? [];
  return (
    <li className="py-0.5">
      <div className="flex flex-wrap items-baseline gap-x-2 text-sm">
        <span className={depth === 0 ? "font-medium" : "text-muted"}>{node.label}</span>
        {node.state && <Badge tone={STATE_TONE[node.state] ?? "neutral"}>{node.state}</Badge>}
        {node.value && <span className="break-all">{node.value}</span>}
      </div>
      {kids.length > 0 && (
        <ul className="ml-4 border-l border-line pl-3">
          {kids.map((k, i) => (
            <Node key={i} node={k} depth={depth + 1} />
          ))}
        </ul>
      )}
    </li>
  );
}

function Half({ title, cfg, term }: { title: string; cfg: ReportConfig; term: string }) {
  const exts = cfg.extensions
    .map((e) => ({ ...e, settings: filterNodes(e.settings, term) }))
    .filter((e) => e.settings.length > 0 || (!term && e.noApi));
  return (
    <Card title={title} actions={<Badge tone={cfg.enabled ? "ok" : "warn"}>{cfg.enabled ? "Applies" : "Disabled"}</Badge>}>
      {exts.length === 0 ? (
        <p className="text-sm text-muted">{term ? "Nothing matches." : "No settings are configured."}</p>
      ) : (
        <div className="flex flex-col gap-2">
          {exts.map((e, i) => (
            <details key={`${e.name}-${i}`} open={Boolean(term) || i === 0} className="rounded border border-line px-3 py-2">
              <summary className="cursor-pointer text-sm font-medium">
                {e.name || e.kind || "Settings"} <span className="text-xs text-muted">({e.settings.length})</span>
              </summary>
              {e.noApi && (
                <p className="mt-1 text-xs text-muted">Read-only here: no supported API changes this. Use the Group Policy Management Console.</p>
              )}
              <ul className="mt-1">
                {e.settings.map((s, j) => (
                  <Node key={j} node={s} depth={0} />
                ))}
              </ul>
            </details>
          ))}
        </div>
      )}
    </Card>
  );
}

/**
 * The "every setting" view (ADR-0083 section 2): a GPO's settings as Microsoft's own report lists them, computer and user,
 * by extension, with a search. Read-only: nothing here can change a setting.
 */
export function SettingsTree({ report }: { report: GpoReport }) {
  const [term, setTerm] = useState("");
  const shown = useMemo(() => term, [term]);
  return (
    <div className="flex flex-col gap-3">
      {report.findings.map((f) => (
        <Alert key={f} tone="danger" title="Finding">
          {f}
        </Alert>
      ))}
      {report.truncated && (
        <Alert tone="warn">
          This GPO has more settings than fit here ({report.settings} of {report.total} lines are shown). Open it in the Group Policy
          Management Console for the rest.
        </Alert>
      )}
      <TextField label="Search the settings" value={term} onChange={(e) => setTerm(e.target.value)} placeholder="Name, value or state" />
      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <Half title="Computer configuration" cfg={report.computer} term={shown} />
        <Half title="User configuration" cfg={report.user} term={shown} />
      </div>
    </div>
  );
}
