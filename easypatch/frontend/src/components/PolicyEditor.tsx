import { useEffect, useId, useMemo, useState, type FormEvent, type ReactNode } from 'react';
import { Plus, RotateCcw, Save, X } from 'lucide-react';
import {
  DEFAULT_INSTALL_CATEGORIES,
  POLICY_CATEGORIES,
  type ApplicationUpdateSettings,
  type PolicyDto,
  type PolicyRequest,
  type PolicyScope,
  type UpdateCategory,
} from '../api/types';
import { describeApplicationUpdates, isValidAppId, MAX_APPROVED_APPS, parseAppIds, SUGGESTED_APPS } from '../lib/applications';
import { DAY_LABELS, formatDays, formatDuration, humanize, isMacOS, isValidTime, isWindows, normalizeKb } from '../lib/format';
import {
  DEFAULT_RESTART_SCHEDULE,
  describeRestartSchedule,
  mergeWindowsUpdate,
  RestartScheduleFields,
  validateRestartSchedule,
  validateWindowsUpdate,
  WindowsUpdateSection,
} from './PolicySections';
import { Alert, Badge, Button, Card, cx, InlineError, Input, Select } from './ui';

/** Values a lower scope inherits (already resolved from the parent scopes), used for "inherited" hints. */
export type InheritedPolicy = Omit<PolicyRequest, 'excludedKbs'> & { excludedKbs: string[] };

const EMPTY: PolicyRequest = {
  checkInIntervalSeconds: null,
  scanIntervalMinutes: null,
  inventoryIntervalMinutes: null,
  jitterPercent: null,
  allowedCategories: null,
  includeOptional: null,
  excludedKbs: [],
  acceptEulas: null,
  autoInstallEnabled: null,
  maintenanceDays: null,
  maintenanceStart: null,
  maintenanceDurationMinutes: null,
  scanStaleAfterHours: null,
  maxConcurrentInstallsPerSite: null,
  trayIconEnabled: null,
  installNotificationsEnabled: null,
  restartSchedule: null,
  windowsUpdate: null,
  agentAutoUpdateEnabled: null,
  installDelayDays: null,
  securityInstallDelayDays: null,
  knownExploitedSkipsDelay: null,
  applicationUpdates: null,
  preDownloadHours: null,
};

export function toRequest(policy: PolicyDto | null | undefined): PolicyRequest {
  if (!policy) return { ...EMPTY };
  return {
    checkInIntervalSeconds: policy.checkInIntervalSeconds,
    scanIntervalMinutes: policy.scanIntervalMinutes,
    inventoryIntervalMinutes: policy.inventoryIntervalMinutes,
    jitterPercent: policy.jitterPercent,
    allowedCategories: policy.allowedCategories,
    includeOptional: policy.includeOptional,
    excludedKbs: policy.excludedKbs ?? [],
    acceptEulas: policy.acceptEulas,
    autoInstallEnabled: policy.autoInstallEnabled,
    maintenanceDays: policy.maintenanceDays,
    maintenanceStart: policy.maintenanceStart ? policy.maintenanceStart.slice(0, 5) : null,
    maintenanceDurationMinutes: policy.maintenanceDurationMinutes,
    scanStaleAfterHours: policy.scanStaleAfterHours,
    maxConcurrentInstallsPerSite: policy.maxConcurrentInstallsPerSite,
    trayIconEnabled: policy.trayIconEnabled ?? null,
    installNotificationsEnabled: policy.installNotificationsEnabled ?? null,
    restartSchedule: policy.restartSchedule ? { ...policy.restartSchedule, time: policy.restartSchedule.time.slice(0, 5) } : null,
    windowsUpdate: policy.windowsUpdate ?? null,
    agentAutoUpdateEnabled: policy.agentAutoUpdateEnabled ?? null,
    installDelayDays: policy.installDelayDays ?? null,
    securityInstallDelayDays: policy.securityInstallDelayDays ?? null,
    knownExploitedSkipsDelay: policy.knownExploitedSkipsDelay ?? null,
    applicationUpdates: policy.applicationUpdates ?? null,
    preDownloadHours: policy.preDownloadHours ?? null,
  };
}

/** Resolves parent layers (most specific last) into the values a child scope would inherit. */
export function resolveInherited(layers: (PolicyDto | null | undefined)[]): InheritedPolicy {
  const out: InheritedPolicy = { ...EMPTY, excludedKbs: [] };
  const kbs = new Set<string>();
  for (const layer of layers) {
    if (!layer) continue;
    const r = toRequest(layer);
    for (const key of Object.keys(r) as (keyof PolicyRequest)[]) {
      if (key === 'excludedKbs' || key === 'maintenanceDays' || key === 'maintenanceStart' || key === 'maintenanceDurationMinutes' || key === 'windowsUpdate') continue;
      const v = r[key];
      if (v !== null && v !== undefined) (out as unknown as Record<string, unknown>)[key] = v;
    }
    if (r.maintenanceDays !== null) {
      out.maintenanceDays = r.maintenanceDays;
      out.maintenanceStart = r.maintenanceStart ?? '02:00';
      out.maintenanceDurationMinutes = r.maintenanceDurationMinutes ?? 180;
    }
    for (const kb of r.excludedKbs ?? []) kbs.add(kb.toUpperCase());
  }
  out.excludedKbs = [...kbs];
  out.windowsUpdate = mergeWindowsUpdate(layers.map((l) => l?.windowsUpdate));
  return out;
}

interface NumberSpec {
  key:
    | 'checkInIntervalSeconds'
    | 'scanIntervalMinutes'
    | 'inventoryIntervalMinutes'
    | 'jitterPercent'
    | 'scanStaleAfterHours'
    | 'maxConcurrentInstallsPerSite'
    | 'installDelayDays'
    | 'securityInstallDelayDays'
    | 'preDownloadHours';
  label: string;
  unit: string;
  min: number;
  max: number;
  hint: string;
}

const NUMBER_FIELDS: NumberSpec[] = [
  { key: 'checkInIntervalSeconds', label: 'Check-in interval', unit: 'seconds', min: 15, max: 3600, hint: 'How often idle agents contact the server. Agents with an active job check in every 15 s.' },
  { key: 'scanIntervalMinutes', label: 'Scan interval', unit: 'minutes', min: 30, max: 10080, hint: 'How often agents scan for updates (Windows Update, apt/dnf on Linux, softwareupdate on macOS).' },
  { key: 'inventoryIntervalMinutes', label: 'Inventory interval', unit: 'minutes', min: 60, max: 10080, hint: 'How often agents report OS and hardware inventory.' },
  { key: 'jitterPercent', label: 'Jitter', unit: '%', min: 0, max: 50, hint: 'Randomizes intervals so endpoints do not all check in together.' },
  { key: 'scanStaleAfterHours', label: 'Scan considered stale after', unit: 'hours', min: 1, max: 720, hint: 'Endpoints without a successful scan for this long are reported as Scan stale.' },
  { key: 'maxConcurrentInstallsPerSite', label: 'Max concurrent installs per site', unit: 'endpoints', min: 1, max: 1000, hint: 'Limits how many endpoints in one site install at the same time.' },
];

/** Rollout delays (0 = no delay). Not required in the global policy: an empty value there means 0. */
const DELAY_FIELDS: NumberSpec[] = [
  {
    key: 'securityInstallDelayDays',
    label: 'Security updates',
    unit: 'days',
    min: 0,
    max: 90,
    hint: 'Includes the monthly cumulative updates. Definition (antivirus) updates are never delayed.',
  },
  { key: 'installDelayDays', label: 'Other updates', unit: 'days', min: 0, max: 365, hint: 'Non-security updates in the allowed categories.' },
];

const PRE_DOWNLOAD_FIELD: NumberSpec = {
  key: 'preDownloadHours',
  label: 'Download before the window',
  unit: 'hours before it opens (0 = off)',
  min: 0,
  max: 24,
  hint: 'Windows agents 1.8.0 and later download the updates up to this many hours before the window opens, without installing them, so the installation in the window starts with the downloads done. Downloads in a site are limited like installations.',
};

/** A delay this long leaves endpoints without fixes for a long time; the editor warns about it. */
export const LONG_DELAY_DAYS = 30;

export function PolicyEditor({
  scope,
  policy,
  inherited,
  readOnly,
  saving,
  deleting,
  error,
  onSave,
  onReset,
  timeZone,
  platform,
}: {
  scope: PolicyScope;
  policy: PolicyDto | null;
  inherited?: InheritedPolicy;
  readOnly: boolean;
  saving?: boolean;
  deleting?: boolean;
  error?: unknown;
  onSave: (request: PolicyRequest) => void;
  /** Removes this policy layer (everything inherits). Not offered for the global policy. */
  onReset?: () => void;
  timeZone?: string;
  /**
   * The endpoint's platform, for an endpoint policy. On Linux and macOS endpoints the tray, winget and Windows Update settings
   * are hidden: those agents do not use them. Other scopes leave it out and show everything.
   */
  platform?: string | null;
}) {
  // Without a platform (global, organization, site and tag policies) every setting is shown.
  const windowsOnlyHidden = platform != null && !isWindows(platform);
  const isGlobal = scope === 'Global';
  const isEndpoint = scope === 'Endpoint';
  const isTag = scope === 'Tag';
  const initial = useMemo(() => {
    const r = toRequest(policy);
    if (isGlobal) {
      // Older global policies have no delay stored: that means no delay.
      r.installDelayDays ??= 0;
      r.securityInstallDelayDays ??= 0;
    }
    return r;
  }, [policy, isGlobal]);
  const [form, setForm] = useState<PolicyRequest>(initial);
  const [kbInput, setKbInput] = useState('');
  const [kbError, setKbError] = useState<string | null>(null);
  useEffect(() => setForm(initial), [initial]);

  const dirty = JSON.stringify(form) !== JSON.stringify(initial);
  const windowExplicit = form.maintenanceDays !== null;
  const validation = validatePolicy(form, isGlobal);

  function update<K extends keyof PolicyRequest>(key: K, value: PolicyRequest[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (validation) return;
    onSave({ ...form, excludedKbs: form.excludedKbs ?? [] });
  }

  function addKb() {
    const kb = normalizeKb(kbInput);
    if (!kb) {
      setKbError('Enter a KB number such as KB5034441.');
      return;
    }
    setKbError(null);
    const list = form.excludedKbs ?? [];
    if (!list.includes(kb)) update('excludedKbs', [...list, kb]);
    setKbInput('');
  }

  const categories = form.allowedCategories as UpdateCategory[] | null;
  const effectiveCategories = (categories ?? (inherited?.allowedCategories as UpdateCategory[] | null) ?? DEFAULT_INSTALL_CATEGORIES) as readonly UpdateCategory[];

  return (
    <form onSubmit={submit} className="flex flex-col gap-4">
      {isTag && (
        <Alert tone="info">
          A tag policy applies to every endpoint with the tag, after the site policy and before the endpoint’s own policy. Fields set to{' '}
          <strong>Inherit</strong> are left to each endpoint’s site, organization or global policy (the values shown are the global ones). When an endpoint has
          several tags with policies, the tag with the higher priority wins.
        </Alert>
      )}
      {!isGlobal && !isTag && (
        <Alert tone="info">
          Fields set to <strong>Inherit</strong> use the value from the{' '}
          {scope === 'Endpoint' ? 'tag, site, organization or global' : scope === 'Site' ? 'organization or global' : 'global'} policy. Excluded KBs are added to
          the inherited exclusions; the maintenance window and the restart schedule are inherited or overridden as a whole.
        </Alert>
      )}

      <Card title="Agent schedule">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {NUMBER_FIELDS.filter((f) => f.key !== 'scanStaleAfterHours' && f.key !== 'maxConcurrentInstallsPerSite').map((f) => (
            <NumberRow key={f.key} spec={f} value={form[f.key]} inherited={inherited?.[f.key] ?? null} isGlobal={isGlobal} readOnly={readOnly} onChange={(v) => update(f.key, v)} />
          ))}
        </div>
      </Card>

      <Card title="What gets installed">
        <div className="flex flex-col gap-5">
          <Row
            label="Allowed categories"
            hint="Updates in other categories are never installed by “Install all missing updates” or scheduled installs. Driver and Feature updates are excluded by default because they can change hardware behavior or upgrade Windows to a new release."
            inheritable={!isGlobal}
            explicit={categories !== null}
            readOnly={readOnly}
            inheritedText={inherited?.allowedCategories ? inherited.allowedCategories.map(humanize).join(', ') : 'Default categories'}
            onToggle={(explicit) => update('allowedCategories', explicit ? [...effectiveCategories] : null)}
          >
            <div className="flex flex-wrap gap-2">
              {POLICY_CATEGORIES.map((c) => {
                const checked = effectiveCategories.includes(c);
                const disabled = readOnly || (!isGlobal && categories === null);
                return (
                  <label
                    key={c}
                    className={cx(
                      'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-sm',
                      checked ? 'border-accent/50 bg-accent-soft' : 'border-line',
                      disabled && 'opacity-60',
                    )}
                  >
                    <input
                      type="checkbox"
                      className="size-3.5"
                      checked={checked}
                      disabled={disabled}
                      onChange={(e) => {
                        const set = new Set(effectiveCategories);
                        if (e.target.checked) set.add(c);
                        else set.delete(c);
                        update('allowedCategories', POLICY_CATEGORIES.filter((x) => set.has(x)));
                      }}
                    />
                    {humanize(c)}
                    {(c === 'Driver' || c === 'Feature') && <Badge tone="warn" className="ml-0.5">caution</Badge>}
                  </label>
                );
              })}
            </div>
          </Row>

          <BoolRow
            label="Include optional updates"
            hint="Optional (non-mandatory) updates such as preview cumulative updates."
            value={form.includeOptional}
            inherited={inherited?.includeOptional ?? null}
            isGlobal={isGlobal}
            readOnly={readOnly}
            onChange={(v) => update('includeOptional', v)}
          />
          <BoolRow
            label="Accept license agreements automatically"
            hint="Some updates require accepting a EULA. When off, those updates are skipped."
            value={form.acceptEulas}
            inherited={inherited?.acceptEulas ?? null}
            isGlobal={isGlobal}
            readOnly={readOnly}
            onChange={(v) => update('acceptEulas', v)}
          />

          <div>
            <p className="text-sm font-medium">Excluded KBs</p>
            <p className="text-xs text-muted">
              Never installed by EasyPatch at this scope or below. Use for updates with known problems.
              {windowsOnlyHidden &&
                ` KB exclusions apply to Windows updates only; exclude a ${isMacOS(platform) ? 'macOS update' : 'Linux package update'} on the endpoint’s Updates tab.`}
            </p>
            {!isGlobal && inherited && inherited.excludedKbs.length > 0 && (
              <p className="mt-1 text-xs text-muted">Inherited: {inherited.excludedKbs.join(', ')}</p>
            )}
            <div className="mt-2 flex flex-wrap gap-1.5">
              {(form.excludedKbs ?? []).length === 0 && <span className="text-sm text-subtle">None at this scope</span>}
              {(form.excludedKbs ?? []).map((kb) => (
                <span key={kb} className="inline-flex items-center gap-1 rounded-full bg-neutral-soft py-0.5 pr-1 pl-2.5 font-mono text-xs">
                  {kb}
                  {!readOnly && (
                    <button type="button" aria-label={`Remove ${kb}`} className="rounded-full p-0.5 hover:bg-hover" onClick={() => update('excludedKbs', (form.excludedKbs ?? []).filter((k) => k !== kb))}>
                      <X className="size-3" aria-hidden />
                    </button>
                  )}
                </span>
              ))}
            </div>
            {!readOnly && (
              <div className="mt-2 flex max-w-sm gap-2">
                <Input
                  aria-label="KB number to exclude"
                  placeholder="KB5034441"
                  value={kbInput}
                  onChange={(e) => setKbInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      addKb();
                    }
                  }}
                  aria-invalid={kbError ? true : undefined}
                />
                <Button onClick={addKb} icon={<Plus className="size-4" aria-hidden />}>
                  Add
                </Button>
              </div>
            )}
            {kbError && <p className="mt-1 text-xs text-danger">{kbError}</p>}
          </div>
        </div>
      </Card>

      <Card title="Automatic installation and maintenance window">
        <div className="flex flex-col gap-5">
          <Alert tone="info">
            When automatic installation is on, EasyPatch queues “Install all missing updates” jobs <strong>only while the maintenance window is open</strong>, using the
            categories above. Installing never restarts an endpoint; use a restart schedule (below) or restart endpoints from the console.
          </Alert>
          <BoolRow
            label="Automatic installation"
            value={form.autoInstallEnabled}
            inherited={inherited?.autoInstallEnabled ?? null}
            isGlobal={isGlobal}
            readOnly={readOnly}
            onChange={(v) => update('autoInstallEnabled', v)}
            onLabel="On"
            offLabel="Off"
          />
          <Row
            label="Maintenance window"
            hint={`Times are in the ${timeZone ? `${timeZone} ` : ''}time zone of the site (or organization).`}
            inheritable={!isGlobal}
            explicit={windowExplicit}
            readOnly={readOnly}
            inheritedText={
              inherited?.maintenanceDays
                ? `${formatDays(inherited.maintenanceDays)} at ${inherited.maintenanceStart ?? '02:00'} for ${formatDuration(inherited.maintenanceDurationMinutes ?? 180)}`
                : 'No window'
            }
            onToggle={(explicit) =>
              setForm((f) => ({
                ...f,
                maintenanceDays: explicit ? (inherited?.maintenanceDays ?? []) : null,
                maintenanceStart: explicit ? (inherited?.maintenanceStart ?? '02:00') : null,
                maintenanceDurationMinutes: explicit ? (inherited?.maintenanceDurationMinutes ?? 180) : null,
              }))
            }
          >
            <MaintenanceWindowFields form={form} setForm={setForm} disabled={readOnly || (!isGlobal && !windowExplicit)} isGlobal={isGlobal} />
          </Row>
          <div className="md:max-w-md">
            <NumberRow
              spec={PRE_DOWNLOAD_FIELD}
              value={form.preDownloadHours}
              inherited={inherited?.preDownloadHours ?? 0}
              isGlobal={isGlobal}
              readOnly={readOnly}
              onChange={(v) => update('preDownloadHours', v)}
            />
          </div>
        </div>
      </Card>

      <Card title="Rollout delay">
        <div className="flex flex-col gap-4">
          <p className="text-sm text-muted">
            An update is not required, and scheduled installs skip it, until this many days after EasyPatch first saw it on any endpoint. Use a short delay for a
            pilot group (for example a “Pilot” tag) and a longer one for everyone else. A newer update that replaces an older one keeps the older one’s start date.
            Installing manually ignores the delay.
          </p>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {DELAY_FIELDS.map((f) => (
              <NumberRow key={f.key} spec={f} value={form[f.key]} inherited={inherited?.[f.key] ?? 0} isGlobal={isGlobal} readOnly={readOnly} onChange={(v) => update(f.key, v)} />
            ))}
          </div>
          <BoolRow
            label="Known-exploited vulnerabilities"
            hint="Updates that fix a vulnerability in the CISA Known Exploited Vulnerabilities catalog are required at once instead of waiting for the delay. See Updates → known exploited."
            value={form.knownExploitedSkipsDelay}
            inherited={isGlobal ? true : (inherited?.knownExploitedSkipsDelay ?? true)}
            isGlobal={isGlobal}
            readOnly={readOnly}
            onChange={(v) => update('knownExploitedSkipsDelay', v)}
            onLabel="Skip the delay"
            offLabel="Wait"
          />
          {DELAY_FIELDS.some((f) => (form[f.key] ?? 0) > LONG_DELAY_DAYS) && (
            <Alert tone="warn">
              A delay longer than {LONG_DELAY_DAYS} days leaves endpoints without released fixes for over a month. Endpoints still count as compliant while updates
              wait.
            </Alert>
          )}
        </div>
      </Card>

      <Card title="Scheduled restarts">
        <Row
          label="Restart schedule"
          hint={
            <>
              EasyPatch restarts endpoints only on this schedule or when an administrator requests a restart. Times are in the{' '}
              {timeZone ? `${timeZone} ` : ''}time zone of the site (or organization). If nobody is signed in, the endpoint restarts at once. Agents older than 1.1.0
              ignore this schedule.
            </>
          }
          inheritable={!isGlobal}
          explicit={isGlobal || form.restartSchedule !== null}
          readOnly={readOnly}
          inheritedText={describeRestartSchedule(inherited?.restartSchedule ?? null)}
          onToggle={(explicit) =>
            update('restartSchedule', explicit ? { ...(inherited?.restartSchedule ?? DEFAULT_RESTART_SCHEDULE), enabled: true } : null)
          }
        >
          {isGlobal && form.restartSchedule === null ? (
            <div className="flex flex-wrap items-center gap-3">
              <span className="text-sm text-muted">No restart schedule.</span>
              {!readOnly && (
                <Button size="sm" onClick={() => update('restartSchedule', { ...DEFAULT_RESTART_SCHEDULE })}>
                  Add a schedule
                </Button>
              )}
            </div>
          ) : (
            form.restartSchedule && (
              <RestartScheduleFields value={form.restartSchedule} disabled={readOnly} onChange={(v) => update('restartSchedule', v)} />
            )
          )}
        </Row>
      </Card>

      {!windowsOnlyHidden && (
        <Card title="User experience">
          <div className="grid grid-cols-1 gap-5 md:grid-cols-2">
            <BoolRow
              label="EasyPatch icon in the notification area"
              hint="Users open the EasyPatch status window from the icon (status, Check in now, Check for updates, recent log). When hidden, the icon appears only while a message or a restart request is shown, so users cannot open the status window."
              value={form.trayIconEnabled}
              inherited={isGlobal ? true : (inherited?.trayIconEnabled ?? true)}
              isGlobal={isGlobal}
              readOnly={readOnly}
              onChange={(v) => update('trayIconEnabled', v)}
              onLabel="Show"
              offLabel="Hide"
            />
            <BoolRow
              label="Installation notifications"
              hint="Tell signed-in users when updates start installing and when they have finished (or need a restart)."
              value={form.installNotificationsEnabled}
              inherited={isGlobal ? true : (inherited?.installNotificationsEnabled ?? true)}
              isGlobal={isGlobal}
              readOnly={readOnly}
              onChange={(v) => update('installNotificationsEnabled', v)}
              onLabel="On"
              offLabel="Off"
            />
          </div>
        </Card>
      )}

      <Card title="EasyPatch agent">
        <BoolRow
          label="Agent updates"
          hint="Automatic: computers with agent 1.2.0 or newer install a newer signed agent package as soon as it is on the server (a few at a time). Manual: only when someone clicks Update agent. Agents check the release signature themselves and never downgrade."
          value={form.agentAutoUpdateEnabled}
          inherited={isGlobal ? true : (inherited?.agentAutoUpdateEnabled ?? true)}
          isGlobal={isGlobal}
          readOnly={readOnly}
          onChange={(v) => update('agentAutoUpdateEnabled', v)}
          onLabel="Automatic"
          offLabel="Manual"
        />
      </Card>

      {!windowsOnlyHidden && (
        <Card title="Application updates (winget)">
          <Row
            label="Third-party application updates"
            hint={
              <>
                Upgrades approved applications with winget from the winget community repository, only on computers where the application is already installed
                machine-wide. Updates of approved applications are installed like Windows updates (scheduled installs and “Install all missing updates”); an upgrade
                counts as installed only when winget then lists the new version. Requires agent 1.4.0 and App Installer (winget) 1.6 or newer, which Windows Server
                2019 and 2022 do not include. See docs/application-updates.md.
              </>
            }
            inheritable={!isGlobal}
            explicit={isGlobal || form.applicationUpdates !== null}
            readOnly={readOnly}
            inheritedText={describeApplicationUpdates(inherited?.applicationUpdates)}
            onToggle={(explicit) =>
              update('applicationUpdates', explicit ? { enabled: false, approvedApps: [], ...inherited?.applicationUpdates } : null)
            }
          >
            <ApplicationUpdatesFields
              value={form.applicationUpdates ?? { enabled: false, approvedApps: [] }}
              disabled={readOnly || (!isGlobal && form.applicationUpdates === null)}
              onChange={(v) => update('applicationUpdates', v)}
            />
          </Row>
        </Card>
      )}

      {!windowsOnlyHidden && (
        <Card title="Windows Update settings">
          <WindowsUpdateSection
            value={form.windowsUpdate}
            inherited={inherited?.windowsUpdate ?? null}
            isGlobal={isGlobal}
            readOnly={readOnly}
            onChange={(v) => update('windowsUpdate', v)}
          />
        </Card>
      )}

      <Card title="Compliance and limits">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          {NUMBER_FIELDS.filter((f) => f.key === 'scanStaleAfterHours' || (f.key === 'maxConcurrentInstallsPerSite' && !isEndpoint && !isTag)).map((f) => (
            <NumberRow key={f.key} spec={f} value={form[f.key]} inherited={inherited?.[f.key] ?? null} isGlobal={isGlobal} readOnly={readOnly} onChange={(v) => update(f.key, v)} />
          ))}
        </div>
      </Card>

      {validation && <Alert tone="warn">{validation}</Alert>}
      <InlineError error={error} />

      {!readOnly && (
        <div className="sticky bottom-0 -mx-1 flex flex-wrap items-center justify-end gap-2 border-t border-line bg-canvas/95 px-1 py-3">
          {policy?.updatedAt && <span className="mr-auto text-xs text-muted">Last changed {new Date(policy.updatedAt).toLocaleString()}</span>}
          {!isGlobal && onReset && policy?.id && (
            <Button variant="danger-ghost" onClick={onReset} loading={deleting} icon={<RotateCcw className="size-4" aria-hidden />}>
              Inherit everything
            </Button>
          )}
          <Button onClick={() => setForm(initial)} disabled={!dirty}>
            Discard changes
          </Button>
          <Button type="submit" variant="primary" loading={saving} disabled={!dirty || !!validation} icon={<Save className="size-4" aria-hidden />}>
            Save policy
          </Button>
        </div>
      )}
    </form>
  );
}

/** Client-side mirror of the server policy validation, for immediate feedback (the server enforces it). */
export function validatePolicy(form: PolicyRequest, isGlobal: boolean): string | null {
  for (const f of NUMBER_FIELDS) {
    const v = form[f.key];
    if (v === null) {
      if (isGlobal) return `${f.label} is required in the global policy.`;
      continue;
    }
    if (!Number.isInteger(v) || v < f.min || v > f.max) return `${f.label} must be between ${f.min} and ${f.max} ${f.unit}.`;
  }
  for (const f of DELAY_FIELDS) {
    const v = form[f.key];
    if (v !== null && (!Number.isInteger(v) || v < f.min || v > f.max)) return `Rollout delay for ${f.label.toLowerCase()} must be between ${f.min} and ${f.max} days.`;
  }
  const pre = form.preDownloadHours;
  if (pre !== null && (!Number.isInteger(pre) || pre < 0 || pre > 24)) return 'Download before the window must be between 0 and 24 hours.';
  if (isGlobal && (form.includeOptional === null || form.acceptEulas === null || form.autoInstallEnabled === null)) {
    return 'Every setting is required in the global policy.';
  }
  if (form.allowedCategories !== null && form.allowedCategories.length === 0) return 'Select at least one update category.';
  const apps = form.applicationUpdates?.approvedApps ?? [];
  if (apps.length > MAX_APPROVED_APPS) return `Approve at most ${MAX_APPROVED_APPS} applications.`;
  if (apps.some((id) => !isValidAppId(id))) return 'Approved applications must be winget package IDs such as Mozilla.Firefox.';
  if (form.maintenanceDays !== null) {
    if (!form.maintenanceStart || !isValidTime(form.maintenanceStart)) return 'Maintenance window start must be a time such as 02:00.';
    const d = form.maintenanceDurationMinutes;
    if (d === null || !Number.isInteger(d) || d < 15 || d > 1440) return 'Maintenance window duration must be between 15 and 1440 minutes.';
  }
  if (form.autoInstallEnabled === true && form.maintenanceDays !== null && form.maintenanceDays.length === 0) {
    return 'Automatic installation needs at least one maintenance day.';
  }
  return validateRestartSchedule(form.restartSchedule) ?? validateWindowsUpdate(form.windowsUpdate);
}

function ApplicationUpdatesFields({ value, disabled, onChange }: {
  value: ApplicationUpdateSettings;
  disabled: boolean;
  onChange: (value: ApplicationUpdateSettings) => void;
}) {
  const id = useId();
  const [input, setInput] = useState('');
  const [inputError, setInputError] = useState<string | null>(null);
  const approved = value.approvedApps;

  function add(text: string) {
    const { ids, invalid } = parseAppIds(text, approved);
    if (invalid.length > 0) {
      setInputError(`Not a winget package ID: ${invalid.slice(0, 3).join(', ')}. Use the ID shown by “winget search”, such as Mozilla.Firefox.`);
      return;
    }
    if (approved.length + ids.length > MAX_APPROVED_APPS) {
      setInputError(`Approve at most ${MAX_APPROVED_APPS} applications.`);
      return;
    }
    setInputError(null);
    if (ids.length > 0) onChange({ ...value, approvedApps: [...approved, ...ids] });
    setInput('');
  }

  const suggestions = SUGGESTED_APPS.filter((s) => !approved.some((a) => a.toLowerCase() === s.id.toLowerCase()));
  return (
    <div className={cx('flex flex-col gap-3', disabled && 'opacity-60')}>
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={id} className="text-sm">
          Status
        </label>
        <Select id={id} value={value.enabled ? 'on' : 'off'} disabled={disabled} onChange={(e) => onChange({ ...value, enabled: e.target.value === 'on' })} className="w-auto">
          <option value="off">Off</option>
          <option value="on">On for the approved applications</option>
        </Select>
      </div>
      <div>
        <p className="text-sm font-medium">Approved applications</p>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {approved.length === 0 && <span className="text-sm text-subtle">None</span>}
          {approved.map((app) => (
            <span key={app} className="inline-flex items-center gap-1 rounded-full bg-neutral-soft py-0.5 pr-1 pl-2.5 font-mono text-xs">
              {app}
              {!disabled && (
                <button
                  type="button"
                  aria-label={`Remove ${app}`}
                  className="rounded-full p-0.5 hover:bg-hover"
                  onClick={() => onChange({ ...value, approvedApps: approved.filter((a) => a !== app) })}
                >
                  <X className="size-3" aria-hidden />
                </button>
              )}
            </span>
          ))}
        </div>
      </div>
      {!disabled && (
        <>
          <div className="flex max-w-md gap-2">
            <Input
              aria-label="winget package ID to approve"
              placeholder="Mozilla.Firefox"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  add(input);
                }
              }}
              aria-invalid={inputError ? true : undefined}
            />
            <Button onClick={() => add(input)} icon={<Plus className="size-4" aria-hidden />}>
              Approve
            </Button>
          </div>
          {inputError && <p className="text-xs text-danger">{inputError}</p>}
          {suggestions.length > 0 && (
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-xs text-muted">Common:</span>
              {suggestions.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  title={s.id}
                  className="rounded-full border border-line px-2 py-0.5 text-xs hover:bg-hover"
                  onClick={() => add(s.id)}
                >
                  + {s.name}
                </button>
              ))}
            </div>
          )}
        </>
      )}
      {value.enabled && approved.length === 0 && <p className="text-xs text-warn">No applications are approved, so none are checked.</p>}
      <p className="text-xs text-muted">
        Applications installed only for one user (for example in AppData) are not visible to the agent. Installers may close a running application. EasyPatch never
        installs an application that is not already there and never restarts a computer because of an application update.
      </p>
    </div>
  );
}

function Row({ label, hint, inheritable, explicit, readOnly, inheritedText, onToggle, children }: {
  label: string;
  hint?: ReactNode;
  inheritable: boolean;
  explicit: boolean;
  readOnly: boolean;
  inheritedText: ReactNode;
  onToggle: (explicit: boolean) => void;
  children: ReactNode;
}) {
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-medium">{label}</p>
        {inheritable && <InheritToggle explicit={explicit} readOnly={readOnly} onToggle={onToggle} />}
      </div>
      {hint && <p className="text-xs text-muted">{hint}</p>}
      {inheritable && !explicit && <p className="mt-1 text-xs text-muted">Inherited: {inheritedText}</p>}
      <div className="mt-2">{children}</div>
    </div>
  );
}

function InheritToggle({ explicit, readOnly, onToggle }: { explicit: boolean; readOnly: boolean; onToggle: (explicit: boolean) => void }) {
  return (
    <div className="inline-flex rounded-md border border-line p-0.5 text-xs" role="group" aria-label="Inherit or override">
      <button
        type="button"
        disabled={readOnly}
        aria-pressed={!explicit}
        onClick={() => onToggle(false)}
        className={cx('rounded px-2 py-0.5', !explicit ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg')}
      >
        Inherit
      </button>
      <button
        type="button"
        disabled={readOnly}
        aria-pressed={explicit}
        onClick={() => onToggle(true)}
        className={cx('rounded px-2 py-0.5', explicit ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg')}
      >
        Override
      </button>
    </div>
  );
}

function NumberRow({ spec, value, inherited, isGlobal, readOnly, onChange }: {
  spec: NumberSpec;
  value: number | null;
  inherited: number | null;
  isGlobal: boolean;
  readOnly: boolean;
  onChange: (value: number | null) => void;
}) {
  const id = useId();
  const explicit = value !== null || isGlobal;
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label htmlFor={id} className="text-sm font-medium">
          {spec.label}
        </label>
        {!isGlobal && <InheritToggle explicit={value !== null} readOnly={readOnly} onToggle={(e) => onChange(e ? (inherited ?? spec.min) : null)} />}
      </div>
      <div className="mt-1.5 flex items-center gap-2">
        <Input
          id={id}
          type="number"
          min={spec.min}
          max={spec.max}
          step={1}
          className="max-w-36"
          disabled={readOnly || !explicit}
          value={value ?? inherited ?? ''}
          onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
        />
        <span className="text-xs text-muted">{spec.unit}</span>
        {!isGlobal && value === null && <span className="text-xs text-subtle">(inherited)</span>}
      </div>
      <p className="mt-1 text-xs text-muted">{spec.hint}</p>
    </div>
  );
}

function BoolRow({ label, hint, value, inherited, isGlobal, readOnly, onChange, onLabel = 'Yes', offLabel = 'No' }: {
  label: string;
  hint?: string;
  value: boolean | null;
  inherited: boolean | null;
  isGlobal: boolean;
  readOnly: boolean;
  onChange: (value: boolean | null) => void;
  onLabel?: string;
  offLabel?: string;
}) {
  const id = useId();
  const explicit = value !== null || isGlobal;
  const shown = value ?? inherited ?? false;
  return (
    <div>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        {!isGlobal && <InheritToggle explicit={value !== null} readOnly={readOnly} onToggle={(e) => onChange(e ? (inherited ?? false) : null)} />}
      </div>
      {hint && <p className="text-xs text-muted">{hint}</p>}
      <Select id={id} className="mt-1.5 max-w-36" disabled={readOnly || !explicit} value={shown ? 'true' : 'false'} onChange={(e) => onChange(e.target.value === 'true')}>
        <option value="true">{onLabel}</option>
        <option value="false">{offLabel}</option>
      </Select>
    </div>
  );
}

function MaintenanceWindowFields({ form, setForm, disabled, isGlobal }: {
  form: PolicyRequest;
  setForm: (updater: (f: PolicyRequest) => PolicyRequest) => void;
  disabled: boolean;
  isGlobal: boolean;
}) {
  const startId = useId();
  const durationId = useId();
  const days = form.maintenanceDays ?? [];
  return (
    <div className="flex flex-col gap-3">
      <fieldset>
        <legend className="mb-1 text-xs font-medium text-muted">Days</legend>
        <div className="flex flex-wrap gap-1.5">
          {DAY_LABELS.map((label, d) => {
            const on = days.includes(d);
            return (
              <button
                key={d}
                type="button"
                disabled={disabled}
                aria-pressed={on}
                onClick={() =>
                  setForm((f) => {
                    const current = f.maintenanceDays ?? [];
                    const next = on ? current.filter((x) => x !== d) : [...current, d].sort((a, b) => a - b);
                    return { ...f, maintenanceDays: next };
                  })
                }
                className={cx(
                  'h-8 w-12 rounded-md border text-sm transition-colors disabled:opacity-60',
                  on ? 'border-accent bg-accent text-accent-fg' : 'border-line bg-surface text-fg hover:bg-hover',
                )}
              >
                {label}
              </button>
            );
          })}
        </div>
        {isGlobal && days.length === 0 && <p className="mt-1 text-xs text-muted">No days selected: no maintenance window (automatic installation never runs).</p>}
      </fieldset>
      <div className="flex flex-wrap gap-4">
        <div className="flex flex-col gap-1">
          <label htmlFor={startId} className="text-xs font-medium text-muted">
            Start time
          </label>
          <Input
            id={startId}
            type="time"
            className="w-32"
            disabled={disabled}
            value={form.maintenanceStart ?? ''}
            onChange={(e) => setForm((f) => ({ ...f, maintenanceStart: e.target.value || null }))}
          />
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor={durationId} className="text-xs font-medium text-muted">
            Duration (minutes)
          </label>
          <Input
            id={durationId}
            type="number"
            min={15}
            max={1440}
            step={15}
            className="w-32"
            disabled={disabled}
            value={form.maintenanceDurationMinutes ?? ''}
            onChange={(e) => setForm((f) => ({ ...f, maintenanceDurationMinutes: e.target.value === '' ? null : Number(e.target.value) }))}
          />
        </div>
      </div>
    </div>
  );
}
