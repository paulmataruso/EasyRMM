import { useId, type ReactNode } from 'react';
import {
  AUTO_UPDATE_MODES,
  RESTART_MODES,
  WINDOWS_UPDATE_POLICY_GROUPS,
  type AutoUpdateMode,
  type AutomaticUpdatesSettings,
  type FeatureUpdateSettings,
  type PolicyGroupSetting,
  type PolicyWindowsUpdate,
  type QualityUpdateSettings,
  type RestartBehaviorSettings,
  type RestartMode,
  type RestartScheduleDto,
  type WindowsUpdateGroupSettings,
  type WindowsUpdatePolicyGroup,
} from '../api/types';
import { DAY_LABELS, formatDays, formatDuration, isValidTime } from '../lib/format';
import { Alert, Checkbox, cx, Input, Select } from './ui';

// ---------------------------------------------------------------------------------------------
// Restarts
// ---------------------------------------------------------------------------------------------

export const RESTART_MODE_INFO: Record<RestartMode, { label: string; description: string }> = {
  PromptWithDeadline: {
    label: 'Ask users, restart at a deadline',
    description: 'Signed-in users can restart now or postpone (1 hour, 4 hours or 1 day) until the deadline. At the deadline a 5-minute countdown starts.',
  },
  Countdown: { label: 'Countdown, then restart', description: 'Signed-in users see a countdown and can only restart sooner.' },
  PromptNoDeadline: {
    label: 'Ask users, no deadline',
    description: 'Signed-in users decide when to restart. The request is dropped if nobody restarts within 7 days.',
  },
  Immediate: { label: 'Restart immediately', description: 'No warning. Signed-in users lose unsaved work.' },
};

export const COUNTDOWN_OPTIONS = [1, 2, 5, 10, 15, 30, 60];
export const DEADLINE_OPTIONS = [15, 30, 60, 120, 240, 480, 1440, 2880, 4320, 10080];
export const EXPIRY_OPTIONS = [15, 30, 60, 120, 240, 480, 720, 1440];

export const DEFAULT_RESTART_SCHEDULE: RestartScheduleDto = {
  enabled: true,
  days: [0],
  time: '03:00',
  condition: 'OnlyIfPending',
  mode: 'PromptWithDeadline',
  countdownMinutes: 5,
  deadlineMinutes: 240,
  expiryMinutes: 120,
};

export function describeRestartSchedule(s: RestartScheduleDto | null | undefined): string {
  if (!s) return 'No restart schedule';
  if (!s.enabled) return 'Off';
  const mode =
    s.mode === 'PromptWithDeadline'
      ? `ask users, deadline ${formatDuration(s.deadlineMinutes)}`
      : s.mode === 'Countdown'
        ? `${s.countdownMinutes}-minute countdown`
        : s.mode === 'PromptNoDeadline'
          ? 'ask users, no deadline'
          : 'restart immediately';
  return `${formatDays(s.days)} at ${s.time.slice(0, 5)}, ${s.condition === 'OnlyIfPending' ? 'only when a restart is pending' : 'always'}, ${mode}`;
}

export function validateRestartSchedule(s: RestartScheduleDto | null): string | null {
  if (!s || !s.enabled) return null;
  if (s.days.length === 0) return 'Choose at least one day for the restart schedule.';
  if (!isValidTime(s.time)) return 'The restart time must be a time such as 03:00.';
  if (s.expiryMinutes < 15 || s.expiryMinutes > 1440) return 'A scheduled restart can wait 15 minutes to 24 hours for an offline computer.';
  if (s.mode === 'Countdown' && (s.countdownMinutes < 1 || s.countdownMinutes > 60)) return 'The countdown must be between 1 and 60 minutes.';
  if (s.mode === 'PromptWithDeadline' && (s.deadlineMinutes < 15 || s.deadlineMinutes > 10080)) return 'The deadline must be between 15 minutes and 7 days.';
  return null;
}

/** Mode, countdown and deadline (shared by the restart schedule and the one-off restart dialog). */
export function RestartModeFields({ mode, countdownMinutes, deadlineMinutes, disabled, onChange }: {
  mode: RestartMode;
  countdownMinutes: number;
  deadlineMinutes: number;
  disabled?: boolean;
  onChange: (change: { mode?: RestartMode; countdownMinutes?: number; deadlineMinutes?: number }) => void;
}) {
  const modeId = useId();
  const extraId = useId();
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <label htmlFor={modeId} className="text-xs font-medium text-muted">
          How users are asked
        </label>
        <Select id={modeId} className="max-w-sm" disabled={disabled} value={mode} onChange={(e) => onChange({ mode: e.target.value as RestartMode })}>
          {RESTART_MODES.map((m) => (
            <option key={m} value={m}>
              {RESTART_MODE_INFO[m].label}
            </option>
          ))}
        </Select>
        <p className={cx('text-xs', mode === 'Immediate' ? 'text-danger' : 'text-muted')}>{RESTART_MODE_INFO[mode].description}</p>
      </div>
      {mode === 'Countdown' && (
        <div className="flex flex-col gap-1">
          <label htmlFor={extraId} className="text-xs font-medium text-muted">
            Countdown
          </label>
          <Select id={extraId} className="w-40" disabled={disabled} value={countdownMinutes} onChange={(e) => onChange({ countdownMinutes: Number(e.target.value) })}>
            {withCurrent(COUNTDOWN_OPTIONS, countdownMinutes).map((m) => (
              <option key={m} value={m}>
                {formatDuration(m)}
              </option>
            ))}
          </Select>
        </div>
      )}
      {mode === 'PromptWithDeadline' && (
        <div className="flex flex-col gap-1">
          <label htmlFor={extraId} className="text-xs font-medium text-muted">
            Deadline (after users are first asked)
          </label>
          <Select id={extraId} className="w-40" disabled={disabled} value={deadlineMinutes} onChange={(e) => onChange({ deadlineMinutes: Number(e.target.value) })}>
            {withCurrent(DEADLINE_OPTIONS, deadlineMinutes).map((m) => (
              <option key={m} value={m}>
                {formatDuration(m)}
              </option>
            ))}
          </Select>
        </div>
      )}
    </div>
  );
}

export function RestartScheduleFields({ value, disabled, onChange }: { value: RestartScheduleDto; disabled: boolean; onChange: (value: RestartScheduleDto) => void }) {
  const enabledId = useId();
  const timeId = useId();
  const conditionId = useId();
  const expiryId = useId();
  const set = (change: Partial<RestartScheduleDto>) => onChange({ ...value, ...change });
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-1">
        <label htmlFor={enabledId} className="text-xs font-medium text-muted">
          Schedule
        </label>
        <Select id={enabledId} className="w-40" disabled={disabled} value={value.enabled ? 'on' : 'off'} onChange={(e) => set({ enabled: e.target.value === 'on' })}>
          <option value="on">On</option>
          <option value="off">Off</option>
        </Select>
      </div>
      {value.enabled && (
        <>
          <fieldset>
            <legend className="mb-1 text-xs font-medium text-muted">Days</legend>
            <DayButtons days={value.days} disabled={disabled} onChange={(days) => set({ days })} />
          </fieldset>
          <div className="flex flex-wrap gap-4">
            <div className="flex flex-col gap-1">
              <label htmlFor={timeId} className="text-xs font-medium text-muted">
                Time
              </label>
              <Input id={timeId} type="time" className="w-32" disabled={disabled} value={value.time} onChange={(e) => set({ time: e.target.value })} />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor={conditionId} className="text-xs font-medium text-muted">
                Restart
              </label>
              <Select id={conditionId} className="w-64" disabled={disabled} value={value.condition} onChange={(e) => set({ condition: e.target.value as RestartScheduleDto['condition'] })}>
                <option value="OnlyIfPending">Only when Windows reports a pending restart</option>
                <option value="Always">Always</option>
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor={expiryId} className="text-xs font-medium text-muted">
                If the computer is off, give up after
              </label>
              <Select id={expiryId} className="w-40" disabled={disabled} value={value.expiryMinutes} onChange={(e) => set({ expiryMinutes: Number(e.target.value) })}>
                {withCurrent(EXPIRY_OPTIONS, value.expiryMinutes).map((m) => (
                  <option key={m} value={m}>
                    {formatDuration(m)}
                  </option>
                ))}
              </Select>
            </div>
          </div>
          <RestartModeFields
            mode={value.mode}
            countdownMinutes={value.countdownMinutes}
            deadlineMinutes={value.deadlineMinutes}
            disabled={disabled}
            onChange={(change) => set(change)}
          />
        </>
      )}
    </div>
  );
}

export function DayButtons({ days, disabled, onChange }: { days: number[]; disabled: boolean; onChange: (days: number[]) => void }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {DAY_LABELS.map((label, d) => {
        const on = days.includes(d);
        return (
          <button
            key={d}
            type="button"
            disabled={disabled}
            aria-pressed={on}
            onClick={() => onChange(on ? days.filter((x) => x !== d) : [...days, d].sort((a, b) => a - b))}
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
  );
}

function withCurrent(options: number[], current: number): number[] {
  return options.includes(current) ? options : [...options, current].sort((a, b) => a - b);
}

// ---------------------------------------------------------------------------------------------
// Windows Update policy
// ---------------------------------------------------------------------------------------------

type GroupKey = keyof PolicyWindowsUpdate;

export const WU_GROUPS: Record<WindowsUpdatePolicyGroup, { key: GroupKey; label: string; hint: string }> = {
  AutomaticUpdates: {
    key: 'automaticUpdates',
    label: 'Automatic Updates',
    hint: 'Whether and how Windows downloads and installs updates by itself.',
  },
  FeatureUpdates: {
    key: 'featureUpdates',
    label: 'Feature updates',
    hint: 'Delay new Windows releases, or keep endpoints on a specific version.',
  },
  QualityUpdates: {
    key: 'qualityUpdates',
    label: 'Quality updates and pausing',
    hint: 'Delay monthly updates, and stop users pausing updates in Settings.',
  },
  RestartBehavior: {
    key: 'restartBehavior',
    label: 'Restart behaviour',
    hint: 'Stop Windows restarting by itself while someone is signed in, and set active hours.',
  },
};

export const WU_DEFAULTS: WindowsUpdateGroupSettings = {
  AutomaticUpdates: { mode: 'AutoDownloadNotifyInstall', scheduledInstallDay: 0, scheduledInstallHour: 3 },
  FeatureUpdates: { deferDays: 180, targetProductVersion: null, targetReleaseVersion: null },
  QualityUpdates: { deferDays: null, disablePause: true },
  RestartBehavior: { noAutoRestartWithSignedInUsers: true, activeHoursStart: 8, activeHoursEnd: 18 },
};

export const AUTO_UPDATE_MODE_LABELS: Record<AutoUpdateMode, string> = {
  Disabled: 'Turn off Automatic Updates',
  NotifyDownload: 'Notify before downloading and installing',
  AutoDownloadNotifyInstall: 'Download automatically, notify to install',
  AutoDownloadScheduleInstall: 'Download automatically, install on a schedule',
};

const INSTALL_DAYS = ['Every day', 'Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
const hour = (h: number) => `${String(h).padStart(2, '0')}:00`;

export function describeWindowsUpdateGroup(group: WindowsUpdatePolicyGroup, value: unknown): string {
  if (!value) return 'Not configured';
  switch (group) {
    case 'AutomaticUpdates': {
      const v = value as AutomaticUpdatesSettings;
      return v.mode === 'AutoDownloadScheduleInstall'
        ? `${AUTO_UPDATE_MODE_LABELS[v.mode]} (${INSTALL_DAYS[v.scheduledInstallDay] ?? '?'} at ${hour(v.scheduledInstallHour)})`
        : AUTO_UPDATE_MODE_LABELS[v.mode];
    }
    case 'FeatureUpdates': {
      const v = value as FeatureUpdateSettings;
      const parts = [v.deferDays !== null ? `defer ${v.deferDays} days` : 'no deferral'];
      if (v.targetProductVersion && v.targetReleaseVersion) parts.push(`stay on ${v.targetProductVersion} ${v.targetReleaseVersion}`);
      return parts.join(', ');
    }
    case 'QualityUpdates': {
      const v = value as QualityUpdateSettings;
      return [v.deferDays !== null ? `defer ${v.deferDays} days` : 'no deferral', v.disablePause ? 'pausing disabled' : 'users may pause'].join(', ');
    }
    case 'RestartBehavior': {
      const v = value as RestartBehaviorSettings;
      const parts = [v.noAutoRestartWithSignedInUsers ? 'no automatic restart while signed in' : 'Windows may restart while signed in'];
      if (v.activeHoursStart !== null && v.activeHoursEnd !== null) parts.push(`active hours ${hour(v.activeHoursStart)}–${hour(v.activeHoursEnd)}`);
      return parts.join(', ');
    }
  }
}

function describeSetting(group: WindowsUpdatePolicyGroup, setting: PolicyGroupSetting<unknown> | null): string {
  if (!setting || !setting.managed) return 'Not configured';
  return describeWindowsUpdateGroup(group, setting.value);
}

/** Client-side mirror of the server's Windows Update validation. */
export function validateWindowsUpdate(wu: PolicyWindowsUpdate | null): string | null {
  if (!wu) return null;
  for (const group of WINDOWS_UPDATE_POLICY_GROUPS) {
    const setting = wu[WU_GROUPS[group].key];
    if (setting?.managed && !setting.value) return `Windows Update ${WU_GROUPS[group].label}: choose the settings to apply.`;
  }
  const au = wu.automaticUpdates?.managed ? wu.automaticUpdates.value : null;
  if (au && (au.scheduledInstallHour < 0 || au.scheduledInstallHour > 23)) return 'The scheduled install hour must be between 0 and 23.';
  const fu = wu.featureUpdates?.managed ? wu.featureUpdates.value : null;
  if (fu) {
    if (fu.deferDays !== null && (!Number.isInteger(fu.deferDays) || fu.deferDays < 0 || fu.deferDays > 365)) return 'Feature updates can be deferred by 0-365 days.';
    const product = !!fu.targetProductVersion;
    const release = !!fu.targetReleaseVersion;
    if (product !== release) return 'To pin the Windows version, set both the product and the version (for example 24H2).';
    if (release && !/^[0-9]{2}H[12]$/i.test(fu.targetReleaseVersion ?? '')) return 'The pinned version must look like 24H2.';
  }
  const qu = wu.qualityUpdates?.managed ? wu.qualityUpdates.value : null;
  if (qu && qu.deferDays !== null && (!Number.isInteger(qu.deferDays) || qu.deferDays < 0 || qu.deferDays > 30)) return 'Quality updates can be deferred by 0-30 days.';
  const rb = wu.restartBehavior?.managed ? wu.restartBehavior.value : null;
  if (rb && (rb.activeHoursStart === null) !== (rb.activeHoursEnd === null)) return 'Set both the start and the end of active hours.';
  if (rb && rb.activeHoursStart !== null && rb.activeHoursEnd !== null) {
    const span = (rb.activeHoursEnd - rb.activeHoursStart + 24) % 24;
    if (span === 0 || span > 18) return 'Active hours must span 1 to 18 hours.';
  }
  return null;
}

/** Merges Windows Update groups from parent layers (most specific last): the last layer that sets a group wins. */
export function mergeWindowsUpdate(layers: (PolicyWindowsUpdate | null | undefined)[]): PolicyWindowsUpdate {
  const out: PolicyWindowsUpdate = { automaticUpdates: null, featureUpdates: null, qualityUpdates: null, restartBehavior: null };
  for (const layer of layers) {
    if (!layer) continue;
    for (const group of WINDOWS_UPDATE_POLICY_GROUPS) {
      const key = WU_GROUPS[group].key;
      if (layer[key]) (out as unknown as Record<string, unknown>)[key] = layer[key];
    }
  }
  return out;
}

type GroupState = 'inherit' | 'off' | 'on';

export function WindowsUpdateSection({ value, inherited, isGlobal, readOnly, onChange }: {
  value: PolicyWindowsUpdate | null;
  inherited: PolicyWindowsUpdate | null;
  isGlobal: boolean;
  readOnly: boolean;
  onChange: (value: PolicyWindowsUpdate | null) => void;
}) {
  const current: PolicyWindowsUpdate = value ?? { automaticUpdates: null, featureUpdates: null, qualityUpdates: null, restartBehavior: null };

  function setGroup(key: GroupKey, setting: PolicyGroupSetting<unknown> | null) {
    const next = { ...current, [key]: setting } as PolicyWindowsUpdate;
    onChange(WINDOWS_UPDATE_POLICY_GROUPS.every((g) => next[WU_GROUPS[g].key] === null) ? null : next);
  }

  return (
    <div className="flex flex-col gap-5">
      <Alert tone="info">
        EasyPatch writes these settings on each endpoint under <code>HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate</code>, the same place Group Policy
        uses. <strong>Not configured</strong> leaves Windows alone. Endpoints keep their original values and get them back when a group is no longer configured or
        the agent is uninstalled. If domain Group Policy or another tool changes the same values, EasyPatch reports a conflict and stops re-applying them. WSUS server
        settings are never changed.
      </Alert>
      {WINDOWS_UPDATE_POLICY_GROUPS.map((group) => {
        const { key, label, hint } = WU_GROUPS[group];
        const setting = current[key] as PolicyGroupSetting<unknown> | null;
        const inheritedSetting = (inherited?.[key] ?? null) as PolicyGroupSetting<unknown> | null;
        const state: GroupState = setting === null ? (isGlobal ? 'off' : 'inherit') : setting.managed ? 'on' : 'off';
        return (
          <div key={group}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="text-sm font-medium">{label}</p>
              <GroupStateToggle
                state={state}
                isGlobal={isGlobal}
                readOnly={readOnly}
                onChange={(s) =>
                  setGroup(
                    key,
                    s === 'inherit' || (s === 'off' && isGlobal)
                      ? null
                      : s === 'off'
                        ? { managed: false, value: null }
                        : { managed: true, value: setting?.value ?? (inheritedSetting?.managed ? inheritedSetting.value : null) ?? WU_DEFAULTS[group] },
                  )
                }
              />
            </div>
            <p className="text-xs text-muted">{hint}</p>
            {state === 'inherit' && <p className="mt-1 text-xs text-muted">Inherited: {describeSetting(group, inheritedSetting)}</p>}
            {state === 'on' && setting?.value != null && (
              <div className="mt-2">
                <GroupFields group={group} value={setting.value} disabled={readOnly} onChange={(v) => setGroup(key, { managed: true, value: v })} />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function GroupStateToggle({ state, isGlobal, readOnly, onChange }: { state: GroupState; isGlobal: boolean; readOnly: boolean; onChange: (s: GroupState) => void }) {
  const options: [GroupState, string][] = isGlobal
    ? [
        ['off', 'Not configured'],
        ['on', 'Configure'],
      ]
    : [
        ['inherit', 'Inherit'],
        ['off', 'Not configured'],
        ['on', 'Configure'],
      ];
  return (
    <div className="inline-flex rounded-md border border-line p-0.5 text-xs" role="group" aria-label="Windows Update group setting">
      {options.map(([s, label]) => (
        <button
          key={s}
          type="button"
          disabled={readOnly}
          aria-pressed={state === s}
          onClick={() => onChange(s)}
          className={cx('rounded px-2 py-0.5', state === s ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg')}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

function GroupFields({ group, value, disabled, onChange }: { group: WindowsUpdatePolicyGroup; value: unknown; disabled: boolean; onChange: (v: unknown) => void }) {
  switch (group) {
    case 'AutomaticUpdates':
      return <AutomaticUpdatesFields value={value as AutomaticUpdatesSettings} disabled={disabled} onChange={onChange} />;
    case 'FeatureUpdates':
      return <FeatureUpdatesFields value={value as FeatureUpdateSettings} disabled={disabled} onChange={onChange} />;
    case 'QualityUpdates':
      return <QualityUpdatesFields value={value as QualityUpdateSettings} disabled={disabled} onChange={onChange} />;
    case 'RestartBehavior':
      return <RestartBehaviorFields value={value as RestartBehaviorSettings} disabled={disabled} onChange={onChange} />;
  }
}

function Labeled({ label, children }: { label: string; children: (id: string) => ReactNode }) {
  const id = useId();
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-muted">
        {label}
      </label>
      {children(id)}
    </div>
  );
}

function AutomaticUpdatesFields({ value, disabled, onChange }: { value: AutomaticUpdatesSettings; disabled: boolean; onChange: (v: AutomaticUpdatesSettings) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <Labeled label="Mode">
        {(id) => (
          <Select id={id} className="max-w-sm" disabled={disabled} value={value.mode} onChange={(e) => onChange({ ...value, mode: e.target.value as AutoUpdateMode })}>
            {AUTO_UPDATE_MODES.map((m) => (
              <option key={m} value={m}>
                {AUTO_UPDATE_MODE_LABELS[m]}
              </option>
            ))}
          </Select>
        )}
      </Labeled>
      {value.mode === 'Disabled' && (
        <p className="text-xs text-muted">Windows stops checking for updates by itself. EasyPatch scans and installations keep working.</p>
      )}
      {value.mode === 'AutoDownloadScheduleInstall' && (
        <div className="flex flex-wrap gap-4">
          <Labeled label="Install day">
            {(id) => (
              <Select id={id} className="w-40" disabled={disabled} value={value.scheduledInstallDay} onChange={(e) => onChange({ ...value, scheduledInstallDay: Number(e.target.value) })}>
                {INSTALL_DAYS.map((d, i) => (
                  <option key={d} value={i}>
                    {d}
                  </option>
                ))}
              </Select>
            )}
          </Labeled>
          <Labeled label="Install time (endpoint's local time)">
            {(id) => (
              <Select id={id} className="w-32" disabled={disabled} value={value.scheduledInstallHour} onChange={(e) => onChange({ ...value, scheduledInstallHour: Number(e.target.value) })}>
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {hour(h)}
                  </option>
                ))}
              </Select>
            )}
          </Labeled>
        </div>
      )}
    </div>
  );
}

function OptionalDays({ label, value, max, disabled, onChange }: { label: string; value: number | null; max: number; disabled: boolean; onChange: (v: number | null) => void }) {
  return (
    <Labeled label={label}>
      {(id) => (
        <div className="flex items-center gap-2">
          <Input
            id={id}
            type="number"
            min={0}
            max={max}
            step={1}
            className="w-28"
            placeholder="No deferral"
            disabled={disabled}
            value={value ?? ''}
            onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
          />
          <span className="text-xs text-muted">days (0-{max}; empty for no deferral)</span>
        </div>
      )}
    </Labeled>
  );
}

function FeatureUpdatesFields({ value, disabled, onChange }: { value: FeatureUpdateSettings; disabled: boolean; onChange: (v: FeatureUpdateSettings) => void }) {
  const pinned = value.targetProductVersion !== null;
  return (
    <div className="flex flex-col gap-3">
      <OptionalDays label="Defer feature updates" value={value.deferDays} max={365} disabled={disabled} onChange={(deferDays) => onChange({ ...value, deferDays })} />
      <div className="flex flex-wrap items-end gap-4">
        <Labeled label="Stay on a Windows version">
          {(id) => (
            <Select
              id={id}
              className="w-44"
              disabled={disabled}
              value={value.targetProductVersion ?? ''}
              onChange={(e) =>
                onChange({
                  ...value,
                  targetProductVersion: e.target.value || null,
                  targetReleaseVersion: e.target.value ? (value.targetReleaseVersion ?? '') : null,
                })
              }
            >
              <option value="">Do not pin</option>
              <option value="Windows 10">Windows 10</option>
              <option value="Windows 11">Windows 11</option>
            </Select>
          )}
        </Labeled>
        {pinned && (
          <Labeled label="Version">
            {(id) => (
              <Input
                id={id}
                className="w-28 font-mono"
                placeholder="24H2"
                maxLength={4}
                disabled={disabled}
                value={value.targetReleaseVersion ?? ''}
                onChange={(e) => onChange({ ...value, targetReleaseVersion: e.target.value.toUpperCase() })}
              />
            )}
          </Labeled>
        )}
      </div>
    </div>
  );
}

function QualityUpdatesFields({ value, disabled, onChange }: { value: QualityUpdateSettings; disabled: boolean; onChange: (v: QualityUpdateSettings) => void }) {
  return (
    <div className="flex flex-col gap-3">
      <OptionalDays label="Defer quality updates" value={value.deferDays} max={30} disabled={disabled} onChange={(deferDays) => onChange({ ...value, deferDays })} />
      <Checkbox
        label="Stop users pausing updates"
        hint="Removes “Pause updates” from Windows Settings."
        checked={value.disablePause}
        disabled={disabled}
        onChange={(e) => onChange({ ...value, disablePause: e.target.checked })}
      />
    </div>
  );
}

function RestartBehaviorFields({ value, disabled, onChange }: { value: RestartBehaviorSettings; disabled: boolean; onChange: (v: RestartBehaviorSettings) => void }) {
  const hasHours = value.activeHoursStart !== null;
  return (
    <div className="flex flex-col gap-3">
      <Checkbox
        label="Windows does not restart by itself while someone is signed in"
        hint="Restarts requested through EasyPatch are not affected."
        checked={value.noAutoRestartWithSignedInUsers}
        disabled={disabled}
        onChange={(e) => onChange({ ...value, noAutoRestartWithSignedInUsers: e.target.checked })}
      />
      <Checkbox
        label="Set active hours"
        hint="Windows does not restart by itself during these hours (endpoint's local time)."
        checked={hasHours}
        disabled={disabled}
        onChange={(e) => onChange({ ...value, activeHoursStart: e.target.checked ? 8 : null, activeHoursEnd: e.target.checked ? 18 : null })}
      />
      {hasHours && (
        <div className="flex flex-wrap gap-4 pl-6">
          <Labeled label="From">
            {(id) => (
              <Select id={id} className="w-28" disabled={disabled} value={value.activeHoursStart ?? 8} onChange={(e) => onChange({ ...value, activeHoursStart: Number(e.target.value) })}>
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {hour(h)}
                  </option>
                ))}
              </Select>
            )}
          </Labeled>
          <Labeled label="To">
            {(id) => (
              <Select id={id} className="w-28" disabled={disabled} value={value.activeHoursEnd ?? 18} onChange={(e) => onChange({ ...value, activeHoursEnd: Number(e.target.value) })}>
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>
                    {hour(h)}
                  </option>
                ))}
              </Select>
            )}
          </Labeled>
        </div>
      )}
    </div>
  );
}
