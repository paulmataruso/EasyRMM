import { useEffect, useState } from 'react';
import { Tag as TagIcon } from 'lucide-react';
import { api } from '../api/client';
import { useApiMutation, useApi } from '../api/hooks';
import type { BulkEndpointTagsRequest, TagDto, TagRefDto } from '../api/types';
import { Dialog } from './Dialog';
import { useToast } from './Toast';
import { Alert, Button, cx, EmptyState, InlineError, Spinner } from './ui';

const COLOR_CLASSES: Record<string, string> = {
  gray: 'bg-neutral-soft text-muted',
  blue: 'bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300',
  green: 'bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300',
  amber: 'bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300',
  red: 'bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300',
  purple: 'bg-purple-100 text-purple-800 dark:bg-purple-950 dark:text-purple-300',
  teal: 'bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300',
  pink: 'bg-pink-100 text-pink-800 dark:bg-pink-950 dark:text-pink-300',
};

/** "from its site" / "from its organization" for a tag an endpoint has through its site or organization. */
export function inheritedLabel(tag: TagRefDto): string | null {
  if (tag.inheritedFrom === 'Site') return 'from its site';
  if (tag.inheritedFrom === 'Organization') return 'from its organization';
  return null;
}

export function TagChip({ tag, className }: { tag: TagRefDto; className?: string }) {
  const inherited = inheritedLabel(tag);
  return (
    <span
      className={cx(
        'inline-flex max-w-40 items-center gap-1 truncate rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap',
        COLOR_CLASSES[tag.color] ?? COLOR_CLASSES.gray,
        // An inherited tag is outlined with a dashed border so it reads as "not set here".
        inherited && 'outline-1 -outline-offset-1 outline-current/40 outline-dashed',
        className,
      )}
      title={inherited ? `${tag.name} (${inherited})` : tag.name}
    >
      {tag.name}
    </span>
  );
}

export function TagList({ tags, max = 3 }: { tags: TagRefDto[] | null | undefined; max?: number }) {
  if (!tags || tags.length === 0) return null;
  const shown = tags.slice(0, max);
  const rest = tags.length - shown.length;
  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {shown.map((t) => (
        <TagChip key={t.id} tag={t} />
      ))}
      {rest > 0 && (
        <span className="text-xs text-muted" title={tags.slice(max).map((t) => t.name).join(', ')}>
          +{rest}
        </span>
      )}
    </span>
  );
}

function TagCheckboxes({ tags, selected, onChange, locked }: {
  tags: TagDto[];
  selected: Set<string>;
  onChange: (next: Set<string>) => void;
  /** Tags that apply anyway (from a site or organization), with where they come from. Shown ticked and disabled. */
  locked?: Map<string, string>;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      {tags.map((t) => (
        <label key={t.id} className="flex items-start gap-2.5 rounded-md px-2 py-1.5 hover:bg-hover">
          <input
            type="checkbox"
            className="mt-0.5 size-4"
            checked={selected.has(t.id) || (locked?.has(t.id) ?? false)}
            disabled={locked?.has(t.id) && !selected.has(t.id)}
            onChange={(e) => {
              const next = new Set(selected);
              if (e.target.checked) next.add(t.id);
              else next.delete(t.id);
              onChange(next);
            }}
          />
          <span className="min-w-0">
            <TagChip tag={t} />
            {t.hasPolicy && <span className="ml-2 text-xs text-muted">has a policy</span>}
            {locked?.has(t.id) && <span className="ml-2 text-xs text-muted">{locked.get(t.id)}</span>}
            {t.description && <span className="block text-xs text-muted">{t.description}</span>}
          </span>
        </label>
      ))}
    </div>
  );
}

/** Edits the tags of one endpoint (replaces its own tags; tags from its site or organization are shown but not changed here). */
export function EndpointTagsDialog({ open, onClose, endpointId, hostname, current, siteName, organizationName }: {
  open: boolean;
  onClose: () => void;
  endpointId: string;
  hostname: string;
  current: TagRefDto[];
  siteName?: string | null;
  organizationName?: string | null;
}) {
  const inherited = new Map(
    current
      .filter((t) => t.inheritedFrom)
      .map((t) => [t.id, t.inheritedFrom === 'Site' ? `from site ${siteName ?? ''}`.trim() : `from organization ${organizationName ?? ''}`.trim()]),
  );
  return (
    <TagsDialog
      open={open}
      onClose={onClose}
      url={`/endpoints/${endpointId}/tags`}
      name={hostname}
      current={current.filter((t) => !t.inheritedFrom)}
      inherited={inherited}
      description="Tags group endpoints across customers (for example an update ring). A tag can carry a policy. Tags of the endpoint's site and organization apply as well; change them on the organization."
    />
  );
}

/** Edits the tags of an organization or a site: every endpoint in it has them (for example a pilot ring). */
export function GroupTagsDialog({ target, onClose }: {
  target: { kind: 'organization' | 'site'; id: string; name: string; current: TagRefDto[]; organization?: { name: string; tags: TagRefDto[] } } | null;
  onClose: () => void;
}) {
  const inherited = new Map((target?.organization?.tags ?? []).map((t) => [t.id, `from organization ${target?.organization?.name ?? ''}`.trim()]));
  return (
    <TagsDialog
      open={target !== null}
      onClose={onClose}
      url={target ? `/${target.kind === 'site' ? 'sites' : 'organizations'}/${target.id}/tags` : ''}
      name={target?.name ?? ''}
      current={target?.current ?? []}
      inherited={inherited}
      description={
        target?.kind === 'site'
          ? 'Every endpoint in this site has these tags, and their tag policies apply to it. Tag a site "Pilot" to put its computers in your pilot ring.'
          : 'Every endpoint of this organization, in every site, has these tags, and their tag policies apply to it. Tag a customer "Pilot" to put all its computers in your pilot ring.'
      }
    />
  );
}

function TagsDialog({ open, onClose, url, name, current, inherited, description }: {
  open: boolean;
  onClose: () => void;
  url: string;
  name: string;
  current: TagRefDto[];
  inherited: Map<string, string>;
  description: string;
}) {
  const toast = useToast();
  const tags = useApi<TagDto[]>(open ? '/tags' : null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Reset only when the dialog opens: `current` is a new array on every poll.
  const [wasOpen, setWasOpen] = useState(false);
  if (open !== wasOpen) {
    setWasOpen(open);
    if (open) setSelected(new Set(current.map((t) => t.id)));
  }
  const save = useApiMutation((ids: string[]) => api.put(url, { tagIds: ids }), {
    invalidate: ['/endpoints', '/tags', '/organizations', '/sites'],
    onSuccess: () => {
      toast.success(`Tags of ${name} saved.`);
      onClose();
    },
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`Tags of ${name}`}
      description={description}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" loading={save.isPending} disabled={!tags.data} onClick={() => save.mutate([...selected])}>
            Save tags
          </Button>
        </>
      }
    >
      {tags.isPending ? (
        <Spinner />
      ) : (tags.data ?? []).length === 0 ? (
        <EmptyState title="No tags yet" icon={<TagIcon className="size-8" aria-hidden />}>
          A super administrator creates tags under Settings → Tags.
        </EmptyState>
      ) : (
        <TagCheckboxes tags={tags.data ?? []} selected={selected} onChange={setSelected} locked={inherited} />
      )}
      <InlineError error={tags.error ?? save.error} />
    </Dialog>
  );
}

/** Adds or removes tags on several endpoints at once. */
export function BulkTagsDialog({ open, onClose, endpointIds, onDone }: { open: boolean; onClose: () => void; endpointIds: string[]; onDone?: () => void }) {
  const toast = useToast();
  const tags = useApi<TagDto[]>(open ? '/tags' : null);
  const [mode, setMode] = useState<'add' | 'remove'>('add');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (open) {
      setSelected(new Set());
      setMode('add');
    }
  }, [open]);
  const save = useApiMutation(
    (req: BulkEndpointTagsRequest) => api.post<{ changed: number }>('/endpoints/tags/bulk', req),
    {
      invalidate: ['/endpoints', '/tags'],
      onSuccess: (r) => {
        toast.success(`Tags changed on ${r.changed} endpoint(s).`);
        onDone?.();
        onClose();
      },
    },
  );
  const ids = [...selected];

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={`${mode === 'add' ? 'Add tags to' : 'Remove tags from'} ${endpointIds.length} endpoint(s)`}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            loading={save.isPending}
            disabled={ids.length === 0}
            onClick={() => save.mutate({ endpointIds, addTagIds: mode === 'add' ? ids : null, removeTagIds: mode === 'remove' ? ids : null })}
          >
            {mode === 'add' ? 'Add tags' : 'Remove tags'}
          </Button>
        </>
      }
    >
      <div className="mb-3 inline-flex rounded-md border border-line p-0.5 text-sm" role="group" aria-label="Add or remove">
        {(['add', 'remove'] as const).map((m) => (
          <button
            key={m}
            type="button"
            aria-pressed={mode === m}
            onClick={() => setMode(m)}
            className={cx('rounded px-3 py-1', mode === m ? 'bg-accent-soft font-medium text-accent' : 'text-muted hover:text-fg')}
          >
            {m === 'add' ? 'Add' : 'Remove'}
          </button>
        ))}
      </div>
      {tags.isPending ? (
        <Spinner />
      ) : (tags.data ?? []).length === 0 ? (
        <Alert tone="info">No tags yet. A super administrator creates tags under Settings → Tags.</Alert>
      ) : (
        <TagCheckboxes tags={tags.data ?? []} selected={selected} onChange={setSelected} />
      )}
      <InlineError error={tags.error ?? save.error} />
    </Dialog>
  );
}
