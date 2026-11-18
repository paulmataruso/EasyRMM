import { useEffect, useId, useState } from 'react';
import { Search } from 'lucide-react';
import { useOrganizations, useSites } from '../api/hooks';
import { Field, Input, Select, cx } from './ui';

export function SearchInput({ value, onChange, placeholder = 'Search…', label = 'Search', className }: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  label?: string;
  className?: string;
}) {
  const [text, setText] = useState(value);
  const id = useId();
  useEffect(() => setText(value), [value]);
  useEffect(() => {
    if (text === value) return;
    const t = window.setTimeout(() => onChange(text.trim()), 350);
    return () => window.clearTimeout(t);
  }, [text, value, onChange]);
  return (
    <Field label={label} htmlFor={id} className={cx('min-w-48 flex-1', className)}>
      <div className="relative">
        <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-subtle" aria-hidden />
        <Input id={id} type="search" value={text} placeholder={placeholder} onChange={(e) => setText(e.target.value)} className="pl-8" />
      </div>
    </Field>
  );
}

export function OrganizationSelect({ value, onChange, label = 'Organization', allLabel = 'All organizations', required = false, className, disabled }: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  allLabel?: string;
  required?: boolean;
  className?: string;
  disabled?: boolean;
}) {
  const orgs = useOrganizations();
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className={cx('min-w-44', className)} required={required}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} required={required} disabled={disabled || orgs.isPending}>
        <option value="">{required ? 'Select an organization…' : allLabel}</option>
        {orgs.page.items
          .filter((o) => o.isActive || o.id === value)
          .map((o) => (
            <option key={o.id} value={o.id}>
              {o.name}
            </option>
          ))}
      </Select>
    </Field>
  );
}

export function SiteSelect({ organizationId, value, onChange, label = 'Site', allLabel = 'All sites', className, disabled }: {
  organizationId: string;
  value: string;
  onChange: (value: string) => void;
  label?: string;
  allLabel?: string;
  className?: string;
  disabled?: boolean;
}) {
  const sites = useSites(organizationId || null);
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className={cx('min-w-40', className)}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled || !organizationId}>
        <option value="">{organizationId ? allLabel : 'Select an organization first'}</option>
        {sites.page.items
          .filter((s) => s.isActive || s.id === value)
          .map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
      </Select>
    </Field>
  );
}

export function EnumSelect<T extends string>({ label, value, onChange, options, allLabel = 'Any', format, className }: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  options: readonly T[];
  allLabel?: string;
  format?: (value: T) => string;
  className?: string;
}) {
  const id = useId();
  return (
    <Field label={label} htmlFor={id} className={cx('min-w-36', className)}>
      <Select id={id} value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">{allLabel}</option>
        {options.map((o) => (
          <option key={o} value={o}>
            {format ? format(o) : o}
          </option>
        ))}
      </Select>
    </Field>
  );
}
