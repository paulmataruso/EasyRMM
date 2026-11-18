import type { PackageInfoDto } from '../api/types';
import { formatVersionChange } from '../lib/format';

const MAX_ADVISORIES = 3;

/** Security advisories (USN, DSA, RHSA…): the first few, with the rest in the tooltip. */
export function Advisories({ advisories, max = MAX_ADVISORIES, className }: { advisories: string[]; max?: number; className?: string }) {
  if (advisories.length === 0) return null;
  const shown = advisories.slice(0, max);
  const more = advisories.length - shown.length;
  return (
    <span className={className} title={more > 0 ? advisories.join(', ') : 'Security advisories'}>
      <span className="font-mono">{shown.join(', ')}</span>
      {more > 0 && ` +${more} more`}
    </span>
  );
}

/**
 * Linux package facts shown where Windows updates show KB numbers: (name,) installed → new version, architecture,
 * repository and advisories. The installed version is only known in endpoint views. macOS updates (Apple software update) have
 * neither a KB number nor a package.
 */
export function PackageFacts({ pkg, showName = false, className }: { pkg: PackageInfoDto; showName?: boolean; className?: string }) {
  const version = pkg.installedVersion ? formatVersionChange(pkg.installedVersion, pkg.version) : showName ? pkg.version : null;
  return (
    <span className={className ?? 'flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted'}>
      {showName && <span className="font-mono text-fg">{pkg.name}</span>}
      {version && (
        <span className="font-mono" title={pkg.installedVersion ? 'Installed version → available version' : 'Version'}>
          {version}
        </span>
      )}
      {pkg.architecture && <span title="Architecture">{pkg.architecture}</span>}
      {pkg.repository && <span title="Repository">{pkg.repository}</span>}
      <Advisories advisories={pkg.advisories} />
    </span>
  );
}
