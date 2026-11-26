import { AlertTriangle } from "lucide-react";
import { useList } from "../../api/hooks";
import type { LeftBehindDevice } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { CopyButton } from "../../components/Copy";
import { Alert } from "../../components/ui";
import { formatDateTime } from "../../lib/format";

/**
 * Removes EasyRMM's own MeshAgent from a Windows computer, by exact service name, folder and registry keys (ADR-0071).
 * The same text is in docs/operations/removing-our-meshagent.md; a test keeps them equal.
 */
export const REMOVE_MESHAGENT_SCRIPT = String.raw`$ErrorActionPreference = 'Continue'
$name = 'EasyRMMMeshAgent'
$dir  = Join-Path $env:ProgramFiles 'EasyRMM\MeshAgent'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
    Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Null
}
# Only a process that runs our own program, by its full path.
$exe = Join-Path $dir 'meshagent.exe'
Get-CimInstance Win32_Process -Filter "Name='meshagent.exe'" |
    Where-Object { $_.ExecutablePath -ieq $exe } |
    ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
foreach ($k in "HKLM:\SOFTWARE\Open Source\$name",
               "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$name") {
    Remove-Item -LiteralPath $k -Recurse -Force -ErrorAction SilentlyContinue
}
`;

/**
 * Removed Windows devices whose EasyRMM agent was not there to remove EasyRMM's MeshAgent. EasyRMM does not ask
 * MeshCentral to uninstall it (that would also delete another MeshAgent's Diagnostic Agent), so it may still be on
 * the computer. Shown to those who may remove devices; the server limits the list to their sites.
 */
export function LeftBehindNotice() {
  const { can } = useAuth();
  const list = useList<LeftBehindDevice>(can("device.retire") ? "/removed-devices/left-behind" : null);
  if (list.items.length === 0) return null;
  return (
    <Alert tone="warn" title="Remote access may still be installed on removed devices" className="mb-4">
      <p>
        {list.items.length === 1 ? "This device was" : "These devices were"} removed while its EasyRMM agent was off, so EasyRMM&apos;s
        MeshAgent (remote access) may still be on the computer. EasyRMM does not ask MeshCentral to remove it, because that could also
        remove a MeshAgent that belongs to someone else. Run the script below on the computer, in an elevated PowerShell. It removes only
        EasyRMM&apos;s own service, folder and registry keys, by exact name; another MeshAgent is not touched. If the EasyRMM agent comes
        back within 90 days, it removes MeshAgent itself.
      </p>
      <ul className="mt-2 list-inside list-disc">
        {list.items.map((d) => (
          <li key={d.id}>
            {d.name}, removed {formatDateTime(d.removedAt)}
          </li>
        ))}
      </ul>
      <div className="mt-3 flex items-center gap-2">
        <AlertTriangle className="size-4" aria-hidden />
        <CopyButton text={REMOVE_MESHAGENT_SCRIPT} label="Copy the removal script" />
      </div>
      <pre aria-label="Removal script" className="mt-2 max-h-64 overflow-auto rounded-sm border border-line bg-surface-2 p-3 text-xs">
        {REMOVE_MESHAGENT_SCRIPT}
      </pre>
    </Alert>
  );
}
