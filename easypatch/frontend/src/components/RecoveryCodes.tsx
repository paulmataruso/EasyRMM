import { useState } from 'react';
import { CopyButton, DownloadButton, OneTimeNotice } from './Copy';
import { Button } from './ui';

/** Shows freshly generated recovery codes once; the user confirms they saved them before continuing. */
export function RecoveryCodesView({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const text = codes.join('\n');
  return (
    <div className="flex flex-col gap-3.5">
      <OneTimeNotice>
        Each recovery code signs you in once if you lose your authenticator app or security key. Store them in your password manager.
      </OneTimeNotice>
      <ul className="grid grid-cols-2 gap-1.5 rounded-md border border-line bg-raised p-3 font-mono text-sm">
        {codes.map((c) => (
          <li key={c} className="select-all">
            {c}
          </li>
        ))}
      </ul>
      <div className="flex gap-2">
        <CopyButton text={text} label="Copy codes" />
        <DownloadButton fileName="easypatch-recovery-codes.txt" text={`EasyPatch recovery codes\n\n${text}\n`} />
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} className="size-4" />
        I have saved these recovery codes
      </label>
      <Button variant="primary" disabled={!saved} onClick={onDone}>
        Continue
      </Button>
    </div>
  );
}
