/**
 * What an error code the patching engine reports means: Windows Update's HRESULTs, in hex, with EasyRMM's explanation of
 * the common ones and what to do about them. The engine's own table (WindowsUpdateErrors) words the same codes for its
 * messages; this one adds the next step.
 */

/** The meaning of a known HRESULT, and what to try. */
export interface CodeMeaning {
  meaning: string;
  advice?: string;
}

const MEANINGS: Record<string, CodeMeaning> = {
  "0x00000000": { meaning: "No error." },
  "0x80240001": { meaning: "Windows Update could not provide the service." },
  "0x8024000B": { meaning: "The operation was cancelled." },
  "0x8024000E": { meaning: "Windows Update received update metadata it could not read." },
  "0x80240016": {
    meaning: "Another installation is in progress, or the device must restart before it can install more.",
    advice: "Restart the device, then install again.",
  },
  "0x80240017": { meaning: "The update does not apply to this device." },
  "0x8024001E": { meaning: "Windows Update or the device was shutting down." },
  "0x80240020": { meaning: "The update needs a user signed in at the device." },
  "0x80240022": {
    meaning: "Every update in the operation failed.",
    advice: "Each update's own code says why.",
  },
  "0x80240024": { meaning: "There were no updates to install." },
  "0x80240025": { meaning: "Windows Update is turned off for this user." },
  "0x8024002E": { meaning: "Policy turns off access to Windows Update." },
  "0x80240032": { meaning: "The update search was not valid." },
  "0x80240438": {
    meaning: "Windows Update's service could not be reached.",
    advice: "Check the device's network route, firewall and proxy.",
  },
  "0x80240FFF": { meaning: "Windows Update hit an unexpected error." },
  "0x80244007": { meaning: "The update server returned a SOAP fault.", advice: "Check the WSUS server's health." },
  "0x80244010": { meaning: "Too many round trips to the update server." },
  "0x80244017": { meaning: "The update server refused access (HTTP 401)." },
  "0x80244018": { meaning: "The update server or a proxy refused the request (HTTP 403)." },
  "0x80244019": { meaning: "The update server did not find what was asked for (HTTP 404).", advice: "For WSUS, check its address and content." },
  "0x8024401B": { meaning: "The proxy needs authentication (HTTP 407)." },
  "0x8024401C": { meaning: "The request to the update server timed out (HTTP 408)." },
  "0x8024401F": { meaning: "The update server had an internal error (HTTP 500)." },
  "0x80244022": { meaning: "The update server is unavailable (HTTP 503)." },
  "0x8024402C": {
    meaning: "The name of the update server or proxy could not be resolved.",
    advice: "Check the device's DNS and proxy settings.",
  },
  "0x8024200D": { meaning: "The update must be downloaded again." },
  "0x80242016": { meaning: "The update was in an unexpected state after its restart." },
  "0x80246007": { meaning: "The update was not downloaded." },
  "0x80246008": { meaning: "Windows Update could not reach the Background Intelligent Transfer Service (BITS)." },
  "0x8024A10A": { meaning: "The Windows Update service was shutting down." },
  "0x80070005": { meaning: "Access denied." },
  "0x8007000E": { meaning: "The device ran out of memory." },
  "0x80070070": { meaning: "Not enough free disk space.", advice: "Free space on the system drive, then install again." },
  "0x80070422": {
    meaning: "A service the update needs (Windows Update or BITS) is disabled.",
    advice: "Set the Windows Update and BITS services to start.",
  },
  "0x80070643": {
    meaning: "The installer failed (an MSI-based update).",
    advice: "Often a .NET or Defender update: install it again, or repair the product it updates.",
  },
  "0x80070BC2": { meaning: "A restart is needed to finish.", advice: "Restart the device." },
  "0x80070BC9": { meaning: "An earlier operation needs a restart before this update can install.", advice: "Restart the device, then install again." },
  "0x80072EE2": { meaning: "The connection to the update server timed out." },
  "0x80072EE7": { meaning: "The update server's name could not be resolved.", advice: "Check the device's DNS." },
  "0x80072EFD": { meaning: "No connection to the update server could be made." },
  "0x80072EFE": { meaning: "The connection to the update server was cut off." },
  "0x80072F8F": {
    meaning: "A secure connection to the update server failed.",
    advice: "Check the device's clock and that TLS inspection does not intercept Windows Update.",
  },
  "0x80073712": {
    meaning: "The Windows component store is damaged.",
    advice: "Run DISM /Online /Cleanup-Image /RestoreHealth, then install again.",
  },
  "0x800F081F": { meaning: "Servicing could not find the source files.", advice: "Run DISM /Online /Cleanup-Image /RestoreHealth." },
  "0x800F0831": { meaning: "The component store is missing a manifest it needs.", advice: "Install the latest servicing stack update, then try again." },
  "0x800F0922": {
    meaning: "Servicing's advanced installers failed.",
    advice: "Often too little space on the System Reserved partition, or a VPN in the way.",
  },
};

/** An error code as hex ("0x80240022"), from hex in any case or a signed or unsigned decimal; null if it is not a number. */
export function hresultHex(code: string): string | null {
  const c = code.trim();
  let n: number;
  if (/^0x[0-9a-f]{1,8}$/i.test(c)) n = parseInt(c.slice(2), 16);
  else if (/^-?\d{1,10}$/.test(c)) n = Number(c);
  else return null;
  if (n < -0x80000000 || n > 0xffffffff) return null;
  return "0x" + (n >>> 0).toString(16).toUpperCase().padStart(8, "0");
}

/** What a code means: known, Windows Update's but not one EasyRMM explains, another HRESULT, or not an HRESULT at all. */
export type Explained =
  | { kind: "known"; hex: string; meaning: string; advice?: string }
  | { kind: "unknown"; hex: string; windowsUpdate: boolean }
  | { kind: "other"; code: string };

export function explainCode(code: string): Explained {
  const hex = hresultHex(code);
  if (!hex) return { kind: "other", code };
  const m = MEANINGS[hex];
  if (m) return { kind: "known", hex, ...m };
  return { kind: "unknown", hex, windowsUpdate: hex.startsWith("0x8024") };
}
