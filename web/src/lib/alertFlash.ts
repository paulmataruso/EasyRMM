// Whether active alerts pulse (index.css, "Active alerts pulse"). The pulse runs for as long as an alert is active, so
// anyone can stop it (WCAG 2.2.2): the Alerts page and a device's Alerts card offer the switch, and this browser keeps
// the choice, as it keeps the theme. Stopped, active alerts hold a steady red, as they do under reduced motion.
import { useSyncExternalStore } from "react";

const STORAGE_KEY = "easyrmm.alertFlash";
const listeners = new Set<() => void>();

/** What this browser kept: true unless someone stopped the flashing here. */
export function getStoredAlertFlash(): boolean {
  try {
    return window.localStorage.getItem(STORAGE_KEY) !== "off";
  } catch {
    return true;
  }
}

/** Shows the choice: data-alert-flash="off" on the page's root stops every pulse. */
export function applyAlertFlash(on: boolean): void {
  const root = document.documentElement;
  if (on) delete root.dataset.alertFlash;
  else root.dataset.alertFlash = "off";
  for (const listener of listeners) listener();
}

/** Shows the choice and keeps it in this browser. */
export function setAlertFlash(on: boolean): void {
  applyAlertFlash(on);
  try {
    if (on) window.localStorage.removeItem(STORAGE_KEY);
    else window.localStorage.setItem(STORAGE_KEY, "off");
  } catch {
    // Storage unavailable (private mode, blocked): the choice still holds for this page view.
  }
}

const flashing = () => document.documentElement.dataset.alertFlash !== "off";

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Another tab's choice applies here too.
  const onStorage = (e: StorageEvent) => {
    if (e.key === STORAGE_KEY || e.key === null) applyAlertFlash(getStoredAlertFlash());
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/** Whether active alerts pulse, and the switch. */
export function useAlertFlash(): [boolean, (on: boolean) => void] {
  return [useSyncExternalStore(subscribe, flashing, () => true), setAlertFlash];
}
