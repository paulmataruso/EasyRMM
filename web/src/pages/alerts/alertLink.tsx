// Opening and closing an alert's card (AlertDetail.tsx). The card is ?alert=<id> on whatever page lists the alert, so
// it can be linked to, and each opening adds a history entry, so the browser's Back closes it.
import type { ReactNode } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";

export const ALERT_PARAM = "alert";

/** Where the card sits in the history, kept in the state of the newest entry it added: how many entries the card
 * added (an alert opened from another alert's history adds one more), and whether the entry under them is the page
 * without a card. It is not when the first card came from a pasted link or a reload. */
function placeOf(state: unknown): { depth: number; overPage: boolean } {
  const s = state !== null && typeof state === "object" ? (state as { alertCard?: unknown; alertOverPage?: unknown }) : {};
  const d = s.alertCard;
  const depth = typeof d === "number" && Number.isInteger(d) && d > 0 ? d : 0;
  return { depth, overPage: depth > 0 && s.alertOverPage === true };
}

/** Opens an alert's card over the current page. */
export function AlertLink({ id, children, className, label, title }: {
  id: string;
  children: ReactNode;
  className?: string;
  /** The accessible name, when the text alone does not say what opens. */
  label?: string;
  title?: string;
}) {
  const location = useLocation();
  const params = new URLSearchParams(location.search);
  const { depth, overPage } = params.has(ALERT_PARAM) ? placeOf(location.state) : { depth: 0, overPage: true };
  params.set(ALERT_PARAM, id);
  const state = location.state !== null && typeof location.state === "object" ? location.state : {};
  return (
    <Link
      to={{ pathname: location.pathname, search: `?${params.toString()}`, hash: location.hash }}
      state={{ ...state, alertCard: depth + 1, alertOverPage: overPage }}
      className={className}
      aria-label={label}
      title={title}
    >
      {children}
    </Link>
  );
}

/** Closes the card, however it was reached: back past the entries it added to the page under them, or, when no page
 * without a card is under them (a pasted link), by dropping ?alert= in place. */
export function useCloseAlertCard(): () => void {
  const location = useLocation();
  const navigate = useNavigate();
  const [, setParams] = useSearchParams();
  return () => {
    const { depth, overPage } = placeOf(location.state);
    if (overPage) {
      void navigate(-depth);
      return;
    }
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        next.delete(ALERT_PARAM);
        return next;
      },
      { replace: true },
    );
  };
}
