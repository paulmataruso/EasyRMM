// Opening and closing an alert's card (AlertDetail.tsx). The card is ?alert=<id> on whatever page lists the alert, so
// it can be linked to, and each opening adds a history entry, so the browser's Back closes it.
import type { ReactNode } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";

export const ALERT_PARAM = "alert";

/** How many history entries the card has added, kept in the state of the newest, so closing it goes back past all of
 * them: an alert opened from another alert's history closes with it. */
function depthOf(state: unknown): number {
  const d = state !== null && typeof state === "object" ? (state as { alertCard?: unknown }).alertCard : undefined;
  return typeof d === "number" && Number.isInteger(d) && d > 0 ? d : 0;
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
  const depth = params.has(ALERT_PARAM) ? depthOf(location.state) : 0;
  params.set(ALERT_PARAM, id);
  const state = location.state !== null && typeof location.state === "object" ? location.state : {};
  return (
    <Link
      to={{ pathname: location.pathname, search: `?${params.toString()}`, hash: location.hash }}
      state={{ ...state, alertCard: depth + 1 }}
      className={className}
      aria-label={label}
      title={title}
    >
      {children}
    </Link>
  );
}

/** Closes the card: back past the entries it added, or, for a card opened from a link, drops ?alert= in place. */
export function useCloseAlertCard(): () => void {
  const location = useLocation();
  const navigate = useNavigate();
  const [, setParams] = useSearchParams();
  return () => {
    const depth = depthOf(location.state);
    if (depth > 0) {
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
