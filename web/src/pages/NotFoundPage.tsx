import { Link } from "react-router";
import { Compass } from "lucide-react";
import { buttonClasses, EmptyState } from "../components/ui";

export function NotFoundPage() {
  return (
    <EmptyState
      title="Page not found"
      icon={<Compass className="size-8" aria-hidden />}
      action={
        <Link to="/" className={buttonClasses("primary")}>
          Go to the dashboard
        </Link>
      }
    >
      The address may be mistyped, or the page may have moved.
    </EmptyState>
  );
}
