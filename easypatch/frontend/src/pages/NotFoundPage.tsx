import { Link, useLocation } from 'react-router';
import { Compass } from 'lucide-react';
import { buttonClasses, EmptyState } from '../components/ui';

export function NotFoundPage() {
  const location = useLocation();
  return (
    <div className="py-16">
      <EmptyState
        title="Page not found"
        icon={<Compass className="size-8" aria-hidden />}
        action={
          <Link to="/" className={buttonClasses('secondary', 'md')}>
            Back to the dashboard
          </Link>
        }
      >
        Nothing lives at <span className="font-mono">{location.pathname}</span>.
      </EmptyState>
    </div>
  );
}
