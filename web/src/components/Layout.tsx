import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router";
import { Building2, LayoutDashboard, LogOut, Menu, Moon, Settings, Sun, UserCircle, X } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { applyTheme, getStoredTheme, storeTheme, type Theme } from "../lib/theme";
import { cx } from "./ui";

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  end?: boolean;
}

export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => getStoredTheme());
  useEffect(() => applyTheme(theme), [theme]);
  return [
    theme,
    () =>
      setTheme((t) => {
        const next = t === "dark" ? "light" : "dark";
        storeTheme(next);
        return next;
      }),
  ];
}

export function ThemeToggle({ className }: { className?: string }) {
  const [theme, toggle] = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      title={theme === "dark" ? "Light theme" : "Dark theme"}
      className={cx("inline-flex size-8 items-center justify-center rounded-md text-muted hover:bg-hover hover:text-fg", className)}
    >
      {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
    </button>
  );
}

/**
 * Logo mark plus wordmark. The wordmark's colors are made for dark backgrounds; `onDark` is for surfaces that are
 * dark in both themes (the sidebar), otherwise the light-background variant is shown in the light theme.
 */
export function Logo({ className, onDark = false, large = false }: { className?: string; onDark?: boolean; large?: boolean }) {
  const mark = large ? "size-12" : "size-8";
  const word = cx("w-auto", large ? "h-10" : "h-7");
  return (
    <span className={cx("inline-flex items-center gap-2", className)}>
      <img src="/logo.svg" alt="" className={cx("shrink-0", mark)} />
      {onDark ? (
        <img src="/wordmark.svg" alt="EasyRMM" className={word} />
      ) : (
        <>
          <img src="/wordmark.svg" alt="EasyRMM" className={cx("hidden dark:block", word)} />
          <img src="/wordmark-light.svg" alt="EasyRMM" className={cx("dark:hidden", word)} />
        </>
      )}
    </span>
  );
}

export function AppLayout() {
  const { session, can, signOut } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => setMobileOpen(false), [location.pathname]);

  const nav: NavItem[] = [
    { to: "/", label: "Dashboard", icon: <LayoutDashboard className="size-4" aria-hidden />, end: true },
    { to: "/organizations", label: "Organizations", icon: <Building2 className="size-4" aria-hidden /> },
  ];
  if (can("user.view") || can("audit.view")) {
    nav.push({ to: "/settings", label: "Settings", icon: <Settings className="size-4" aria-hidden /> });
  }

  async function logout() {
    await signOut();
    navigate("/login", { replace: true });
  }

  const sidebar = (
    <nav aria-label="Main" className="flex h-full flex-col bg-sidebar text-sidebar-fg">
      <div className="flex h-14 items-center justify-between px-4 text-white">
        <Logo onDark />
        <button type="button" className="rounded p-1 lg:hidden" onClick={() => setMobileOpen(false)} aria-label="Close menu">
          <X className="size-5" aria-hidden />
        </button>
      </div>
      <ul className="flex-1 space-y-0.5 overflow-y-auto px-2 py-2">
        {nav.map((item) => (
          <li key={item.to}>
            <NavLink
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  isActive ? "bg-sidebar-active font-medium text-white" : "hover:bg-sidebar-active/60 hover:text-white",
                )
              }
            >
              {item.icon}
              <span className="flex-1">{item.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="border-t border-white/10 px-2 py-2">
        <NavLink
          to="/account"
          className={({ isActive }) =>
            cx("flex items-center gap-2.5 rounded-md px-3 py-2 text-sm", isActive ? "bg-sidebar-active text-white" : "hover:bg-sidebar-active/60 hover:text-white")
          }
        >
          <UserCircle className="size-4" aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="block truncate">{session?.user.displayName}</span>
            {/* EasyPatch shows the role here. EasyRMM roles are per organization, so only the platform-wide one is named. */}
            <span className="block truncate text-xs text-sidebar-fg/70">{session?.isSuperAdmin ? "Super administrator" : session?.user.email}</span>
          </span>
        </NavLink>
        <button
          type="button"
          onClick={logout}
          className="mt-0.5 flex w-full items-center gap-2.5 rounded-md px-3 py-2 text-sm hover:bg-sidebar-active/60 hover:text-white"
        >
          <LogOut className="size-4" aria-hidden />
          Sign out
        </button>
      </div>
    </nav>
  );

  return (
    <div className="flex h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside className="hidden w-60 shrink-0 lg:block">{sidebar}</aside>
      {mobileOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/50" onClick={() => setMobileOpen(false)} aria-hidden />
          <aside className="relative h-full w-64 shadow-xl">{sidebar}</aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-line bg-surface px-4">
          <button type="button" className="rounded-md p-1.5 text-muted hover:bg-hover lg:hidden" onClick={() => setMobileOpen(true)} aria-label="Open menu">
            <Menu className="size-5" aria-hidden />
          </button>
          <div className="lg:hidden">
            <Logo />
          </div>
          <div className="flex-1" />
          <ThemeToggle />
        </header>
        <main id="main" className="min-w-0 flex-1 overflow-y-auto px-4 py-5 sm:px-6 lg:px-8">
          <div className="mx-auto max-w-[1440px]">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

/** Centered layout for setup, sign-in, MFA and password pages. */
export function AuthShell({ children, title, subtitle, wide = false }: { children: ReactNode; title: string; subtitle?: ReactNode; wide?: boolean }) {
  return (
    <div className="flex min-h-full flex-col items-center justify-center px-4 py-10">
      <div className="absolute top-3 right-3">
        <ThemeToggle />
      </div>
      <div className={cx("w-full", wide ? "max-w-md" : "max-w-sm")}>
        <div className="mb-6 flex justify-center">
          <Logo large />
        </div>
        <main className="rounded-xl border border-line bg-surface p-6 shadow-sm">
          <h1 className="text-lg font-semibold">{title}</h1>
          {subtitle && <p className="mt-1 text-sm text-muted">{subtitle}</p>}
          <div className="mt-5">{children}</div>
        </main>
      </div>
    </div>
  );
}
