/** The application shell: top bar, sidebar, breadcrumb and page header. */

import clsx from 'clsx';
import {
  Bot,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Clipboard,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Menu as MenuIcon,
  Moon,
  Puzzle,
  Radar,
  ScrollText,
  Search,
  Settings,
  SlidersHorizontal,
  Sun,
  Users,
  UsersRound,
  X,
} from 'lucide-react';
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link, NavLink, useLocation, useNavigate } from 'react-router-dom';

import { Badge, Button, Menu, MenuItem } from '@/components/ui';
import { LogoMark } from '@/components/ui/Logo';
import { initialsOf } from '@/lib/format';
import { useAuth } from './auth-context';
import { useTheme } from './theme';

const SIDEBAR_STATE_KEY = 'xenoproxy.sidebar.collapsed';

interface NavItem {
  to: string;
  label: string;
  icon: ReactNode;
  permission?: string;
}

const MAIN_NAV: NavItem[] = [
  { to: '/scan', label: 'New scan', icon: <Radar className="h-[18px] w-[18px]" aria-hidden /> },
  { to: '/jobs', label: 'Jobs', icon: <Clipboard className="h-[18px] w-[18px]" aria-hidden /> },
  {
    to: '/dashboard',
    label: 'Dashboard',
    icon: <LayoutDashboard className="h-[18px] w-[18px]" aria-hidden />,
  },
  { to: '/assistant', label: 'Assistant', icon: <Bot className="h-[18px] w-[18px]" aria-hidden /> },
  { to: '/settings', label: 'My access', icon: <KeyRound className="h-[18px] w-[18px]" aria-hidden /> },
];

const ADMIN_NAV: NavItem[] = [
  {
    to: '/admin/plugins',
    label: 'Plugins & keys',
    icon: <Settings className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'analyzers:manage',
  },
  {
    to: '/admin/playbooks',
    label: 'Playbooks',
    icon: <Clipboard className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'playbooks:manage',
  },
  {
    to: '/admin/plugin-packages',
    label: 'Plugin packages',
    icon: <Puzzle className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'plugins:manage',
  },
  {
    to: '/admin/settings',
    label: 'Settings',
    icon: <SlidersHorizontal className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'settings:manage',
  },
  {
    to: '/admin/groups',
    label: 'Groups',
    icon: <UsersRound className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'groups:manage',
  },
  {
    to: '/admin/users',
    label: 'Users',
    icon: <Users className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'users:manage',
  },
  {
    to: '/admin/audit',
    label: 'Audit',
    icon: <ScrollText className="h-[18px] w-[18px]" aria-hidden />,
    permission: 'audit:read',
  },
];

function readCollapsed(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_STATE_KEY) === 'true';
  } catch {
    return false;
  }
}

function SidebarLink({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  return (
    <NavLink
      to={item.to}
      title={collapsed ? item.label : undefined}
      className={({ isActive }) =>
        clsx(
          'group relative flex items-center gap-3 rounded-lg py-2 text-sm',
          'transition-colors duration-fast ease-out',
          collapsed ? 'justify-center px-0' : 'px-3',
          isActive
            ? 'bg-primary-soft font-medium text-primary'
            : 'text-muted hover:bg-surface-hover hover:text-content',
        )
      }
    >
      {({ isActive }) => (
        <>
          {/* The active marker is a bar on the rail rather than a filled row:
              it survives collapsing, where a label would not. */}
          <span
            className={clsx(
              'absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-r-pill bg-primary',
              'transition-opacity duration-base ease-out',
              isActive ? 'opacity-100' : 'opacity-0',
            )}
            aria-hidden
          />
          {item.icon}
          {collapsed ? null : <span className="truncate">{item.label}</span>}
        </>
      )}
    </NavLink>
  );
}

export function AppShell({ children }: { children: ReactNode }) {
  const { user, signOut, can } = useAuth();
  const { theme, setTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(readCollapsed);
  // The drawer is the narrow-window form of the same navigation. It is not
  // remembered: it is a transient overlay, and reopening it on every page load
  // would cover the content the reader came for.
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [search, setSearch] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  const drawerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    try {
      window.localStorage.setItem(SIDEBAR_STATE_KEY, String(collapsed));
    } catch {
      // The preference is a convenience; a failed write is not an error.
    }
  }, [collapsed]);

  // Following a link is the point of opening the drawer, so it closes itself.
  useEffect(() => {
    setDrawerOpen(false);
  }, [location.pathname]);

  // While it covers the page, the page must not scroll behind it.
  useEffect(() => {
    if (!drawerOpen) return undefined;
    const previous = window.document.body.style.overflow;
    window.document.body.style.overflow = 'hidden';
    return () => {
      window.document.body.style.overflow = previous;
    };
  }, [drawerOpen]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === '/' && !typing) {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === 'Escape') {
        setDrawerOpen((open) => {
          // Focus goes back to the button that opened it, or the reader is left
          // with nothing selected in the middle of the page.
          if (open) drawerRef.current?.focus();
          return false;
        });
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  function submitSearch(event: React.FormEvent) {
    event.preventDefault();
    const term = search.trim();
    if (term) navigate(`/jobs?search=${encodeURIComponent(term)}`);
  }

  const adminItems = ADMIN_NAV.filter((item) => !item.permission || can(item.permission));
  const displayName = user?.display_name ?? user?.username ?? '';
  const railCollapsed = collapsed && !drawerOpen;

  return (
    <div className="flex min-h-full flex-col">
      <header
        className="glass sticky top-0 z-30 grid grid-cols-[1fr_auto_1fr] items-center gap-3 border-b border-border px-3 sm:px-4"
        style={{ height: 'var(--topbar-height)' }}
      >
        <div className="flex min-w-0 items-center gap-3">
          <Button
            ref={drawerRef}
            variant="ghost"
            className="lg:hidden"
            aria-label="Open the navigation"
            aria-expanded={drawerOpen}
            aria-controls="main-navigation"
            onClick={() => setDrawerOpen(true)}
            icon={<MenuIcon className="h-5 w-5" aria-hidden />}
          />

          <Link
            to="/scan"
            className="flex items-center gap-2.5 rounded-md px-1 py-1"
            aria-label="XenoProxy home"
          >
            <LogoMark size={26} />
            <span className="text-gradient text-base font-bold tracking-[0.16em]">XenoProxy</span>
          </Link>
        </div>

        <form onSubmit={submitSearch} className="hidden w-[28rem] max-w-full md:block">
          <label className="sr-only" htmlFor="global-search">
            Search jobs by observable
          </label>
          <div className="group relative">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-faint"
              aria-hidden
            />
            <input
              id="global-search"
              ref={searchRef}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search an observable…"
              className={clsx(
                'h-9 w-full rounded-pill border border-border bg-surface-sunken pl-9 pr-16 text-sm',
                'transition-[border-color,box-shadow] duration-fast ease-out placeholder:text-faint',
                'hover:border-border-strong focus:border-primary focus:shadow-accent focus:outline-none',
              )}
            />
            <span className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2">
              <kbd className="kbd">Ctrl K</kbd>
            </span>
          </div>
        </form>

        <div className="flex items-center justify-end gap-1">
          <Button
            variant="ghost"
            aria-label={theme === 'dark' ? 'Use the light theme' : 'Use the dark theme'}
            onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            icon={
              theme === 'dark' ? (
                <Sun className="h-[18px] w-[18px]" aria-hidden />
              ) : (
                <Moon className="h-[18px] w-[18px]" aria-hidden />
              )
            }
          />
          <Button
            variant="ghost"
            aria-label="Open the help for this page"
            onClick={() => navigate('/help')}
            icon={<CircleHelp className="h-[18px] w-[18px]" aria-hidden />}
          />

          <Menu
            trigger={({ open, toggle }) => (
              <button
                type="button"
                onClick={toggle}
                aria-haspopup="menu"
                aria-expanded={open}
                className={clsx(
                  'ml-1 flex items-center gap-2 rounded-pill border border-transparent py-1 pl-1 pr-1.5',
                  'transition-colors duration-fast ease-out hover:bg-surface-hover',
                  'focus-visible:shadow-focus focus-visible:outline-none',
                  open && 'border-border bg-surface-hover',
                )}
              >
                <span
                  className={clsx(
                    'grid h-7 w-7 shrink-0 place-items-center rounded-pill text-[11px] font-semibold',
                    'bg-gradient-to-br from-accent-from to-accent-to text-primary-content',
                  )}
                  aria-hidden
                >
                  {initialsOf(displayName)}
                </span>
                <span className="hidden max-w-36 truncate text-sm font-medium sm:block">
                  {displayName}
                </span>
              </button>
            )}
          >
            {({ close }) => (
              <>
                <div className="border-b border-border-subtle px-2.5 pb-2 pt-1.5">
                  <p className="truncate text-sm font-medium">{displayName}</p>
                  <p className="truncate text-xs text-muted">{user?.email ?? user?.username}</p>
                  {user?.role ? (
                    <Badge tone="primary" className="mt-1.5">
                      {user.role}
                    </Badge>
                  ) : null}
                </div>
                <div className="pt-1">
                  <MenuItem
                    icon={<KeyRound className="h-4 w-4" aria-hidden />}
                    onClick={() => {
                      close();
                      navigate('/settings');
                    }}
                  >
                    My access
                  </MenuItem>
                  <MenuItem
                    icon={<CircleHelp className="h-4 w-4" aria-hidden />}
                    onClick={() => {
                      close();
                      navigate('/help');
                    }}
                  >
                    Help
                  </MenuItem>
                  <MenuItem
                    tone="danger"
                    icon={<LogOut className="h-4 w-4" aria-hidden />}
                    onClick={() => {
                      close();
                      void signOut();
                    }}
                  >
                    Sign out
                  </MenuItem>
                </div>
              </>
            )}
          </Menu>
        </div>
      </header>

      <div className="flex flex-1 items-start">
        {/* The drawer's backdrop. It closes on a click, which is what a reader
            expects of an overlay, and it only exists while the drawer is open. */}
        {drawerOpen ? (
          <div
            className="fixed inset-0 z-30 bg-black/60 backdrop-blur-sm lg:hidden"
            onClick={() => setDrawerOpen(false)}
            aria-hidden
          />
        ) : null}

        <nav
          id="main-navigation"
          aria-label="Main navigation"
          className={clsx(
            'shrink-0 border-r border-border bg-surface/60 p-2.5',
            // Above the breakpoint it is part of the layout. Below it, it is an
            // overlay that slides in, so the content keeps the full width.
            'flex flex-col',
            'transition-[width] duration-base ease-out',
            // The navigation stays put while a long settings page scrolls:
            // it sticks under the top bar and takes exactly the remaining
            // height, scrolling on its own if the entries do not fit.
            'lg:sticky lg:top-[var(--topbar-height)]',
            'lg:h-[calc(100vh-var(--topbar-height))] lg:overflow-y-auto',
            'max-lg:fixed max-lg:inset-y-0 max-lg:left-0 max-lg:z-40 max-lg:w-64 max-lg:bg-surface',
            'max-lg:transition-transform',
            drawerOpen ? 'max-lg:translate-x-0' : 'max-lg:-translate-x-full',
          )}
          style={{
            width: collapsed ? 'var(--sidebar-width-collapsed)' : 'var(--sidebar-width)',
          }}
        >
          <div className="mb-2 flex items-center justify-between lg:hidden">
            <span className="px-2 text-sm font-semibold">Menu</span>
            <Button
              variant="ghost"
              aria-label="Close the navigation"
              onClick={() => {
                setDrawerOpen(false);
                drawerRef.current?.focus();
              }}
              icon={<X className="h-4 w-4" aria-hidden />}
            />
          </div>

          <div className="flex flex-1 flex-col gap-0.5">
            {MAIN_NAV.map((item) => (
              <SidebarLink key={item.to} item={item} collapsed={railCollapsed} />
            ))}

            {adminItems.length > 0 ? (
              <>
                {railCollapsed ? (
                  <hr className="my-3 border-border-subtle" />
                ) : (
                  <p className="mb-1 mt-5 px-3 text-[11px] font-semibold uppercase tracking-[0.1em] text-faint">
                    Administration
                  </p>
                )}
                {adminItems.map((item) => (
                  <SidebarLink key={item.to} item={item} collapsed={railCollapsed} />
                ))}
              </>
            ) : null}
          </div>

          <div className="mt-3 border-t border-border-subtle pt-2">
            <Button
              variant="ghost"
              size="sm"
              className="hidden w-full justify-start lg:inline-flex"
              onClick={() => setCollapsed((previous) => !previous)}
              aria-label={collapsed ? 'Expand the navigation' : 'Collapse the navigation'}
              icon={
                <ChevronLeft
                  className={clsx('h-4 w-4 transition-transform duration-base ease-out', collapsed && 'rotate-180')}
                  aria-hidden
                />
              }
            >
              {railCollapsed ? null : <span className="text-xs">Collapse</span>}
            </Button>
            {railCollapsed ? null : (
              <p className="px-3 pt-1 text-[11px] text-faint">XenoProxy v0.1.0</p>
            )}
          </div>
        </nav>

        <main className="min-w-0 flex-1 px-4 py-5 lg:px-7 lg:py-7">{children}</main>
      </div>
    </div>
  );
}

export function PageHeader({
  breadcrumb,
  title,
  description,
  actions,
}: {
  breadcrumb: string[];
  title: string;
  description?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="mb-6">
      <nav aria-label="Breadcrumb" className="mb-2 flex items-center gap-1 text-xs text-faint">
        {breadcrumb.map((crumb, index) => (
          <span key={`${crumb}-${index}`} className="flex items-center gap-1">
            {index > 0 ? <ChevronRight className="h-3 w-3" aria-hidden /> : null}
            <span className={index === breadcrumb.length - 1 ? 'text-muted' : undefined}>
              {crumb}
            </span>
          </span>
        ))}
      </nav>
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-semibold">{title}</h1>
          {description ? <p className="mt-1.5 max-w-2xl text-sm text-muted">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </div>
  );
}
