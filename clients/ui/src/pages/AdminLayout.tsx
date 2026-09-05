import type { Tenant } from "@bentoforge/umami-iam";
import {
  ArrowsRightLeftIcon,
  Bars3Icon,
  ChevronDownIcon,
  ComputerDesktopIcon,
  MoonIcon,
  SunIcon,
  UserCircleIcon,
  XMarkIcon,
} from "@heroicons/react/24/outline";
import { Fragment, type SVGProps, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { NavLink, Outlet } from "react-router-dom";
import { useUmami } from "../auth/UmamiProvider";
import { errMsg, Footer, Logo } from "../components";
import { getTheme, setTheme, type Theme } from "../theme";
import { card, headerIconButton, input } from "../ui";

type NavItem = { to: string; label: string; show: boolean; end?: boolean };

/** Dropdown surface: the card look without its baked-in `p-6`, so each popover can set its own
 * (much smaller) padding — otherwise `card`'s `p-6` wins the Tailwind cascade over any `p-*` added
 * after it, and the menus stay heavily padded. */
const popoverSurface = card.replace(" p-6", "");

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  `px-3 py-1.5 rounded-lg text-sm font-medium ${
    isActive
      ? "text-header-accent"
      : "text-header-muted hover:text-header-text hover:bg-header-hover"
  }`;

/** Authenticated shell: logo + nav, theme/tenant switchers, user menu (desktop) or hamburger
 * (mobile), the impersonation banner, and the active route. */
export function AdminLayout() {
  const { client, me, activeTenantId, activeTenantName } = useUmami();
  const { t } = useTranslation();
  const can = (permission: string) => client.hasPermission(permission);
  const [mobileOpen, setMobileOpen] = useState(false);

  const homeTenantId = me?.user.tenantId;
  const switched = !!activeTenantId && activeTenantId !== homeTenantId;

  const navItems: NavItem[] = [
    { to: "/", label: t("nav.start"), show: true, end: true },
    { to: "/tenants", label: t("nav.tenants"), show: can("manage:tenants") },
    { to: "/users", label: t("nav.users"), show: can("manage:users") },
    { to: "/api-tokens", label: t("nav.apiTokens"), show: can("manage:service-keys") },
  ].filter((item) => item.show);

  // Personal/account items — the user menu (desktop) and part of the mobile menu.
  const menuItems: NavItem[] = [
    { to: "/profile", label: t("nav.profile"), show: true },
    { to: "/audit", label: t("nav.audit"), show: can("view:audit") },
    { to: "/rate-limits", label: t("nav.rateLimits"), show: can("view:ratelimits") },
    { to: "/config", label: t("nav.config"), show: can("manage:config") },
  ].filter((item) => item.show);

  const fullName = me?.user.fullName?.trim() || me?.user.username || "";
  const tenantName = activeTenantName ?? me?.tenant?.name ?? me?.user.tenantId ?? "";

  return (
    <div className="min-h-screen flex flex-col bg-slate-100 dark:bg-slate-900">
      <header className="bg-header-bg border-b border-header-border text-header-text">
        <div className="mx-auto max-w-6xl px-6 py-3 flex items-center gap-4">
          {/* Logo → Start. Theme-aware (config `branding.logoLight`/`logoDark`, else built-in). */}
          <NavLink to="/" className="shrink-0" onClick={() => setMobileOpen(false)}>
            <Logo className="h-8 w-auto" />
          </NavLink>

          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => (
              <NavLink key={item.to} to={item.to} end={item.end} className={navLinkClass}>
                {item.label}
              </NavLink>
            ))}
          </nav>

          <div className="ml-auto flex items-center gap-1">
            <ThemeSwitcher />
            {can("switch:tenant") && (
              <div className="hidden md:block">
                <TenantSwitcher />
              </div>
            )}
            <div className="hidden md:block">
              <UserMenu fullName={fullName} tenantName={tenantName} items={menuItems} />
            </div>
            <button
              type="button"
              className={`${headerIconButton} md:hidden`}
              aria-label={t("layout.menu")}
              onClick={() => setMobileOpen((open) => !open)}
            >
              {mobileOpen ? <XMarkIcon className="h-6 w-6" /> : <Bars3Icon className="h-6 w-6" />}
            </button>
          </div>
        </div>

        {mobileOpen && (
          <MobileMenu
            navItems={navItems}
            menuItems={menuItems}
            onNavigate={() => setMobileOpen(false)}
          />
        )}
      </header>

      {/* Keyed on the active tenant so a switch remounts the pages → they refetch against the new
          token without a full reload (a reload would silently refresh back to the home tenant). */}
      <main key={activeTenantId ?? "none"} className="mx-auto w-full max-w-6xl flex-1 px-6 py-8">
        {/* Below the bar rather than inside it, and spaced like any other block:
            stuck to the header it read as part of the chrome, which is the one
            thing this must not be — it is a state you have to be able to leave. */}
        {switched && <ImpersonationNotice />}
        <Outlet />
      </main>

      {/* The same legal line as the sign-in page, in a slate tone for the admin ground —
          `flex-1` on main keeps it at the foot even when a page is short. */}
      <Footer className="text-slate-500 dark:text-slate-400" />
    </div>
  );
}

/**
 * Acting as another tenant, and the way out of it.
 *
 * Amber and boxed, not a thin strip: everything below it belongs to someone
 * else, and that is worth a block of its own rather than a line of chrome.
 */
// Dark values are literal rather than Tailwind's amber scale: `amber-950`
// composited over slate-900 lands on rgb(37 24 26) — red dominant, green and blue
// level — which reads as a dark red rather than as a warning. These are the same
// amber the noonu app uses, where blue stays clearly lowest.
function ImpersonationNotice() {
  const { me, activeTenantId, activeTenantName, switchTenant } = useUmami();
  const { t } = useTranslation();
  const home = me?.user.tenantId;

  return (
    <div className="mb-6 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 dark:border-[#d9a445]/40 dark:bg-[#2a2314]">
      <span className="text-sm text-amber-800 dark:text-[#e5b963]">
        {t("layout.impersonating")} <strong>{activeTenantName ?? activeTenantId}</strong>
      </span>
      {home && (
        <button
          type="button"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg p-2 text-sm font-medium text-amber-800 hover:bg-amber-100 dark:text-[#e5b963] dark:hover:bg-[#d9a445]/15"
          onClick={() => void switchTenant(home, me?.tenant?.name)}
        >
          <XMarkIcon className="h-4 w-4" aria-hidden="true" />
          {t("layout.endImpersonation")}
        </button>
      )}
    </div>
  );
}

/** A half-filled circle — the theme/appearance glyph (Heroicons has no half-circle).
 *
 * The title is a required prop rather than a constant in here: it is the only human-readable string
 * in the icon, and a component this far from a hook has no `t` of its own. */
function HalfCircleIcon({ title, ...props }: SVGProps<SVGSVGElement> & { title: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      role="img"
      aria-hidden="true"
      {...props}
    >
      <title>{title}</title>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" />
    </svg>
  );
}

// Keys, not words: the list is module-level and `t` only exists inside the component below.
const THEME_OPTIONS: { value: Theme; labelKey: string; Icon: typeof SunIcon }[] = [
  { value: "auto", labelKey: "layout.themeAuto", Icon: ComputerDesktopIcon },
  { value: "light", labelKey: "layout.themeLight", Icon: SunIcon },
  { value: "dark", labelKey: "layout.themeDark", Icon: MoonIcon },
];

/** Theme menu: half-circle trigger opening auto / light / dark, the active one highlighted. */
function ThemeSwitcher() {
  const { t } = useTranslation();
  const [theme, setThemeState] = useState(getTheme());
  const [open, setOpen] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  const choose = (value: Theme) => {
    setTheme(value);
    setThemeState(value);
    setOpen(false);
  };

  return (
    <div className="relative" ref={boxRef}>
      <button
        type="button"
        className={headerIconButton}
        onClick={() => setOpen((v) => !v)}
        title={t("layout.theme")}
        aria-label={t("layout.theme")}
      >
        <HalfCircleIcon className="h-5 w-5" title={t("layout.theme")} />
      </button>
      {open && (
        <div className={`${popoverSurface} absolute right-0 mt-2 w-40 z-20 p-2 shadow-lg`}>
          {THEME_OPTIONS.map(({ value, labelKey, Icon }) => (
            <button
              key={value}
              type="button"
              onClick={() => choose(value)}
              className={`flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-sm ${
                theme === value
                  ? "bg-primary/10 text-primary font-medium"
                  : "text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              }`}
            >
              <Icon className="h-4 w-4" /> {t(labelKey)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/** Icon-only user menu: full name + tenant, opening the account items plus a way out. */
function UserMenu({
  fullName,
  tenantName,
  items,
}: {
  fullName: string;
  tenantName: string;
  items: NavItem[];
}) {
  const { signOut } = useUmami();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) {
      return;
    }
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  return (
    <div className="relative" ref={boxRef}>
      <button
        type="button"
        className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-header-hover"
        onClick={() => setOpen((v) => !v)}
      >
        <UserCircleIcon className="h-7 w-7 text-header-muted shrink-0" />
        <span className="hidden lg:flex flex-col text-left leading-tight">
          <span className="text-sm font-medium text-header-text">{fullName}</span>
          <span className="text-xs text-header-muted">{tenantName}</span>
        </span>
        <ChevronDownIcon className="h-4 w-4 text-header-muted" />
      </button>
      {open && (
        <div className={`${popoverSurface} absolute right-0 mt-2 w-56 z-20 p-2 shadow-lg`}>
          <div className="px-3 py-1.5 lg:hidden">
            <div className="text-sm font-medium text-slate-900 dark:text-white">{fullName}</div>
            <div className="text-xs text-slate-500">{tenantName}</div>
          </div>
          {items.map((item) => (
            <Fragment key={item.to}>
              {item.to === "/audit" && (
                <div className="my-1 border-t border-slate-200 dark:border-slate-700" />
              )}
              <NavLink
                to={item.to}
                onClick={() => setOpen(false)}
                className="block rounded-lg px-3 py-1.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
              >
                {item.label}
              </NavLink>
            </Fragment>
          ))}
          <div className="my-1 border-t border-slate-200 dark:border-slate-700" />
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              void signOut();
            }}
            className="block w-full text-left rounded-lg px-3 py-1.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700"
          >
            {t("layout.logout")}
          </button>
        </div>
      )}
    </div>
  );
}

/** Collapsed nav for small screens: nav + account items + (when impersonating) end-impersonation. */
function MobileMenu({
  navItems,
  menuItems,
  onNavigate,
}: {
  navItems: NavItem[];
  menuItems: NavItem[];
  onNavigate: () => void;
}) {
  const { me, signOut, activeTenantId, switchTenant } = useUmami();
  const { t } = useTranslation();
  const homeTenantId = me?.user.tenantId;
  const switched = !!activeTenantId && activeTenantId !== homeTenantId;

  const linkClass =
    "block rounded-lg px-3 py-1.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700";

  const divider = <div className="my-1 border-t border-slate-200 dark:border-slate-700" />;

  return (
    <div className="md:hidden border-t border-slate-200 dark:border-slate-700 px-4 py-2 space-y-0.5">
      {navItems.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          end={item.end}
          className={linkClass}
          onClick={onNavigate}
        >
          {item.label}
        </NavLink>
      ))}
      {/* Account items below a rule; the system config gets its own rule above it. */}
      {menuItems.map((item, index) => (
        <Fragment key={item.to}>
          {(index === 0 || item.to === "/audit") && divider}
          <NavLink to={item.to} end={item.end} className={linkClass} onClick={onNavigate}>
            {item.label}
          </NavLink>
        </Fragment>
      ))}
      {switched && homeTenantId && (
        <>
          <div className="my-1 border-t border-slate-200 dark:border-slate-700" />
          <button
            type="button"
            className="flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-sm text-amber-700 dark:text-amber-300 hover:bg-slate-100 dark:hover:bg-slate-700"
            onClick={() => {
              onNavigate();
              void switchTenant(homeTenantId, me?.tenant?.name);
            }}
          >
            <XMarkIcon className="h-4 w-4" /> {t("layout.endImpersonation")}
          </button>
        </>
      )}
      <div className="my-1 border-t border-slate-200 dark:border-slate-700" />
      <button
        type="button"
        className={`w-full text-left ${linkClass}`}
        onClick={() => {
          onNavigate();
          void signOut();
        }}
      >
        {t("layout.logout")}
      </button>
    </div>
  );
}

/** Icon dropdown: search tenants (5 shown, newest-updated first), switch into one, and — while
 * impersonating — end the impersonation below the list. */
function TenantSwitcher() {
  const { client, me, activeTenantId, switchTenant } = useUmami();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Tenant[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const homeTenantId = me?.user.tenantId;
  const switched = !!activeTenantId && activeTenantId !== homeTenantId;

  useEffect(() => {
    if (!open) {
      return;
    }
    const onClick = (e: MouseEvent) => {
      if (boxRef.current && !boxRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, [open]);

  useEffect(() => {
    if (!open) {
      return;
    }
    const handle = setTimeout(async () => {
      setError(null);
      try {
        const res = await client.listTenants(query.trim() || undefined, 5);
        setResults(res.tenants);
      } catch (err) {
        setError(errMsg(err));
        setResults([]);
      }
    }, 200);
    return () => clearTimeout(handle);
  }, [open, query, client]);

  const pick = async (tenantId: string, name?: string) => {
    setBusy(true);
    setError(null);
    try {
      await switchTenant(tenantId, name);
      setOpen(false);
      setQuery("");
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative" ref={boxRef}>
      <button
        type="button"
        className={headerIconButton}
        onClick={() => setOpen((v) => !v)}
        title={t("layout.switchTenant")}
        aria-label={t("layout.switchTenant")}
      >
        <ArrowsRightLeftIcon className="h-5 w-5" />
      </button>
      {open && (
        <div
          className={`${popoverSurface} absolute right-0 mt-2 w-80 z-20 p-2 space-y-2 shadow-lg max-h-96 overflow-auto`}
        >
          <input
            className={input}
            placeholder={t("common.search")}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
          {results.length === 0 ? (
            <p className="text-xs text-slate-400 px-1">{t("layout.noTenants")}</p>
          ) : (
            <ul className="space-y-0.5">
              {results.map((tenant) => (
                <li key={tenant.tenantId}>
                  <button
                    type="button"
                    disabled={busy}
                    onClick={() => void pick(tenant.tenantId, tenant.name)}
                    className={`w-full text-left rounded-lg px-3 py-1.5 text-sm hover:bg-slate-50 dark:hover:bg-slate-700 ${
                      tenant.tenantId === activeTenantId
                        ? "text-primary"
                        : "text-slate-700 dark:text-slate-200"
                    }`}
                  >
                    <div className="font-medium">{tenant.name}</div>
                    <div className="text-xs text-slate-400 font-mono">{tenant.tenantId}</div>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {switched && homeTenantId && (
            <>
              <div className="border-t border-slate-200 dark:border-slate-700" />
              <button
                type="button"
                disabled={busy}
                onClick={() => void pick(homeTenantId, me?.tenant?.name)}
                className="flex w-full items-center gap-2 rounded-lg px-3 py-1.5 text-sm text-amber-700 dark:text-amber-300 hover:bg-slate-50 dark:hover:bg-slate-700"
              >
                <XMarkIcon className="h-4 w-4" /> {t("layout.endImpersonation")}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
