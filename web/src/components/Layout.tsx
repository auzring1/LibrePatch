import { useState } from "react";
import { ActionIcon, Drawer } from "@mantine/core";
import { useMediaQuery } from "@mantine/hooks";
import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { api, setCsrf } from "../api/client";
import { useLiveEvents } from "../api/events";
import { useSession } from "../api/session";
import { BrandMark, useBranding, useDocumentTitle } from "../branding/BrandingProvider";
import { forgetLocalAppearance } from "../design/AppearanceProvider";
import { CommandPaletteProvider, SearchButton } from "../ui/CommandPalette";
import { NotificationsBell } from "../ui/NotificationsBell";
import { SiteScopeProvider } from "../ui/SiteScope";
import { SiteSwitcher } from "../ui/SiteSwitcher";
import { useNavLayout } from "../ui/useNavLayout";
import { setDisplay } from "../api/format";
import { useEffective } from "../settings/useEffective";
import * as I from "../ui/icons";
import { locate } from "../ui/nav";
import { SideNav } from "../ui/SideNav";
import { UserMenu } from "../ui/UserMenu";
import "../ui/ui.css";

export function Layout() {
  const { session, can } = useSession();
  const nav = useNavigate();
  const qc = useQueryClient();
  const brand = useBranding();
  const loc = useLocation();
  const narrow = useMediaQuery("(max-width: 62em)", false) ?? false;
  const [drawer, setDrawer] = useState(false);
  const { layout, setCollapsed } = useNavLayout();
  const rail = !narrow && layout.collapsed;
  // The organization's date format, clock and time zone (Settings > Appearance). The page area is keyed by them, so a
  // change applies at once without a reload.
  const eff = useEffective();
  const ap = eff.data?.appearance;
  const displayKey = ap ? [ap.locale, ap.date_format, ap.time_format, ap.time_zone].join("|") : "";
  if (ap) setDisplay({ locale: ap.locale, dateFormat: ap.date_format, timeFormat: ap.time_format, timeZone: ap.time_zone });
  useLiveEvents(can("devices:read"));

  const logout = async () => {
    await api("POST", "/auth/logout", {}).catch(() => undefined);
    setCsrf("");
    forgetLocalAppearance();
    // Drop everything cached for the old user, but keep the session query itself so the mounted
    // provider sees "signed out" at once (clear() would detach it and leave a stale session). The public
    // branding is not user data, and its provider stays mounted, so it must stay in the cache too.
    qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "session" && q.queryKey[0] !== "branding" });
    qc.setQueryData(["session"], null);
    nav("/login", { replace: true });
  };

  const here = locate(loc.pathname)?.item;
  useDocumentTitle(here?.label ?? (loc.pathname.startsWith("/account") ? "Account" : undefined));

  return (
    <SiteScopeProvider>
    <CommandPaletteProvider>
    <div className="lp-shell" data-rail={rail ? "true" : undefined}>
      <a className="lp-skip-link" href="#main">
        Skip to main content
      </a>
      <header className="lp-topbar">
        {narrow && (
          <ActionIcon variant="subtle" color="gray" size="lg" onClick={() => setDrawer(true)} aria-label="Open navigation" aria-expanded={drawer} aria-controls="mobile-nav">
            <I.Menu size={20} aria-hidden />
          </ActionIcon>
        )}
        {!narrow && (
          <ActionIcon variant="subtle" color="gray" size="lg" onClick={() => setCollapsed(!rail)} aria-label="Toggle sidebar" aria-pressed={rail} title={rail ? "Expand sidebar" : "Collapse sidebar to icons"} data-testid="topbar-nav-toggle">
            {rail ? <I.SidebarExpand size={20} aria-hidden /> : <I.SidebarCollapse size={20} aria-hidden />}
          </ActionIcon>
        )}
        {/* No aria-label: a label that leaves out text people can see fails WCAG 2.5.3 (axe "label-content-name-mismatch").
            The name comes from the visible product and organization names, plus a hidden "home". */}
        <Link to="/" className="lp-topbar__brand">
          <BrandMark height={28} />
          <span className="lp-topbar__product" data-testid="product-name">
            {brand.product_name}
          </span>
          <span className="lp-topbar__org" data-testid="org-name">
            {brand.org_name || session?.org.name}
          </span>
          <span className="lp-visually-hidden"> home</span>
        </Link>
        <SiteSwitcher />
        <div className="lp-topbar__search">
          <SearchButton />
        </div>
        <span className="lp-topbar__spacer" />
        <div className="lp-topbar__right">
          <NotificationsBell />
          <UserMenu name={session?.user.display_name ?? ""} email={session?.user.email ?? ""} onSignOut={() => void logout()} />
        </div>
      </header>
      {!narrow && (
        <div className="lp-nav lp-nav--static">
          <SideNav rail={rail} />
          <div className="lp-nav__foot">
            <button type="button" className="lp-nav__link lp-nav__rail-toggle" onClick={() => setCollapsed(!rail)} aria-pressed={rail} title={rail ? "Expand sidebar" : undefined} data-testid="nav-rail-toggle">
              {rail ? <I.SidebarExpand size={18} aria-hidden /> : <I.SidebarCollapse size={18} aria-hidden />}
              <span className={rail ? "lp-visually-hidden" : "lp-nav__text"}>{rail ? "Expand sidebar" : "Collapse sidebar"}</span>
            </button>
          </div>
        </div>
      )}
      {narrow && (
        <Drawer opened={drawer} onClose={() => setDrawer(false)} size={290} padding="sm" title="Navigation" id="mobile-nav" withinPortal>
          <SideNav onNavigate={() => setDrawer(false)} />
        </Drawer>
      )}
      <main id="main" className="lp-main" tabIndex={-1} key={displayKey}>
        <Outlet />
      </main>
    </div>
    </CommandPaletteProvider>
    </SiteScopeProvider>
  );
}
