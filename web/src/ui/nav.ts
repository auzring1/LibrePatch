import type { ComponentType } from "react";
import * as I from "./icons";

type IconType = ComponentType<{ size?: number; "aria-hidden"?: boolean }>;

export interface NavItem {
  /** Stable id (kept in the person's saved layout, so never rename one). */
  id: string;
  to: string;
  label: string;
  /** The permission needed to see the link; "" = any signed-in person. */
  perm: string;
  /** Visible with the permission for some sites only (the device pages). */
  any?: boolean;
  /** Visible with any one of these permissions (organization-wide) instead of `perm`. */
  anyOf?: string[];
  /** Hidden while this part of the console is switched off for the organization (Settings > Update defaults). */
  feature?: "windows-updates";
  icon: IconType;
  /** Match this path exactly (a sibling lives below it). */
  end?: boolean;
  /** For a Settings entry: the id of its section on the server. */
  section?: string;
  /** Other words the command palette should find it by. */
  keywords?: string[];
  /** A submenu. */
  children?: NavItem[];
  /** False: not in the sidebar (the page is reached from another page), but still found by the command palette. */
  sidebar?: false;
}
export interface NavGroup {
  id: string;
  /** "" = items stand on their own, without a heading. */
  label: string;
  items: NavItem[];
}

/** Settings sections: the left navigation inside the Settings area (the sidebar has a single Settings link) and the command palette. */
export const SETTINGS_SECTIONS: NavItem[] = [
  { id: "settings-general", section: "general", to: "/settings", label: "General", perm: "catalog:read", icon: I.NavSettings, end: true, keywords: ["per-user installs"] },
  { id: "settings-branding", section: "branding", to: "/settings/branding", label: "Branding", perm: "branding:write", icon: I.Palette, keywords: ["logo", "name", "colors", "login"] },
  { id: "settings-appearance", section: "appearance", to: "/settings/appearance", label: "Appearance", perm: "settings:appearance", icon: I.Brush, keywords: ["theme", "density", "language", "time zone", "date format"] },
  { id: "settings-security", section: "security", to: "/settings/security", label: "Security", perm: "settings:security", icon: I.NavSecurity, keywords: ["session", "password", "mfa", "ip allow-list", "lockout", "banner"] },
  { id: "settings-notifications", section: "notifications", to: "/settings/notifications", label: "Notifications", perm: "settings:notifications", icon: I.Bell, keywords: ["email", "smtp", "webhook", "alerts"] },
  { id: "settings-sso", section: "sso", to: "/settings/sso", label: "Single sign-on", perm: "settings:security", icon: I.NavSecurity, keywords: ["entra", "azure", "microsoft", "oidc", "openid", "login", "sso"] },
  { id: "settings-updates", section: "updates", to: "/settings/updates", label: "Update defaults", perm: "settings:updates", icon: I.NavSource, keywords: ["update source", "ring", "restart", "active hours", "maintenance window", "drivers"] },
  { id: "settings-devices", section: "devices", to: "/settings/devices", label: "Device defaults", perm: "settings:devices", icon: I.NavDevices, keywords: ["offline", "stale", "custom fields", "tags", "columns"] },
  { id: "settings-downloads", section: "downloads", to: "/settings/downloads", label: "Downloads", perm: "settings:devices", icon: I.Download, keywords: ["peer cache", "share downloads", "bandwidth", "installers", "lan"] },
  { id: "settings-scripts", section: "scripts", to: "/settings/scripts", label: "Scripts", perm: "settings:security", icon: I.NavScripts, keywords: ["approval", "four eyes", "powershell"] },
  { id: "settings-reports", section: "reports", to: "/settings/reports", label: "Scheduled reports", perm: "settings:reports", icon: I.NavReports, keywords: ["scheduled reports", "pdf", "csv"] },
  { id: "settings-data", section: "data", to: "/settings/data", label: "Data and retention", perm: "settings:data", icon: I.NavData, keywords: ["maintenance", "retention", "backup", "export"] },
  { id: "settings-vulnerabilities", section: "vulnerabilities", to: "/settings/vulnerabilities", label: "Vulnerability data", perm: "settings:integrations", icon: I.Shield, keywords: ["cve", "nvd", "cisa", "kev", "exploited", "security"] },
  { id: "settings-integrations", section: "integrations", to: "/settings/integrations", label: "Integrations", perm: "settings:integrations", icon: I.NavIntegrations, keywords: ["webhooks", "api tokens", "events"] },
  { id: "settings-about", section: "about", to: "/settings/about", label: "About", perm: "settings:write", icon: I.Info, keywords: ["version", "support bundle", "build"] },
];

/** The console's navigation. Links the person may not use are filtered out by the shell. */
export const NAV: NavGroup[] = [
  { id: "overview", label: "", items: [{ id: "dashboard", to: "/", label: "Dashboard", perm: "", icon: I.Dashboard, end: true, keywords: ["home", "overview", "summary"] }] },
  {
    id: "endpoints",
    label: "Endpoints",
    items: [
      { id: "devices", to: "/devices", label: "Devices", perm: "devices:read", any: true, icon: I.NavDevices, keywords: ["computers", "endpoints", "fleet"] },
      { id: "groups", to: "/groups", label: "Groups", perm: "groups:read", icon: I.NavGroups },
      { id: "sites", to: "/sites", label: "Sites", perm: "sites:write", icon: I.NavSites, keywords: ["locations"] },
      { id: "enrollment", to: "/enrollment", label: "Enrollment", perm: "enrollment:read", icon: I.NavEnrollment, keywords: ["tokens", "add devices", "install"] },
    ],
  },
  {
    id: "updates",
    label: "Updates",
    items: [
      { id: "software-updates", to: "/software-updates", label: "Software updates", perm: "deployments:read", icon: I.NavSoftwareUpdates, keywords: ["program updates", "outdated", "apps", "newer version", "patch software"] },
      { id: "windows-updates", to: "/updates", label: "Windows updates", perm: "updates:read", feature: "windows-updates", icon: I.NavUpdates, end: true, keywords: ["patches", "kb", "approve"] },
      {
        id: "automations",
        to: "/automations",
        label: "Automations",
        perm: "",
        anyOf: ["policies:read", "updates:read"],
        icon: I.NavPolicy,
        keywords: ["policy", "policies", "keep updated", "baseline", "rings", "rules", "rollout", "approval", "restart", "schedule", "update rings and rules", "software policies"],
      },
      { id: "held-updates", to: "/updates/held", label: "Held updates", perm: "updates:read", feature: "windows-updates", sidebar: false, icon: I.NavHeld, keywords: ["holds", "blocked"] },
    ],
  },
  {
    id: "software",
    label: "Software",
    items: [
      { id: "inventory", to: "/software", label: "Inventory", perm: "devices:read", icon: I.NavSoftware, keywords: ["installed software", "apps", "programs"] },
      { id: "catalog", to: "/catalog", label: "Catalog", perm: "catalog:read", icon: I.NavCatalog, keywords: ["packages"] },
      { id: "deployments", to: "/deployments", label: "Deployments", perm: "deployments:read", icon: I.NavDeployments, keywords: ["install", "jobs"] },
      { id: "scripts", to: "/scripts", label: "Scripts", perm: "scripts:read", icon: I.NavScripts, keywords: ["powershell", "run script", "automation", "remote command"] },
    ],
  },
  {
    id: "insights",
    label: "",
    items: [
      { id: "vulnerabilities", to: "/vulnerabilities", label: "Vulnerabilities", perm: "reports:read", icon: I.Shield, keywords: ["cve", "exploited", "security", "risk", "kev", "nvd"] },
      { id: "reports", to: "/reports", label: "Reports", perm: "reports:read", icon: I.NavReports, keywords: ["compliance", "export"] },
    ],
  },
  {
    id: "administration",
    label: "Administration",
    items: [
      { id: "users", to: "/users", label: "Users and roles", perm: "users:read", icon: I.NavUsers, keywords: ["accounts", "rbac", "tokens"] },
      { id: "audit", to: "/audit", label: "Audit log", perm: "audit:read", icon: I.NavAudit, keywords: ["history", "events"] },
      { id: "agent-updates", to: "/agent-updates", label: "Agent updates", perm: "releases:read", icon: I.NavAgentUpdates, keywords: ["releases", "self-update", "agent versions"] },
      { id: "settings", to: "/settings", label: "Settings", perm: "catalog:read", icon: I.NavSettings, children: SETTINGS_SECTIONS, keywords: ["configuration", "options"] },
      { id: "styleguide", to: "/styleguide", label: "Style guide", perm: "branding:write", icon: I.Palette },
    ],
  },
];

export interface Allow {
  can: (perm: string) => boolean;
  canOrg: (perm: string) => boolean;
  /** Parts of the console the organization switched off; absent means everything is on. */
  features?: { windowsUpdates: boolean };
}

/** Whether the person may see a link. */
export const allowed = (n: NavItem, a: Allow) => {
  if (n.feature === "windows-updates" && a.features?.windowsUpdates === false) return false;
  if (n.anyOf) return n.anyOf.some((p) => a.canOrg(p));
  return n.perm === "" || (n.any ? a.can(n.perm) : a.canOrg(n.perm));
};

/** What the sidebar shows: the navigation without the pages that are reached from another page. */
export function sidebarNav(a: Allow): NavGroup[] {
  return visibleNav(a)
    .map((g) => ({ ...g, items: g.items.filter((i) => i.sidebar !== false) }))
    .filter((g) => g.items.length > 0);
}

/** The navigation filtered for a person: empty groups and unavailable links are dropped. */
export function visibleNav(a: Allow): NavGroup[] {
  const keep = (n: NavItem): NavItem | null => {
    if (!allowed(n, a)) return null;
    if (!n.children) return n;
    const kids = n.children.filter((c) => allowed(c, a));
    return { ...n, children: kids };
  };
  return NAV.map((g) => ({ ...g, items: g.items.map(keep).filter((x): x is NavItem => x !== null) })).filter((g) => g.items.length > 0);
}

/** Every link, flattened (submenu entries after their parent). */
export function flatNav(groups: NavGroup[] = NAV): { item: NavItem; group: NavGroup; parent?: NavItem }[] {
  const out: { item: NavItem; group: NavGroup; parent?: NavItem }[] = [];
  for (const g of groups) {
    for (const it of g.items) {
      out.push({ item: it, group: g });
      for (const c of it.children ?? []) out.push({ item: c, group: g, parent: it });
    }
  }
  return out;
}

export const ALL_NAV_ITEMS: NavItem[] = flatNav().map((x) => x.item);

const within = (path: string, to: string, end?: boolean) => (to === "/" ? path === "/" : end ? path === to : path === to || path.startsWith(to + "/"));

/** The entry whose page a path belongs to: the most specific match (a submenu entry beats its parent). */
export function locate(pathname: string) {
  const path = pathname.replace(/\/+$/, "") || "/";
  let best: ReturnType<typeof flatNav>[number] | undefined;
  for (const x of flatNav()) {
    if (!within(path, x.item.to, x.item.end)) continue;
    if (!best || x.item.to.length >= best.item.to.length) best = x; // a submenu entry beats its parent on a tie (General is /settings itself)
  }
  // /devices/:id is the Devices page's child; the dashboard only owns "/".
  return best;
}

/** Breadcrumb trail for a path: group, parent, page. The last entry has no link. */
export function trail(pathname: string): { label: string; to?: string }[] {
  const hit = locate(pathname);
  if (!hit) return [];
  const t: { label: string; to?: string }[] = [];
  if (hit.group.label) t.push({ label: hit.group.label });
  if (hit.parent) t.push({ label: hit.parent.label, to: hit.parent.to });
  t.push({ label: hit.item.label, to: hit.item.to });
  return t;
}
