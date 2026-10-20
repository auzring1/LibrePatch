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
  icon: IconType;
  /** Match this path exactly (a sibling lives below it). */
  end?: boolean;
  /** For a Settings entry: the id of its section on the server. */
  section?: string;
  /** Other words the command palette should find it by. */
  keywords?: string[];
  /** A submenu. */
  children?: NavItem[];
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
  { id: "settings-updates", section: "updates", to: "/settings/updates", label: "Update defaults", perm: "settings:updates", icon: I.NavSource, keywords: ["update source", "ring", "restart", "active hours", "maintenance window", "drivers"] },
  { id: "settings-devices", section: "devices", to: "/settings/devices", label: "Device defaults", perm: "settings:devices", icon: I.NavDevices, keywords: ["offline", "stale", "custom fields", "tags", "columns"] },
  { id: "settings-downloads", section: "downloads", to: "/settings/downloads", label: "Downloads", perm: "settings:devices", icon: I.Download, keywords: ["peer cache", "share downloads", "bandwidth", "installers", "lan"] },
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
      { id: "windows-updates", to: "/updates", label: "Windows updates", perm: "updates:read", icon: I.NavUpdates, end: true, keywords: ["patches", "kb", "approve"] },
      { id: "update-rings", to: "/update-policy", label: "Update rings and rules", perm: "updates:read", icon: I.NavPolicy, keywords: ["policy", "rings", "rules", "restart"] },
      { id: "held-updates", to: "/updates/held", label: "Held updates", perm: "updates:read", icon: I.NavHeld, keywords: ["holds", "blocked"] },
      { id: "agent-updates", to: "/agent-updates", label: "Agent updates", perm: "releases:read", icon: I.NavAgentUpdates, keywords: ["releases", "self-update"] },
    ],
  },
  {
    id: "software",
    label: "Software",
    items: [
      { id: "inventory", to: "/software", label: "Inventory", perm: "devices:read", icon: I.NavSoftware, keywords: ["installed software", "apps", "programs"] },
      { id: "catalog", to: "/catalog", label: "Catalog", perm: "catalog:read", icon: I.NavCatalog, keywords: ["packages"] },
      { id: "deployments", to: "/deployments", label: "Deployments", perm: "deployments:read", icon: I.NavDeployments, keywords: ["install", "jobs"] },
      { id: "software-policies", to: "/policies", label: "Software policies", perm: "policies:read", icon: I.NavSoftwarePolicy, keywords: ["keep updated", "baseline"] },
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
      { id: "settings", to: "/settings", label: "Settings", perm: "catalog:read", icon: I.NavSettings, children: SETTINGS_SECTIONS, keywords: ["configuration", "options"] },
      { id: "styleguide", to: "/styleguide", label: "Style guide", perm: "branding:write", icon: I.Palette },
    ],
  },
];

export interface Allow {
  can: (perm: string) => boolean;
  canOrg: (perm: string) => boolean;
}

/** Whether the person may see a link. */
export const allowed = (n: NavItem, a: Allow) => n.perm === "" || (n.any ? a.can(n.perm) : a.canOrg(n.perm));

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
