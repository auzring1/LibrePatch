// The widget library: every kind of widget, what it is called, which settings it has and who may see it.

import type { Dashboard } from "../../api/client";
import type { Features } from "../../settings/features";
import { allTiles } from "./widgets";
import { startSteps, startVisible } from "./start";
import type { WidgetKind } from "./boards";

export interface WidgetCtx {
  d: Dashboard;
  canOrg: (perm: string) => boolean;
  can: (perm: string) => boolean;
  features: Features;
  startDismissed: boolean;
}

export type SettingField = "title" | "site" | "range" | "count" | "metric" | "dest" | "text";

export interface WidgetDef {
  kind: WidgetKind;
  title: string;
  description: string;
  group: "Numbers" | "Lists" | "Charts" | "Other";
  /** The settings dialog shows these fields (the title is always there). */
  fields: SettingField[];
  available: (c: WidgetCtx) => boolean;
}

export const WIDGETS: WidgetDef[] = [
  { kind: "stat", title: "Number tile", description: "One number that opens its list: online or offline devices, apps out of date, failed jobs, patch compliance…", group: "Numbers", fields: ["metric", "site"], available: (c) => allTiles(c.d).length > 0 },
  { kind: "shortcut", title: "Report or page shortcut", description: "A tile that opens a report or a page, such as the compliance report or the vulnerabilities list.", group: "Numbers", fields: ["dest"], available: (c) => destinationsFor(c).length > 0 },
  { kind: "compliance", title: "Patch compliance", description: "Compliance over time and now, with the devices in each state.", group: "Charts", fields: ["range", "site"], available: (c) => !!c.d.compliance },
  { kind: "agents", title: "Agent versions", description: "How many devices run each agent version.", group: "Charts", fields: ["count", "site"], available: (c) => !!c.d.devices },
  { kind: "apps", title: "Apps out of date", description: "The apps on the most devices that have a newer version.", group: "Lists", fields: ["count", "site"], available: (c) => !!c.d.software },
  { kind: "top-missing", title: "Top missing updates", description: "Windows updates missing on the most devices.", group: "Lists", fields: ["count", "site"], available: (c) => !!c.d.compliance },
  { kind: "attention", title: "Devices needing attention", description: "Offline, restart-pending or failing devices, worst first.", group: "Lists", fields: ["count", "site"], available: (c) => !!c.d.devices },
  { kind: "activity", title: "Recent activity", description: "The latest entries of the audit log, in plain words.", group: "Lists", fields: ["count"], available: (c) => (c.d.activity ?? []).length > 0 },
  { kind: "vulnerabilities", title: "Vulnerabilities", description: "Known vulnerabilities on your devices, exploited ones first. Needs the vulnerability lookup to be switched on.", group: "Lists", fields: ["count"], available: (c) => c.features.vulnerabilities && c.canOrg("reports:read") },
  { kind: "start", title: "Getting started", description: "The first steps on a new installation.", group: "Other", fields: [], available: (c) => startVisible(startSteps(c.d, c.canOrg), c.startDismissed) },
  { kind: "text", title: "Note", description: "Plain text: a reminder, a runbook link, who is on call.", group: "Other", fields: ["text"], available: () => true },
];

export const widgetDef = (kind: string): WidgetDef | undefined => WIDGETS.find((w) => w.kind === kind);

/** Kinds this person can use, given what the dashboard data and the organization's settings allow. */
export function availableKinds(c: WidgetCtx): WidgetKind[] {
  return WIDGETS.filter((w) => w.available(c)).map((w) => w.kind);
}

/** The stat metrics the person can show. */
export function availableMetrics(d: Dashboard): { value: string; label: string }[] {
  return allTiles(d).map((t) => ({ value: t.key, label: t.label }));
}

export interface Destination {
  id: string;
  label: string;
  hint: string;
  to: string;
  show: (c: Pick<WidgetCtx, "canOrg" | "can" | "features">) => boolean;
}

/** Where a shortcut tile can lead. Each is shown only to someone who may open it. */
export const DESTINATIONS: Destination[] = [
  { id: "report-compliance", label: "Patch compliance report", hint: "All devices and their compliance state", to: "/reports", show: (c) => c.canOrg("reports:read") && c.features.windowsUpdates },
  { id: "report-noncompliant", label: "Non-compliant devices", hint: "The compliance report, filtered to devices that are not compliant", to: "/reports?state=non_compliant", show: (c) => c.canOrg("reports:read") && c.features.windowsUpdates },
  { id: "missing-critical", label: "Critical updates missing", hint: "Critical Windows updates that devices are missing", to: "/updates?severity=Critical&missing=1", show: (c) => c.can("updates:read") && c.features.windowsUpdates },
  { id: "software-updates", label: "Software updates", hint: "Apps with a newer version", to: "/software-updates", show: (c) => c.canOrg("deployments:read") },
  { id: "vulnerabilities", label: "Vulnerabilities", hint: "Known vulnerabilities on your devices", to: "/vulnerabilities", show: (c) => c.canOrg("reports:read") && c.features.vulnerabilities },
  { id: "offline", label: "Offline devices", hint: "Devices that are not connected", to: "/devices?state=offline", show: (c) => c.can("devices:read") },
  { id: "devices", label: "All devices", hint: "The device list", to: "/devices", show: (c) => c.can("devices:read") },
  { id: "failed-jobs", label: "Failed jobs", hint: "Deployments with failures", to: "/deployments?failed=1", show: (c) => c.can("deployments:read") },
  { id: "audit", label: "Audit log", hint: "Who did what", to: "/audit", show: (c) => c.canOrg("audit:read") },
];

export function destinationsFor(c: Pick<WidgetCtx, "canOrg" | "can" | "features">): Destination[] {
  return DESTINATIONS.filter((x) => x.show(c));
}

export const RANGE_CHOICES = [
  { value: "7d", label: "Last 7 days" },
  { value: "14d", label: "Last 14 days" },
  { value: "30d", label: "Last 30 days" },
];
