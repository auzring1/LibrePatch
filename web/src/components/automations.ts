/** The tabs of the Automations page, in display order. */
export const AUTOMATION_TABS = ["software", "windows"] as const;
export type AutomationTab = (typeof AUTOMATION_TABS)[number];

/** Old and alternative `?tab=` values and the tab that holds their content. */
export const AUTOMATION_TAB_ALIASES: Readonly<Record<string, AutomationTab>> = {
  policies: "software",
  "software-policies": "software",
  software_policies: "software",
  apps: "software",
  programs: "software",
  "windows-updates": "windows",
  windows_updates: "windows",
  "update-policy": "windows",
  updates: "windows",
  wu: "windows",
};

/** Which tabs the person may see. Windows needs the organization to manage Windows updates and `updates:read`; Software needs `policies:read`. */
export interface AutomationAccess {
  software: boolean;
  windows: boolean;
}

export const availableAutomationTabs = (a: AutomationAccess): AutomationTab[] => AUTOMATION_TABS.filter((t) => a[t]);

/**
 * The tab to show for a `?tab=` value. An unknown or missing value, and a tab the person cannot see (Windows updates switched
 * off, or no permission), lead to the first tab they can see; Software comes first because most of the work is there.
 */
export function resolveAutomationTab(raw: string | null, a: AutomationAccess): AutomationTab {
  const avail = availableAutomationTabs(a);
  const key = (raw ?? "").toLowerCase();
  const want = (AUTOMATION_TABS as readonly string[]).includes(key) ? (key as AutomationTab) : AUTOMATION_TAB_ALIASES[key];
  if (want && avail.includes(want)) return want;
  return avail[0] ?? "software";
}
