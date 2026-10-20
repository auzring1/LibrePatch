/** The tabs of the device page, in display order. */
export const DEVICE_TABS = ["overview", "hardware", "software", "vulnerabilities", "software-updates", "updates", "jobs", "activity"] as const;
export type DeviceTab = (typeof DEVICE_TABS)[number];

/**
 * Old and alternative `?tab=` values and the tab that now holds their content.
 * "Missing updates" is now the "Software updates" tab and the Windows update names all lead to "Windows updates";
 * "Users" moved into Overview and "Client certificates" into Hardware.
 */
export const DEVICE_TAB_ALIASES: Readonly<Record<string, DeviceTab>> = {
  missing: "software-updates",
  "missing-updates": "software-updates",
  missing_updates: "software-updates",
  "program-updates": "software-updates",
  software_updates: "software-updates",
  softwareupdates: "software-updates",
  "windows-updates": "updates",
  windows_updates: "updates",
  windowsupdates: "updates",
  winupdates: "updates",
  wu: "updates",
  users: "overview",
  cve: "vulnerabilities",
  cves: "vulnerabilities",
  security: "vulnerabilities",
  certificates: "hardware",
  certs: "hardware",
  "client-certificates": "hardware",
};

/** Which optional tabs the person may see. Overview, Hardware, Software and Vulnerabilities are always available (they need only access to the device). */
export interface DeviceTabAccess {
  /** `updates:read`: the Windows updates tab. */
  hasUpdates: boolean;
  /** `deployments:read`: the Software updates tab (programs that have a newer version in the catalog). */
  hasSoftwareUpdates: boolean;
  /** `deployments:read` */
  hasJobs: boolean;
  /** `audit:read` on the organization */
  hasActivity: boolean;
}

export function availableDeviceTabs(access: DeviceTabAccess): DeviceTab[] {
  return DEVICE_TABS.filter((t) =>
    t === "updates" ? access.hasUpdates : t === "software-updates" ? access.hasSoftwareUpdates : t === "jobs" ? access.hasJobs : t === "activity" ? access.hasActivity : true,
  );
}

/**
 * Turns whatever is in `?tab=` into the tab to show: old names are mapped through the alias table,
 * and anything unknown or not permitted falls back to Overview.
 */
export function resolveDeviceTab(raw: string | null | undefined, access: DeviceTabAccess): DeviceTab {
  const key = (raw ?? "").trim().toLowerCase();
  const tab = (DEVICE_TABS as readonly string[]).includes(key)
    ? (key as DeviceTab)
    : Object.prototype.hasOwnProperty.call(DEVICE_TAB_ALIASES, key)
      ? DEVICE_TAB_ALIASES[key]
      : undefined;
  return tab && availableDeviceTabs(access).includes(tab) ? tab : "overview";
}
