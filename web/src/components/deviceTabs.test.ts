import { describe, expect, it } from "vitest";
import { availableDeviceTabs, DEVICE_TAB_ALIASES, DEVICE_TABS, resolveDeviceTab, type DeviceTabAccess } from "./deviceTabs";

const all: DeviceTabAccess = { hasUpdates: true, hasSoftwareUpdates: true, hasJobs: true, hasInspect: true, hasActivity: true };
const none: DeviceTabAccess = { hasUpdates: false, hasSoftwareUpdates: false, hasJobs: false, hasInspect: false, hasActivity: false };

describe("resolveDeviceTab", () => {
  it("keeps every valid tab the person may see", () => {
    for (const t of DEVICE_TABS) expect(resolveDeviceTab(t, all)).toBe(t);
  });

  it("maps the old tab values", () => {
    for (const k of ["windows-updates", "winupdates", "wu"]) expect(resolveDeviceTab(k, all)).toBe("updates");
    for (const k of ["missing", "missing-updates", "program-updates", "software_updates"]) expect(resolveDeviceTab(k, all)).toBe("software-updates");
    expect(resolveDeviceTab("users", all)).toBe("overview");
    expect(resolveDeviceTab("certificates", all)).toBe("hardware");
    expect(resolveDeviceTab("certs", all)).toBe("hardware");
    // every alias resolves to a real tab
    for (const t of Object.values(DEVICE_TAB_ALIASES)) expect(DEVICE_TABS).toContain(t);
  });

  it("leads the old and short names for the vulnerabilities tab there", () => {
    for (const k of ["cve", "cves", "security", "vulnerabilities"]) expect(resolveDeviceTab(k, none)).toBe("vulnerabilities");
  });

  it("leads the short names of the read-only views to their tab, for people who may use it", () => {
    for (const k of ["processes", "services", "events", "event-log"]) {
      expect(resolveDeviceTab(k, all)).toBe("inspect");
      expect(resolveDeviceTab(k, none)).toBe("overview");
    }
  });

  it("is forgiving about case and whitespace", () => {
    expect(resolveDeviceTab(" Hardware ", all)).toBe("hardware");
    expect(resolveDeviceTab("WU", all)).toBe("updates");
  });

  it("falls back to overview for missing or unknown values", () => {
    expect(resolveDeviceTab(null, all)).toBe("overview");
    expect(resolveDeviceTab(undefined, all)).toBe("overview");
    expect(resolveDeviceTab("", all)).toBe("overview");
    expect(resolveDeviceTab("nope", all)).toBe("overview");
    expect(resolveDeviceTab("__proto__", all)).toBe("overview");
    expect(resolveDeviceTab("constructor", all)).toBe("overview");
  });

  it("falls back to overview for tabs the person may not see, including through aliases", () => {
    expect(resolveDeviceTab("jobs", { ...all, hasJobs: false })).toBe("overview");
    expect(resolveDeviceTab("activity", { ...all, hasActivity: false })).toBe("overview");
    expect(resolveDeviceTab("updates", none)).toBe("overview");
    expect(resolveDeviceTab("software-updates", none)).toBe("overview");
    expect(resolveDeviceTab("software-updates", { ...all, hasSoftwareUpdates: false })).toBe("overview");
    expect(resolveDeviceTab("updates", { ...all, hasUpdates: false })).toBe("overview");
    expect(resolveDeviceTab("missing", none)).toBe("overview");
    expect(resolveDeviceTab("users", none)).toBe("overview");
    expect(resolveDeviceTab("certs", none)).toBe("hardware");
    expect(resolveDeviceTab("software", none)).toBe("software");
  });
});

describe("availableDeviceTabs", () => {
  it("keeps the display order", () => {
    expect(availableDeviceTabs(all)).toEqual(["overview", "hardware", "software", "vulnerabilities", "software-updates", "updates", "jobs", "inspect", "activity"]);
    expect(availableDeviceTabs(none)).toEqual(["overview", "hardware", "software", "vulnerabilities"]);
    expect(availableDeviceTabs({ hasUpdates: true, hasSoftwareUpdates: false, hasJobs: false, hasInspect: false, hasActivity: true })).toEqual(["overview", "hardware", "software", "vulnerabilities", "updates", "activity"]);
  });
});
