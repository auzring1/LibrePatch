import { describe, expect, it } from "vitest";
import { ALL_NAV_ITEMS, flatNav, locate, trail, visibleNav } from "./nav";

const everything = { can: () => true, canOrg: () => true };
const nothing = { can: () => false, canOrg: () => false };
const only = (...perms: string[]) => ({ can: (p: string) => perms.includes(p), canOrg: (p: string) => perms.includes(p) });

describe("navigation tree", () => {
  it("has unique ids and paths", () => {
    const ids = flatNav().map((x) => x.item.id);
    expect(new Set(ids).size).toBe(ids.length);
    const paths = ALL_NAV_ITEMS.filter((i) => !i.children).map((i) => i.to); // a parent shares its first child's path
    expect(new Set(paths).size).toBe(paths.length);
  });

  it("keeps every id in the form the server accepts for saved layouts", () => {
    for (const { item, group } of flatNav()) {
      expect(item.id).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
      expect(group.id).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
    }
  });

  it("shows only the dashboard to someone with no permissions", () => {
    const v = visibleNav(nothing);
    expect(v.flatMap((g) => g.items.map((i) => i.id))).toEqual(["dashboard"]);
  });

  it("filters by permission and drops empty groups", () => {
    const v = visibleNav(only("devices:read", "updates:read"));
    const ids = v.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toEqual(["dashboard", "devices", "windows-updates", "automations", "held-updates", "inventory"]);
    expect(v.map((g) => g.id)).not.toContain("administration");
  });

  it("lists Software updates in the Updates group, above Windows updates", () => {
    const updates = visibleNav(everything).find((g) => g.id === "updates")!;
    const ids = updates.items.map((i) => i.id);
    expect(ids.slice(0, 2)).toEqual(["software-updates", "windows-updates"]);
    expect(visibleNav(only("updates:read")).flatMap((g) => g.items.map((i) => i.id))).not.toContain("software-updates");
    expect(locate("/software-updates")?.item.id).toBe("software-updates");
  });

  it("keeps Automations for anyone who can read policies or updates, and moved Software policies into it", () => {
    const ids = (a: Parameters<typeof visibleNav>[0]) => visibleNav(a).flatMap((g) => g.items.map((i) => i.id));
    expect(ids(only("policies:read"))).toContain("automations");
    expect(ids(only("updates:read"))).toContain("automations");
    expect(ids(only("devices:read"))).not.toContain("automations");
    expect(ids(everything)).not.toContain("software-policies");
    expect(locate("/automations")?.item.id).toBe("automations");
  });

  it("hides the Windows pages, and only those, when Windows updates are switched off", () => {
    const off = { ...everything, features: { windowsUpdates: false } };
    const ids = visibleNav(off).flatMap((g) => g.items.map((i) => i.id));
    expect(ids).not.toContain("windows-updates");
    expect(ids).not.toContain("held-updates");
    expect(ids).toEqual(expect.arrayContaining(["software-updates", "automations", "agent-updates", "deployments", "vulnerabilities"]));
    const on = { ...everything, features: { windowsUpdates: true } };
    expect(visibleNav(on).flatMap((g) => g.items.map((i) => i.id))).toEqual(expect.arrayContaining(["windows-updates", "held-updates"]));
  });

  it("keeps the Settings sections for the Settings page and the command palette (the sidebar shows one Settings link)", () => {
    const settings = visibleNav(only("catalog:read")).flatMap((g) => g.items).find((i) => i.id === "settings");
    expect(settings?.children?.map((c) => c.id)).toEqual(["settings-general"]);
    const admin = visibleNav(everything).flatMap((g) => g.items).find((i) => i.id === "settings");
    expect(admin?.children?.length).toBeGreaterThan(5);
  });
});

describe("locate and trail", () => {
  it("matches the most specific entry", () => {
    expect(locate("/")?.item.id).toBe("dashboard");
    expect(locate("/devices")?.item.id).toBe("devices");
    expect(locate("/devices/3b1c")?.item.id).toBe("devices");
    expect(locate("/updates")?.item.id).toBe("windows-updates");
    expect(locate("/updates/held")?.item.id).toBe("held-updates");
    expect(locate("/settings")?.item.id).toBe("settings-general");
    expect(locate("/settings/branding")?.item.id).toBe("settings-branding");
    expect(locate("/deployments/new")?.item.id).toBe("deployments");
    expect(locate("/nowhere")).toBeUndefined();
  });

  it("builds breadcrumbs from group, parent and page", () => {
    expect(trail("/devices").map((c) => c.label)).toEqual(["Endpoints", "Devices"]);
    expect(trail("/updates/held").map((c) => c.label)).toEqual(["Updates", "Held updates"]);
    expect(trail("/settings/branding").map((c) => c.label)).toEqual(["Administration", "Settings", "Branding"]);
    expect(trail("/").map((c) => c.label)).toEqual(["Dashboard"]);
    expect(trail("/account")).toEqual([]);
  });
});
