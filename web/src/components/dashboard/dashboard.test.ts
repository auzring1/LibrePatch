import { describe, expect, it } from "vitest";
import { WIDGET_IDS } from "./layout";
import { moveWidget, resolveLayout, setWidgetHidden } from "./layout";
import { historySummary, humanAction, missingUpdateLink, niceMax, normaliseHistory } from "./format";
import { startSteps, startVisible } from "./start";
import { availableWidgets, tileList } from "./widgets";

const ALL = ["a", "b", "c", "d"];

describe("resolveLayout", () => {
  it("uses the default order without preferences", () => {
    expect(resolveLayout(ALL)).toEqual({ order: ALL, visible: ALL, hidden: [] });
    expect(resolveLayout(ALL, {})).toEqual({ order: ALL, visible: ALL, hidden: [] });
    expect(resolveLayout(ALL, null).visible).toEqual(ALL);
  });
  it("applies the saved order and appends new widgets at the end", () => {
    const r = resolveLayout(ALL, { order: ["c", "a"] });
    expect(r.order).toEqual(["c", "a", "b", "d"]);
    expect(r.visible).toEqual(["c", "a", "b", "d"]);
  });
  it("drops unknown ids and duplicates", () => {
    const r = resolveLayout(ALL, { order: ["x", "b", "b", "a", "y"], hidden: ["zzz", "a", "a"] });
    expect(r.order).toEqual(["b", "a", "c", "d"]);
    expect(r.hidden).toEqual(["a"]);
    expect(r.visible).toEqual(["b", "c", "d"]);
  });
  it("can hide everything", () => {
    const r = resolveLayout(ALL, { hidden: ALL });
    expect(r.visible).toEqual([]);
    expect(r.hidden).toEqual(ALL);
  });
  it("keeps real widget ids valid for the preferences schema", () => {
    for (const id of WIDGET_IDS) expect(id).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
  });
});

describe("moveWidget", () => {
  it("swaps with the neighbour", () => {
    expect(moveWidget(ALL, "b", -1, ALL)).toEqual(["b", "a", "c", "d"]);
    expect(moveWidget(ALL, "b", 1, ALL)).toEqual(["a", "c", "b", "d"]);
  });
  it("does nothing at the ends", () => {
    expect(moveWidget(ALL, "a", -1, ALL)).toEqual(ALL);
    expect(moveWidget(ALL, "d", 1, ALL)).toEqual(ALL);
  });
  it("skips widgets the person cannot see", () => {
    // c is not available: b moving down swaps with d, c stays put
    expect(moveWidget(ALL, "b", 1, ["a", "b", "d"])).toEqual(["a", "d", "c", "b"]);
  });
});

describe("setWidgetHidden", () => {
  it("adds and removes in display order", () => {
    expect(setWidgetHidden(ALL, ["c"], "a", true)).toEqual(["a", "c"]);
    expect(setWidgetHidden(ALL, ["a", "c"], "a", false)).toEqual(["c"]);
  });
});

describe("format helpers", () => {
  it("links a missing update by KB, else title", () => {
    expect(missingUpdateLink({ kb: ["KB5034441"], title: "x" })).toBe("/updates?q=KB5034441&missing=1");
    expect(missingUpdateLink({ kb: [], title: "Defender definitions" })).toBe("/updates?q=Defender+definitions&missing=1");
    expect(missingUpdateLink({})).toBe("/updates?missing=1");
  });
  it("humanises actions", () => {
    expect(humanAction("device.restart_requested")).toBe("Device restart requested");
    expect(humanAction("")).toBe("Unknown action");
  });
  it("normalises and summarises history", () => {
    const days = normaliseHistory([{ date: "2026-10-02", compliant: 3 }, { date: "2026-10-01", compliant: 1, non_compliant: 2, unknown: 1 }, {}]);
    expect(days.map((d) => d.date)).toEqual(["2026-10-01", "2026-10-02"]);
    expect(days[0]!.total).toBe(4);
    expect(historySummary([])).toMatch(/No compliance history/);
    expect(historySummary(days.slice(0, 1))).toMatch(/2026-10-01/);
    expect(historySummary(days)).toMatch(/2 days/);
  });
  it("picks a nice axis maximum", () => {
    expect([0, 1, 3, 7, 12, 99, 101].map(niceMax)).toEqual([1, 1, 5, 10, 20, 100, 200]);
  });
});

describe("apps out of date", () => {
  const base = { software: { apps: 3, devices: 5, vendor: 1, automated: 1, all_apps_policy: false, top: [] } };
  it("adds a tile and a widget when the server sends the numbers", () => {
    const tiles = tileList(base as never);
    expect(tiles.map((t) => t.key)).toContain("apps");
    expect(tiles.find((t) => t.key === "apps")).toMatchObject({ value: 3, to: "/software-updates", hint: "on 5 devices", kind: "warning" });
    expect(availableWidgets(base as never)).toContain("apps");
  });
  it("is quiet when every app is current, and absent when the caller may not see it", () => {
    const none = tileList({ software: { apps: 0, devices: 0, vendor: 0, automated: 0, all_apps_policy: false, top: [] } } as never).find((t) => t.key === "apps");
    expect(none).toMatchObject({ value: 0, hint: "every app is current" });
    expect(none?.kind).toBeUndefined();
    expect(tileList({} as never).some((t) => t.key === "apps")).toBe(false);
    expect(availableWidgets({} as never)).not.toContain("apps");
  });
  it("sits right after the key numbers by default", () => {
    expect(WIDGET_IDS.indexOf("apps")).toBe(WIDGET_IDS.indexOf("tiles") + 1);
    expect(WIDGET_IDS[0]).toBe("start");
  });
});

describe("getting started", () => {
  const all = () => true;
  const fresh = { devices: { total: 0, pending: 0, online: 0, offline: 0 }, setup: { policies: 0, deployments: 0 } };
  it("lists the steps a person can take and which are done", () => {
    const steps = startSteps(fresh as never, all);
    expect(steps.map((s) => s.id)).toEqual(["device", "policy", "deploy"]);
    expect(steps.every((s) => !s.done)).toBe(true);
    const later = startSteps({ ...fresh, devices: { ...fresh.devices, total: 3 }, setup: { policies: 1, deployments: 0 } } as never, all);
    expect(later.map((s) => s.done)).toEqual([true, true, false]);
  });
  it("counts a device waiting for approval as the first step done", () => {
    expect(startSteps({ ...fresh, devices: { ...fresh.devices, pending: 1 } } as never, all)[0]!.done).toBe(true);
  });
  it("offers only what the person may do and the numbers can tell", () => {
    expect(startSteps(fresh as never, (p) => p === "policies:write").map((s) => s.id)).toEqual(["policy"]);
    expect(startSteps({ devices: fresh.devices } as never, all).map((s) => s.id)).toEqual(["device"]);
    expect(startSteps({} as never, all)).toEqual([]);
  });
  it("is shown until every step is done or it is put away", () => {
    const steps = startSteps(fresh as never, all);
    expect(startVisible(steps, false)).toBe(true);
    expect(startVisible(steps, true)).toBe(false);
    expect(startVisible(steps.map((s) => ({ ...s, done: true })), false)).toBe(false);
    expect(startVisible([], false)).toBe(false);
  });
  it("is an available dashboard widget only while it is visible", () => {
    expect(availableWidgets(fresh as never, { canOrg: all, dismissed: false })).toContain("start");
    expect(availableWidgets(fresh as never, { canOrg: all, dismissed: true })).not.toContain("start");
    expect(availableWidgets(fresh as never)).not.toContain("start");
  });
});
