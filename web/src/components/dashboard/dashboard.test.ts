import { describe, expect, it } from "vitest";
import { WIDGET_IDS } from "./layout";
import { resolveLayout } from "./layout";
import { historySummary, humanAction, missingUpdateLink, niceMax, normaliseHistory } from "./format";
import { startSteps, startVisible } from "./start";
import { allTiles, rangeDays, tileList } from "./widgets";
import { clampRect, flow, overlaps, place, readingOrder, settle, type Placed } from "./grid";
import { addWidget, cleanSettings, copyName, defaultBoard, duplicateWidget, knownWidgets, moveResize, newBoardId, newWidgetId, removeWidget, toPlaced, WIDGET_SIZES } from "./boards";
import { availableKinds, availableMetrics, destinationsFor, WIDGETS, type WidgetCtx } from "./registry";

const ALL = ["a", "b", "c", "d"];
const everything = () => true;
/** A widget context for the registry tests: the person may do everything unless said otherwise. */
const ctx = (d: object, over: Partial<WidgetCtx> = {}): WidgetCtx => ({ d: d as never, canOrg: everything, can: everything, features: { windowsUpdates: true, vulnerabilities: true }, startDismissed: false, ...over });

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
    expect(availableKinds(ctx(base))).toContain("apps");
  });
  it("is quiet when every app is current, and absent when the caller may not see it", () => {
    const none = tileList({ software: { apps: 0, devices: 0, vendor: 0, automated: 0, all_apps_policy: false, top: [] } } as never).find((t) => t.key === "apps");
    expect(none).toMatchObject({ value: 0, hint: "every app is current" });
    expect(none?.kind).toBeUndefined();
    expect(tileList({} as never).some((t) => t.key === "apps")).toBe(false);
    expect(availableKinds(ctx({}))).not.toContain("apps");
  });
  it("is also a number tile on its own", () => {
    expect(availableMetrics(base as never).map((m) => m.value)).toContain("apps");
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
    expect(availableKinds(ctx(fresh, { startDismissed: false }))).toContain("start");
    expect(availableKinds(ctx(fresh, { startDismissed: true }))).not.toContain("start");
  });
});

describe("number tiles", () => {
  const d = {
    devices: { total: 10, online: 7, offline: 3, pending: 0 },
    compliance: { compliant: 8, non_compliant: 2, unknown: 0, history: [] },
    needs_restart: 1,
  };
  it("offers every metric the data allows, including the ones the old strip hid", () => {
    const keys = allTiles(d as never).map((t) => t.key);
    expect(keys).toEqual(expect.arrayContaining(["online", "offline", "total", "pending", "restart", "compliant"]));
    expect(keys).not.toContain("apps");
    expect(tileList(d as never).map((t) => t.key)).toEqual(["online", "offline", "restart"]);
    expect(allTiles(d as never).find((t) => t.key === "compliant")).toMatchObject({ value: "80%", to: "/reports" });
  });
  it("offers none without data", () => {
    expect(allTiles({} as never)).toEqual([]);
    expect(availableKinds(ctx({}))).toEqual(["shortcut", "vulnerabilities", "text"]);
  });
});

describe("widget library", () => {
  it("hides vulnerabilities while the lookup is off or without reports access", () => {
    expect(availableKinds(ctx({}))).toContain("vulnerabilities");
    expect(availableKinds(ctx({}, { features: { windowsUpdates: true, vulnerabilities: false } }))).not.toContain("vulnerabilities");
    expect(availableKinds(ctx({}, { canOrg: (p) => p !== "reports:read" }))).not.toContain("vulnerabilities");
  });
  it("offers a shortcut only to a destination the person may open", () => {
    expect(availableKinds(ctx({}, { can: () => false, canOrg: () => false }))).not.toContain("shortcut");
    expect(destinationsFor(ctx({}, { can: () => false, canOrg: (p) => p === "audit:read" })).map((x) => x.id)).toEqual(["audit"]);
    expect(destinationsFor(ctx({}, { features: { windowsUpdates: false, vulnerabilities: false } })).map((x) => x.id)).not.toContain("report-compliance");
  });
  it("keeps every kind valid for the preferences schema, with a size", () => {
    for (const w of WIDGETS) {
      expect(w.kind).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
      expect(WIDGET_SIZES[w.kind]).toBeDefined();
    }
  });
});

describe("range", () => {
  it("reads 7d, 24h and falls back to 30 days", () => {
    expect([rangeDays("7d"), rangeDays("14d"), rangeDays("48h"), rangeDays("x"), rangeDays(undefined)]).toEqual([7, 14, 2, 30, 30]);
  });
});

describe("grid", () => {
  const at = (id: string, x: number, y: number, w: number, h: number): Placed => ({ id, x, y, w, h });
  it("detects overlaps", () => {
    expect(overlaps(at("a", 0, 0, 4, 2), at("b", 3, 1, 4, 2))).toBe(true);
    expect(overlaps(at("a", 0, 0, 4, 2), at("b", 4, 0, 4, 2))).toBe(false);
    expect(overlaps(at("a", 0, 0, 4, 2), at("b", 0, 2, 4, 2))).toBe(false);
  });
  it("keeps a rectangle on the grid and above its minimum size", () => {
    expect(clampRect({ x: 10, y: -3, w: 6, h: 0 }, { w: 2, h: 2 })).toEqual({ x: 6, y: 0, w: 6, h: 2 });
    expect(clampRect({ x: 0, y: 0, w: 99, h: 1 })).toMatchObject({ w: 12 });
    expect(clampRect({ x: NaN, y: 0, w: 1, h: 1 }).x).toBe(0);
  });
  it("lets the others fall up into free space (no holes) and never overlap", () => {
    const out = settle([at("a", 0, 5, 6, 2), at("b", 6, 9, 6, 2), at("c", 0, 20, 12, 2)]);
    expect(out.map((p) => [p.id, p.x, p.y])).toEqual([["a", 0, 0], ["b", 6, 0], ["c", 0, 2]]);
  });
  it("pushes widgets down when one is dropped on them", () => {
    const items = [at("a", 0, 0, 6, 3), at("b", 6, 0, 6, 3), at("c", 0, 3, 12, 2)];
    const out = place(items, "c", { x: 0, y: 0, w: 12, h: 2 });
    expect(out.find((p) => p.id === "c")).toMatchObject({ x: 0, y: 0 });
    expect(out.find((p) => p.id === "a")).toMatchObject({ y: 2 });
    expect(out.find((p) => p.id === "b")).toMatchObject({ y: 2 });
    for (const p of out) for (const q of out) if (p !== q) expect(overlaps(p, q)).toBe(false);
  });
  it("resizes without leaving the grid or going below the minimum", () => {
    const out = place([at("a", 8, 0, 4, 2)], "a", { x: 8, y: 0, w: 9, h: 1 }, { w: 2, h: 2 });
    expect(out[0]).toMatchObject({ x: 3, w: 9, h: 2 });
  });
  it("packs a row left to right, wrapping when full, rows as tall as their tallest", () => {
    const out = flow([{ id: "a", w: 6, h: 3 }, { id: "b", w: 4, h: 5 }, { id: "c", w: 4, h: 2 }, { id: "d", w: 12, h: 1 }]);
    expect(out.map((p) => [p.id, p.x, p.y])).toEqual([["a", 0, 0], ["b", 6, 0], ["c", 0, 5], ["d", 0, 7]]);
  });
  it("orders widgets for a phone by reading order", () => {
    expect(readingOrder([at("b", 6, 0, 6, 1), at("c", 0, 3, 6, 1), at("a", 0, 0, 6, 1)]).map((p) => p.id)).toEqual(["a", "b", "c"]);
  });
  it("settles at random without ever overlapping", () => {
    let seed = 7;
    const rnd = (n: number) => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff), seed % n);
    for (let round = 0; round < 50; round++) {
      let items: Placed[] = [];
      for (let i = 0; i < 8; i++) {
        const r = clampRect({ x: rnd(12), y: rnd(10), w: 1 + rnd(8), h: 1 + rnd(5) });
        items.push({ id: `w${i}`, ...r });
      }
      items = place(items, "w0", clampRect({ x: rnd(12), y: rnd(10), w: 1 + rnd(8), h: 1 + rnd(5) }));
      for (const p of items) for (const q of items) if (p !== q) expect(overlaps(p, q)).toBe(false);
    }
  });
});

describe("boards", () => {
  const all = { kinds: ["stat", "start", "apps", "compliance", "top-missing", "attention", "activity", "agents"], metrics: ["online", "offline", "apps", "restart", "critical", "failed"] };
  it("builds the standard dashboard: stat tiles in a row, then the original widgets two to a row", () => {
    const b = defaultBoard(all);
    const stats = b.widgets.filter((w) => w.type === "stat");
    expect(stats.every((w) => w.w === 2 && w.y === stats[0]!.y)).toBe(true);
    expect(stats.map((w) => w.settings?.metric)).toEqual(["online", "offline", "apps", "restart", "critical", "failed"]);
    const apps = b.widgets.find((w) => w.type === "apps")!;
    const comp = b.widgets.find((w) => w.type === "compliance")!;
    // The reported gap under "Apps out of date" came from cards of different heights in one row: now both are the same height.
    expect(apps.h).toBe(comp.h);
    expect(apps.y).toBe(comp.y);
  });
  it("leaves out what the person cannot see and closes the row", () => {
    const b = defaultBoard({ kinds: ["stat", "apps"], metrics: ["online", "apps"] });
    expect(b.widgets.map((w) => [w.type, w.x])).toEqual([["stat", 0], ["stat", 2], ["apps", 4]]);
  });
  it("honours the hidden widgets and order of the old single layout", () => {
    const b = defaultBoard(all, { order: ["agents"], hidden: ["tiles", "activity"] });
    expect(b.widgets.some((w) => w.type === "stat")).toBe(false);
    expect(b.widgets.some((w) => w.type === "activity")).toBe(false);
    expect(b.widgets[0]!.type).toBe("agents");
  });
  it("adds a widget at the bottom, duplicates it, and settles after a removal", () => {
    const b0 = defaultBoard(all);
    const { board: b1, id } = addWidget(b0, "text", { text: "hi" });
    const added = b1.widgets.find((w) => w.id === id)!;
    expect(added.y).toBeGreaterThanOrEqual(Math.max(...b0.widgets.map((w) => w.y + w.h)));
    const { board: b2 } = duplicateWidget(b1, id);
    expect(b2.widgets).toHaveLength(b1.widgets.length + 1);
    expect(new Set(b2.widgets.map((w) => w.id)).size).toBe(b2.widgets.length);
    const b3 = removeWidget(b2, b0.widgets.find((w) => w.type === "apps")!.id);
    const after = toPlaced(b3.widgets);
    for (const p of after) for (const q of after) if (p !== q) expect(overlaps(p, q)).toBe(false);
  });
  it("never shrinks a widget below its minimum size", () => {
    const b = addWidget({ id: "x", name: "x", refresh: 60, widgets: [] }, "stat").board;
    const out = moveResize(b, b.widgets[0]!.id, { x: 0, y: 0, w: 1, h: 1 });
    expect(out.widgets[0]).toMatchObject({ w: 2, h: 2 });
  });
  it("produces ids and settings the server accepts", () => {
    expect(newBoardId()).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
    expect(newWidgetId()).toMatch(/^[a-z][a-z0-9-]{0,39}$/);
    expect(cleanSettings({ title: "  ", count: 0, site: "", text: " " })).toEqual({});
    expect(cleanSettings({ title: " A ", metric: "online" })).toEqual({ title: "A", metric: "online" });
  });
  it("skips kinds it does not know without deleting them from the board", () => {
    const widgets = [{ id: "a", type: "future-thing", x: 0, y: 0, w: 2, h: 2 }, { id: "b", type: "text", x: 2, y: 0, w: 2, h: 2 }];
    expect(knownWidgets(widgets, ["text"]).map((w) => w.id)).toEqual(["b"]);
  });
  it("names copies", () => {
    expect(copyName("Ops", ["Ops"])).toBe("Ops (copy)");
    expect(copyName("Ops (copy)", ["Ops", "Ops (copy)"])).toBe("Ops (copy 2)");
  });
});
