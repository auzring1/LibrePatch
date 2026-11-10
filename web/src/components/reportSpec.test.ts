import { describe, expect, it } from "vitest";
import type { ReportColumn, ReportDataset, ReportSpec } from "../api/client";
import { filterReady, groupedColumns, newFilter, opLabel, opNeedsValue, scopeText, sendable, specKey, startSpec, switchDataset } from "./reportSpec";

const col = (id: string, kind: ReportColumn["kind"], ops: string[], extra: Partial<ReportColumn> = {}): ReportColumn => ({ id, label: id, kind, group: "G", ops, ...extra });
const text = col("hostname", "text", ["contains", "eq", "is_empty"]);
const num = col("ram_gb", "number", ["gt", "lt", "is_empty"]);
const when = col("last_seen", "time", ["within_days", "after", "is_empty"]);
const flag = col("online", "bool", ["is"]);
const ds: ReportDataset = { id: "devices", label: "Devices", description: "", default_columns: ["hostname", "ram_gb"], columns: [text, num, when, flag, col("state", "text", ["eq"], { group: "H", choices: ["A", "B"] })] };
const ds2: ReportDataset = { id: "disks", label: "Disks", description: "", default_columns: ["hostname", "drive"], columns: [text, col("drive", "text", ["eq"])] };

describe("report filters", () => {
  it("words the comparisons by kind", () => {
    expect(opLabel("number", "gt")).toBe("is more than");
    expect(opLabel("text", "gt")).toBe("gt");
    expect(opNeedsValue("is_empty")).toBe(false);
    expect(opNeedsValue("contains")).toBe(true);
  });
  it("starts a filter with the first comparison and a usable value", () => {
    expect(newFilter(num)).toEqual({ column: "ram_gb", op: "gt", value: "" });
    expect(newFilter(flag)).toEqual({ column: "online", op: "is", value: "true" });
    expect(newFilter(ds.columns[4]!)).toEqual({ column: "state", op: "eq", value: "A" });
  });
  it("knows when a row is finished", () => {
    expect(filterReady(text, { column: "hostname", op: "contains", value: "  " })).toBe(false);
    expect(filterReady(text, { column: "hostname", op: "contains", value: "pc" })).toBe(true);
    expect(filterReady(text, { column: "hostname", op: "is_empty" })).toBe(true);
    expect(filterReady(text, { column: "hostname", op: "gt", value: "1" })).toBe(false);
    expect(filterReady(num, { column: "ram_gb", op: "gt", value: "abc" })).toBe(false);
    expect(filterReady(num, { column: "ram_gb", op: "gt", value: "8.5" })).toBe(true);
    expect(filterReady(when, { column: "last_seen", op: "within_days", value: "30" })).toBe(true);
    expect(filterReady(when, { column: "last_seen", op: "after", value: "30" })).toBe(false);
    expect(filterReady(when, { column: "last_seen", op: "after", value: "2026-01-31" })).toBe(true);
    expect(filterReady(undefined, { column: "x", op: "eq", value: "1" })).toBe(false);
  });
});

describe("building the request", () => {
  it("drops unfinished filters, unknown and repeated columns, and a sort on a hidden column", () => {
    const spec: ReportSpec = {
      dataset: "devices",
      columns: ["hostname", "hostname", "gone", "ram_gb"],
      filters: [
        { column: "hostname", op: "contains", value: " pc " },
        { column: "ram_gb", op: "gt", value: "" },
        { column: "last_seen", op: "is_empty", value: "stale" },
      ],
      sort: { column: "last_seen" },
      site_ids: ["s1"],
    };
    expect(sendable(spec, ds)).toEqual({
      dataset: "devices",
      columns: ["hostname", "ram_gb"],
      filters: [{ column: "hostname", op: "contains", value: "pc" }, { column: "last_seen", op: "is_empty" }],
      site_ids: ["s1"],
    });
    expect(sendable({ ...spec, sort: { column: "ram_gb", desc: true } }, ds).sort).toEqual({ column: "ram_gb", desc: true });
  });
  it("starts from a dataset's defaults and keeps columns that still fit when the data changes", () => {
    expect(startSpec(ds)).toEqual({ dataset: "devices", columns: ["hostname", "ram_gb"], filters: [] });
    const sw = switchDataset({ dataset: "devices", columns: ["ram_gb", "hostname"], filters: [{ column: "ram_gb", op: "gt", value: "1" }], group_id: "g" }, ds2);
    expect(sw).toEqual({ dataset: "disks", columns: ["hostname"], filters: [], site_ids: undefined, group_id: "g" });
    expect(switchDataset({ dataset: "devices", columns: ["ram_gb"], filters: [] }, ds2).columns).toEqual(["hostname", "drive"]);
  });
  it("tells a change from no change", () => {
    const a: ReportSpec = { dataset: "devices", columns: ["hostname"], filters: [] };
    expect(specKey(a)).toBe(specKey({ ...a }));
    expect(specKey(a)).not.toBe(specKey({ ...a, columns: ["hostname", "ram_gb"] }));
  });
});

describe("report text", () => {
  it("says what the scope is", () => {
    const names = new Map([["s1", "North"]]);
    expect(scopeText({ dataset: "devices", columns: ["a"] }, names)).toBe("all devices");
    expect(scopeText({ dataset: "devices", columns: ["a"], site_ids: ["s1"], group_id: "g" }, names, "Laptops")).toBe("sites: North; group: Laptops");
  });
  it("groups the picker in the dataset's order", () => {
    expect(groupedColumns(ds).map((g) => [g.group, g.columns.length])).toEqual([["G", 4], ["H", 1]]);
  });
});
