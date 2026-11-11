import { describe, expect, it } from "vitest";
import { minWidthOf, toolbarMode } from "./DataTable";

describe("toolbarMode", () => {
  const base = { simple: false, rows: 0, loading: false, error: false, inUse: false };
  it("hides Views, Columns, density and Export when the list is empty", () => {
    expect(toolbarMode(base)).toBe("bare");
    expect(toolbarMode({ ...base, simple: true })).toBe("bare");
  });
  it("keeps the full toolbar while loading, on error, with rows, and while a search or filter is in use", () => {
    expect(toolbarMode({ ...base, loading: true })).toBe("full");
    expect(toolbarMode({ ...base, error: true })).toBe("full");
    expect(toolbarMode({ ...base, rows: 3 })).toBe("full");
    expect(toolbarMode({ ...base, inUse: true })).toBe("full"); // an empty result of a search still needs its search box
  });
  it("stays lean for a short list inside a card", () => {
    expect(toolbarMode({ ...base, simple: true, rows: 3 })).toBe("lean");
    expect(toolbarMode({ ...base, simple: true, rows: 30 })).toBe("full");
  });
});

describe("minWidthOf", () => {
  it("keeps an explicit minimum", () => {
    expect(minWidthOf({ header: "Severity", width: 130, minWidth: 120 })).toBe(120);
  });
  it("is wide enough for the column's own header, so it is never cut", () => {
    expect(minWidthOf({ header: "Classification", width: 160, value: () => "" })).toBeGreaterThanOrEqual(150);
    expect(minWidthOf({ header: "Released", width: 120, value: () => "" })).toBeGreaterThanOrEqual(100);
  });
  it("never asks for more than the column's width, and never less than 70", () => {
    expect(minWidthOf({ header: "A very long column heading indeed", width: 90, value: () => "" })).toBe(90);
    expect(minWidthOf({ header: "", width: 40 })).toBe(70);
  });
});
