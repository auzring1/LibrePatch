import { describe, expect, it } from "vitest";
import { toolbarMode } from "./DataTable";

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
