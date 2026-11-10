import { describe, expect, it } from "vitest";
import { bulkTargets } from "./deviceSelection";

describe("bulkTargets", () => {
  it("lets a selection of active devices be refreshed (select-all used to work for revoked devices only)", () => {
    const t = bulkTargets([
      { id: "a", status: "active" },
      { id: "b", status: "active" },
    ]);
    expect(t.active.map((d) => d.id)).toEqual(["a", "b"]);
    expect(t.revoked).toEqual([]);
  });

  it("deletes only revoked devices from a mixed selection and counts the rest", () => {
    const t = bulkTargets([
      { id: "a", status: "active" },
      { id: "r", status: "revoked" },
      { id: "p", status: "pending" },
    ]);
    expect(t.revoked.map((d) => d.id)).toEqual(["r"]);
    expect(t.active.map((d) => d.id)).toEqual(["a"]);
    expect(t.others).toBe(2);
  });
});
