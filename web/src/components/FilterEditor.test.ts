import { describe, expect, it } from "vitest";
import { hasBlankSoftware, newGroup, newSoftwareCondition } from "./FilterEditor";

describe("hasBlankSoftware", () => {
  it("is true for the blank group a new dynamic group starts with", () => {
    expect(hasBlankSoftware(newGroup())).toBe(true);
  });
  it("is true for a blank condition inside a nested group", () => {
    expect(hasBlankSoftware({ op: "and", children: [{ op: "software", title: "chrome", match: "contains" }, newGroup("or")] })).toBe(true);
  });
  it("is false once every software condition has a product name", () => {
    expect(hasBlankSoftware({ op: "and", children: [{ ...newSoftwareCondition(), title: " chrome " }] })).toBe(false);
  });
  it("ignores groups with only device conditions", () => {
    expect(hasBlankSoftware({ op: "and", children: [{ op: "device", field: "online", cmp: "eq", value: true }] })).toBe(false);
  });
});
