import { describe, expect, it } from "vitest";
import { updatesEmpty } from "./softwareUpdatesEmpty";

describe("updatesEmpty", () => {
  it("does not claim 'up to date' when the catalog is empty and winget is off", () => {
    const r = updatesEmpty({ index: { enabled: false, package_count: 0 }, catalogCount: 0 });
    expect(r.kind).toBe("unchecked");
    expect(r.title).not.toMatch(/up to date/i);
  });
  it("says the index is not downloaded yet instead of 'up to date'", () => {
    expect(updatesEmpty({ index: { enabled: true, package_count: 0 }, catalogCount: 0 }).kind).toBe("waiting");
  });
  it("limits the claim to the catalog when winget is off but the catalog has packages", () => {
    const r = updatesEmpty({ index: { enabled: false, package_count: 0 }, catalogCount: 3 });
    expect(r.kind).toBe("current");
    expect(r.title).toContain("catalog");
  });
  it("is plainly up to date when something was compared", () => {
    expect(updatesEmpty({ index: { enabled: true, package_count: 15000 }, catalogCount: 0 }).title).toBe("Everything is up to date");
    expect(updatesEmpty({ index: { enabled: true, package_count: 0 }, catalogCount: 2 }).title).toBe("Everything is up to date");
  });
  it("falls back to the plain message while loading or without catalog access", () => {
    expect(updatesEmpty({}).title).toBe("Everything is up to date");
    expect(updatesEmpty({ index: { enabled: false, package_count: 0 } }).title).toBe("Everything is up to date");
  });
});
