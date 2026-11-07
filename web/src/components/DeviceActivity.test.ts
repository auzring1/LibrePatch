import { describe, expect, it } from "vitest";
import { auditActionLabel, auditDetailsSummary } from "./DeviceActivity";

describe("device activity formatting", () => {
  it("names known and unknown audit actions", () => {
    expect(auditActionLabel("device.revoke")).toBe("Device revoked");
    expect(auditActionLabel("wu.something_new")).toBe("Wu something new");
    expect(auditActionLabel("")).toBe("—");
  });
  it("summarizes simple details only and shortens long ones", () => {
    expect(auditDetailsSummary({ reason: "GUI test", count: 2, nested: { a: 1 }, empty: "", none: null })).toBe("reason: GUI test · count: 2");
    expect(auditDetailsSummary(undefined)).toBe("");
    expect(auditDetailsSummary({ note: "x".repeat(300) }, 20)).toHaveLength(20);
  });
});
