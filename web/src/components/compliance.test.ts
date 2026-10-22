import { describe, expect, it } from "vitest";
import { complianceSummary } from "./compliance";

describe("complianceSummary", () => {
  it("does not call a fleet with no devices 0% compliant", () => {
    expect(complianceSummary({})).toMatchObject({ value: "—", kind: "neutral", total: 0 });
    expect(complianceSummary(null).value).toBe("—");
  });
  it("does not call devices that have never scanned 0% compliant", () => {
    const s = complianceSummary({ unknown: 3 });
    expect(s).toMatchObject({ value: "—", kind: "neutral", scanned: 0, total: 3 });
    expect(s.hint).toBe("No scan reported yet by 3 devices");
    expect(complianceSummary({ unknown: 1 }).hint).toBe("No scan reported yet by 1 device");
  });
  it("gives a percentage of all devices once there is something to judge", () => {
    expect(complianceSummary({ compliant: 9, non_compliant: 1 })).toMatchObject({ value: "90%", kind: "success", hint: "9 of 10 devices" });
    expect(complianceSummary({ compliant: 7, non_compliant: 2, unknown: 1 })).toMatchObject({ value: "70%", kind: "warning", hint: "7 of 10 devices; 1 not scanned lately" });
    expect(complianceSummary({ compliant: 0, non_compliant: 4 })).toMatchObject({ value: "0%", kind: "danger" });
  });
});
