import { describe, expect, it } from "vitest";
import type { SoftwareRollout } from "../api/client";
import { summarizeRollout } from "./rollout";

const base = (over: Partial<SoftwareRollout>): SoftwareRollout => ({
  version: "2.0",
  imported_at: "2026-10-01T00:00:00Z",
  approval: "not_required",
  waiting: 3,
  stages: [],
  ...over,
});
const stage = (name: string, state: string) => ({ name, ring: true, devices: 2, waiting: 1, installed: 0, failed: 0, state: state as never });

describe("summarizeRollout", () => {
  it("shows nothing for a policy without rings or approval", () => {
    expect(summarizeRollout(null)).toBeNull();
    expect(summarizeRollout(undefined)).toBeNull();
  });
  it("says a version is waiting for approval, with how many devices wait", () => {
    expect(summarizeRollout(base({ approval: "pending", blocked: "pending_approval" }))).toEqual({ kind: "warning", text: "2.0 is waiting for approval (3 devices)" });
    expect(summarizeRollout(base({ approval: "pending", blocked: "pending_approval", waiting: 1 }))?.text).toContain("(1 device)");
  });
  it("does not ask for approval of a version nobody needs", () => {
    expect(summarizeRollout(base({ approval: "pending", blocked: "pending_approval", waiting: 0 }))).toEqual({ kind: "success", text: "2.0 is installed wherever it is needed" });
  });
  it("says a declined version stays put", () => {
    expect(summarizeRollout(base({ approval: "declined", blocked: "declined" }))?.text).toBe("2.0 was declined");
  });
  it("names the ring that is rolling out and how many stages are left", () => {
    const r = base({ stages: [stage("Pilot", "running"), stage("Broad", "waiting"), stage("Devices in no ring", "waiting")] });
    expect(summarizeRollout(r)).toEqual({ kind: "info", text: "2.0: Pilot is rolling out, 2 more stages to go" });
  });
  it("shows a hold as a problem", () => {
    const r = base({ stages: [stage("Pilot", "held"), stage("Broad", "waiting")] });
    expect(summarizeRollout(r)).toEqual({ kind: "danger", text: "2.0 is held after ring Pilot" });
  });
  it("says when everything is rolled out", () => {
    const r = base({ waiting: 0, stages: [stage("Pilot", "done"), stage("Broad", "done")] });
    expect(summarizeRollout(r)).toEqual({ kind: "success", text: "2.0 is rolled out" });
  });
  it("explains why nothing goes out when the package is excluded", () => {
    expect(summarizeRollout(base({ blocked: "excluded" }))?.text).toContain("excluded");
  });
});
