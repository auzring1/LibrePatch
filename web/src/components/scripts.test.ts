import { describe, expect, it } from "vitest";
import { jobOutcome, refusedHint, runIsOpen, runStatus, shortSha } from "./scripts";

describe("runStatus", () => {
  it("names every state in plain words and tolerates an unknown one", () => {
    expect(runStatus("pending_approval").label).toBe("Waiting for approval");
    expect(runStatus("expired").label).toBe("Not approved in time");
    expect(runStatus("nonsense").label).toBe("nonsense");
  });
});

describe("jobOutcome", () => {
  it("separates a script that failed from one that was too slow or refused", () => {
    expect(jobOutcome("succeeded", "", 0).label).toBe("Finished");
    expect(jobOutcome("failed", "script_failed", 7).label).toBe("Failed (exit code 7)");
    expect(jobOutcome("failed", "script_timeout", -1).label).toBe("Stopped: too slow");
    expect(jobOutcome("rejected", "x", null).label).toBe("Refused by the computer");
    expect(jobOutcome("queued", "", null).kind).toBe("neutral");
  });
});

describe("runIsOpen", () => {
  it("is open while waiting for a decision or while a device still has work", () => {
    expect(runIsOpen("pending_approval", [])).toBe(true);
    expect(runIsOpen("running", [{ status: "succeeded" }, { status: "running" }])).toBe(true);
    expect(runIsOpen("running", [{ status: "succeeded" }, { status: "failed" }])).toBe(false);
    expect(runIsOpen("cancelled", [{ status: "running" }])).toBe(false);
  });
});

describe("helpers", () => {
  it("shortens a fingerprint and explains the opt-in refusal", () => {
    expect(shortSha("0123456789abcdef0123")).toBe("0123456789ab");
    expect(refusedHint("scripts are not switched on on this computer")).toMatch(/Update the agent/);
    expect(refusedHint("scripts are switched off on this computer (the agent was installed with --no-scripts)")).toMatch(/--no-scripts/);
    expect(refusedHint("other")).toBe("");
  });
});
