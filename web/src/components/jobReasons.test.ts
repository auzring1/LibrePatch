import { describe, expect, it } from "vitest";
import { jobCanBeCancelled, jobReason } from "./jobReasons";

describe("jobReason", () => {
  it("explains the reasons a job waits or ends", () => {
    expect(jobReason("waiting_other_job")).toBe("Waiting for another job on this PC to finish");
    expect(jobReason("cancelled_by_administrator")).toBe("Cancelled by an administrator");
    expect(jobReason("something_new")).toBe("something_new");
    expect(jobReason(null)).toBe("");
  });
  it("lets an unfinished job be cancelled and nothing else", () => {
    for (const s of ["queued", "sent", "accepted", "waiting", "running"]) expect(jobCanBeCancelled(s)).toBe(true);
    for (const s of ["succeeded", "failed", "expired", "cancelled", "rejected"]) expect(jobCanBeCancelled(s)).toBe(false);
  });
});
