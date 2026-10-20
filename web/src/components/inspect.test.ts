import { describe, expect, it } from "vitest";
import { eventLevel, isFinalStatus, kb, waitingText } from "./inspect";

describe("kb", () => {
  it("scales to MB and GB", () => {
    expect(kb(512)).toBe("512 KB");
    expect(kb(2048)).toBe("2.0 MB");
    expect(kb(20 * 1024)).toBe("20 MB");
    expect(kb(3 * 1024 * 1024)).toBe("3.0 GB");
  });
});

describe("eventLevel", () => {
  it("names the levels and shows an unknown one as a number", () => {
    expect(eventLevel(2)).toBe("Error");
    expect(eventLevel(3)).toBe("Warning");
    expect(eventLevel(0)).toBe("0");
  });
});

describe("waitingText", () => {
  it("says what is going on, and why it failed", () => {
    expect(waitingText("queued", "")).toMatch(/Waiting for the device/);
    expect(waitingText("running", "")).toMatch(/reading/);
    expect(waitingText("failed", "failed")).toContain("(failed)");
    expect(waitingText("rejected", "")).toMatch(/local policy/);
    expect(waitingText("expired", "")).toMatch(/did not answer/);
  });
  it("knows when to stop waiting", () => {
    for (const s of ["succeeded", "failed", "expired", "rejected", "cancelled"]) expect(isFinalStatus(s)).toBe(true);
    for (const s of ["queued", "sent", "accepted", "running", "waiting"]) expect(isFinalStatus(s)).toBe(false);
  });
});
