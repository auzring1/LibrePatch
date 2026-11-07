import { describe, expect, it } from "vitest";
import { restartSummary } from "./restartInfo";

describe("restartSummary", () => {
  it("says no restart is needed and nothing else when the device reports nothing", () => {
    expect(restartSummary(false)).toEqual({ pending: false, headline: "No restart needed", reasons: [] });
  });

  it("names the reasons Windows gives", () => {
    const s = restartSummary(true, ["windows_update", "computer_rename"]);
    expect(s.pending).toBe(true);
    expect(s.reasons).toEqual(["Windows Update needs a restart to finish", "The computer was renamed and needs a restart"]);
    expect(s.note).toBeUndefined();
  });

  it("keeps an unknown reason readable instead of hiding it", () => {
    expect(restartSummary(true, ["something_new"]).reasons).toEqual(["something_new"]);
  });

  it("explains that queued deletions are not a restart request", () => {
    const s = restartSummary(false, [], 5);
    expect(s.pending).toBe(false);
    expect(s.headline).toBe("No restart needed");
    expect(s.note).toContain("5 files are queued for deletion");
    expect(s.note).toContain("do not mean Windows needs a restart");
  });

  it("uses the singular for one file", () => {
    expect(restartSummary(false, [], 1).note).toContain("1 file is queued");
  });

  it("says why a device is pending only because of queued deletions", () => {
    const s = restartSummary(true, [], 3);
    expect(s.pending).toBe(true);
    expect(s.reasons).toEqual(["3 files are queued for deletion at the next restart"]);
    expect(s.note).toContain("Device defaults");
  });

  it("still lists real reasons when deletions are queued too", () => {
    const s = restartSummary(true, ["windows_update"], 4);
    expect(s.reasons).toEqual(["Windows Update needs a restart to finish"]);
    expect(s.note).toBeUndefined();
  });
});
