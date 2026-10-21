import { describe, expect, it } from "vitest";
import { SILENT, describePrompts, fromPrompts, needsPrograms, parsePrograms, toPrompts } from "./prompts";

describe("toPrompts", () => {
  it("sends nothing when everything is at its default, so the deployment stays silent", () => {
    expect(toPrompts(SILENT)).toBeNull();
    expect(toPrompts({ ...SILENT, askTimeoutS: 120, deferMinutes: 30, restartMinutes: 9 })).toBeNull();
  });
  it("sends only the numbers that belong to the choice", () => {
    expect(toPrompts({ ...SILENT, inUse: "skip", deferMinutes: 30 })).toEqual({ in_use: "skip", restart: "none", defer_minutes: 30 });
    expect(toPrompts({ ...SILENT, inUse: "ask", askTimeoutS: 120, deferMinutes: 45 })).toEqual({ in_use: "ask", restart: "none", ask_timeout_s: 120, defer_minutes: 45 });
    expect(toPrompts({ ...SILENT, inUse: "close", askTimeoutS: "180" })).toEqual({ in_use: "close", restart: "none", ask_timeout_s: 180 });
    expect(toPrompts({ ...SILENT, restart: "countdown", restartMinutes: 10 })).toEqual({ in_use: "ignore", restart: "countdown", restart_notify_minutes: 10 });
  });
});

describe("fromPrompts", () => {
  it("round-trips a stored choice and treats null as silent", () => {
    expect(fromPrompts(null)).toEqual(SILENT);
    const p = { in_use: "ask", ask_timeout_s: 90, defer_minutes: 20, restart: "ask", restart_notify_minutes: 3 } as const;
    expect(toPrompts(fromPrompts(p))).toEqual(p);
  });
});

describe("describePrompts", () => {
  it("says nothing for a silent deployment and a plain sentence otherwise", () => {
    expect(describePrompts(null)).toBe("");
    expect(describePrompts({ in_use: "ignore", restart: "none" })).toBe("");
    expect(describePrompts({ in_use: "ask", restart: "countdown", ask_timeout_s: 120, restart_notify_minutes: 10 })).toBe(
      "asks the user to close the program (question stays up 2 min); restarts after a 10 min countdown when the installer needs it",
    );
  });
});

describe("programs", () => {
  it("are parsed from commas, spaces and lines", () => {
    expect(parsePrograms("chrome.exe, GoogleCrashHandler.exe\nfoo.exe")).toEqual(["chrome.exe", "GoogleCrashHandler.exe", "foo.exe"]);
    expect(parsePrograms("  ")).toEqual([]);
  });
  it("are only needed when the program is waited for, asked about or closed", () => {
    expect(needsPrograms(SILENT)).toBe(false);
    expect(needsPrograms({ ...SILENT, restart: "ask" })).toBe(false);
    expect(needsPrograms({ ...SILENT, inUse: "skip" })).toBe(true);
  });
});
