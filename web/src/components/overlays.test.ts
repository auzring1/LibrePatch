import { describe, expect, it } from "vitest";
import { isPublicKey, looksLikeOverlayFile, overlayCounts, overlayOrigin, overlayStatus } from "./overlays";

describe("overlayStatus", () => {
  it("says a switched-off source is off, whatever its last check said", () => {
    expect(overlayStatus({ enabled: false, status: "error", last_error: "x" }).label).toBe("Off");
  });
  it("shows a failed check as a problem and keeps the reason", () => {
    expect(overlayStatus({ enabled: true, status: "error", last_error: "older than the version you have" })).toEqual({ kind: "danger", label: "Problem", title: "older than the version you have" });
  });
  it("shows a working source as in use", () => {
    expect(overlayStatus({ enabled: true, status: "ok", last_error: "" })).toEqual({ kind: "success", label: "In use" });
  });
});

describe("overlayOrigin", () => {
  it("names the host of a URL source and calls an upload an uploaded file", () => {
    expect(overlayOrigin({ kind: "url", url: "https://example.org/overlays/clinic.lpov" })).toBe("example.org");
    expect(overlayOrigin({ kind: "upload", url: "" })).toBe("Uploaded file");
    expect(overlayOrigin({ kind: "url", url: "not a url" })).toBe("not a url");
  });
});

describe("overlayCounts", () => {
  it("counts packages and verified ones", () => {
    expect(overlayCounts({ entries: 1, verified_entries: 0 })).toBe("1 package");
    expect(overlayCounts({ entries: 12, verified_entries: 3 })).toBe("12 packages, 3 verified");
  });
});

describe("file and key checks", () => {
  it("recognizes a signed overlay file and refuses other JSON", () => {
    expect(looksLikeOverlayFile('{"format":"librepatch-overlay-bundle/1","overlay":{}}')).toBe(true);
    expect(looksLikeOverlayFile('{"format":"librepatch-overlay/1"}')).toBe(false);
    expect(looksLikeOverlayFile("hello")).toBe(false);
    expect(looksLikeOverlayFile("null")).toBe(false);
  });
  it("accepts a 64-character hex key with whitespace around it", () => {
    expect(isPublicKey(" " + "ab".repeat(32) + "\n")).toBe(true);
    expect(isPublicKey("ab".repeat(31))).toBe(false);
    expect(isPublicKey("zz".repeat(32))).toBe(false);
  });
});
