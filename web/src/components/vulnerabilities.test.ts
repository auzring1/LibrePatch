import { describe, expect, it } from "vitest";
import type { VulnerabilityStatus } from "../api/client";
import { describeData, dueText, fixText, nvdLink, scoreText, SEVERITY_KIND } from "./vulnerabilities";

const status = (over: Partial<VulnerabilityStatus>): VulnerabilityStatus => ({
  enabled: true,
  counts: { cves: 10, cves_with_versions: 8, exploited: 2 },
  feeds: [],
  tracked_products: 3,
  kev_updated_at: "2026-10-19T08:00:00Z",
  nvd_updated_at: "2026-10-19T07:00:00Z",
  problems: 0,
  ...over,
});

describe("describeData", () => {
  it("tells the person the lookup is off, and how to turn it on", () => {
    const d = describeData(status({ enabled: false, counts: { cves: 0, cves_with_versions: 0, exploited: 0 } }));
    expect(d.ok).toBe(false);
    expect(d.title).toBe("The lookup is turned off");
    expect(d.text).toContain("Settings > Vulnerability data");
  });
  it("says when the first download is still to come", () => {
    const d = describeData(status({ counts: { cves: 0, cves_with_versions: 0, exploited: 0 }, kev_updated_at: null, nvd_updated_at: null }));
    expect(d.ok).toBe(false);
    expect(d.title).toBe("Waiting for the first download");
  });
  it("keeps using old data when a download fails, and says so", () => {
    const d = describeData(status({ problems: 2 }));
    expect(d).toMatchObject({ ok: true, kind: "warning", title: "2 downloads failed on the last try" });
    expect(describeData(status({ problems: 1 })).title).toBe("1 download failed on the last try");
  });
  it("warns that the list may be incomplete while products are still downloading", () => {
    expect(describeData(status({ nvd_updated_at: null })).title).toBe("Still downloading");
  });
  it("shows the date of the CISA list when all is well", () => {
    expect(describeData(status({}))).toMatchObject({ ok: true, kind: "success", title: "Up to date", text: "CISA list of 2026-10-19." });
    expect(describeData(null).title).toBe("Loading");
  });
  it("still shows data when the lookup was turned off after a download", () => {
    expect(describeData(status({ enabled: false })).ok).toBe(true);
  });
});

describe("small helpers", () => {
  it("formats a score and links to the NVD", () => {
    expect(scoreText(8.8)).toBe("8.8");
    expect(scoreText(5)).toBe("5.0");
    expect(scoreText(null)).toBe("");
    expect(nvdLink("CVE-2026-0001")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2026-0001");
  });
  it("says what to update to, or that no fix is listed", () => {
    expect(fixText({ fixed_in: ["Google Chrome 130.0.6723.58"] })).toBe("Google Chrome 130.0.6723.58");
    expect(fixText({ fixed_in: [] })).toBe("No fixed version listed");
  });
  it("maps severity onto the update severity colours", () => {
    expect(SEVERITY_KIND.critical).toBe("critical");
    expect(SEVERITY_KIND.high).toBe("important");
    expect(SEVERITY_KIND[""]).toBe("neutral");
  });
  it("says when a fix was, or is, due", () => {
    const now = new Date("2026-10-19T12:00:00Z");
    expect(dueText("2026-10-22T00:00:00Z", now)).toBe("fix due 2026-10-22 (in 3 days)");
    expect(dueText("2026-10-19T00:00:00Z", now)).toBe("fix is due today");
    expect(dueText("2026-10-16T00:00:00Z", now)).toBe("fix was due 2026-10-16 (3 days ago)");
    expect(dueText("2026-10-18T00:00:00Z", now)).toBe("fix was due 2026-10-18 (1 day ago)");
    expect(dueText(null, now)).toBe("");
  });
});
