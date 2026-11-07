import { describe, expect, it } from "vitest";
import { ago, bytes, duration } from "./format";

describe("format", () => {
  it("formats bytes, including protobuf uint64 strings", () => {
    expect(bytes(0)).toBe("—");
    expect(bytes(1536)).toBe("1.5 KB");
    expect(bytes("17179869184")).toBe("16 GB");
  });
  it("formats relative time", () => {
    const now = Date.parse("2026-01-01T00:10:00Z");
    expect(ago(null, now)).toBe("never");
    expect(ago("2026-01-01T00:09:30Z", now)).toBe("30s ago");
    expect(ago("2026-01-01T00:00:00Z", now)).toBe("10 min ago");
  });
  it("formats durations", () => {
    expect(duration(90061)).toBe("1d 1h");
    expect(duration(3720)).toBe("1h 2m");
  });
});

import { formatDate, formatDateTime } from "./format";

describe("organization date formats", () => {
  const d = new Date("2026-03-04T21:05:00Z");
  const base = { locale: "en-US", dateFormat: "locale", timeFormat: "locale", timeZone: "UTC" };
  it("writes the chosen date format", () => {
    expect(formatDate(d, { ...base, dateFormat: "iso" })).toBe("2026-03-04");
    expect(formatDate(d, { ...base, dateFormat: "dmy" })).toBe("04/03/2026");
    expect(formatDate(d, { ...base, dateFormat: "mdy" })).toBe("03/04/2026");
  });
  it("honours the time zone and the clock", () => {
    expect(formatDateTime(d, { ...base, dateFormat: "iso", timeFormat: "24h", timeZone: "Europe/Berlin" })).toBe("2026-03-04 22:05");
    expect(formatDateTime(d, { ...base, dateFormat: "iso", timeFormat: "12h" })).toMatch(/2026-03-04 0?9:05\s?PM/);
  });
  it("falls back to the viewer's zone for an unknown name", () => {
    expect(() => formatDateTime(d, { ...base, timeZone: "Mars/Base" })).not.toThrow();
  });
});
