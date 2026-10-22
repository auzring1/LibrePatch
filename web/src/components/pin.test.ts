import { describe, expect, it } from "vitest";
import { describePin, formatPin, parsePin } from "./pin";

describe("parsePin", () => {
  it("reads the shapes the server stores", () => {
    expect(parsePin("")).toEqual({ mode: "newest", version: "" });
    expect(parsePin("latest")).toEqual({ mode: "newest", version: "" });
    expect(parsePin(undefined)).toEqual({ mode: "newest", version: "" });
    expect(parsePin("= 24.08")).toEqual({ mode: "exact", version: "24.08" });
    expect(parsePin("< 25")).toEqual({ mode: "below", version: "25" });
  });
  it("keeps anything else as written", () => {
    expect(parsePin("~> 3")).toEqual({ mode: "custom", version: "~> 3" });
  });
});

describe("formatPin", () => {
  it("writes what the server accepts, and round-trips", () => {
    expect(formatPin({ mode: "newest", version: "ignored" })).toBe("");
    expect(formatPin({ mode: "exact", version: " 24.08 " })).toBe("= 24.08");
    expect(formatPin({ mode: "below", version: "25" })).toBe("< 25");
    expect(formatPin({ mode: "exact", version: "" })).toBe("");
    for (const pin of ["", "= 1.2.3", "< 10"]) expect(formatPin(parsePin(pin))).toBe(pin);
    expect(formatPin(parsePin("latest"))).toBe("");
  });
});

describe("describePin", () => {
  it("says what the choice does", () => {
    expect(describePin({ mode: "newest", version: "" })).toMatch(/as soon as/);
    expect(describePin({ mode: "exact", version: "24.08" })).toMatch(/version 24\.08/);
    expect(describePin({ mode: "below", version: "25" })).toMatch(/older than 25/);
    expect(describePin({ mode: "exact", version: "" })).toMatch(/Choose/);
  });
});
