import { describe, expect, it } from "vitest";
import vectors from "../../../internal/server/branding/testdata/contrast_vectors.json";
import { ACCENT_SWATCHES, checks, colorProblems, contrast, DEFAULT_ACCENT, isHexColor, SECONDARY_SWATCHES } from "./contrast";

describe("contrast (shared vectors with the server)", () => {
  it("matches the reference ratios", () => {
    for (const v of vectors.ratios) {
      expect(Math.round(contrast(v.a, v.b) * 100) / 100).toBeCloseTo(v.ratio, 2);
      expect(contrast(v.b, v.a)).toBe(contrast(v.a, v.b));
    }
  });

  it("accepts and blocks the same accent/secondary pairs as the server", () => {
    for (const v of vectors.accents) {
      const failing = checks(v.accent, v.secondary).filter((c) => !c.pass);
      expect(failing.length === 0, `${v.accent} + ${v.secondary}: ${"why" in v ? v.why : ""}`).toBe(v.ok);
    }
  });

  it("passes the built-in accent", () => {
    expect(checks(DEFAULT_ACCENT, "").every((c) => c.pass)).toBe(true);
    expect(colorProblems("", "")).toEqual({});
  });

  it("explains which field is the problem", () => {
    expect(colorProblems("#ffd43b", "").accent).toMatch(/Not accessible/);
    const p = colorProblems("#1971c2", "#ffff99");
    expect(p.accent).toBeUndefined();
    expect(p.secondary).toMatch(/Not accessible/);
    expect(colorProblems("blue", "").accent).toMatch(/like #/);
  });

  it("validates hex syntax", () => {
    expect(isHexColor("#1971C2")).toBe(true);
    for (const bad of ["#17c", "1971c2", "#1971c2;x", "rgb(0,0,0)", ""]) expect(isHexColor(bad)).toBe(false);
  });

  it("only suggests colors that can be saved", () => {
    for (const a of ACCENT_SWATCHES) expect(colorProblems(a, ""), a).toEqual({});
    for (const c of SECONDARY_SWATCHES) expect(colorProblems(DEFAULT_ACCENT, c), c).toEqual({});
  });
});
