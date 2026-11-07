import { describe, expect, it } from "vitest";
import { fitScale } from "./DataTable";

const cols = [
  { id: "a", width: 200, min: 70 },
  { id: "b", width: 200, min: 70 },
  { id: "c", width: 200, min: 70 },
];

describe("fitScale", () => {
  it("leaves the columns alone when they fit, or before the frame is measured", () => {
    expect(fitScale(1000, cols, {}, 0)).toBe(1);
    expect(fitScale(600, cols, {}, 0)).toBe(1);
    expect(fitScale(0, cols, {}, 0)).toBe(1);
  });
  it("shrinks them together to fit a narrower frame", () => {
    expect(fitScale(540, cols, {}, 0)).toBeCloseTo(540 / 600);
  });
  it("counts the selection and action columns and the columns the person resized as fixed", () => {
    // 100 fixed + 150 resized leaves 180 of the 430 frame for the 200 that can give way
    expect(fitScale(430, cols.slice(0, 2), { b: 150 }, 100)).toBeCloseTo((430 - 100 - 150) / 200);
  });
  it("never squeezes below 85%: past that the table scrolls sideways", () => {
    expect(fitScale(200, cols, {}, 0)).toBe(0.85);
  });
  it("does nothing when every column was resized by hand", () => {
    expect(fitScale(100, cols, { a: 300, b: 300, c: 300 }, 0)).toBe(1);
  });
});
