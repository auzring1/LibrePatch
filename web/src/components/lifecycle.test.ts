import { describe, expect, it } from "vitest";
import { LIFECYCLE_KIND, LIFECYCLE_LABEL, whenSupportEnds } from "./lifecycle";

describe("whenSupportEnds", () => {
  it("says how long ago support ended", () => {
    expect(whenSupportEnds(-6)).toBe("ended 6 days ago");
    expect(whenSupportEnds(-1)).toBe("ended 1 day ago");
  });
  it("says when it ends", () => {
    expect(whenSupportEnds(0)).toBe("ends today");
    expect(whenSupportEnds(1)).toBe("ends in 1 day");
    expect(whenSupportEnds(22)).toBe("ends in 22 days");
  });
  it("says nothing when the date is not known", () => {
    expect(whenSupportEnds(null)).toBe("");
    expect(whenSupportEnds(undefined)).toBe("");
  });
});

describe("status words", () => {
  it("never shows unknown as supported", () => {
    expect(LIFECYCLE_LABEL.unknown).toBe("Unknown");
    expect(LIFECYCLE_KIND.unknown).toBe("neutral");
    expect(LIFECYCLE_KIND.unsupported).toBe("danger");
    expect(LIFECYCLE_KIND.ending_soon).toBe("warning");
  });
});
