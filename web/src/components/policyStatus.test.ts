import { describe, expect, it } from "vitest";
import { describeFilter, policyState, until } from "./policyStatus";

describe("policyState", () => {
  it("colours the states an administrator acts on", () => {
    expect(policyState("up_to_date").kind).toBe("success");
    expect(policyState("waiting_approval").kind).toBe("warning");
    expect(policyState("held").kind).toBe("danger");
    expect(policyState("apps_need_attention").kind).toBe("danger");
  });
  it("shows an unknown state as words, not a code", () => {
    expect(policyState("something_new").label).toBe("something new");
    expect(policyState(undefined).label).toBe("Unknown");
  });
});

describe("until", () => {
  const now = Date.UTC(2026, 9, 22, 12, 0, 0);
  const at = (s: number) => new Date(now + s * 1000).toISOString();
  it("says when the next check is due", () => {
    expect(until(null, now)).toBe("—");
    expect(until(at(10), now)).toBe("any moment");
    expect(until(at(-600), now)).toBe("any moment");
    expect(until(at(250), now)).toBe("in 5 min");
    expect(until(at(7200), now)).toBe("in 2 h");
    expect(until(at(3 * 86400), now)).toBe("in 3 d");
  });
});

describe("describeFilter", () => {
  it("says which apps an all-apps policy handles", () => {
    expect(describeFilter({ verified_only: true, include_self_updating: true, exclude: [] })).toBe("verified apps only");
    expect(describeFilter({ verified_only: false, include_unlisted: true, include_self_updating: true, exclude: ["A.B", "C.D"] })).toBe("verified and unverified apps; adds apps from winget; 2 left alone");
    expect(describeFilter({ verified_only: true, include_self_updating: false, exclude: [] })).toBe("verified apps only; leaves self-updating apps to their vendor");
    expect(describeFilter(null)).toBe("");
  });
});
