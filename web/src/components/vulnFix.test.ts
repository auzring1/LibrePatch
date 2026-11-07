import { describe, expect, it } from "vitest";
import type { VulnerabilityDevice } from "../api/client";
import { fixLabel, fixPlan } from "./vulnFix";

type Update = NonNullable<VulnerabilityDevice["update"]>;
const upd = (o: Partial<Update> = {}): Update => ({ package_id: "pkg-ff", package_name: "Mozilla Firefox", in_catalog: true, latest_version: "125.0.2", verified: true, self_updating: false, deployable: true, scope: "machine", fixes: "yes", ...o });
const hit = (device: string, o: Partial<VulnerabilityDevice> = {}): VulnerabilityDevice => ({ device_id: device, hostname: `host-${device}`, product: "Mozilla Firefox", installed: "120.0", fixed_in: "125.0.1", update: upd(), ...o });

describe("fixPlan", () => {
  it("groups the devices by program and counts them once", () => {
    const p = fixPlan([hit("a"), hit("b"), hit("a", { product: "Mozilla Firefox (second copy)" })]);
    expect(p.updates).toHaveLength(1);
    expect(p.updates[0]).toMatchObject({ package_id: "pkg-ff", latest_version: "125.0.2", deployable: true, in_catalog: true });
    expect(p.updates[0]!.devices.map((d) => d.device_id)).toEqual(["a", "b"]);
    expect(p.devices).toBe(2);
  });
  it("leaves out what an update cannot fix, and says why", () => {
    const p = fixPlan([
      hit("a"),
      hit("b", { update: upd({ fixes: "no" }) }),
      hit("c", { update: upd({ deployable: false }) }),
      hit("d", { update: null }),
    ]);
    expect(p.devices).toBe(1);
    expect(p).toMatchObject({ stillAffected: 1, vendor: 1, noUpdate: 1 });
  });
  it("offers the update when the advisory names no fixed version", () => {
    const p = fixPlan([hit("a", { fixed_in: "", update: upd({ fixes: "unknown" }) })]);
    expect(p.devices).toBe(1);
  });
  it("keeps a program that is not in the catalog yet, so it can be added", () => {
    const p = fixPlan([hit("a", { update: upd({ package_id: null, in_catalog: false, winget_id: "Vendor.Tool", package_name: "Tool" }) })]);
    expect(p.updates[0]).toMatchObject({ in_catalog: false, winget_id: "Vendor.Tool", package_id: "00000000-0000-0000-0000-000000000000" });
  });
  it("is empty without hits", () => {
    expect(fixPlan([])).toMatchObject({ updates: [], devices: 0 });
  });
});

describe("fixLabel", () => {
  it("says in words what the update does", () => {
    expect(fixLabel(hit("a"))).toEqual({ kind: "success", text: "Update to 125.0.2" });
    expect(fixLabel(hit("a", { update: upd({ fixes: "no" }) })).kind).toBe("warning");
    expect(fixLabel(hit("a", { update: upd({ fixes: "unknown" }) })).text).toMatch(/not confirmed/);
    expect(fixLabel(hit("a", { update: upd({ deployable: false }) })).text).toMatch(/own updater/);
    expect(fixLabel(hit("a", { update: null }))).toEqual({ kind: "neutral", text: "Update to 125.0.1" });
    expect(fixLabel(hit("a", { update: null, fixed_in: "" })).text).toBe("No update known");
  });
});
