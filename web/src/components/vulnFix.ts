import type { FleetUpdate, VulnerabilityDevice } from "../api/client";

const NIL = "00000000-0000-0000-0000-000000000000";

export interface FixPlan {
  /** What to deploy: one entry per program, with the devices that have an older copy (the shape the Software updates page uses). */
  updates: FleetUpdate[];
  /** Devices an update can fix (or probably fixes: the advisory names no fixed version). */
  devices: number;
  /** Hits whose newest available version is still affected. */
  stillAffected: number;
  /** Hits whose program is left to its own updater. */
  vendor: number;
  /** Hits with no update to offer (a Windows version, or no newer version known). */
  noUpdate: number;
}

/** Works out what "Update the affected devices" would deploy for one vulnerability. */
export function fixPlan(hits: VulnerabilityDevice[]): FixPlan {
  const plan: FixPlan = { updates: [], devices: 0, stillAffected: 0, vendor: 0, noUpdate: 0 };
  const byPkg = new Map<string, FleetUpdate>();
  const devices = new Set<string>();
  for (const h of hits) {
    const u = h.update;
    if (!u) {
      plan.noUpdate++;
      continue;
    }
    if (!u.deployable) {
      plan.vendor++;
      continue;
    }
    if (u.fixes === "no") {
      plan.stillAffected++;
      continue;
    }
    const key = u.package_id ?? `winget:${u.winget_id ?? u.package_name}`;
    let f = byPkg.get(key);
    if (!f) {
      f = {
        package_id: u.package_id ?? NIL,
        package_name: u.package_name,
        winget_id: u.winget_id,
        in_catalog: u.in_catalog,
        latest_version: u.latest_version,
        verified: u.verified,
        self_updating: u.self_updating,
        deployable: true,
        devices: [],
      };
      byPkg.set(key, f);
      plan.updates.push(f);
    }
    if (!f.devices.some((d) => d.device_id === h.device_id && d.scope === u.scope && d.installed_version === h.installed)) {
      f.devices.push({ device_id: h.device_id, hostname: h.hostname, installed_version: h.installed, scope: u.scope });
    }
    devices.add(h.device_id);
  }
  plan.devices = devices.size;
  return plan;
}

/** What the "Fix" column says about one hit. */
export function fixLabel(h: VulnerabilityDevice): { kind: "success" | "warning" | "neutral"; text: string } {
  const u = h.update;
  if (!u) return { kind: "neutral", text: h.fixed_in ? `Update to ${h.fixed_in}` : "No update known" };
  if (!u.deployable) return { kind: "neutral", text: "Left to the app's own updater" };
  if (u.fixes === "no") return { kind: "warning", text: `Newest (${u.latest_version}) is still affected` };
  if (u.fixes === "unknown") return { kind: "neutral", text: `Update to ${u.latest_version} (fix not confirmed)` };
  return { kind: "success", text: `Update to ${u.latest_version}` };
}
