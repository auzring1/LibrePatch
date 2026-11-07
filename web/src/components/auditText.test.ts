import { describe, expect, it } from "vitest";
import type { AuditEntry } from "../api/client";
import { actorLabel, describeAudit, entryObject } from "./auditText";

const entry = (o: Partial<AuditEntry>): AuditEntry => ({ id: 1, ts: "2026-10-22T10:00:00Z", actor_type: "user", actor_id: "u1", actor_name: "Ada Admin", action: "device.reboot", outcome: "success", target_ids: [], details: {}, ...o });

describe("describeAudit", () => {
  it("says who did what to what", () => {
    expect(describeAudit(entry({ details: { hostname: "LAP-01" } }))).toBe("Ada Admin restarted “LAP-01”");
    expect(describeAudit(entry({ action: "policy.create", details: { name: "Keep Chrome current" } }))).toBe("Ada Admin created the policy “Keep Chrome current”");
    expect(describeAudit(entry({ action: "auth.login" }))).toBe("Ada Admin signed in");
  });
  it("uses a plain noun when the entry names nothing", () => {
    expect(describeAudit(entry({ action: "device.approve" }))).toBe("Ada Admin approved a device");
  });
  it("names the system and devices as what they are", () => {
    expect(describeAudit(entry({ actor_type: "system", actor_name: undefined, action: "policy.auto_add_app", details: { app: "7-Zip", policy: "Keep all current" } }))).toBe("The server added “7-Zip” to the all-apps policy “Keep all current”");
    expect(describeAudit(entry({ actor_type: "device", actor_name: undefined, action: "agent.security_event" }))).toBe("A device reported a security event");
  });
  it("says why an app was dropped from an all-apps policy", () => {
    const text = describeAudit(entry({ actor_type: "system", actor_name: undefined, action: "policy.auto_remove_app", details: { app: "Zeta", policy: "All", reason: "you excluded it" } }));
    expect(text).toBe("The server stopped keeping “Zeta” updated in the all-apps policy “All” because you excluded it");
  });
  it("falls back to the technical name in words for an action it does not know", () => {
    expect(describeAudit(entry({ action: "thing.happened_now" }))).toBe("Ada Admin: thing happened now");
  });
  it("knows the common actions, so none of them falls back to a raw code", () => {
    for (const a of ["auth.login", "device.revoke", "catalog.import", "deployment.create", "wu.install", "user.role_add", "software.approve", "settings.update", "site.create", "group.members", "script.run_approve", "policy.update"]) {
      expect(describeAudit(entry({ action: a }))).not.toMatch(/^Ada Admin: /);
    }
  });
});

describe("entryObject and actorLabel", () => {
  it("picks the first name an entry gives", () => {
    expect(entryObject({ details: { name: "x", hostname: "h" } })).toBe("h");
    expect(entryObject({ details: { count: 3 } })).toBeUndefined();
    expect(entryObject({ details: { name: "  " } })).toBeUndefined();
  });
  it("labels actors", () => {
    expect(actorLabel({ actor_type: "user", actor_name: "ada@example.com", actor_id: "1" })).toBe("ada@example.com");
    expect(actorLabel({ actor_type: "user", actor_id: "1" })).toBe("Someone");
    expect(actorLabel({ actor_type: "token", actor_id: "t" })).toBe("An API token");
  });
});
