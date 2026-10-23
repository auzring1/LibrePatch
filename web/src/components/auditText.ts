import type { AuditEntry } from "../api/client";
import { humanAction } from "./dashboard/format";

type Phrase = (o: string | undefined, d: Record<string, unknown>) => string;

const q = (o: string) => `“${o}”`;
/** "<verb> <object>" with a fallback noun when the entry names nothing. */
const on = (verb: string, fallback: string): Phrase => (o) => `${verb} ${o ? q(o) : fallback}`;
const plain = (s: string): Phrase => () => s;

/** What each audit action means in a sentence, as a predicate for the actor ("Ada Admin <phrase>"). */
const PHRASES: Record<string, Phrase> = {
  "auth.login": plain("signed in"),
  "auth.logout": plain("signed out"),
  "auth.lockout": plain("was locked out after too many wrong passwords"),
  "auth.mfa": plain("completed the second sign-in step"),
  "auth.mfa_enroll": plain("set up a second sign-in factor"),
  "auth.password_change": plain("changed their password"),
  "auth.securitykey_add": plain("added a security key"),
  "auth.securitykey_remove": plain("removed a security key"),
  "auth.sso": plain("signed in through single sign-on"),
  "sso.keep_last_admin": plain("kept the last administrator's role, although the provider no longer gives it"),
  "sso.roles_synced": (o) => `had their roles updated from the sign-in provider${o ? ` (${o})` : ""}`,
  "audit.verify": plain("checked that the audit log is intact"),
  "agent.release_add": plain("added an agent release"),
  "agent.release_delete": plain("deleted an agent release"),
  "agent.rollout_hold": plain("held the agent rollout"),
  "agent.rollout_set": plain("changed the agent rollout"),
  "agent.security_event": plain("reported a security event"),
  "branding.update": plain("changed the branding"),
  "branding.reset": plain("reset the branding"),
  "branding.asset_set": plain("changed a branding image"),
  "branding.asset_delete": plain("removed a branding image"),
  "catalog.custom": on("added the custom package", "a custom package"),
  "catalog.import": on("imported", "a package"),
  "catalog.index_refresh": plain("refreshed the winget index"),
  "catalog.overlay_add": plain("added a catalog overlay"),
  "catalog.overlay_update": plain("changed a catalog overlay"),
  "catalog.overlay_replace": plain("replaced a catalog overlay's file"),
  "catalog.overlay_refresh": plain("refreshed a catalog overlay"),
  "catalog.overlay_delete": plain("removed a catalog overlay"),
  "catalog.override": on("changed how to deploy", "a package"),
  "catalog.remove": on("removed from the catalog:", "a package"),
  "catalog.upload": on("uploaded an installer for", "a package"),
  "catalog.verify": on("marked as verified:", "a package"),
  "catalog.unverify": on("took the verified mark off", "a package"),
  "deployment.create": on("started the deployment", "a deployment"),
  "deployment.cancel": plain("canceled a deployment"),
  "device.approve": on("approved", "a device"),
  "device.enroll": on("enrolled", "a device"),
  "device.certificate_issue": on("issued a certificate to", "a device"),
  "device.certificate_renew": on("renewed the certificate of", "a device"),
  "device.delete": on("deleted", "a device"),
  "device.revoke": on("revoked", "a device"),
  "device.reboot": on("restarted", "a device"),
  "device.refresh": on("asked for a fresh inventory from", "a device"),
  "device.wake": on("woke up", "a device"),
  "device.inspect": on("looked at the running programs, services or event log of", "a device"),
  "device.fields_update": on("changed the custom fields of", "a device"),
  "group.create": on("created the group", "a group"),
  "group.update": on("changed the group", "a group"),
  "group.delete": on("deleted the group", "a group"),
  "group.members": on("changed the members of", "a group"),
  "inventory.export": plain("exported the inventory"),
  "policy.create": on("created the policy", "a policy"),
  "policy.update": on("changed the policy", "a policy"),
  "policy.delete": on("deleted the policy", "a policy"),
  "policy.auto_add_app": (_o, d) => `added ${text(d.app) ? q(text(d.app)!) : "an app"} to the all-apps policy${text(d.policy) ? ` ${q(text(d.policy)!)}` : ""}`,
  "policy.auto_remove_app": (_o, d) => `stopped keeping ${text(d.app) ? q(text(d.app)!) : "an app"} updated in the all-apps policy${text(d.policy) ? ` ${q(text(d.policy)!)}` : ""}${text(d.reason) ? ` because ${text(d.reason)}` : ""}`,
  "script.create": plain("added a script"),
  "script.update": plain("changed a script"),
  "script.delete": plain("deleted a script"),
  "script.run_request": plain("asked to run a script"),
  "script.run_approve": plain("approved a script run"),
  "script.run_reject": plain("rejected a script run"),
  "script.run_cancel": plain("canceled a script run"),
  "script.run_start": plain("started a script run"),
  "settings.update": plain("changed settings"),
  "settings.export": plain("exported the settings"),
  "settings.import": plain("imported settings"),
  "settings.report_send_now": plain("sent a report right away"),
  "settings.support_bundle": plain("created a support bundle"),
  "settings.test_email": plain("sent a test email"),
  "settings.test_webhook": plain("sent a test webhook"),
  "site.create": on("created the site", "a site"),
  "site.update": on("changed the site", "a site"),
  "site.delete": on("deleted the site", "a site"),
  "software.approve": plain("approved a software version"),
  "software.decline": plain("declined a software version"),
  "software.approval_reset": plain("took back a decision about a software version"),
  "software.hold": plain("held a software version back after a ring did badly"),
  "software.hold_release": plain("released a held software version"),
  "software.uninstall": on("uninstalled software from", "a device"),
  "user.create": on("added the user", "a user"),
  "user.update": on("changed the user", "a user"),
  "user.delete": on("deleted the user", "a user"),
  "user.mfa_reset": on("reset the second sign-in factor of", "a user"),
  "user.password_reset": on("reset the password of", "a user"),
  "user.role_add": on("gave a role to", "a user"),
  "user.role_remove": on("took a role away from", "a user"),
  "wu.scan": on("scanned for Windows updates on", "a device"),
  "wu.scan_online": on("checked Windows Update online for", "a device"),
  "wu.install": on("installed Windows updates on", "a device"),
  "wu.install_online": on("installed Windows updates from the internet on", "a device"),
  "wu.decision": plain("decided about a Windows update"),
  "wu.auto_approve": plain("approved a Windows update by rule"),
  "wu.hide": plain("hid a Windows update"),
  "wu.hold": plain("held a Windows update back"),
  "wu.hold_release": plain("released a held Windows update"),
  "wu.ring_create": on("created the ring", "a ring"),
  "wu.ring_update": on("changed the ring", "a ring"),
  "wu.ring_delete": on("deleted the ring", "a ring"),
  "wu.rule_create": plain("added an auto-approval rule"),
  "wu.rule_update": plain("changed an auto-approval rule"),
  "wu.rule_delete": plain("deleted an auto-approval rule"),
  "admin.backup": plain("made a backup"),
  "admin.restore": plain("restored a backup"),
  "apitoken.create": on("created the API token", "an API token"),
  "apitoken.revoke": on("revoked the API token", "an API token"),
  "enrollment_token.create": on("created the enrollment token", "an enrollment token"),
  "enrollment_token.revoke": on("revoked the enrollment token", "an enrollment token"),
  "enrollment_token.delete": on("deleted the enrollment token", "an enrollment token"),
  "gateway.protocol_violation": plain("sent something the server could not accept"),
  "job.retry": plain("retried a job"),
  "maintenance.retention": plain("cleaned up old records"),
  "master_key.acknowledge": plain("confirmed that the master key is saved"),
  "master_key.view": plain("viewed the master key"),
  "setup.complete": plain("finished the first-time setup"),
  "setup.token": plain("used the one-time setup token"),
  "vulns.sync": plain("updated the vulnerability data"),
  "vulns.import": plain("loaded vulnerability data from a file"),
  "vulns.product_add": on("added a program to the vulnerability lookup:", "a program"),
  "vulns.product_update": on("changed a program in the vulnerability lookup:", "a program"),
  "vulns.product_delete": on("removed a program from the vulnerability lookup:", "a program"),
};

function text(v: unknown): string | undefined {
  return typeof v === "string" && v.trim() !== "" ? v.trim() : undefined;
}

/** The name an entry gives for what it was about, when it gives one. */
export function entryObject(a: Pick<AuditEntry, "details">): string | undefined {
  const d = (a.details ?? {}) as Record<string, unknown>;
  for (const k of ["hostname", "name", "title", "identifier", "package", "email", "label", "file_name"]) {
    const v = text(d[k]);
    if (v) return v;
  }
  return undefined;
}

/** Who did it, as a name a person would use. */
export function actorLabel(a: Pick<AuditEntry, "actor_type" | "actor_name" | "actor_id">): string {
  switch (a.actor_type) {
    case "user":
      return a.actor_name || "Someone";
    case "system":
      return "The server";
    case "device":
      return "A device";
    case "token":
    case "api_token":
      return "An API token";
    default:
      return a.actor_name || (a.actor_type ? a.actor_type[0]!.toUpperCase() + a.actor_type.slice(1) : "Someone");
  }
}

/** One plain sentence for an audit entry: "Ada Admin restarted “vm”". Unknown actions fall back to the technical name in words. */
export function describeAudit(a: AuditEntry): string {
  const who = actorLabel(a);
  const phrase = PHRASES[a.action];
  if (!phrase) return `${who}: ${humanAction(a.action).toLowerCase()}`;
  return `${who} ${phrase(entryObject(a), (a.details ?? {}) as Record<string, unknown>)}`;
}
