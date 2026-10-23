import type { SoftwareAutoFilter } from "../api/client";
import type { PillKind } from "../ui";

/** What a software policy's last check found, as a short label and a colour. The server sends the sentence (state_text); this is for the pill. */
export const POLICY_STATE: Record<string, { kind: PillKind; label: string }> = {
  up_to_date: { kind: "success", label: "Up to date" },
  updating: { kind: "info", label: "Updating" },
  waiting_approval: { kind: "warning", label: "Needs your approval" },
  waiting_delay: { kind: "neutral", label: "Waiting out the delay" },
  waiting_ring: { kind: "neutral", label: "Waiting for a ring" },
  held: { kind: "danger", label: "Held" },
  retry: { kind: "warning", label: "Will retry" },
  gave_up: { kind: "danger", label: "Gave up on some devices" },
  declined: { kind: "neutral", label: "Version declined" },
  left_to_vendor: { kind: "neutral", label: "Left to the vendor" },
  excluded: { kind: "neutral", label: "Excluded" },
  no_version: { kind: "warning", label: "No version to install" },
  package_missing: { kind: "danger", label: "Package missing" },
  error: { kind: "danger", label: "Check failed" },
  new: { kind: "neutral", label: "Not checked yet" },
  off: { kind: "neutral", label: "Switched off" },
  // all-apps policies
  no_apps: { kind: "neutral", label: "No apps to update" },
  first_check_soon: { kind: "neutral", label: "Not checked yet" },
  apps_waiting: { kind: "warning", label: "Some apps waiting" },
  apps_updating: { kind: "info", label: "Updating apps" },
  apps_all_current: { kind: "success", label: "All apps up to date" },
  apps_need_attention: { kind: "danger", label: "Needs attention" },
};

export function policyState(state: string | undefined): { kind: PillKind; label: string } {
  return POLICY_STATE[state ?? ""] ?? { kind: "neutral", label: (state ?? "").replace(/_/g, " ") || "Unknown" };
}

/** Policies whose check found something you may have to act on. */
export const NEEDS_ATTENTION = new Set(["held", "gave_up", "error", "package_missing", "apps_need_attention", "waiting_approval"]);

/** "in 4 min" for a time ahead of now; "now" when it has passed (the check is due). */
export function until(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "—";
  const s = Math.round((new Date(iso).getTime() - now) / 1000);
  if (s <= 30) return "any moment";
  if (s < 3600) return `in ${Math.ceil(s / 60)} min`;
  if (s < 86400) return `in ${Math.round(s / 3600)} h`;
  return `in ${Math.round(s / 86400)} d`;
}

/** One line about which apps an all-apps policy handles. */
export function describeFilter(f: SoftwareAutoFilter | undefined | null): string {
  if (!f) return "";
  const parts = [f.verified_only === false ? "verified and unverified apps" : "verified apps only"];
  if (f.include_unlisted) parts.push("adds apps from winget");
  if (f.exclude && f.exclude.length > 0) parts.push(`${f.exclude.length} left alone`);
  return parts.join("; ");
}
