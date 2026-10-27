import type { PillKind } from "../ui";

/** Status of a script run, in plain words. */
export const RUN_STATUS: Record<string, { label: string; kind: PillKind }> = {
  pending_approval: { label: "Waiting for approval", kind: "warning" },
  running: { label: "Running", kind: "info" },
  rejected: { label: "Rejected", kind: "danger" },
  cancelled: { label: "Cancelled", kind: "neutral" },
  expired: { label: "Not approved in time", kind: "neutral" },
};

export const runStatus = (s: string) => RUN_STATUS[s] ?? { label: s, kind: "neutral" as PillKind };

/** One device's job in a run. */
export function jobOutcome(status: string, reason: string, exit: number | null | undefined): { label: string; kind: PillKind } {
  switch (status) {
    case "succeeded":
      return { label: "Finished", kind: "success" };
    case "failed":
      if (reason === "script_timeout") return { label: "Stopped: too slow", kind: "danger" };
      return { label: exit !== null && exit !== undefined ? `Failed (exit code ${exit})` : "Failed", kind: "danger" };
    case "rejected":
      return { label: "Refused by the computer", kind: "danger" };
    case "expired":
      return { label: "Computer did not answer in time", kind: "neutral" };
    case "cancelled":
      return { label: "Cancelled", kind: "neutral" };
    case "running":
      return { label: "Running", kind: "info" };
    case "accepted":
    case "waiting":
      return { label: "Waiting to start", kind: "info" };
    default:
      return { label: "Queued", kind: "neutral" };
  }
}

/** A run still moves while it is running or waiting for a decision. */
export const runIsOpen = (status: string, jobs: { status: string }[]) =>
  status === "pending_approval" || (status === "running" && jobs.some((j) => !["succeeded", "succeeded_reboot", "failed", "expired", "cancelled", "rejected"].includes(j.status)));

/** The first characters of a fingerprint, for lists. */
export const shortSha = (sha: string) => sha.slice(0, 12);

/** Why a "Rejected" job is most likely rejected, when the reason says so. */
export function refusedHint(reason: string): string {
  if (/switched off on this computer/.test(reason)) return "Scripts were switched off on this computer when its agent was installed (--no-scripts or ALLOWSCRIPTS=0). Reinstall the agent without that option to allow them.";
  // An agent from before scripts were on by default says this; it switches them on when it is updated.
  if (/not switched on/.test(reason)) return "This computer's agent is older and still has scripts off. Update the agent (Agent updates) to switch them on.";
  return "";
}
