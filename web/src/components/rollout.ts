import type { SoftwareRollout } from "../api/client";
import type { PillKind } from "../ui";

export type StageState = "waiting" | "running" | "passed" | "done" | "held";

export const STAGE_LABEL: Record<StageState, string> = {
  waiting: "Waiting",
  running: "Rolling out",
  passed: "Passed",
  done: "Done",
  held: "Held",
};

export const STAGE_KIND: Record<StageState, PillKind> = {
  waiting: "neutral",
  running: "info",
  passed: "success",
  done: "success",
  held: "danger",
};

export interface RolloutSummary {
  kind: PillKind;
  text: string;
}

const BLOCKED: Record<string, string> = {
  excluded: "Package is excluded in the catalog",
  self_updating: "Left to the program's own updater",
  no_version: "No version to roll out",
  declined: "was declined",
};

const devices = (n: number) => `${n} device${n === 1 ? "" : "s"}`;

/** One line for the policy list: what the newest version is doing. */
export function summarizeRollout(r: SoftwareRollout | null | undefined): RolloutSummary | null {
  if (!r) return null;
  const v = r.version;
  switch (r.blocked) {
    case "pending_approval":
      if (r.waiting === 0) return { kind: "success", text: `${v} is installed wherever it is needed` };
      return { kind: "warning", text: `${v} is waiting for approval${r.waiting ? ` (${devices(r.waiting)})` : ""}` };
    case "declined":
      return { kind: "neutral", text: `${v} ${BLOCKED.declined}` };
    case "excluded":
    case "self_updating":
    case "no_version":
      return { kind: "neutral", text: BLOCKED[r.blocked]! };
    case "delay":
      return { kind: "neutral", text: `${v} is waiting out its delay` };
  }
  const held = r.stages.find((s) => s.state === "held");
  if (held) return { kind: "danger", text: `${v} is held after ring ${held.name}` };
  const active = r.stages.findIndex((s) => s.state === "running" || s.state === "passed");
  if (active >= 0) {
    const later = r.stages.slice(active + 1).filter((s) => s.state === "waiting").length;
    return { kind: "info", text: `${v}: ${r.stages[active]!.name} ${r.stages[active]!.state === "running" ? "is rolling out" : "has passed"}${later ? `, ${later} more stage${later === 1 ? "" : "s"} to go` : ""}` };
  }
  if (r.waiting === 0) return { kind: "success", text: `${v} is rolled out` };
  return { kind: "neutral", text: `${v} is waiting for its first ring` };
}
