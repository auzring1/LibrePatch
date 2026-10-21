import type { PillKind } from "../ui";

export type LifecycleStatus = "supported" | "ending_soon" | "unsupported" | "unknown";

export const LIFECYCLE_LABEL: Record<LifecycleStatus, string> = {
  unsupported: "Out of support",
  ending_soon: "Ending soon",
  supported: "Supported",
  unknown: "Unknown",
};

export const LIFECYCLE_KIND: Record<LifecycleStatus, PillKind> = {
  unsupported: "danger",
  ending_soon: "warning",
  supported: "success",
  unknown: "neutral",
};

/** "ended 6 days ago", "ends today", "ends in 22 days"; empty when the end date is not known. */
export function whenSupportEnds(daysLeft: number | null | undefined): string {
  if (daysLeft === null || daysLeft === undefined) return "";
  const n = Math.abs(daysLeft);
  const unit = n === 1 ? "day" : "days";
  if (daysLeft < 0) return `ended ${n} ${unit} ago`;
  if (daysLeft === 0) return "ends today";
  return `ends in ${n} ${unit}`;
}
