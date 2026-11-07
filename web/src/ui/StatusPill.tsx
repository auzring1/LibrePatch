import type { ReactNode } from "react";
import { Clock, Critical, Danger, Flame, Info, Offline, Online, Pause, Restart, Success, Unknown, Warning, Caution } from "./icons";

/** The semantic kinds. The first five are status; the last four are update severity. */
export type PillKind = "success" | "warning" | "danger" | "info" | "neutral" | "critical" | "important" | "moderate" | "low";

const ICONS: Record<PillKind, typeof Success> = {
  success: Success,
  warning: Warning,
  danger: Danger,
  info: Info,
  neutral: Unknown,
  critical: Critical,
  important: Flame,
  moderate: Caution,
  low: Info,
};

interface PillProps {
  kind: PillKind;
  /** The visible text. Status is always icon + color + text, never color alone. */
  children: ReactNode;
  icon?: typeof Success | null;
  size?: "sm" | "md";
  title?: string;
}

/** A status pill: icon, tinted background and text, all from the theme's semantic tokens. */
export function StatusPill({ kind, children, icon, size = "md", title }: PillProps) {
  const Icon = icon === null ? null : (icon ?? ICONS[kind]);
  return (
    <span className={`lp-pill lp-pill--${kind} lp-pill--${size}`} title={title} data-kind={kind}>
      {Icon && <Icon size={size === "sm" ? 12 : 14} stroke={2.25} aria-hidden="true" />}
      <span>{children}</span>
    </span>
  );
}

export type Severity = "critical" | "important" | "moderate" | "low";

/** Update severity as Microsoft names it; anything else is shown as a neutral "Unspecified". */
export function SeverityBadge({ severity, size }: { severity: string | null | undefined; size?: "sm" | "md" }) {
  const s = (severity ?? "").toLowerCase();
  if (s === "critical" || s === "important" || s === "moderate" || s === "low") {
    return (
      <StatusPill kind={s} size={size}>
        {s[0]!.toUpperCase() + s.slice(1)}
      </StatusPill>
    );
  }
  return (
    <StatusPill kind="neutral" size={size}>
      Unspecified
    </StatusPill>
  );
}

const STATUS: Record<string, { kind: PillKind; label?: string; icon?: typeof Success }> = {
  // devices and tokens
  active: { kind: "success", label: "Active" },
  pending: { kind: "warning", label: "Pending", icon: Clock },
  revoked: { kind: "danger", label: "Revoked" },
  retired: { kind: "neutral", label: "Retired" },
  expired: { kind: "neutral", label: "Expired" },
  exhausted: { kind: "neutral", label: "Used up" },
  // connection
  online: { kind: "success", label: "Online", icon: Online },
  offline: { kind: "neutral", label: "Offline", icon: Offline },
  // jobs and deployments
  queued: { kind: "neutral", label: "Queued", icon: Clock },
  scheduled: { kind: "info", label: "Scheduled", icon: Clock },
  waiting: { kind: "neutral", label: "Waiting", icon: Clock },
  running: { kind: "info", label: "Running" },
  succeeded: { kind: "success", label: "Succeeded" },
  success: { kind: "success", label: "Success" },
  completed: { kind: "success", label: "Completed" },
  failed: { kind: "danger", label: "Failed" },
  error: { kind: "danger", label: "Error" },
  canceled: { kind: "neutral", label: "Canceled" },
  cancelled: { kind: "neutral", label: "Canceled" },
  skipped: { kind: "neutral", label: "Skipped" },
  paused: { kind: "warning", label: "Paused", icon: Pause },
  reboot_pending: { kind: "warning", label: "Restart pending", icon: Restart },
  // compliance
  compliant: { kind: "success", label: "Compliant" },
  non_compliant: { kind: "danger", label: "Not compliant" },
  unknown: { kind: "neutral", label: "Unknown" },
};

/** Maps a status word from the API to a pill; unknown words become a neutral pill with the word itself. */
export function Status({ value, size, label }: { value: string; size?: "sm" | "md"; label?: string }) {
  const s = STATUS[value] ?? { kind: "neutral" as PillKind, label: value.replace(/_/g, " ") };
  return (
    <StatusPill kind={s.kind} icon={s.icon} size={size}>
      {label ?? s.label ?? value}
    </StatusPill>
  );
}

export const statusKind = (value: string): PillKind => STATUS[value]?.kind ?? "neutral";
