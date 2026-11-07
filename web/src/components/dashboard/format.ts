// Small pure helpers for the dashboard widgets.

export type Reason = "offline" | "reboot_pending" | "critical_missing" | "failed_updates";

export const REASON_TEXT: Record<Reason, string> = {
  offline: "Offline for over a day",
  reboot_pending: "Restart pending",
  critical_missing: "Critical updates missing",
  failed_updates: "Failed updates",
};

/** "device.restart_requested" -> "Device restart requested". */
export function humanAction(action: string): string {
  const s = action.replace(/[._:-]+/g, " ").replace(/\s+/g, " ").trim();
  return s ? s[0]!.toUpperCase() + s.slice(1) : "Unknown action";
}

/** Where a top-missing update's row goes: the Updates list filtered to devices missing it, searched by KB number or title. */
export function missingUpdateLink(u: { kb?: string[]; title?: string }): string {
  const kb = (u.kb ?? []).find((k) => k.trim() !== "");
  const q = (kb ?? u.title ?? "").trim();
  const p = new URLSearchParams();
  if (q) p.set("q", q);
  p.set("missing", "1");
  return `/updates?${p.toString()}`;
}

export const kbLabel = (kb: string) => (/^kb/i.test(kb) ? kb.toUpperCase() : `KB${kb}`);

export interface HistoryPoint {
  date?: string;
  compliant?: number;
  non_compliant?: number;
  unknown?: number;
}

/** A normalised history point (missing numbers are 0) with its total. */
export interface Day {
  date: string;
  compliant: number;
  nonCompliant: number;
  unknown: number;
  total: number;
}

export function normaliseHistory(h: readonly HistoryPoint[] | undefined): Day[] {
  return (h ?? [])
    .filter((p) => !!p.date)
    .map((p) => {
      const compliant = p.compliant ?? 0;
      const nonCompliant = p.non_compliant ?? 0;
      const unknown = p.unknown ?? 0;
      return { date: p.date!, compliant, nonCompliant, unknown, total: compliant + nonCompliant + unknown };
    })
    .sort((a, b) => a.date.localeCompare(b.date));
}

/** A "nice" upper bound for the chart's y axis (1, 2, 5 x 10^n), at least 1. */
export function niceMax(n: number): number {
  if (n <= 1) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(n)));
  const f = n / p;
  return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
}

/** One-sentence summary used as the chart's accessible name. */
export function historySummary(days: readonly Day[]): string {
  if (days.length === 0) return "No compliance history yet";
  const last = days[days.length - 1]!;
  const now = `${last.compliant} compliant, ${last.nonCompliant} not compliant, ${last.unknown} not scanned`;
  if (days.length === 1) return `Compliance on ${last.date}: ${now}`;
  const first = days[0]!;
  return `Compliance from ${first.date} to ${last.date} (${days.length} days). First day: ${first.compliant} compliant, ${first.nonCompliant} not compliant, ${first.unknown} not scanned. Latest: ${now}`;
}

export const positiveKind = <K extends string>(n: number | null | undefined, kind: K): K | undefined => ((n ?? 0) > 0 ? kind : undefined);
