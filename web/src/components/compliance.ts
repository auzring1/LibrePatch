import type { PillKind } from "../ui";

export interface ComplianceCounts {
  compliant?: number;
  non_compliant?: number;
  unknown?: number;
}

export interface ComplianceSummary {
  total: number;
  /** Devices with a recent Windows Update scan (compliant or not). */
  scanned: number;
  /** The headline: a percentage, or "—" when no device has been scanned (0% would claim they are all bad). */
  value: string;
  kind: PillKind;
  hint: string;
}

const devices = (n: number) => `${n} ${n === 1 ? "device" : "devices"}`;

/** The patch-compliance headline, honest about having nothing to judge yet. */
export function complianceSummary(c: ComplianceCounts | null | undefined): ComplianceSummary {
  const compliant = c?.compliant ?? 0;
  const bad = c?.non_compliant ?? 0;
  const unknown = c?.unknown ?? 0;
  const total = compliant + bad + unknown;
  const scanned = compliant + bad;
  if (total === 0) return { total, scanned, value: "—", kind: "neutral", hint: "Nothing to measure yet" };
  if (scanned === 0) return { total, scanned, value: "—", kind: "neutral", hint: `No scan reported yet by ${devices(total)}` };
  const pct = Math.round((100 * compliant) / total);
  const note = unknown > 0 ? `; ${unknown} not scanned lately` : "";
  return { total, scanned, value: `${pct}%`, kind: pct >= 90 ? "success" : pct >= 70 ? "warning" : "danger", hint: `${compliant} of ${devices(total)}${note}` };
}
