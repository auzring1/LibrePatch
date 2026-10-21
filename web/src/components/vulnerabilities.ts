import type { Vulnerability, VulnerabilityStatus } from "../api/client";
import type { PillKind } from "../ui";

export const SEVERITY_LABEL: Record<string, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low", "": "Not scored" };

/** Severity uses the same pill colours as update severity. */
export const SEVERITY_KIND: Record<string, PillKind> = { critical: "critical", high: "important", medium: "moderate", low: "low", "": "neutral" };

export const nvdLink = (cve: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`;

/** "8.8" or an empty string. */
export const scoreText = (cvss: number | null | undefined) => (cvss === null || cvss === undefined ? "" : cvss.toFixed(1));

export interface DataState {
  /** True when the table can be trusted to show what is known; false when the person should look at the data first. */
  ok: boolean;
  kind: PillKind;
  title: string;
  text: string;
}

const day = (iso: string | null | undefined) => (iso ? new Date(iso).toISOString().slice(0, 10) : "");

/** Says in plain words whether there is vulnerability data and how fresh it is. */
export function describeData(st: VulnerabilityStatus | null | undefined): DataState {
  if (!st) return { ok: false, kind: "neutral", title: "Loading", text: "" };
  if (!st.enabled && st.counts.cves === 0) {
    return { ok: false, kind: "neutral", title: "The lookup is turned off", text: "Turn on “Look up known vulnerabilities” under Settings > Vulnerability data. The server then downloads the public lists and matches them against what is installed; nothing about your devices is sent." };
  }
  if (st.counts.cves === 0) {
    return { ok: false, kind: "info", title: "Waiting for the first download", text: "The lists are downloaded in the background. Without an NVD API key the first download takes several minutes. You can start it now with “Update now”." };
  }
  if (st.problems > 0) {
    return { ok: true, kind: "warning", title: `${st.problems} download${st.problems === 1 ? "" : "s"} failed on the last try`, text: "What was downloaded earlier is still used. Settings > Vulnerability data shows the addresses; “Update now” tries again." };
  }
  if (st.enabled && !st.nvd_updated_at && st.tracked_products > 0) {
    return { ok: true, kind: "info", title: "Still downloading", text: "Some programs have not been downloaded yet, so the list may be incomplete." };
  }
  const when = day(st.kev_updated_at);
  return { ok: true, kind: "success", title: "Up to date", text: when ? `CISA list of ${when}.` : "" };
}

/** One line: what to update to. */
export function fixText(v: Pick<Vulnerability, "fixed_in">): string {
  return v.fixed_in.length > 0 ? v.fixed_in.join("; ") : "No fixed version listed";
}

/** When CISA wants an exploited vulnerability fixed by, relative to now: "overdue by 3 days", "due in 5 days", "due today". */
export function dueText(due: string | null | undefined, now: Date = new Date()): string {
  if (!due) return "";
  const d = new Date(due);
  const days = Math.round((Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate())) / 86400000);
  if (days < 0) return `fix was due ${day(due)} (${-days} day${days === -1 ? "" : "s"} ago)`;
  if (days === 0) return "fix is due today";
  return `fix due ${day(due)} (in ${days} day${days === 1 ? "" : "s"})`;
}
