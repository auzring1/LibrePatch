import { parseHHMM } from "../api/format";

type U = Record<string, unknown> | undefined;
const str = (u: U, k: string, d: string) => (typeof u?.[k] === "string" ? (u[k] as string) : d);
const num = (u: U, k: string, d: number) => (typeof u?.[k] === "number" ? (u[k] as number) : d);
const bool = (u: U, k: string, d: boolean) => (typeof u?.[k] === "boolean" ? (u[k] as boolean) : d);
const list = (u: U, k: string): string[] => (Array.isArray(u?.[k]) ? (u[k] as unknown[]).map(String) : []);

const DAY = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];

/** What a new update ring starts with (Settings > Update defaults), as the ring form wants it. */
export function ringDefaults(u: U) {
  const start = parseHHMM(str(u, "window_start", "22:00"));
  const end = parseHHMM(str(u, "window_end", "05:00"));
  return {
    restart: str(u, "ring_restart", "never"),
    activeStart: parseHHMM(str(u, "active_start", "08:00")),
    activeEnd: parseHHMM(str(u, "active_end", "17:00")),
    notify: num(u, "restart_notify_minutes", 15),
    deadline: num(u, "restart_deadline_hours", 24),
    useWindow: bool(u, "window_enabled", false),
    days: list(u, "window_days").map((d) => String(DAY.indexOf(d))).filter((d) => d !== "-1"),
    windowStart: start,
    windowMinutes: end > start ? end - start : 24 * 60 - start + end,
  };
}

export interface RuleTemplate {
  id: string;
  name: string;
  classifications: string[];
  severities: string[];
  include_drivers: boolean;
  delay_days: number;
}

/** What a new auto-approval rule starts with. */
export function ruleDefaults(u: U) {
  return { drivers: bool(u, "rule_include_drivers", false), delay: num(u, "rule_delay_days", 0) };
}

/** The templates offered when adding a rule. */
export function ruleTemplates(u: U): RuleTemplate[] {
  const arr = Array.isArray(u?.["rule_templates"]) ? (u!["rule_templates"] as Record<string, unknown>[]) : [];
  return arr.map((t) => ({
    id: String(t["id"] ?? ""),
    name: String(t["name"] ?? ""),
    classifications: list(t, "classifications"),
    severities: list(t, "severities"),
    include_drivers: t["include_drivers"] === true,
    delay_days: typeof t["delay_days"] === "number" ? (t["delay_days"] as number) : 0,
  }));
}

/** The week's days in the organization's order: [0..6] (0 = Sunday) rotated to start at the chosen first day. */
export function weekOrder(first: string | undefined): number[] {
  const start = first === "sunday" ? 0 : first === "saturday" ? 6 : 1;
  return Array.from({ length: 7 }, (_, i) => (start + i) % 7);
}
