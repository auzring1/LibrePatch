/** Formats a byte count (number or protobuf-JSON uint64 string). */
export function bytes(v: number | string | undefined): string {
  const n = typeof v === "string" ? Number(v) : (v ?? 0);
  if (!n || !Number.isFinite(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let x = n;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i++;
  }
  return `${x.toFixed(x >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

/** "3 min ago" style relative time. */
export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function duration(seconds: number | undefined): string {
  if (!seconds) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

export interface Display {
  locale: string;
  dateFormat: string; // locale | iso | dmy | mdy
  timeFormat: string; // locale | 24h | 12h
  timeZone: string; // "" = the viewer's own
}
let display: Display = { locale: "", dateFormat: "locale", timeFormat: "locale", timeZone: "" };

/** Sets how dates are shown (the organization's Appearance settings). */
export function setDisplay(d: Partial<Display>) {
  display = { ...display, ...d };
}

const safeZone = (z: string) => {
  try {
    if (z) new Intl.DateTimeFormat(undefined, { timeZone: z });
    return z || undefined;
  } catch {
    return undefined;
  }
};

/** A date in the organization's chosen format. */
export function formatDate(d: Date, o: Display = display): string {
  const tz = safeZone(o.timeZone);
  const loc = o.locale || undefined;
  if (o.dateFormat === "locale") return new Intl.DateTimeFormat(loc, { dateStyle: "medium", timeZone: tz }).format(d);
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-US", { year: "numeric", month: "2-digit", day: "2-digit", timeZone: tz }).formatToParts(d).map((p) => [p.type, p.value]));
  return o.dateFormat === "iso" ? `${parts["year"]}-${parts["month"]}-${parts["day"]}` : o.dateFormat === "dmy" ? `${parts["day"]}/${parts["month"]}/${parts["year"]}` : `${parts["month"]}/${parts["day"]}/${parts["year"]}`;
}

/** A date and time in the organization's chosen format and time zone. */
export function formatDateTime(d: Date, o: Display = display): string {
  const tz = safeZone(o.timeZone);
  const loc = o.locale || undefined;
  const hour12 = o.timeFormat === "12h" ? true : o.timeFormat === "24h" ? false : undefined;
  const time = new Intl.DateTimeFormat(loc, { hour: "2-digit", minute: "2-digit", hour12, timeZone: tz }).format(d);
  return `${formatDate(d, o)} ${time}`;
}

export const dateTime = (iso: string | null | undefined) => (iso ? formatDateTime(new Date(iso)) : "—");

/** Minutes after midnight as "HH:MM". */
export const hhmm = (min: number) => `${String(Math.floor(min / 60)).padStart(2, "0")}:${String(min % 60).padStart(2, "0")}`;

/** "HH:MM" as minutes after midnight (0 when it does not parse). */
export const parseHHMM = (s: string) => {
  const m = /^(\d{1,2}):(\d{2})$/.exec(s.trim());
  return m ? Math.min(1439, Number(m[1]) * 60 + Math.min(59, Number(m[2]))) : 0;
};
