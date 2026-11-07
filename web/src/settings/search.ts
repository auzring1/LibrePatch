import type { NavItem } from "../ui/nav";
import type { SettingsSection } from "./types";

export interface Hit {
  to: string;
  label: string;
  section: string;
}

/** Every word of the query must appear somewhere in the haystack. */
export const matchesQuery = (hay: string, q: string) => {
  const h = hay.toLowerCase();
  return q
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((w) => h.includes(w));
};

/** Finds settings by label, help text, key or the keywords of their section; also finds the sections themselves. */
export function searchSettings(sections: SettingsSection[], pages: NavItem[], q: string): Hit[] {
  const out: Hit[] = [];
  const allowedIds = new Set(pages.map((p) => p.section ?? p.id));
  for (const p of pages) {
    if (matchesQuery([p.label, ...(p.keywords ?? [])].join(" "), q)) out.push({ to: p.to, label: p.label, section: "Section" });
  }
  for (const s of sections) {
    if (!allowedIds.has(s.id)) continue;
    const page = pages.find((p) => (p.section ?? p.id) === s.id);
    for (const f of s.fields) {
      if (matchesQuery([f.label, f.help, f.key.replace(/_/g, " ")].join(" "), q)) out.push({ to: `${page?.to ?? "/settings/" + s.id}?field=${encodeURIComponent(f.key)}`, label: f.label, section: s.label });
    }
  }
  return out.slice(0, 25);
}
