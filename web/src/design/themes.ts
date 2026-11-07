// The theme registry. A theme is one CSS file in ./themes: it holds the semantic tokens plus its name, its scheme
// (light or dark, for native controls) and its position in the picker. Adding a theme means adding one file there;
// nothing in this module or in any component changes.
import "./themes-entry";

const sources = import.meta.glob("./themes/*.css", { query: "?raw", import: "default", eager: true }) as Record<string, string>;

export interface ThemeDef {
  id: string;
  name: string;
  scheme: "light" | "dark";
  order: number;
  /** Every `--lp-*` token of the theme, without the prefix. */
  tokens: Record<string, string>;
}

export function parseTheme(id: string, css: string): ThemeDef {
  const tokens: Record<string, string> = {};
  for (const m of css.matchAll(/--lp-([a-z0-9-]+)\s*:([^;]+);/g)) tokens[m[1]!] = m[2]!.trim().replace(/^"(.*)"$/, "$1");
  const scheme = tokens["scheme"] === "dark" ? "dark" : "light";
  return { id, name: tokens["theme-name"] ?? id, scheme, order: Number(tokens["theme-order"] ?? 1000), tokens };
}

export const THEMES: ThemeDef[] = Object.entries(sources)
  .map(([path, css]) => parseTheme(/\/([a-z0-9-]+)\.css$/.exec(path)![1]!, css))
  .sort((a, b) => a.order - b.order || a.id.localeCompare(b.id));

export const SYSTEM_THEME = "system";
export const theme = (id: string): ThemeDef | undefined => THEMES.find((t) => t.id === id);

/** What the administrator allows: every known theme, or only the listed ones. "system" is offered separately. */
export function offeredThemes(allowed: readonly string[], known: readonly ThemeDef[] = THEMES): ThemeDef[] {
  return known.filter((t) => allowed.length === 0 || allowed.includes(t.id));
}

export interface ResolveInput {
  /** The person's own choice ("" = none, or "system"). */
  choice: string;
  /** The organization default ("" = follow the device). */
  orgDefault: string;
  /** The themes the organization offers (empty = all). */
  allowed: readonly string[];
  /** Whether the device prefers a dark appearance. */
  systemDark: boolean;
  /** Which theme ids exist. */
  exists: (id: string) => boolean;
}

/**
 * Picks the concrete theme to show: the person's choice if it is offered, else the organization's default, else the
 * device preference, else the first offered theme. src/design/theme-init.js (which runs before the first paint)
 * implements the same rules; theme-init.test.ts keeps the two in step.
 */
export function resolveTheme(i: ResolveInput): string {
  const offered = (id: string) => i.allowed.length === 0 || i.allowed.includes(id);
  const concrete = (id: string): string | null => {
    if (id === SYSTEM_THEME) {
      // Following the device maps to the plain light or dark theme, whatever else the organization offers.
      if (!offered(SYSTEM_THEME)) return null;
      for (const c of i.systemDark ? ["dark", "light"] : ["light", "dark"]) if (i.exists(c)) return c;
      return null;
    }
    return i.exists(id) && offered(id) ? id : null;
  };
  const order = [i.choice, i.orgDefault || SYSTEM_THEME, ...i.allowed, i.systemDark ? "dark" : "light"];
  for (const id of order) {
    if (!id) continue;
    const r = concrete(id);
    if (r) return r;
  }
  return i.exists("light") ? "light" : (THEMES[0]?.id ?? "light");
}
