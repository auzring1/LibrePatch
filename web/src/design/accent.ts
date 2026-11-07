// Layers the branding accent (and optional secondary color) on top of any theme.
//
// The server only checks the accent against white and the stock dark surface (see internal/server/branding). The
// console has more themes than that, so the accent is adapted per theme: lightened or darkened, in small steps, until
// every use of it meets WCAG AA on that theme's surfaces. The adjusted colors are set as CSS variables on the root
// element; a theme file provides defaults for the same variables.
import { contrast, isHexColor, parseHex, toHex } from "../branding/contrast";
import type { ThemeDef } from "./themes";

type Rgb = [number, number, number];
const mix = (a: Rgb, b: Rgb, t: number): Rgb => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
const mixHex = (a: string, b: string, t: number) => toHex(mix(parseHex(a), parseHex(b), t));
const WHITE = "#ffffff";
const BLACK = "#000000";

/** The surfaces text and graphics sit on. */
export const SURFACE_KEYS = ["bg", "surface", "surface-raised", "surface-sunken", "surface-hover", "surface-selected"] as const;
/** The surfaces an accent fill or a graphic has to stand out from. */
const FIELD_KEYS = ["bg", "surface", "surface-raised", "surface-sunken"] as const;

export interface DerivedAccent {
  accent: string;
  onAccent: string;
  accentText: string;
  subtle: string;
  subtleText: string;
  border: string;
  selected: string;
}

const best = (c: string) => (contrast(c, WHITE) >= contrast(c, BLACK) ? WHITE : BLACK);
const minContrast = (c: string, others: string[]) => Math.min(...others.map((o) => contrast(c, o)));

/** Moves `color` towards `toward` in 2% steps until `ok` accepts it (the extreme if none does). */
function adjust(color: string, toward: string, ok: (c: string) => boolean): string {
  for (let t = 0; t <= 1.0001; t += 0.02) {
    const c = mixHex(color, toward, Math.min(t, 1));
    if (ok(c)) return c;
  }
  return toward;
}

/** Derives the accent colors for one theme. `accent` is any #rrggbb color (even one the server would refuse). */
export function deriveAccent(accent: string, t: ThemeDef): DerivedAccent {
  const tk = t.tokens;
  const dark = t.scheme === "dark";
  const toward = dark ? WHITE : BLACK;
  const field = FIELD_KEYS.map((k) => tk[k]!);
  const all = SURFACE_KEYS.map((k) => tk[k]!);
  const fill = adjust(accent, toward, (c) => minContrast(c, field) >= 3 && contrast(c, best(c)) >= 4.5);
  const accentText = adjust(fill, toward, (c) => minContrast(c, all) >= 4.5);
  const surface = tk["surface"]!;
  const subtle = mixHex(fill, surface, 0.84);
  const subtleText = adjust(accentText, toward, (c) => contrast(c, subtle) >= 4.5 && contrast(c, tk["surface-hover"]!) >= 4.5);
  const selected = mixHex(fill, surface, 0.88);
  return { accent: fill, onAccent: best(fill), accentText, subtle, subtleText, border: mixHex(fill, surface, 0.45), selected };
}

/** A secondary color for graphics: it must stand out from the page (3:1) on this theme. */
export function deriveSecondary(color: string, t: ThemeDef): string {
  const dark = t.scheme === "dark";
  const field = FIELD_KEYS.map((k) => t.tokens[k]!);
  return adjust(color, dark ? WHITE : BLACK, (c) => minContrast(c, field) >= 3);
}

const VARS: Record<keyof DerivedAccent, string> = {
  accent: "--lp-accent",
  onAccent: "--lp-on-accent",
  accentText: "--lp-accent-text",
  subtle: "--lp-accent-subtle",
  subtleText: "--lp-accent-subtle-text",
  border: "--lp-accent-border",
  selected: "--lp-surface-selected",
};

/** Sets (or clears) the derived colors on `root`. An empty or invalid accent leaves the theme's own defaults. */
export function applyAccent(root: HTMLElement, t: ThemeDef, accent: string, secondary: string) {
  const set = (name: string, value: string | null) => (value ? root.style.setProperty(name, value) : root.style.removeProperty(name));
  const d = isHexColor(accent) ? deriveAccent(accent.toLowerCase(), t) : null;
  for (const k of Object.keys(VARS) as (keyof DerivedAccent)[]) set(VARS[k], d ? d[k] : null);
  set("--lp-secondary", isHexColor(secondary) ? deriveSecondary(secondary.toLowerCase(), t) : null);
}
