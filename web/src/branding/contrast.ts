// WCAG 2.1 contrast checks for the accent and secondary colors. This mirrors internal/server/branding/contrast.go
// (the server enforces the same rules; both are tested against testdata/contrast_vectors.json).

export const WHITE = "#ffffff";
/** The page background of the dark theme. */
export const DARK_SURFACE = "#1a1b1e";
export const DEFAULT_ACCENT = "#1971c2";
/** WCAG AA for normal text (1.4.3). */
export const MIN_TEXT = 4.5;
/** WCAG AA for user-interface components and graphics (1.4.11). */
export const MIN_UI = 3.0;

export interface Check {
  id: string;
  label: string;
  foreground: string;
  background: string;
  ratio: number;
  required: number;
  pass: boolean;
}

const HEX = /^#[0-9a-fA-F]{6}$/;

export const isHexColor = (c: string): boolean => HEX.test(c.trim());

export function parseHex(c: string): [number, number, number] {
  if (!isHexColor(c)) throw new Error(`"${c}" is not a color like #1971c2`);
  const v = Number.parseInt(c.trim().slice(1), 16);
  return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
}

export function toHex([r, g, b]: [number, number, number]): string {
  return "#" + [r, g, b].map((x) => Math.max(0, Math.min(255, Math.round(x))).toString(16).padStart(2, "0")).join("");
}

const channel = (c: number): number => {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
};

export function luminance(c: string): number {
  const [r, g, b] = parseHex(c);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

/** The WCAG contrast ratio of two #rrggbb colors, from 1 to 21. */
export function contrast(a: string, b: string): number {
  let la = luminance(a);
  let lb = luminance(b);
  if (la < lb) [la, lb] = [lb, la];
  return (la + 0.05) / (lb + 0.05);
}

const check = (id: string, label: string, fg: string, bg: string, required: number): Check => {
  const ratio = Math.round(contrast(fg, bg) * 100) / 100;
  return { id, label, foreground: fg, background: bg, ratio, required, pass: ratio >= required };
};

/** The pairs the interface actually draws with the accent (empty means the default) and the optional secondary color. */
export function checks(accent: string, secondary: string): Check[] {
  const a = accent.trim() || DEFAULT_ACCENT;
  const out = [
    check("accent_text_light", "Button text (white) on the accent color, and accent links on the white page", WHITE, a, MIN_TEXT),
    check("accent_ui_dark", "Accent outlines and focus rings on the dark theme", a, DARK_SURFACE, MIN_UI),
  ];
  const s = secondary.trim();
  if (s) {
    out.push(
      check("secondary_ui_light", "Secondary color graphics on the white page", s, WHITE, MIN_UI),
      check("secondary_ui_dark", "Secondary color graphics on the dark theme", s, DARK_SURFACE, MIN_UI),
    );
  }
  return out;
}

export interface ColorProblem {
  accent?: string;
  secondary?: string;
}

/** Checks the two colors as typed: format first, then contrast. Returns the problems per field (empty = fine to save). */
export function colorProblems(accent: string, secondary: string): ColorProblem {
  const p: ColorProblem = {};
  if (accent.trim() && !isHexColor(accent)) p.accent = "Use a color like #1971c2.";
  if (secondary.trim() && !isHexColor(secondary)) p.secondary = "Use a color like #e8590c.";
  if (p.accent || p.secondary) return p;
  for (const c of checks(accent, secondary)) {
    if (c.pass) continue;
    const field = c.id.startsWith("secondary") ? "secondary" : "accent";
    p[field] ??= `Not accessible enough: needs ${c.required.toFixed(1)}:1 but has ${c.ratio.toFixed(2)}:1 (${c.label.toLowerCase()}).`;
  }
  return p;
}

/** Suggested accents: each passes every check on the light, dark and stock surfaces. */
export const ACCENT_SWATCHES = ["#1971c2", "#c92a2a", "#0b7285", "#087f5b", "#7048e8", "#d6336c"];
/** Suggested secondary colors (graphics only, 3:1 on light and dark). */
export const SECONDARY_SWATCHES = ["#e8590c", "#2f9e44", "#1971c2", "#d6336c", "#7048e8", "#0b7285"];

