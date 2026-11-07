import { readFileSync } from "node:fs";
import { runInNewContext } from "node:vm";
import { describe, expect, it } from "vitest";
import { contrast } from "../branding/contrast";
import { DEFAULT_ACCENT } from "../branding/contrast";
import { deriveAccent, deriveSecondary, SURFACE_KEYS } from "./accent";
import { offeredThemes, parseTheme, resolveTheme, SYSTEM_THEME, THEMES, type ThemeDef } from "./themes";

const FAMILIES = ["success", "warning", "danger", "info", "neutral", "critical", "important", "moderate", "low"] as const;
const FIELDS = ["bg", "surface", "surface-raised", "surface-sunken"] as const;

/** Every foreground/background pair a component can draw, with the WCAG AA ratio it needs. */
function pairs(t: ThemeDef): { what: string; fg: string; bg: string; min: number }[] {
  const k = t.tokens;
  const out: { what: string; fg: string; bg: string; min: number }[] = [];
  const add = (what: string, fg: string, bg: string, min: number) => out.push({ what, fg: k[fg] ?? fg, bg: k[bg] ?? bg, min });
  for (const s of SURFACE_KEYS) {
    add(`text on ${s}`, "text", s, 4.5);
    add(`muted text on ${s}`, "text-muted", s, 4.5);
    add(`accent text on ${s}`, "accent-text", s, 4.5);
    for (const f of FAMILIES) add(`${f} text/icon on ${s}`, `${f}-fg`, s, 4.5);
  }
  for (const s of FIELDS) {
    add(`control border on ${s}`, "border-strong", s, 3);
    add(`focus ring on ${s}`, "focus", s, 3);
    add(`accent fill on ${s}`, "accent", s, 3);
    for (const f of FAMILIES) add(`${f} fill on ${s}`, `${f}-solid`, s, 3);
    for (let i = 1; i <= 6; i++) add(`chart series ${i} on ${s}`, `chart-${i}`, s, 3);
  }
  add("text on accent", "on-accent", "accent", 4.5);
  add("text on subtle accent", "accent-subtle-text", "accent-subtle", 4.5);
  add("text on selected row", "text", "surface-selected", 4.5);
  for (const f of FAMILIES) {
    add(`${f} pill text`, `${f}-fg`, `${f}-bg`, 4.5);
    add(`text on ${f} fill`, "on-solid", `${f}-solid`, 4.5);
  }
  return out;
}

describe("themes", () => {
  it("ships Light, Dark, High contrast, Slate and Midnight", () => {
    expect(THEMES.map((t) => t.id)).toEqual(expect.arrayContaining(["light", "dark", "contrast", "slate", "midnight"]));
    expect(THEMES.length).toBeGreaterThanOrEqual(5);
    for (const t of THEMES) {
      expect(["light", "dark"]).toContain(t.scheme);
      expect(t.name.length).toBeGreaterThan(0);
    }
  });

  it("defines the same tokens in every theme (a theme file is complete)", () => {
    const first = Object.keys(THEMES[0]!.tokens).sort();
    for (const t of THEMES) expect(Object.keys(t.tokens).sort(), t.id).toEqual(first);
  });

  for (const t of THEMES) {
    it(`${t.id}: every text, border, focus, status, severity and chart color meets WCAG AA`, () => {
      const fails = pairs(t)
        .map((p) => ({ ...p, ratio: contrast(p.fg, p.bg) }))
        .filter((p) => p.ratio < p.min)
        .map((p) => `${p.what}: ${p.fg} on ${p.bg} = ${p.ratio.toFixed(2)} (needs ${p.min})`);
      expect(fails).toEqual([]);
    });
  }

  it("a new theme is just a file: parsing one needs nothing else", () => {
    const t = parseTheme("sunrise", ':root[data-theme="sunrise"] { --lp-theme-name: "Sunrise"; --lp-scheme: light; --lp-theme-order: 60; --lp-bg: #ffffff; }');
    expect(t).toMatchObject({ id: "sunrise", name: "Sunrise", scheme: "light", order: 60 });
    expect(t.tokens["bg"]).toBe("#ffffff");
  });
});

describe("branding accent layered on every theme", () => {
  // Includes colors the server would refuse (yellow, near-white, near-black): the console must stay readable anyway.
  const accents = [DEFAULT_ACCENT, "#c92a2a", "#e8590c", "#0b7285", "#087f5b", "#ffd43b", "#ffffff", "#000000", "#777777", "#123456", "#9c36b5", "#f783ac"];
  for (const t of THEMES) {
    it(`${t.id}: derived accent colors meet WCAG AA for ${accents.length} accents`, () => {
      const fails: string[] = [];
      for (const a of accents) {
        const d = deriveAccent(a, t);
        const need = (what: string, fg: string, bg: string, min: number) => {
          const r = contrast(fg, bg);
          if (r < min) fails.push(`${a} ${what}: ${fg} on ${bg} = ${r.toFixed(2)} (needs ${min})`);
        };
        for (const f of FIELDS) need(`fill on ${f}`, d.accent, t.tokens[f]!, 3);
        need("text on fill", d.onAccent, d.accent, 4.5);
        for (const s of SURFACE_KEYS) need(`accent text on ${s}`, d.accentText, t.tokens[s]!, 4.5);
        need("text on subtle", d.subtleText, d.subtle, 4.5);
        need("body text on selected row", t.tokens["text"]!, d.selected, 4.5);
        need("muted text on selected row", t.tokens["text-muted"]!, d.selected, 4.5);
        need("body text on subtle", t.tokens["text"]!, d.subtle, 4.5);
        for (const f of FIELDS) need(`secondary on ${f}`, deriveSecondary(a, t), t.tokens[f]!, 3);
      }
      expect(fails).toEqual([]);
    });
  }

  it("keeps a good accent as it is", () => {
    const light = THEMES.find((t) => t.id === "light")!;
    expect(deriveAccent(DEFAULT_ACCENT, light).accent).toBe(DEFAULT_ACCENT);
  });
});

describe("choosing a theme", () => {
  const exists = (id: string) => THEMES.some((t) => t.id === id);
  const base = { choice: "", orgDefault: "", allowed: [] as string[], systemDark: false, exists };
  it("follows the device when nothing is chosen", () => {
    expect(resolveTheme(base)).toBe("light");
    expect(resolveTheme({ ...base, systemDark: true })).toBe("dark");
  });
  it("uses the person's choice, then the organization default", () => {
    expect(resolveTheme({ ...base, choice: "midnight", orgDefault: "slate" })).toBe("midnight");
    expect(resolveTheme({ ...base, orgDefault: "slate" })).toBe("slate");
    expect(resolveTheme({ ...base, choice: SYSTEM_THEME, systemDark: true, orgDefault: "slate" })).toBe("dark");
  });
  it("ignores a theme that is unknown or not offered", () => {
    expect(resolveTheme({ ...base, choice: "removed-theme" })).toBe("light");
    expect(resolveTheme({ ...base, choice: "midnight", allowed: ["light", "dark"], orgDefault: "dark" })).toBe("dark");
    expect(resolveTheme({ ...base, choice: "midnight", allowed: ["slate"] })).toBe("slate");
    expect(offeredThemes(["light", "nope"]).map((t) => t.id)).toEqual(["light"]);
  });
});

describe("theme-init.js (runs before first paint) agrees with resolveTheme", () => {
  const src = readFileSync(new URL("../../public/theme-init.js", import.meta.url), "utf8");
  const run = (o: { choice?: string; org?: object; dark?: boolean; known?: string[]; density?: string }) => {
    const attrs: Record<string, string> = {};
    const known = o.known ?? THEMES.map((t) => t.id);
    const store: Record<string, string> = { ...(o.choice ? { "lp-theme": o.choice } : {}), ...(o.density ? { "lp-density": o.density } : {}) };
    const root = {
      setAttribute: (k: string, v: string) => void (attrs[k] = v),
      __theme: () => attrs["data-theme"],
    };
    const ctx = {
      document: { documentElement: root, getElementById: () => (o.org ? { textContent: JSON.stringify(o.org) } : null) },
      window: { localStorage: { getItem: (k: string) => store[k] ?? null }, matchMedia: () => ({ matches: !!o.dark }) },
      getComputedStyle: () => ({ getPropertyValue: () => (known.includes(attrs["data-theme"]!) ? " light" : "") }),
    };
    runInNewContext(src, ctx);
    return attrs;
  };
  const cases: { name: string; o: Parameters<typeof run>[0]; i: { choice: string; orgDefault: string; allowed: string[]; systemDark: boolean } }[] = [
    { name: "nothing set, light device", o: {}, i: { choice: "", orgDefault: "", allowed: [], systemDark: false } },
    { name: "nothing set, dark device", o: { dark: true }, i: { choice: "", orgDefault: "", allowed: [], systemDark: true } },
    { name: "saved choice", o: { choice: "midnight" }, i: { choice: "midnight", orgDefault: "", allowed: [], systemDark: false } },
    { name: "saved choice system on dark device", o: { choice: "system", dark: true }, i: { choice: "system", orgDefault: "", allowed: [], systemDark: true } },
    { name: "org default", o: { org: { default_theme: "slate", allowed_themes: [] } }, i: { choice: "", orgDefault: "slate", allowed: [], systemDark: false } },
    { name: "choice not offered", o: { choice: "midnight", org: { default_theme: "dark", allowed_themes: ["light", "dark"] } }, i: { choice: "midnight", orgDefault: "dark", allowed: ["light", "dark"], systemDark: false } },
    { name: "only one offered", o: { choice: "light", org: { allowed_themes: ["slate"] } }, i: { choice: "light", orgDefault: "", allowed: ["slate"], systemDark: false } },
    { name: "stale unknown choice", o: { choice: "gone" }, i: { choice: "gone", orgDefault: "", allowed: [], systemDark: false } },
  ];
  for (const c of cases) {
    it(c.name, () => {
      const ids = THEMES.map((t) => t.id);
      expect(run(c.o)["data-theme"]).toBe(resolveTheme({ ...c.i, exists: (id) => ids.includes(id) }));
    });
  }
  it("applies a saved density", () => {
    expect(run({ density: "compact" })["data-density"]).toBe("compact");
    expect(run({ density: "weird" })["data-density"]).toBeUndefined();
  });
});
