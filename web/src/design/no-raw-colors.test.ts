import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// Components use semantic tokens (var(--lp-*)), never raw colors, so every theme (and the branding accent layered on
// it) applies everywhere. Theme files, the design folder and the branding preview are where raw colors belong. A line
// can opt out with the marker "lp-allow-raw-color" and a reason.
const ROOTS = ["src/ui", "src/pages", "src/components"];
const RAW = /#[0-9a-fA-F]{3,8}\b|\brgba?\((?!\s*var\()|\bhsla?\((?!\s*var\()|\b(?:white|black)\b(?=\s*[;"'}])/g;

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : /\.(tsx?|css)$/.test(f) && !/\.test\./.test(f) ? [p] : [];
  });
}

describe("no raw colors in components", () => {
  it("only semantic tokens are used", () => {
    const bad: string[] = [];
    for (const root of ROOTS) {
      for (const f of files(root)) {
        readFileSync(f, "utf8")
          .split("\n")
          .forEach((line, i) => {
            if (line.includes("lp-allow-raw-color")) return;
            if (/^\s*(\/\/|\*|\/\*)/.test(line)) return;
            for (const m of line.matchAll(RAW)) bad.push(`${relative(".", f)}:${i + 1}: ${m[0]}  ${line.trim().slice(0, 90)}`);
          });
      }
    }
    expect(bad).toEqual([]);
  });
});
