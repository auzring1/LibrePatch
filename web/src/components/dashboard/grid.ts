// The dashboard grid: a 12-column board where widgets sit at (x, y) with a width and a height in cells. Pure functions
// (unit tested) used by the editor: drop a widget somewhere, and the rest settle around it.

export const COLS = 12;
/** The server accepts rows up to this number (api/preferences.go). */
export const MAX_ROWS = 400;

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}
export interface Placed extends Rect {
  id: string;
}

export function overlaps(a: Rect, b: Rect): boolean {
  return a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h;
}

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, Math.round(Number.isFinite(n) ? n : lo)));

/** Keeps a rectangle on the grid and at least `min` cells big. */
export function clampRect(r: Rect, min: { w: number; h: number } = { w: 1, h: 1 }): Rect {
  const w = clamp(r.w, Math.min(min.w, COLS), COLS);
  const h = clamp(r.h, min.h, 60);
  return { x: clamp(r.x, 0, COLS - w), y: clamp(r.y, 0, MAX_ROWS - h), w, h };
}

/**
 * Lays the widgets out without overlaps. A widget that is being moved or resized (`pinned`) keeps its place; every other
 * one falls as far up as it can, in reading order, like items settling under gravity. With nothing pinned this is a
 * plain "tidy up".
 */
export function settle(items: readonly Placed[], pinned?: Placed): Placed[] {
  const placed: Placed[] = pinned ? [pinned] : [];
  const rest = items.filter((i) => i.id !== pinned?.id).sort((a, b) => a.y - b.y || a.x - b.x);
  for (const item of rest) {
    // The lowest free row: row 0, or the row just under something already placed.
    const rows = [0, ...placed.map((p) => p.y + p.h)].sort((a, b) => a - b);
    const y = rows.find((row) => !placed.some((p) => overlaps({ ...item, y: row }, p))) ?? 0;
    placed.push({ ...item, y });
  }
  // Same order as the input, so callers can compare or render it without reshuffling.
  const byId = new Map(placed.map((p) => [p.id, p]));
  return items.map((i) => byId.get(i.id)!);
}

/** Moves or resizes one widget and lets the others settle around it. `min` is that widget's smallest size. */
export function place(items: readonly Placed[], id: string, to: Rect, min?: { w: number; h: number }): Placed[] {
  const r = clampRect(to, min);
  return settle(items, { id, ...r });
}

/** The row just under everything: where a new widget goes. */
export function bottom(items: readonly Rect[]): number {
  return items.reduce((m, i) => Math.max(m, i.y + i.h), 0);
}

/**
 * Packs widgets of the given sizes from left to right, wrapping when a row is full; each row is as tall as its tallest
 * widget. The default dashboard is built this way from whatever the signed-in person may see, so a missing widget
 * never leaves a hole.
 */
export function flow(sizes: readonly { id: string; w: number; h: number }[]): Placed[] {
  const out: Placed[] = [];
  let x = 0;
  let y = 0;
  let rowH = 0;
  for (const s of sizes) {
    const w = Math.min(s.w, COLS);
    if (x + w > COLS) {
      y += rowH;
      x = 0;
      rowH = 0;
    }
    out.push({ id: s.id, x, y, w, h: s.h });
    x += w;
    rowH = Math.max(rowH, s.h);
  }
  return out;
}

/** Reading order (top to bottom, left to right): the order of the single column used on a phone. */
export function readingOrder<T extends Rect>(items: readonly T[]): T[] {
  return [...items].sort((a, b) => a.y - b.y || a.x - b.x);
}
