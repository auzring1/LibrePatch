// Dashboards (boards) and widget instances as they are saved in the person's preferences, and the pure logic around them:
// the default board, turning the old single layout into a board, and editing a board.

import { flow, place, settle, bottom, type Placed } from "./grid";
import { WIDGET_IDS, resolveLayout, type SavedLayout } from "./layout";

export type WidgetKind =
  | "stat"
  | "compliance"
  | "apps"
  | "top-missing"
  | "attention"
  | "activity"
  | "agents"
  | "start"
  | "vulnerabilities"
  | "shortcut"
  | "text";

export interface WidgetSettings {
  title?: string;
  site?: string;
  range?: string;
  count?: number;
  metric?: string;
  dest?: string;
  text?: string;
}

export interface BoardWidget {
  id: string;
  type: string;
  x: number;
  y: number;
  w: number;
  h: number;
  settings?: WidgetSettings;
}

export type Refresh = 0 | 30 | 60 | 300;

export interface Board {
  id: string;
  name: string;
  /** Seconds between refreshes; 0 = never. */
  refresh: Refresh;
  widgets: BoardWidget[];
}

export const REFRESH_CHOICES: { value: Refresh; label: string }[] = [
  { value: 0, label: "Never" },
  { value: 30, label: "Every 30 seconds" },
  { value: 60, label: "Every minute" },
  { value: 300, label: "Every 5 minutes" },
];

/** Default size of each kind of widget and the smallest it may be resized to, in grid cells (12 columns wide). */
export const WIDGET_SIZES: Record<WidgetKind, { w: number; h: number; minW: number; minH: number }> = {
  stat: { w: 2, h: 2, minW: 2, minH: 2 },
  start: { w: 12, h: 3, minW: 4, minH: 2 },
  compliance: { w: 6, h: 6, minW: 4, minH: 4 },
  apps: { w: 6, h: 6, minW: 3, minH: 3 },
  "top-missing": { w: 6, h: 6, minW: 3, minH: 3 },
  attention: { w: 6, h: 6, minW: 3, minH: 3 },
  activity: { w: 6, h: 6, minW: 3, minH: 3 },
  agents: { w: 6, h: 6, minW: 3, minH: 3 },
  vulnerabilities: { w: 6, h: 6, minW: 3, minH: 3 },
  shortcut: { w: 3, h: 2, minW: 2, minH: 2 },
  text: { w: 4, h: 3, minW: 2, minH: 2 },
};

export function sizeOf(type: string) {
  return WIDGET_SIZES[type as WidgetKind] ?? { w: 4, h: 3, minW: 1, minH: 1 };
}

const rand = () => Math.random().toString(36).slice(2, 8).padEnd(6, "0");
export const newWidgetId = () => `w${rand()}`;
export const newBoardId = () => `b${rand()}`;

/** The stat tiles of the original "Key numbers" strip, in order. */
const DEFAULT_STATS = ["online", "offline", "apps", "restart", "critical", "failed"];

export const DEFAULT_BOARD_ID = "overview";
export const DEFAULT_BOARD_NAME = "Overview";

/**
 * The dashboard everyone starts with: the getting-started card, one stat tile per key number, then the original widgets.
 * `available` says which kinds and stat metrics this person can see; what they cannot see is left out and the rest close
 * up. `legacy` is the old single layout (order and hidden), honoured so nobody's earlier choices are lost.
 */
export function defaultBoard(available: { kinds: readonly string[]; metrics: readonly string[] }, legacy?: SavedLayout | null): Board {
  const layout = resolveLayout(WIDGET_IDS, legacy);
  const sizes: { id: string; type: string; w: number; h: number; settings?: WidgetSettings }[] = [];
  for (const id of layout.visible) {
    if (id === "tiles") {
      for (const m of DEFAULT_STATS) {
        if (available.kinds.includes("stat") && available.metrics.includes(m)) sizes.push({ id: `stat-${m}`, type: "stat", ...pick(sizeOf("stat")), settings: { metric: m } });
      }
      continue;
    }
    if (!available.kinds.includes(id)) continue;
    sizes.push({ id: `${id}-1`, type: id, ...pick(sizeOf(id)) });
  }
  const placed = flow(sizes);
  const byId = new Map(sizes.map((s) => [s.id, s]));
  return {
    id: DEFAULT_BOARD_ID,
    name: DEFAULT_BOARD_NAME,
    refresh: 60,
    widgets: placed.map((p) => ({ ...p, type: byId.get(p.id)!.type, settings: byId.get(p.id)!.settings ?? {} })),
  };
}

const pick = (s: { w: number; h: number }) => ({ w: s.w, h: s.h });

/** The board a widget list with unknown kinds removed would show; kinds the console does not know are skipped, not deleted. */
export function knownWidgets(widgets: readonly BoardWidget[], known: readonly string[]): BoardWidget[] {
  return widgets.filter((w) => known.includes(w.type));
}

export function toPlaced(widgets: readonly BoardWidget[]): Placed[] {
  return widgets.map(({ id, x, y, w, h }) => ({ id, x, y, w, h }));
}

/** Writes new positions back onto the widgets (by id), leaving everything else as it was. */
export function withPositions(widgets: readonly BoardWidget[], placed: readonly Placed[]): BoardWidget[] {
  const byId = new Map(placed.map((p) => [p.id, p]));
  return widgets.map((w) => {
    const p = byId.get(w.id);
    return p ? { ...w, x: p.x, y: p.y, w: p.w, h: p.h } : w;
  });
}

/** Adds a widget of `type` at the bottom of the board. */
export function addWidget(board: Board, type: string, settings: WidgetSettings = {}): { board: Board; id: string } {
  const s = sizeOf(type);
  const id = newWidgetId();
  const widgets = [...board.widgets, { id, type, x: 0, y: bottom(board.widgets), w: s.w, h: s.h, settings }];
  return { board: { ...board, widgets }, id };
}

export function removeWidget(board: Board, id: string): Board {
  const rest = board.widgets.filter((w) => w.id !== id);
  return { ...board, widgets: withPositions(rest, settle(toPlaced(rest))) };
}

/** A copy of a widget placed under the board (then settled up beside the original when there is room). */
export function duplicateWidget(board: Board, id: string): { board: Board; id: string } {
  const src = board.widgets.find((w) => w.id === id);
  if (!src) return { board, id };
  const copy = { ...src, id: newWidgetId(), settings: { ...src.settings }, y: bottom(board.widgets) };
  const widgets = [...board.widgets, copy];
  return { board: { ...board, widgets: withPositions(widgets, settle(toPlaced(widgets))) }, id: copy.id };
}

export function updateSettings(board: Board, id: string, settings: WidgetSettings): Board {
  return { ...board, widgets: board.widgets.map((w) => (w.id === id ? { ...w, settings } : w)) };
}

/** Moves or resizes one widget; the others settle around it. */
export function moveResize(board: Board, id: string, to: { x: number; y: number; w: number; h: number }): Board {
  const w = board.widgets.find((x) => x.id === id);
  if (!w) return board;
  const s = sizeOf(w.type);
  return { ...board, widgets: withPositions(board.widgets, place(toPlaced(board.widgets), id, to, { w: s.minW, h: s.minH })) };
}

/** Removes empty settings so the saved document stays small. */
export function cleanSettings(s: WidgetSettings): WidgetSettings {
  const out: WidgetSettings = {};
  if (s.title?.trim()) out.title = s.title.trim();
  if (s.site) out.site = s.site;
  if (s.range) out.range = s.range;
  if (s.count) out.count = s.count;
  if (s.metric) out.metric = s.metric;
  if (s.dest) out.dest = s.dest;
  if (s.text?.trim()) out.text = s.text;
  return out;
}

/** A name for a copy of a board that is not taken yet ("Operations (copy)", "Operations (copy 2)"). */
export function copyName(name: string, taken: readonly string[]): string {
  const base = name.replace(/ \(copy( \d+)?\)$/, "").slice(0, 30);
  let candidate = `${base} (copy)`;
  for (let n = 2; taken.includes(candidate); n++) candidate = `${base} (copy ${n})`;
  return candidate;
}
