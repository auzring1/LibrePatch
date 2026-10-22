// Dashboard layout: which widgets exist, in which order, and which the person has hidden. Pure functions, unit tested.

/** Stable widget ids (kebab-case, saved in the person's preferences) in their default order. */
export const WIDGET_IDS = ["tiles", "apps", "compliance", "top-missing", "attention", "activity", "agents"] as const;
export type WidgetId = (typeof WIDGET_IDS)[number];

export const WIDGET_TITLES: Record<WidgetId, string> = {
  tiles: "Key numbers",
  apps: "Apps out of date",
  compliance: "Patch compliance",
  "top-missing": "Top missing updates",
  attention: "Devices needing attention",
  activity: "Recent activity",
  agents: "Agent versions",
};

export interface SavedLayout {
  order?: string[];
  hidden?: string[];
}

export interface ResolvedLayout {
  /** Every known id in display order (hidden ones included), ready to be saved back. */
  order: string[];
  /** The ids to show, in order. */
  visible: string[];
  /** The ids the person has hidden. */
  hidden: string[];
}

/**
 * Combines the widgets the page knows (`allIds`, default order) with what the person saved.
 * Unknown saved ids are dropped, duplicates removed, and widgets the person has never seen are appended at the end.
 */
export function resolveLayout(allIds: readonly string[], saved?: SavedLayout | null): ResolvedLayout {
  const known = new Set(allIds);
  const order: string[] = [];
  const seen = new Set<string>();
  for (const id of [...(saved?.order ?? []), ...allIds]) {
    if (!known.has(id) || seen.has(id)) continue;
    seen.add(id);
    order.push(id);
  }
  const hiddenSet = new Set((saved?.hidden ?? []).filter((id) => known.has(id)));
  return { order, visible: order.filter((id) => !hiddenSet.has(id)), hidden: order.filter((id) => hiddenSet.has(id)) };
}

/**
 * Moves `id` one step up or down among the widgets in `among` (the ones the person can see on this page), leaving
 * widgets they cannot see where they are. Returns the new full order.
 */
export function moveWidget(order: readonly string[], id: string, dir: -1 | 1, among: readonly string[]): string[] {
  const list = order.filter((x) => among.includes(x));
  const i = list.indexOf(id);
  const j = i + dir;
  if (i < 0 || j < 0 || j >= list.length) return [...order];
  const a = order.indexOf(list[i]!);
  const b = order.indexOf(list[j]!);
  const next = [...order];
  next[a] = list[j]!;
  next[b] = list[i]!;
  return next;
}

/** Hides or shows one widget; returns the new hidden list (in display order). */
export function setWidgetHidden(order: readonly string[], hidden: readonly string[], id: string, hide: boolean): string[] {
  const set = new Set(hidden);
  if (hide) set.add(id);
  else set.delete(id);
  return order.filter((x) => set.has(x));
}
