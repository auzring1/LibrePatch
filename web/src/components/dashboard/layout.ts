// The original single-column dashboard layout (an order and a hidden list). Dashboards are now boards (boards.ts); this is
// kept to read what people saved before, so the default board starts from their choices. Pure functions, unit tested.

/** Stable widget ids (kebab-case, saved in the person's preferences) in their default order. */
export const WIDGET_IDS = ["start", "tiles", "apps", "compliance", "top-missing", "attention", "activity", "agents"] as const;
export type WidgetId = (typeof WIDGET_IDS)[number];

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
