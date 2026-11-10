import type { ReportColumn, ReportDataset, ReportFilter, ReportSpec } from "../api/client";

/** The words for each comparison, by the kind of column. Numbers and dates read differently from text. */
const OP_LABELS: Record<string, Record<string, string>> = {
  text: { contains: "contains", not_contains: "does not contain", eq: "is", ne: "is not", starts_with: "starts with", is_empty: "is empty", not_empty: "is not empty" },
  number: { eq: "equals", ne: "does not equal", gt: "is more than", ge: "is at least", lt: "is less than", le: "is at most", is_empty: "is unknown", not_empty: "is known" },
  bool: { is: "is" },
  time: { within_days: "is within the last (days)", older_than_days: "is older than (days), or never", before: "is before", after: "is on or after", is_empty: "is never", not_empty: "has a date" },
};

export const opLabel = (kind: string, op: string) => OP_LABELS[kind]?.[op] ?? op;

/** Comparisons that need no value (the value box is hidden). */
export const opNeedsValue = (op: string) => op !== "is_empty" && op !== "not_empty";

/** A new filter row for a column: its first comparison and a sensible starting value. */
export function newFilter(col: ReportColumn): ReportFilter {
  const op = col.ops[0] ?? "eq";
  return { column: col.id, op, value: col.kind === "bool" ? "true" : col.choices?.[0] && op === "eq" ? col.choices[0] : "" };
}

/** Whether the row can be sent (a value is present when the comparison needs one). */
export function filterReady(col: ReportColumn | undefined, f: ReportFilter): boolean {
  if (!col || !col.ops.includes(f.op)) return false;
  if (!opNeedsValue(f.op)) return true;
  const v = (f.value ?? "").trim();
  if (v === "") return false;
  if (col.kind === "number" || (col.kind === "time" && (f.op === "within_days" || f.op === "older_than_days"))) return Number.isFinite(Number(v));
  if (col.kind === "time") return /^\d{4}-\d{2}-\d{2}$/.test(v);
  if (col.kind === "bool") return v === "true" || v === "false";
  return true;
}

/** A report with the dataset's own default columns and no filters. */
export function startSpec(ds: ReportDataset): ReportSpec {
  return { dataset: ds.id, columns: [...ds.default_columns], filters: [] };
}

/**
 * Makes a spec safe to run after the person changed something: unknown columns are dropped, the sort follows a shown
 * column, and filter rows that are not finished (no value yet) are left out of what is sent.
 */
export function sendable(spec: ReportSpec, ds: ReportDataset | undefined): ReportSpec {
  if (!ds) return spec;
  const byId = new Map(ds.columns.map((c) => [c.id, c]));
  const columns = spec.columns.filter((c, i, all) => byId.has(c) && all.indexOf(c) === i);
  const filters = (spec.filters ?? []).filter((f) => filterReady(byId.get(f.column), f)).map((f) => ({ column: f.column, op: f.op, ...(opNeedsValue(f.op) ? { value: (f.value ?? "").trim() } : {}) }));
  const out: ReportSpec = { dataset: spec.dataset, columns, filters };
  if (spec.site_ids?.length) out.site_ids = spec.site_ids;
  if (spec.group_id) out.group_id = spec.group_id;
  if (spec.sort && columns.includes(spec.sort.column)) out.sort = spec.sort;
  return out;
}

/** One line that says what a report is limited to, for the page and the PDF note. */
export function scopeText(spec: ReportSpec, siteNames: Map<string, string>, groupName?: string): string {
  const parts: string[] = [];
  if (spec.site_ids?.length) parts.push(`sites: ${spec.site_ids.map((id) => siteNames.get(id) ?? "?").join(", ")}`);
  if (spec.group_id) parts.push(`group: ${groupName ?? "?"}`);
  return parts.length ? parts.join("; ") : "all devices";
}

/** Columns grouped for the picker, in the order the dataset lists them. */
export function groupedColumns(ds: ReportDataset): { group: string; columns: ReportColumn[] }[] {
  const out: { group: string; columns: ReportColumn[] }[] = [];
  for (const c of ds.columns) {
    let g = out.find((x) => x.group === c.group);
    if (!g) out.push((g = { group: c.group, columns: [] }));
    g.columns.push(c);
  }
  return out;
}

/** Switching the kind of data keeps what still fits: nothing, in practice, so it starts from that data's defaults. */
export function switchDataset(spec: ReportSpec, next: ReportDataset): ReportSpec {
  const keep = spec.columns.filter((c) => next.columns.some((x) => x.id === c));
  return { ...startSpec(next), columns: keep.length ? keep : [...next.default_columns], site_ids: spec.site_ids, group_id: spec.group_id };
}

/** The same definition, to compare "has the person changed anything" without caring about key order. */
export const specKey = (s: ReportSpec) => JSON.stringify([s.dataset, s.columns, s.filters ?? [], s.site_ids ?? [], s.group_id ?? "", s.sort ?? null]);
