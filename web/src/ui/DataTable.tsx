import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnFiltersState,
  type ColumnSizingState,
  type PaginationState,
  type RowSelectionState,
  type SortingState,
  type VisibilityState,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Alert, Button, Checkbox, Group, Menu, Modal, Popover, Select, Stack, TextInput } from "@mantine/core";
import { useAppearance, type SavedView } from "../design/AppearanceProvider";
import { downloadText, toCsv } from "./csv";
import { EmptyState } from "./EmptyState";
import { IconButton } from "./IconButton";
import * as I from "./icons";
import { TableSkeleton } from "./Skeletons";

export interface FilterSpec {
  type: "select" | "text";
  options?: { value: string; label: string }[];
}

export interface Column<T> {
  id: string;
  header: string;
  /** What is shown. Defaults to the plain value. */
  cell?: (row: T) => ReactNode;
  /** The plain value used for sorting, searching, filtering and CSV. */
  value?: (row: T) => string | number | boolean | Date | null | undefined;
  /** CSV text when it differs from the value (false leaves the column out of the export). */
  csv?: false | ((row: T) => string);
  sortable?: boolean;
  width?: number;
  minWidth?: number;
  align?: "left" | "right" | "center";
  /** Hidden until the person adds it with the column picker. */
  defaultHidden?: boolean;
  /** Cannot be hidden (the name column). */
  required?: boolean;
  /** The row's main link goes here when `rowHref` is set. */
  primary?: boolean;
  /** Lets the cell wrap onto several lines. */
  wrap?: boolean;
  filter?: FilterSpec;
}

export interface DataTableProps<T> {
  /** Stable id: keys the saved views and the remembered layout. */
  id: string;
  label: string;
  data: T[] | undefined;
  columns: Column<T>[];
  rowId: (row: T) => string;
  loading?: boolean;
  error?: unknown;
  empty?: ReactNode;
  rowHref?: (row: T) => string | undefined;
  onRowClick?: (row: T) => void;
  /** true, or a predicate for rows that can be selected. */
  selectable?: boolean | ((row: T) => boolean);
  rowLabel?: (row: T) => string;
  bulkActions?: (selected: T[], clear: () => void) => ReactNode;
  rowActions?: (row: T) => ReactNode;
  /** Extra controls in the toolbar (a segmented control, a button...). */
  toolbar?: ReactNode;
  searchPlaceholder?: string;
  pageSize?: number;
  /** Virtual scrolling instead of pages, for long lists. */
  virtual?: boolean;
  /** Enables "Export CSV"; the value is the file name stem. */
  exportName?: string;
  initialSort?: { id: string; desc?: boolean };
  /** First column stays in view when scrolling sideways. */
  stickyFirst?: boolean;
  /**
   * For a short list inside a card (a few rings, rules or overlays): show the search, filter, views and columns controls
   * only when there are many rows or a search or filter is in use, so a page with several lists is not several toolbars.
   */
  simple?: boolean;
  /** data-testid of each body row (default "row"). */
  rowTestId?: string;
  /** Called with the rows that are currently shown after filtering (for tiles that mirror the table). */
  onVisibleRows?: (rows: T[]) => void;
  /**
   * Filters and a search to start from, e.g. when a dashboard tile links here. While a preset is set the table
   * adopts it and does not remember the layout (a drill-down must not become the next visit's default).
   */
  preset?: { filters?: { id: string; value: string }[]; search?: string };
  /**
   * What the rows belong to, for a table that is shown again for something else (the device a tab is about). The search, the
   * sort and the filters belong to what is being looked at, so they are not remembered between visits and start afresh when
   * the scope changes; the column layout (shown, order, widths, page size) is still shared by every scope.
   */
  scope?: string;
}

interface Layout {
  sorting: SortingState;
  hidden: string[];
  order: string[];
  sizes: ColumnSizingState;
  filters: ColumnFiltersState;
  search: string;
  pageSize?: number;
}

const EMPTY: never[] = []; // a stable empty list: a fresh [] every render would reset the page index forever
const SELECT = "__select";
/** A `simple` table shows its controls only above this many rows. */
const SIMPLE_ROWS = 8;
const ACTIONS = "__actions";
const layoutKey = (id: string) => `lp-dt:${id}`;
const loadLayout = (id: string): Partial<Layout> => {
  try {
    return JSON.parse(window.localStorage.getItem(layoutKey(id)) ?? "{}") as Partial<Layout>;
  } catch {
    return {};
  }
};

/**
 * How much to shrink the columns the person has not resized so the table fits its frame. Columns keep at least 85% of
 * their width (and their own minimum): past that the table scrolls sideways as before, rather than squeezing text away.
 */
export function fitScale(frame: number, cols: { id: string; width: number; min: number }[], sizes: Record<string, number>, fixed: number): number {
  if (frame <= 0) return 1;
  let flex = 0;
  let pinned = fixed;
  for (const c of cols) {
    if (sizes[c.id] !== undefined) pinned += sizes[c.id]!;
    else flex += c.width;
  }
  if (flex <= 0 || pinned + flex <= frame) return 1;
  return Math.max(0.85, (frame - pinned) / flex);
}

const text = (v: unknown) => (v === null || v === undefined ? "" : v instanceof Date ? v.toISOString() : String(v));

export function DataTable<T>(p: DataTableProps<T>) {
  const { columns } = p;
  const { density, setDensity, views, saveViews } = useAppearance();
  const scoped = p.scope !== undefined;
  const saved = useMemo(() => {
    const l = loadLayout(p.id);
    return scoped ? { hidden: l.hidden, order: l.order, sizes: l.sizes, pageSize: l.pageSize } : l; // a scoped table never restores what was searched or sorted
  }, [p.id, scoped]);
  const defaults = useMemo(
    () => ({
      hidden: columns.filter((c) => c.defaultHidden).map((c) => c.id),
      sorting: p.initialSort ? [{ id: p.initialSort.id, desc: !!p.initialSort.desc }] : [],
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const [sorting, setSorting] = useState<SortingState>(saved.sorting ?? defaults.sorting);
  const [visibility, setVisibility] = useState<VisibilityState>(() => Object.fromEntries((saved.hidden ?? defaults.hidden).map((id) => [id, false])));
  const [order, setOrder] = useState<string[]>(saved.order ?? columns.map((c) => c.id));
  const [sizes, setSizes] = useState<ColumnSizingState>(saved.sizes ?? {});
  const [filters, setFilters] = useState<ColumnFiltersState>(p.preset ? (p.preset.filters ?? []) : (saved.filters ?? []));
  const [search, setSearch] = useState(p.preset ? (p.preset.search ?? "") : (saved.search ?? ""));
  const presetKey = p.preset ? JSON.stringify(p.preset) : "";
  useEffect(() => {
    if (!presetKey) return;
    const x = JSON.parse(presetKey) as NonNullable<DataTableProps<T>["preset"]>;
    setFilters(x.filters ?? []);
    setSearch(x.search ?? "");
  }, [presetKey]);
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize: saved.pageSize ?? p.pageSize ?? 25 });
  const [activeView, setActiveView] = useState<string>("");
  // How wide the table's frame is, so columns can share it instead of pushing the table into a sideways scroll.
  const [box, setBox] = useState<HTMLDivElement | null>(null);
  const [boxW, setBoxW] = useState(0);
  useEffect(() => {
    if (!box) return;
    const measure = () => setBoxW(box.clientWidth);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(measure);
    ro.observe(box);
    return () => ro.disconnect();
  }, [box]);
  const fit = useMemo(
    () => fitScale(boxW, columns.filter((c) => visibility[c.id] !== false).map((c) => ({ id: c.id, width: c.width ?? 160, min: c.minWidth ?? 70 })), sizes, (p.selectable ? 44 : 0) + (p.rowActions ? 132 : 0)),
    [boxW, columns, visibility, sizes, p.selectable, p.rowActions],
  );

  // Another thing to look at (a different device): start from a clean search, sort and filters.
  const firstScope = useRef(true);
  useEffect(() => {
    if (firstScope.current) {
      firstScope.current = false;
      return;
    }
    if (!scoped) return;
    setSorting(defaults.sorting);
    setFilters([]);
    setSearch("");
    setRowSelection({});
    setActiveView("");
    setPagination((x) => ({ ...x, pageIndex: 0 }));
  }, [p.scope, scoped, defaults]);

  // Keep the layout across visits on this device.
  useEffect(() => {
    if (presetKey) return;
    const hidden = Object.entries(visibility).filter(([, v]) => v === false).map(([k]) => k);
    const l: Layout = scoped
      ? ({ hidden, order, sizes, pageSize: pagination.pageSize } as Layout)
      : { sorting, hidden, order, sizes, filters, search, pageSize: pagination.pageSize };
    try {
      window.localStorage.setItem(layoutKey(p.id), JSON.stringify(l));
    } catch {
      /* private mode */
    }
  }, [p.id, scoped, sorting, visibility, order, sizes, filters, search, pagination.pageSize, presetKey]);

  const isSelectable = useCallback((row: T) => (typeof p.selectable === "function" ? p.selectable(row) : !!p.selectable), [p.selectable]);

  const defs = useMemo<ColumnDef<T>[]>(() => {
    const out: ColumnDef<T>[] = [];
    if (p.selectable) out.push({ id: SELECT, header: "", size: 44, enableSorting: false, enableHiding: false, enableResizing: false });
    for (const c of columns) {
      out.push({
        id: c.id,
        header: c.header,
        accessorFn: (row) => (c.value ? (c.value(row) ?? "") : ""),
        cell: (ctx) => (c.cell ? c.cell(ctx.row.original) : text(c.value?.(ctx.row.original)) || "—"),
        size: Math.max(c.minWidth ?? 70, Math.round((c.width ?? 160) * fit)),
        minSize: c.minWidth ?? 70,
        enableSorting: c.sortable ?? !!c.value,
        enableHiding: !c.required,
        sortingFn: "auto",
        filterFn: (row, _id, value: string) => {
          const v = text(c.value?.(row.original));
          return c.filter?.type === "text" ? v.toLowerCase().includes(String(value).toLowerCase()) : v === value;
        },
        meta: c,
      });
    }
    if (p.rowActions) out.push({ id: ACTIONS, header: "", size: 132, enableSorting: false, enableHiding: false, enableResizing: false });
    return out;
  }, [columns, p.selectable, p.rowActions, fit]);

  const fullOrder = useMemo(() => {
    const known = new Set(order);
    const ids = [...order.filter((id) => columns.some((c) => c.id === id)), ...columns.filter((c) => !known.has(c.id)).map((c) => c.id)];
    return [...(p.selectable ? [SELECT] : []), ...ids, ...(p.rowActions ? [ACTIONS] : [])];
  }, [order, columns, p.selectable, p.rowActions]);

  const table = useReactTable<T>({
    data: p.data ?? (EMPTY as T[]),
    columns: defs,
    getRowId: (row) => p.rowId(row),
    state: { sorting, columnVisibility: visibility, columnOrder: fullOrder, columnSizing: sizes, columnFilters: filters, globalFilter: search, rowSelection, pagination },
    onSortingChange: setSorting,
    onColumnVisibilityChange: setVisibility,
    onColumnSizingChange: setSizes,
    onColumnFiltersChange: setFilters,
    onGlobalFilterChange: setSearch,
    onRowSelectionChange: setRowSelection,
    onPaginationChange: setPagination,
    columnResizeMode: "onChange",
    enableRowSelection: (row) => isSelectable(row.original),
    globalFilterFn: (row, _id, value: string) => {
      const needle = String(value).toLowerCase();
      return columns.some((c) => c.value && text(c.value(row.original)).toLowerCase().includes(needle));
    },
    autoResetPageIndex: true,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    ...(p.virtual ? {} : { getPaginationRowModel: getPaginationRowModel() }),
  });

  const rows = table.getRowModel().rows;
  const filteredRows = table.getPrePaginationRowModel().rows;
  const selected = table.getSelectedRowModel().rows.map((r) => r.original);
  const clearSelection = useCallback(() => setRowSelection({}), []);
  const onVisible = useRef(p.onVisibleRows);
  onVisible.current = p.onVisibleRows;
  useEffect(() => onVisible.current?.(filteredRows.map((r) => r.original)), [filteredRows]);

  // Virtual scrolling.
  const scrollRef = useRef<HTMLDivElement>(null);
  const rowH = density === "compact" ? 36 : 48;
  const virt = useVirtualizer({ count: p.virtual ? rows.length : 0, getScrollElement: () => scrollRef.current, estimateSize: () => rowH, overscan: 12 });
  const vItems = p.virtual ? virt.getVirtualItems() : [];
  const padTop = p.virtual && vItems.length ? vItems[0]!.start : 0;
  const padBottom = p.virtual && vItems.length ? virt.getTotalSize() - vItems[vItems.length - 1]!.end : 0;
  const shown = p.virtual ? vItems.map((v) => rows[v.index]!) : rows;

  const visibleCols = table.getVisibleLeafColumns();
  const totalWidth = visibleCols.reduce((s, c) => s + c.getSize(), 0);

  // ---- saved views (kept on the account) ----
  const myViews = views(p.id);
  const currentState = (): Record<string, unknown> => ({
    sorting,
    hidden: Object.entries(visibility).filter(([, v]) => v === false).map(([k]) => k),
    order,
    sizes,
    filters,
    search,
  });
  const applyState = (s: Record<string, unknown>) => {
    setSorting((s.sorting as SortingState) ?? defaults.sorting);
    setVisibility(Object.fromEntries(((s.hidden as string[]) ?? defaults.hidden).map((id) => [id, false])));
    setOrder((s.order as string[]) ?? columns.map((c) => c.id));
    setSizes((s.sizes as ColumnSizingState) ?? {});
    setFilters((s.filters as ColumnFiltersState) ?? []);
    setSearch((s.search as string) ?? "");
  };
  const [saveOpen, setSaveOpen] = useState(false);
  const [viewName, setViewName] = useState("");
  const persistView = () => {
    const name = viewName.trim();
    if (!name) return;
    const id = `${name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 30) || "view"}-${Date.now().toString(36).slice(-4)}`;
    saveViews(p.id, [...myViews, { id, name, state: currentState() } as SavedView]);
    setActiveView(id);
    setSaveOpen(false);
    setViewName("");
  };

  // ---- filters ----
  const filterable = columns.filter((c) => c.filter);
  const [fCol, setFCol] = useState<string | null>(null);
  const [fVal, setFVal] = useState("");
  const [fOpen, setFOpen] = useState(false);
  const fSpec = filterable.find((c) => c.id === fCol)?.filter;
  const addFilter = () => {
    if (!fCol || !fVal.trim()) return;
    setFilters((cur) => [...cur.filter((f) => f.id !== fCol), { id: fCol, value: fVal.trim() }]);
    setFOpen(false);
    setFCol(null);
    setFVal("");
  };
  const chipLabel = (id: string, value: unknown) => {
    const c = columns.find((x) => x.id === id);
    const opt = c?.filter?.options?.find((o) => o.value === value);
    return `${c?.header ?? id}: ${opt?.label ?? String(value)}`;
  };

  // ---- export ----
  const exportCsv = () => {
    const cols = visibleCols.map((c) => columns.find((x) => x.id === c.id)).filter((c): c is Column<T> => !!c && c.csv !== false);
    const src = selected.length ? selected : filteredRows.map((r) => r.original);
    const body = src.map((row) => cols.map((c) => (typeof c.csv === "function" ? c.csv(row) : c.value?.(row))));
    downloadText(`${p.exportName ?? p.id}-${new Date().toISOString().slice(0, 10)}.csv`, toCsv(cols.map((c) => c.header), body));
  };

  // ---- resize by keyboard ----
  const resizeKey = (e: KeyboardEvent, id: string, width: number) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const col = columns.find((c) => c.id === id);
    setSizes((s) => ({ ...s, [id]: Math.max(col?.minWidth ?? 70, width + (e.key === "ArrowRight" ? 16 : -16)) }));
  };

  const empty = !p.loading && !p.error && (p.data?.length ?? 0) === 0;
  const noMatches = !empty && !p.loading && rows.length === 0;
  const hasFilters = filters.length > 0 || search !== "";
  const resetLayout = () => applyState({});

  const rowClick = (row: T, e: React.MouseEvent) => {
    if (!p.onRowClick) return;
    if ((e.target as HTMLElement).closest("a,button,input,label,[role='checkbox'],[data-no-row-click]")) return;
    p.onRowClick(row);
  };

  const pageCount = table.getPageCount();
  const from = filteredRows.length === 0 ? 0 : pagination.pageIndex * pagination.pageSize + 1;
  const to = Math.min(filteredRows.length, (pagination.pageIndex + 1) * pagination.pageSize);

  const lean = !!p.simple && (p.data?.length ?? 0) <= SIMPLE_ROWS && filters.length === 0 && !search;
  return (
    <div className="lp-dt" data-testid={`table-${p.id}`}>
      {!lean && (
        <div className="lp-dt__toolbar" role="toolbar" aria-label={`${p.label} controls`}>
          <label className="lp-dt__searchbox">
            <I.Search size={16} aria-hidden="true" />
            <span className="lp-visually-hidden">Search {p.label}</span>
            <input value={search} onChange={(e) => setSearch(e.currentTarget.value)} placeholder={p.searchPlaceholder ?? "Search"} type="search" />
          </label>
          {filterable.length > 0 && (
            <Popover opened={fOpen} onChange={setFOpen} position="bottom-start" withArrow shadow="md" trapFocus>
              <Popover.Target>
                <Button variant="default" leftSection={<I.Filter size={16} aria-hidden />} onClick={() => setFOpen((o) => !o)} aria-haspopup="dialog">
                  Add filter
                </Button>
              </Popover.Target>
              <Popover.Dropdown>
                <Stack gap="sm" w={260}>
                  <Select label="Column" data={filterable.map((c) => ({ value: c.id, label: c.header }))} value={fCol} onChange={(v) => (setFCol(v), setFVal(""))} allowDeselect={false} comboboxProps={{ withinPortal: false }} />
                  {fSpec?.type === "select" && <Select label="Value" data={fSpec.options ?? []} value={fVal || null} onChange={(v) => setFVal(v ?? "")} allowDeselect={false} comboboxProps={{ withinPortal: false }} />}
                  {fSpec?.type === "text" && <TextInput label="Contains" value={fVal} onChange={(e) => setFVal(e.currentTarget.value)} onKeyDown={(e) => e.key === "Enter" && addFilter()} />}
                  <Button onClick={addFilter} disabled={!fCol || !fVal.trim()}>
                    Apply filter
                  </Button>
                </Stack>
              </Popover.Dropdown>
            </Popover>
          )}
          {p.toolbar}
          <span className="lp-dt__toolbar-spacer" />
          <Menu position="bottom-end" shadow="md" withinPortal>
            <Menu.Target>
              <Button variant="default" leftSection={<I.Bookmark size={16} aria-hidden />} rightSection={<I.ChevronDown size={14} aria-hidden />} aria-label="Saved views">
                {myViews.find((v) => v.id === activeView)?.name ?? "Views"}
              </Button>
            </Menu.Target>
            <Menu.Dropdown miw={230}>
              <Menu.Label>Saved views</Menu.Label>
              <Menu.Item onClick={() => (resetLayout(), setActiveView(""))} leftSection={<I.Restore size={15} aria-hidden />}>
                Default view
              </Menu.Item>
              {myViews.map((v) => (
                <Menu.Item
                  key={v.id}
                  onClick={() => (applyState(v.state), setActiveView(v.id))}
                  leftSection={v.id === activeView ? <I.Check size={15} aria-hidden /> : <span style={{ width: 15 }} />}
                  rightSection={
                    <IconButton
                      label={`Delete view ${v.name}`}
                      icon={<I.Trash size={14} aria-hidden />}
                      size="sm"
                      onClick={(e) => (e.stopPropagation(), saveViews(p.id, myViews.filter((x) => x.id !== v.id)), v.id === activeView && setActiveView(""))}
                    />
                  }
                >
                  {v.name}
                </Menu.Item>
              ))}
              <Menu.Divider />
              <Menu.Item leftSection={<I.BookmarkAdd size={15} aria-hidden />} onClick={() => setSaveOpen(true)}>
                Save current view…
              </Menu.Item>
            </Menu.Dropdown>
          </Menu>
          <Popover position="bottom-end" withArrow shadow="md">
            <Popover.Target>
              <Button variant="default" leftSection={<I.Columns size={16} aria-hidden />} aria-haspopup="dialog">
                Columns
              </Button>
            </Popover.Target>
            <Popover.Dropdown>
              <Stack gap={4} w={260}>
                {fullOrder
                  .filter((id) => id !== SELECT && id !== ACTIONS)
                  .map((id, i, list) => {
                    const c = columns.find((x) => x.id === id)!;
                    const col = table.getColumn(id)!;
                    return (
                      <Group key={id} justify="space-between" wrap="nowrap" gap="xs">
                        <Checkbox label={c.header} checked={col.getIsVisible()} disabled={c.required} onChange={(e) => col.toggleVisibility(e.currentTarget.checked)} />
                        <Group gap={0} wrap="nowrap">
                          <IconButton label={`Move ${c.header} left`} icon={<I.ArrowUp size={14} aria-hidden />} size="sm" disabled={i === 0} onClick={() => setOrder(move(list, i, -1))} />
                          <IconButton label={`Move ${c.header} right`} icon={<I.ArrowDown size={14} aria-hidden />} size="sm" disabled={i === list.length - 1} onClick={() => setOrder(move(list, i, 1))} />
                        </Group>
                      </Group>
                    );
                  })}
                <Button variant="subtle" size="xs" onClick={() => (setVisibility(Object.fromEntries(defaults.hidden.map((id) => [id, false]))), setOrder(columns.map((c) => c.id)), setSizes({}))}>
                  Reset columns
                </Button>
              </Stack>
            </Popover.Dropdown>
          </Popover>
          <IconButton
            label={density === "compact" ? "Density: compact (switch to comfortable)" : "Density: comfortable (switch to compact)"}
            icon={density === "compact" ? <I.DensityCompact size={18} aria-hidden /> : <I.DensityComfortable size={18} aria-hidden />}
            variant="default"
            onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
          />
          {p.exportName && (
            <Button variant="default" leftSection={<I.Download size={16} aria-hidden />} onClick={exportCsv} disabled={filteredRows.length === 0}>
              {selected.length ? `Export ${selected.length} selected` : "Export CSV"}
            </Button>
          )}
        </div>
      )}

      {filters.length > 0 && (
        <div className="lp-chips" aria-label="Active filters">
          {filters.map((f) => (
            <span className="lp-chip" key={f.id}>
              {chipLabel(f.id, f.value)}
              <button type="button" aria-label={`Remove filter ${chipLabel(f.id, f.value)}`} onClick={() => setFilters((cur) => cur.filter((x) => x.id !== f.id))}>
                <I.Close size={12} aria-hidden />
              </button>
            </span>
          ))}
          <Button variant="subtle" size="compact-sm" onClick={() => setFilters([])}>
            Clear filters
          </Button>
        </div>
      )}

      {selected.length > 0 && (
        <div className="lp-dt__bulk" role="region" aria-label="Bulk actions" aria-live="polite">
          <span>{selected.length} selected</span>
          {p.bulkActions?.(selected, clearSelection)}
          <Button variant="subtle" size="compact-sm" onClick={clearSelection} leftSection={<I.Close size={14} aria-hidden />}>
            Clear selection
          </Button>
        </div>
      )}

      <div className="lp-dt__frame">
        {p.error ? (
          <Alert color="red" m="md" title="Could not load" icon={<I.Danger size={18} aria-hidden />}>
            {p.error instanceof Error ? p.error.message : "Something went wrong."}
          </Alert>
        ) : p.loading && (p.data?.length ?? 0) === 0 ? (
          <TableSkeleton cols={Math.min(6, visibleCols.length || 5)} />
        ) : empty ? (
          (p.empty ?? <EmptyState title="Nothing here yet" />)
        ) : (
          <>
            <div className="lp-dt__scroll" ref={(el) => ((scrollRef.current = el), setBox(el))} tabIndex={0} role="region" aria-label={`${p.label} table, scrollable`}>
              <table className="lp-dt__table" style={{ width: Math.max(totalWidth, 0), minWidth: "100%" }} aria-label={p.label} aria-rowcount={filteredRows.length}>
                <colgroup>
                  {visibleCols.map((c) => (
                    <col key={c.id} style={{ width: c.getSize() }} />
                  ))}
                </colgroup>
                <thead>
                  {table.getHeaderGroups().map((hg) => (
                    <tr key={hg.id}>
                      {hg.headers.map((h, idx) => {
                        const meta = h.column.columnDef.meta as Column<T> | undefined;
                        const canSort = h.column.getCanSort();
                        const dir = h.column.getIsSorted();
                        return (
                          <th key={h.id} scope="col" data-align={meta?.align} data-sticky={p.stickyFirst && idx === (p.selectable ? 1 : 0) ? "true" : undefined} style={{ position: "sticky" }} aria-sort={dir === "asc" ? "ascending" : dir === "desc" ? "descending" : canSort ? "none" : undefined}>
                            {h.id === SELECT ? (
                              <Checkbox
                                aria-label="Select all rows on this page"
                                checked={table.getIsAllRowsSelected() || (table.getIsAllPageRowsSelected() && rows.length > 0)}
                                indeterminate={table.getIsSomeRowsSelected() && !table.getIsAllPageRowsSelected()}
                                onChange={(e) => table.toggleAllPageRowsSelected(e.currentTarget.checked)}
                              />
                            ) : h.id === ACTIONS ? (
                              <span className="lp-visually-hidden">Actions</span>
                            ) : canSort ? (
                              <button type="button" className="lp-dt__sort" data-active={dir ? "true" : "false"} onClick={h.column.getToggleSortingHandler()} title={`Sort by ${meta?.header ?? h.id}`}>
                                <span className="lp-dt__label">{flexRender(h.column.columnDef.header, h.getContext())}</span>
                                {dir === "asc" ? <I.SortAsc size={14} aria-hidden /> : dir === "desc" ? <I.SortDesc size={14} aria-hidden /> : <I.SortNone size={14} aria-hidden style={{ opacity: 0.55 }} />}
                              </button>
                            ) : (
                              flexRender(h.column.columnDef.header, h.getContext())
                            )}
                            {h.column.getCanResize() && (
                              <button
                                type="button"
                                className="lp-dt__resize"
                                role="separator"
                                aria-orientation="vertical"
                                aria-valuenow={h.getSize()}
                                aria-valuemin={meta?.minWidth ?? 70}
                                aria-valuemax={800}
                                aria-label={`Resize ${meta?.header ?? h.id} column (arrow keys)`}
                                data-active={h.column.getIsResizing() ? "true" : "false"}
                                onMouseDown={h.getResizeHandler()}
                                onTouchStart={h.getResizeHandler()}
                                onKeyDown={(e) => resizeKey(e, h.id, h.getSize())}
                              />
                            )}
                          </th>
                        );
                      })}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {padTop > 0 && (
                    <tr aria-hidden="true">
                      <td colSpan={visibleCols.length} style={{ height: padTop, padding: 0, border: 0 }} />
                    </tr>
                  )}
                  {shown.map((row) => {
                    const href = p.rowHref?.(row.original);
                    return (
                      <tr key={row.id} aria-selected={row.getIsSelected()} data-clickable={p.onRowClick ? "true" : undefined} onClick={(e) => rowClick(row.original, e)} data-testid={p.rowTestId ?? "row"}>
                        {row.getVisibleCells().map((cell, idx) => {
                          const meta = cell.column.columnDef.meta as Column<T> | undefined;
                          const sticky = p.stickyFirst && idx === (p.selectable ? 1 : 0) ? "true" : undefined;
                          if (cell.column.id === SELECT) {
                            return (
                              <td key={cell.id} data-align="center">
                                <Checkbox
                                  aria-label={`Select ${p.rowLabel?.(row.original) ?? row.id}`}
                                  checked={row.getIsSelected()}
                                  disabled={!row.getCanSelect()}
                                  onChange={row.getToggleSelectedHandler()}
                                />
                              </td>
                            );
                          }
                          if (cell.column.id === ACTIONS) {
                            return (
                              <td key={cell.id} data-align="right" data-no-row-click>
                                <div className="lp-dt__actions">{p.rowActions?.(row.original)}</div>
                              </td>
                            );
                          }
                          const content = flexRender(cell.column.columnDef.cell, cell.getContext());
                          return (
                            <td key={cell.id} data-align={meta?.align} data-wrap={meta?.wrap ? "true" : undefined} data-sticky={sticky}>
                              {meta?.primary && href ? (
                                <Link to={href} className="lp-dt__link">
                                  {content}
                                </Link>
                              ) : (
                                content
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    );
                  })}
                  {padBottom > 0 && (
                    <tr aria-hidden="true">
                      <td colSpan={visibleCols.length} style={{ height: padBottom, padding: 0, border: 0 }} />
                    </tr>
                  )}
                </tbody>
              </table>
              {noMatches && (
                <EmptyState
                  icon={<I.ListSearch size={26} />}
                  title="No matching rows"
                  description="Nothing matches the search and filters you set."
                  actions={
                    hasFilters && (
                      <Button variant="default" onClick={() => (setFilters([]), setSearch(""))}>
                        Clear search and filters
                      </Button>
                    )
                  }
                />
              )}
            </div>
            <div className="lp-dt__foot">
              <span aria-live="polite">
                {p.virtual ? `${filteredRows.length} rows` : `${from}–${to} of ${filteredRows.length}`}
                {(p.data?.length ?? 0) !== filteredRows.length && ` (filtered from ${p.data?.length})`}
              </span>
              {!p.virtual && (
                <Group gap="xs">
                  <Select
                    aria-label="Rows per page"
                    size="xs"
                    w={92}
                    data={["10", "25", "50", "100"].map((v) => ({ value: v, label: `${v} / page` }))}
                    value={String(pagination.pageSize)}
                    onChange={(v) => v && table.setPageSize(Number(v))}
                    allowDeselect={false}
                    comboboxProps={{ withinPortal: true }}
                  />
                  <IconButton label="Previous page" icon={<I.ChevronLeft size={16} aria-hidden />} variant="default" disabled={!table.getCanPreviousPage()} onClick={() => table.previousPage()} />
                  <span className="lp-num">
                    Page {pageCount === 0 ? 0 : pagination.pageIndex + 1} of {pageCount}
                  </span>
                  <IconButton label="Next page" icon={<I.ChevronRight size={16} aria-hidden />} variant="default" disabled={!table.getCanNextPage()} onClick={() => table.nextPage()} />
                </Group>
              )}
            </div>
          </>
        )}
      </div>

      <Modal opened={saveOpen} onClose={() => setSaveOpen(false)} title="Save this view" centered size="sm">
        <Stack>
          <TextInput label="Name" description="Saves the columns, order, widths, sorting, filters and search. Views follow your account to any device." value={viewName} onChange={(e) => setViewName(e.currentTarget.value)} maxLength={60} data-autofocus onKeyDown={(e) => e.key === "Enter" && persistView()} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setSaveOpen(false)}>
              Cancel
            </Button>
            <Button onClick={persistView} disabled={!viewName.trim() || myViews.length >= 20}>
              Save view
            </Button>
          </Group>
        </Stack>
      </Modal>
    </div>
  );
}

function move(list: string[], i: number, d: number): string[] {
  const out = [...list];
  const j = i + d;
  if (j < 0 || j >= out.length) return out;
  [out[i], out[j]] = [out[j]!, out[i]!];
  return out;
}
