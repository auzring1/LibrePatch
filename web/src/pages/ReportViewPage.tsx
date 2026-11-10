import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useDebouncedValue } from "@mantine/hooks";
import { Alert, Button, Group, MultiSelect, SegmentedControl, Select, Stack, TextInput } from "@mantine/core";
import { api, downloadReport, errorMessage, type Group as Grp, type ReportCatalog, type ReportColumn, type ReportFilter, type ReportResult, type ReportSpec, type Site } from "../api/client";
import { useSession } from "../api/session";
import { filterReady, groupedColumns, newFilter, opLabel, opNeedsValue, scopeText, sendable, specKey, startSpec, switchDataset } from "../components/reportSpec";
import { useFeatures } from "../settings/features";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, toast, useConfirm, type Column } from "../ui";
import "./reports.css";

interface Row {
  i: number;
  cells: string[];
}

/** One filter row: column, comparison, value. The value box fits the kind of column. */
function FilterRow({ f, cols, onChange, onRemove }: { f: ReportFilter; cols: ReportColumn[]; onChange: (f: ReportFilter) => void; onRemove: () => void }) {
  const col = cols.find((c) => c.id === f.column);
  const valueLabel = "Value";
  return (
    <div className="lp-rpt-filter" role="group" aria-label="Filter">
      <Select
        label="Column"
        data={cols.map((c) => ({ value: c.id, label: c.label }))}
        value={f.column}
        allowDeselect={false}
        searchable
        onChange={(v) => {
          const next = cols.find((c) => c.id === v);
          if (next) onChange(newFilter(next));
        }}
      />
      <Select label="Is" data={(col?.ops ?? []).map((o) => ({ value: o, label: opLabel(col!.kind, o) }))} value={f.op} allowDeselect={false} onChange={(v) => v && onChange({ ...f, op: v, value: v === "within_days" || v === "older_than_days" ? "30" : f.value })} />
      {col && opNeedsValue(f.op) ? (
        col.kind === "bool" ? (
          <Select label={valueLabel} data={[{ value: "true", label: "Yes" }, { value: "false", label: "No" }]} value={f.value || "true"} allowDeselect={false} onChange={(v) => onChange({ ...f, value: v ?? "true" })} />
        ) : col.choices?.length && (f.op === "eq" || f.op === "ne") ? (
          <Select label={valueLabel} data={col.choices} value={f.value || null} allowDeselect={false} onChange={(v) => onChange({ ...f, value: v ?? "" })} />
        ) : (
          <TextInput
            label={valueLabel}
            value={f.value ?? ""}
            type={col.kind === "time" && (f.op === "before" || f.op === "after") ? "date" : col.kind === "number" || f.op === "within_days" || f.op === "older_than_days" ? "number" : "text"}
            error={f.value && !filterReady(col, f) ? "Not a valid value" : undefined}
            onChange={(e) => onChange({ ...f, value: e.currentTarget.value })}
          />
        )
      ) : (
        <div />
      )}
      <Button variant="subtle" color="gray" onClick={onRemove} aria-label={`Remove the filter on ${col?.label ?? "column"}`} leftSection={<Icons.Trash size={16} aria-hidden />}>
        Remove
      </Button>
    </div>
  );
}

/**
 * One report: ready-made, saved, or being built. Anyone with reports:read can look at it and (with inventory:export) get a
 * CSV or PDF. Ready-made reports can be limited to a site or group, and copied into a custom report with Customize.
 */
export function ReportViewPage() {
  const { id = "" } = useParams();
  const [search] = useSearchParams();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const { can } = useSession();
  const { windowsUpdates } = useFeatures();
  const isNew = id === "new";
  const canWrite = can("reports:write");

  const catalog = useQuery({ queryKey: ["reports", "catalog"], queryFn: () => api<ReportCatalog>("GET", "/reports/catalog") });
  const sites = useQuery({ queryKey: ["sites"], queryFn: () => api<{ items: Site[] }>("GET", "/sites"), staleTime: 5 * 60_000 });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups"), enabled: can("groups:read") });
  const c = catalog.data;

  const builtin = c?.builtins.find((b) => b.id === id);
  const saved = c?.saved.find((s) => s.id === id);
  const copyFrom = isNew ? c?.builtins.find((b) => b.id === search.get("from")) ?? c?.saved.find((s) => s.id === search.get("from")) : undefined;
  const found = isNew || builtin || saved;

  const [spec, setSpec] = useState<ReportSpec | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [loadedFor, setLoadedFor] = useState("");
  const [busy, setBusy] = useState<"csv" | "pdf" | null>(null);

  // Take the report's own definition once the catalog is here (and again when the person moves to another report).
  useEffect(() => {
    if (!c || loadedFor === id + search.get("from")) return;
    let next: ReportSpec | undefined;
    if (isNew) {
      const ds = c.datasets.find((d) => d.id === (copyFrom?.spec.dataset ?? "devices")) ?? c.datasets[0];
      next = copyFrom ? { ...copyFrom.spec, filters: [...(copyFrom.spec.filters ?? [])] } : ds ? startSpec(ds) : undefined;
      setName(copyFrom ? `${"name" in copyFrom ? copyFrom.name : ""} (copy)` : "");
      setDescription(copyFrom && "description" in copyFrom ? copyFrom.description : "");
    } else if (builtin) {
      next = { ...builtin.spec, filters: [...(builtin.spec.filters ?? [])] };
      setName(builtin.name);
      setDescription(builtin.description);
    } else if (saved) {
      next = { ...saved.spec, filters: [...(saved.spec.filters ?? [])] };
      setName(saved.name);
      setDescription(saved.description);
    }
    if (next) {
      setSpec(next);
      setLoadedFor(id + search.get("from"));
    }
  }, [c, id, search, isNew, builtin, saved, copyFrom, loadedFor]);

  const ds = c?.datasets.find((d) => d.id === spec?.dataset);
  const editable = isNew || (!!saved && canWrite);
  const outgoing = useMemo(() => (spec ? sendable(spec, ds) : null), [spec, ds]);
  const [debounced] = useDebouncedValue(outgoing, 350);
  const ready = !!debounced && debounced.columns.length > 0 && !!ds;
  const run = useQuery({
    queryKey: ["reports", "run", debounced ? specKey(debounced) : ""],
    queryFn: () => api<ReportResult>("POST", "/reports/run", { spec: debounced, format: "json" }),
    enabled: ready,
    placeholderData: (prev) => prev,
    staleTime: 15_000,
  });

  const original = builtin?.spec ?? saved?.spec ?? copyFrom?.spec;
  const dirty = isNew ? true : !!saved && !!spec && (specKey(spec) !== specKey(saved.spec) || name !== saved.name || description !== saved.description);
  const siteNames = useMemo(() => new Map((sites.data?.items ?? []).map((s) => [s.id, s.name])), [sites.data]);
  const groupName = groups.data?.items.find((g) => g.id === spec?.group_id)?.name;

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description: description.trim(), spec: outgoing };
      return isNew ? api<{ id: string }>("POST", "/reports/saved", body) : api<{ id: string }>("PUT", `/reports/saved/${id}`, body);
    },
    onSuccess: (r) => {
      toast.success(isNew ? "Report saved." : "Changes saved.");
      qc.invalidateQueries({ queryKey: ["reports", "catalog"] });
      if (isNew) navigate(`/reports/${r.id}`, { replace: true });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: () => api("DELETE", `/reports/saved/${id}`),
    onSuccess: () => {
      toast.success("Report deleted.");
      qc.invalidateQueries({ queryKey: ["reports", "catalog"] });
      navigate("/reports", { replace: true });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const exportAs = async (format: "csv" | "pdf") => {
    if (!outgoing) return;
    setBusy(format);
    try {
      const file = await downloadReport(outgoing, name.trim() || ds?.label || "Report", format);
      toast.success(`Saved ${file}`);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const columns = useMemo<Column<Row>[]>(
    () =>
      (run.data?.columns ?? []).map((col, k) => ({
        id: col.id,
        header: col.label,
        required: k === 0,
        width: Math.max(col.label.length * 10 + 56, Math.min(300, col.width * 9 + 24)),
        align: col.kind === "number" ? ("right" as const) : undefined,
        value: (r: Row) => (col.kind === "number" && r.cells[k] !== "" && Number.isFinite(Number(r.cells[k])) ? Number(r.cells[k]) : r.cells[k]),
        csv: (r: Row) => r.cells[k] ?? "",
        cell: (r: Row) => (col.kind === "number" ? <span className="lp-num">{r.cells[k]}</span> : r.cells[k]),
      })),
    [run.data?.columns],
  );
  const rows = useMemo<Row[]>(() => (run.data?.rows ?? []).map((cells, i) => ({ i, cells })), [run.data?.rows]);

  if (catalog.isLoading) return <Page><PageHeader title="Report" /></Page>;
  if (c && !found) {
    return (
      <Page>
        <PageHeader title="Report not found" crumb="Not found" />
        <EmptyState icon={<Icons.NavReports size={26} />} title="This report does not exist" description="It may have been deleted, or it needs Windows updates, which are switched off." actions={<Button component={Link} to="/reports">Back to reports</Button>} />
      </Page>
    );
  }
  if (isNew && !canWrite) {
    return (
      <Page>
        <PageHeader title="New custom report" crumb="New" />
        <EmptyState icon={<Icons.Lock size={26} />} title="You may not build reports" description="Ask an administrator or operator to build this report for you." actions={<Button component={Link} to="/reports">Back to reports</Button>} />
      </Page>
    );
  }

  const title = isNew ? "New custom report" : name || "Report";
  const exportable = can("inventory:export") && ready && !!run.data;
  const siteOptions = (sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }));
  const groupOptions = (groups.data?.items ?? []).map((g) => ({ value: g.id, label: g.name }));
  const upd = (patch: Partial<ReportSpec>) => setSpec((s) => (s ? { ...s, ...patch } : s));
  const filters = spec?.filters ?? [];
  const nameOk = name.trim().length > 0 && name.trim().length <= 120;

  return (
    <Page>
      <PageHeader
        title={title}
        crumb={isNew ? "New" : undefined}
        description={isNew ? "Choose what to list, narrow it down, and save it. Saved reports appear in the library for everyone who can read reports." : description || undefined}
        actions={
          <Group gap="sm">
            {!isNew && builtin && canWrite && (
              <Button component={Link} to={`/reports/new?from=${builtin.id}`} variant="default" leftSection={<Icons.Copy size={16} aria-hidden />}>
                Customize
              </Button>
            )}
            {!isNew && saved && canWrite && (
              <Button
                variant="default"
                color="red"
                leftSection={<Icons.Trash size={16} aria-hidden />}
                loading={del.isPending}
                onClick={async () => {
                  if (await confirm({ title: `Delete “${saved.name}”?`, message: "The report is removed for everyone. Exports already made are not affected.", confirmLabel: "Delete report", danger: true })) del.mutate();
                }}
              >
                Delete
              </Button>
            )}
            {can("inventory:export") && (
              <>
                <Button variant="default" disabled={!exportable} loading={busy === "csv"} onClick={() => exportAs("csv")} leftSection={<Icons.Download size={16} aria-hidden />}>
                  Export CSV
                </Button>
                <Button variant="default" disabled={!exportable} loading={busy === "pdf"} onClick={() => exportAs("pdf")} leftSection={<Icons.Download size={16} aria-hidden />}>
                  Export PDF
                </Button>
              </>
            )}
            {editable && (
              <Button disabled={!dirty || !nameOk || !ready} loading={save.isPending} onClick={() => save.mutate()} leftSection={<Icons.Success size={16} aria-hidden />}>
                {isNew ? "Save report" : "Save changes"}
              </Button>
            )}
          </Group>
        }
      />

      {spec && c && (
        <>
          <Card title="Limit to" description="Leave both empty for every active device.">
            <div style={{ display: "grid", gap: "var(--lp-space-3)", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
              <MultiSelect label="Sites" placeholder={spec.site_ids?.length ? undefined : "All sites"} data={siteOptions} value={spec.site_ids ?? []} onChange={(v) => upd({ site_ids: v })} clearable searchable />
              <Select
                label="Group"
                placeholder="All devices"
                data={groupOptions}
                value={spec.group_id ?? null}
                onChange={(v) => upd({ group_id: v ?? undefined })}
                clearable
                searchable
                disabled={!can("groups:read")}
                description={can("groups:read") ? undefined : "You need permission to read groups."}
              />
            </div>
          </Card>

          {editable && ds && (
            <Card title="Design" description="What the report lists and how.">
              <Stack>
                <div style={{ display: "grid", gap: "var(--lp-space-3)", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))" }}>
                  <TextInput label="Report name" required maxLength={120} value={name} onChange={(e) => setName(e.currentTarget.value)} error={name.length > 0 && !nameOk ? "Use 1 to 120 characters" : undefined} />
                  <TextInput label="Description" maxLength={500} value={description} onChange={(e) => setDescription(e.currentTarget.value)} placeholder="Optional" />
                </div>
                <Select
                  label="List"
                  description={ds.description}
                  data={c.datasets.filter((d) => windowsUpdates || d.id !== "patching").map((d) => ({ value: d.id, label: d.label }))}
                  value={spec.dataset}
                  allowDeselect={false}
                  onChange={(v) => {
                    const next = c.datasets.find((d) => d.id === v);
                    if (next) setSpec(switchDataset(spec, next));
                  }}
                />
                <MultiSelect
                  label="Columns"
                  description="They appear in the order you pick them."
                  data={groupedColumns(ds).map((g) => ({ group: g.group, items: g.columns.map((col) => ({ value: col.id, label: col.label })) }))}
                  value={spec.columns}
                  onChange={(v) => upd({ columns: v, sort: spec.sort && v.includes(spec.sort.column) ? spec.sort : undefined })}
                  searchable
                  clearable
                  hidePickedOptions
                  error={spec.columns.length === 0 ? "Choose at least one column" : undefined}
                />
                <div>
                  <p className="lp-subhead" style={{ marginBottom: "var(--lp-space-2)" }}>
                    Filters
                  </p>
                  <Stack gap="sm">
                    {filters.length === 0 && <p className="lp-hint">No filters: every row is listed.</p>}
                    {filters.map((f, k) => (
                      <FilterRow key={k} f={f} cols={ds.columns} onChange={(nf) => upd({ filters: filters.map((x, j) => (j === k ? nf : x)) })} onRemove={() => upd({ filters: filters.filter((_, j) => j !== k) })} />
                    ))}
                    <div>
                      <Button variant="default" size="xs" leftSection={<Icons.Plus size={14} aria-hidden />} onClick={() => upd({ filters: [...filters, newFilter(ds.columns[0]!)] })}>
                        Add a filter
                      </Button>
                    </div>
                  </Stack>
                </div>
                <Group align="end" gap="md">
                  <Select
                    label="Sort by"
                    data={spec.columns.map((cid) => ({ value: cid, label: ds.columns.find((x) => x.id === cid)?.label ?? cid }))}
                    value={spec.sort?.column ?? null}
                    placeholder="Default"
                    clearable
                    onChange={(v) => upd({ sort: v ? { column: v, desc: spec.sort?.desc } : undefined })}
                  />
                  <SegmentedControl
                    aria-label="Sort direction"
                    disabled={!spec.sort}
                    value={spec.sort?.desc ? "desc" : "asc"}
                    onChange={(v) => spec.sort && upd({ sort: { ...spec.sort, desc: v === "desc" } })}
                    data={[{ value: "asc", label: "A to Z, low to high" }, { value: "desc", label: "Z to A, high to low" }]}
                  />
                </Group>
              </Stack>
            </Card>
          )}

          <Card
            title="Preview"
            description={`${ds?.label ?? "Report"} for ${scopeText(spec, siteNames, groupName)}${filters.some((f) => filterReady(ds?.columns.find((x) => x.id === f.column), f)) ? ", filtered" : ""}.`}
            flush
            footer={
              run.data ? (
                <span className="lp-rpt-meta" role="status">
                  {run.data.truncated ? `Showing the first ${run.data.rows.length.toLocaleString()} of ${run.data.total.toLocaleString()} rows here. The CSV has all of them; the PDF holds up to 5,000.` : `${run.data.total.toLocaleString()} ${run.data.total === 1 ? "row" : "rows"}.`}
                </span>
              ) : undefined
            }
          >
            {run.error && (
              <div style={{ padding: "var(--lp-space-4)" }}>
                <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
                  {errorMessage(run.error)}
                </Alert>
              </div>
            )}
            {outgoing && outgoing.columns.length === 0 ? (
              <EmptyState icon={<Icons.NavReports size={26} />} title="Choose at least one column" />
            ) : (
              <DataTable<Row>
                id={`report-preview-${isNew ? "new" : id}`}
                label={`${title} preview`}
                data={run.isPending && ready ? undefined : rows}
                loading={run.isPending && ready}
                columns={columns}
                rowId={(r) => String(r.i)}
                rowLabel={(r) => r.cells[0] ?? ""}
                searchPlaceholder="Search this preview…"
                pageSize={25}
                empty={<EmptyState icon={<Icons.NavReports size={26} />} title="Nothing matches" description="No rows for these filters and this scope." />}
              />
            )}
          </Card>
          {original && !isNew && builtin && (
            <p className="lp-rpt-meta">
              This is a ready-made report. {canWrite ? "Use Customize to change its columns or filters and keep your own copy." : "An administrator or operator can copy it into a custom report."} Limiting it to a site or group here applies to this view and its exports only.
            </p>
          )}
        </>
      )}
    </Page>
  );
}
