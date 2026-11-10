import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, Button, Group, Menu, Select, TextInput } from "@mantine/core";
import { useSiteScope } from "../ui/SiteScope";
import { api, errorMessage, type Dashboard } from "../api/client";
import { usePreferences } from "../design/usePreferences";
import { Card, EmptyState, Icons, Page, PageHeader, Skel, TileSkeleton, useConfirm } from "../ui";
import { useFeatures } from "../settings/features";
import { useSession } from "../api/session";
import { DashboardGrid } from "../components/dashboard/DashboardGrid";
import { AddWidgetDrawer, NameDialog, WidgetSettingsDialog } from "../components/dashboard/WidgetDialogs";
import { WidgetView } from "../components/dashboard/WidgetView";
import { readStartDismissed, writeStartDismissed } from "../components/dashboard/start";
import { availableKinds, availableMetrics, widgetDef, type WidgetCtx } from "../components/dashboard/registry";
import { addWidget, cleanSettings, copyName, defaultBoard, duplicateWidget, knownWidgets, moveResize, newBoardId, removeWidget, REFRESH_CHOICES, sizeOf, toPlaced, updateSettings, type Board, type Refresh } from "../components/dashboard/boards";
import { settle } from "../components/dashboard/grid";
import "../components/dashboard/dashboard.css";

function CardSkeleton() {
  return (
    <Card>
      <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
        <Skel w="40%" h={16} />
        <Skel h={90} />
        <Skel w="70%" h={12} />
        <span className="lp-visually-hidden">Loading</span>
      </div>
    </Card>
  );
}

export function DashboardPage() {
  const { siteId, sites } = useSiteScope();
  const { canOrg, can } = useSession();
  const features = useFeatures();
  const confirm = useConfirm();
  const { prefs, ready, update } = usePreferences();
  const [startDismissed, setStartDismissed] = useState(readStartDismissed);
  const [draft, setDraft] = useState<Board | null>(null);
  const [adding, setAdding] = useState(false);
  const [settingsFor, setSettingsFor] = useState<string | null>(null);
  const [naming, setNaming] = useState<"new" | "duplicate" | null>(null);
  const [announce, setAnnounce] = useState("");

  const saved = prefs?.dashboard?.boards ?? [];
  const activeId = prefs?.dashboard?.active;
  // The refresh interval belongs to the board being shown; the page's own copy of the numbers follows it.
  const current = saved.find((b) => b.id === activeId) ?? saved[0];
  const refresh = draft?.refresh ?? current?.refresh ?? 60;
  const q = useQuery({
    queryKey: ["dashboard", siteId],
    queryFn: () => api<Dashboard>("GET", `/dashboard${siteId ? `?site=${siteId}` : ""}`),
    refetchInterval: refresh > 0 ? refresh * 1000 : false,
  });
  const d = q.data;

  const ctx: WidgetCtx | null = useMemo(() => (d ? { d, canOrg, can, features, startDismissed } : null), [d, canOrg, can, features, startDismissed]);
  const kinds = useMemo(() => (ctx ? availableKinds(ctx) : []), [ctx]);
  const metrics = useMemo(() => (d ? availableMetrics(d).map((m) => m.value) : []), [d]);

  // Until the person saves a dashboard of their own, they see the default one (built from what they may see).
  const fallback = useMemo(() => defaultBoard({ kinds, metrics }, prefs?.dashboard), [kinds, metrics, prefs?.dashboard]);
  const boards: Board[] = saved.length > 0 ? (saved as Board[]) : [fallback];
  const active = boards.find((b) => b.id === activeId) ?? boards[0]!;
  const board = draft ?? active;
  const editing = draft !== null;

  const visible = useMemo(() => {
    if (!ctx) return [];
    return knownWidgets(board.widgets, kinds).filter((w) => w.type !== "stat" || metrics.includes(w.settings?.metric ?? ""));
  }, [ctx, board.widgets, kinds, metrics]);
  // What is drawn is settled so a widget that is not visible to this person leaves no hole.
  const placed = useMemo(() => settle(toPlaced(visible)), [visible]);

  const persist = (next: Board[], activeBoard: string) =>
    update({ dashboard: { order: prefs?.dashboard?.order ?? [], hidden: prefs?.dashboard?.hidden ?? [], boards: next, active: activeBoard } });
  const withBoard = (b: Board) => (saved.length > 0 ? (saved as Board[]).map((x) => (x.id === b.id ? b : x)) : [b]);

  const startEdit = () => setDraft(structuredClone(active));
  const save = () => {
    if (!draft) return;
    const placedAll = settle(toPlaced(draft.widgets));
    const b: Board = { ...draft, name: draft.name.trim() || active.name, widgets: draft.widgets.map((w, i) => ({ ...w, ...placedAll[i]!, settings: cleanSettings(w.settings ?? {}) })) };
    persist(withBoard(b), b.id);
    setDraft(null);
  };
  const switchTo = (id: string | null) => id && update({ dashboard: { order: prefs?.dashboard?.order ?? [], hidden: prefs?.dashboard?.hidden ?? [], boards: saved as Board[], active: id } });

  const create = (name: string) => {
    const b: Board = { id: newBoardId(), name, refresh: 60, widgets: [] };
    const base = saved.length > 0 ? (saved as Board[]) : [fallback];
    persist([...base, b], b.id);
    setNaming(null);
    setDraft(b);
    setAdding(true);
  };
  const duplicate = (name: string) => {
    const b: Board = { ...structuredClone(active), id: newBoardId(), name };
    const base = saved.length > 0 ? (saved as Board[]) : [fallback];
    persist([...base, b], b.id);
    setNaming(null);
  };
  const remove = async () => {
    if (!(await confirm({ title: `Delete “${active.name}”?`, message: "The dashboard and its widgets are removed from your account. Your other dashboards are not affected.", confirmLabel: "Delete dashboard", danger: true }))) return;
    const rest = (saved as Board[]).filter((b) => b.id !== active.id);
    persist(rest, rest[0]?.id ?? "");
  };
  const reset = async () => {
    if (!(await confirm({ title: `Reset “${active.name}” to the standard layout?`, message: "Its widgets and their settings are replaced by the standard dashboard. Other dashboards are not affected.", confirmLabel: "Reset layout", danger: true }))) return;
    const b: Board = { ...active, widgets: defaultBoard({ kinds, metrics }).widgets };
    persist(withBoard(b), b.id);
  };

  const edit = (fn: (b: Board) => Board) => setDraft((cur) => (cur ? fn(cur) : cur));
  const settingsWidget = settingsFor ? board.widgets.find((w) => w.id === settingsFor) : undefined;
  const nameOf = (id: string) => {
    const w = board.widgets.find((x) => x.id === id);
    return w?.settings?.title || widgetDef(w?.type ?? "")?.title || "widget";
  };

  const nothing = d && kinds.length === 0;
  const empty = d && !nothing && visible.length === 0 && !editing;

  return (
    <Page>
      <PageHeader
        title="Dashboard"
        description="Fleet health and patch status at a glance."
        actions={
          editing ? (
            <>
              <Button variant="default" onClick={() => setAdding(true)} leftSection={<Icons.Plus size={16} aria-hidden="true" />}>
                Add widget
              </Button>
              <Button variant="default" onClick={() => setDraft(null)}>
                Cancel
              </Button>
              <Button onClick={save} leftSection={<Icons.Check size={16} aria-hidden="true" />}>
                Save dashboard
              </Button>
            </>
          ) : (
            <>
              <Button variant="default" leftSection={<Icons.Customize size={16} aria-hidden="true" />} onClick={startEdit} disabled={!d || !ready || nothing}>
                Edit dashboard
              </Button>
              <Menu position="bottom-end" withinPortal>
                <Menu.Target>
                  <Button variant="default" aria-label="Dashboard actions" disabled={!d || !ready}>
                    <Icons.More size={16} aria-hidden="true" />
                  </Button>
                </Menu.Target>
                <Menu.Dropdown>
                  <Menu.Item leftSection={<Icons.Plus size={14} aria-hidden="true" />} onClick={() => setNaming("new")} disabled={boards.length >= 10}>
                    New dashboard
                  </Menu.Item>
                  <Menu.Item leftSection={<Icons.Copy size={14} aria-hidden="true" />} onClick={() => setNaming("duplicate")} disabled={boards.length >= 10}>
                    Duplicate this dashboard
                  </Menu.Item>
                  <Menu.Item leftSection={<Icons.Restore size={14} aria-hidden="true" />} onClick={reset}>
                    Reset to the standard layout
                  </Menu.Item>
                  <Menu.Divider />
                  <Menu.Item color="red" leftSection={<Icons.Trash size={14} aria-hidden="true" />} onClick={remove} disabled={saved.length === 0}>
                    Delete this dashboard
                  </Menu.Item>
                </Menu.Dropdown>
              </Menu>
            </>
          )
        }
      />
      {d && (
        <div className="lp-dash-bar">
          {editing ? (
            <>
              <TextInput aria-label="Dashboard name" value={draft.name} maxLength={40} onChange={(e) => edit((b) => ({ ...b, name: e.currentTarget.value }))} />
              <Select aria-label="Refresh" allowDeselect={false} data={REFRESH_CHOICES.map((r) => ({ value: String(r.value), label: `Refresh: ${r.label.toLowerCase()}` }))} value={String(draft.refresh)} onChange={(v) => edit((b) => ({ ...b, refresh: Number(v ?? 60) as Refresh }))} />
              <span className="lp-dash-editnote">Drag a widget by its handle, resize it from the corner, or focus the handle and use the arrow keys (Shift to resize). Nothing is saved until you press Save dashboard.</span>
            </>
          ) : boards.length > 1 ? (
            <Select aria-label="Dashboard" allowDeselect={false} data={boards.map((b) => ({ value: b.id, label: b.name }))} value={active.id} onChange={switchTo} />
          ) : null}
        </div>
      )}
      <div role="status" aria-live="polite" className="lp-visually-hidden">
        {announce}
      </div>
      {q.isError && (
        <Alert color="red" title="The dashboard could not be loaded" role="alert">
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.isLoading && (
        <>
          <TileSkeleton count={6} />
          <div className="lp-dash">
            <CardSkeleton />
            <CardSkeleton />
          </div>
        </>
      )}
      {nothing && <EmptyState icon={<Icons.Dashboard size={26} />} title="Nothing to show yet" description="Your role does not include any dashboard widgets. Ask an administrator for access to devices, updates or deployments." />}
      {empty && (
        <EmptyState
          icon={<Icons.EyeOff size={26} />}
          title="This dashboard is empty"
          description="Add widgets to see your fleet here."
          actions={
            <Button variant="default" onClick={() => (startEdit(), setAdding(true))}>
              Add a widget
            </Button>
          }
        />
      )}
      {d && ctx && (editing || visible.length > 0) && (
        <DashboardGrid
          items={placed}
          editing={editing}
          minSize={(id) => {
            const s = sizeOf(board.widgets.find((w) => w.id === id)?.type ?? "");
            return { w: s.minW, h: s.minH };
          }}
          nameOf={nameOf}
          onPlace={(id, to) => edit((b) => moveResize({ ...b, widgets: b.widgets.map((w) => ({ ...w, ...(placed.find((p) => p.id === w.id) ?? w) })) }, id, to))}
          onSettings={setSettingsFor}
          onDuplicate={(id) => {
            edit((b) => duplicateWidget(b, id).board);
            setAnnounce(`${nameOf(id)} duplicated`);
          }}
          onRemove={(id) => {
            edit((b) => removeWidget(b, id));
            setAnnounce(`${nameOf(id)} removed`);
          }}
        >
          {(id) => {
            const w = board.widgets.find((x) => x.id === id)!;
            return <WidgetView w={w} ctx={ctx} siteId={siteId} refresh={refresh} onDismissStart={() => (writeStartDismissed(true), setStartDismissed(true))} />;
          }}
        </DashboardGrid>
      )}
      {editing && visible.length === 0 && (
        <Group justify="center" mt="md">
          <span className="lp-dash-editnote">This dashboard has no widgets yet. Use Add widget.</span>
        </Group>
      )}
      <AddWidgetDrawer
        opened={adding}
        onClose={() => setAdding(false)}
        kinds={kinds}
        onAdd={(def) => {
          const defaults = def.kind === "stat" ? { metric: metrics.find((m) => !board.widgets.some((w) => w.type === "stat" && w.settings?.metric === m)) ?? metrics[0] } : {};
          edit((b) => addWidget(b, def.kind, defaults).board);
          setAnnounce(`${def.title} added at the bottom of the dashboard`);
        }}
      />
      <WidgetSettingsDialog
        opened={!!settingsWidget}
        onClose={() => setSettingsFor(null)}
        type={settingsWidget?.type ?? ""}
        settings={settingsWidget?.settings ?? {}}
        sites={sites}
        ctx={ctx}
        onApply={(s) => {
          if (settingsFor) edit((b) => updateSettings(b, settingsFor, s));
          setSettingsFor(null);
        }}
      />
      <NameDialog
        opened={naming !== null}
        onClose={() => setNaming(null)}
        title={naming === "new" ? "New dashboard" : "Duplicate dashboard"}
        initial={naming === "new" ? "" : copyName(active.name, boards.map((b) => b.name))}
        confirm={naming === "new" ? "Create" : "Duplicate"}
        onSubmit={naming === "new" ? create : duplicate}
      />
    </Page>
  );
}
