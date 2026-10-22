import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Button, SegmentedControl } from "@mantine/core";
import { useSession } from "../api/session";
import { useFeatures } from "../settings/features";
import { api, errorMessage, type Device, type ReportOverview } from "../api/client";
import { ago } from "../api/format";
import { useSiteScope } from "../ui/SiteScope";
import { useEffective } from "../settings/useEffective";
import { DataTable, EmptyState, Icons, IconButton, Page, PageHeader, StatGrid, StatTile, Status, StatusPill, TileSkeleton, toast, useConfirm, type Column } from "../ui";

export function DevicesPage() {
  // Links from the dashboard and the command palette arrive with ?status=, ?state=online|offline, ?restart=1 or ?agent=.
  const [params] = useSearchParams();
  const urlStatus = params.get("status");
  const [status, setStatus] = useState(["pending", "active", "revoked"].includes(urlStatus ?? "") ? urlStatus! : "all");
  useEffect(() => setStatus(["pending", "active", "revoked"].includes(urlStatus ?? "") ? urlStatus! : "all"), [urlStatus]);
  const urlState = params.get("state");
  const urlAgent = params.get("agent");
  const urlRestart = params.get("restart");
  const preset = useMemo(() => {
    const filters: { id: string; value: string }[] = [];
    if (urlState === "online" || urlState === "offline") filters.push({ id: "connection", value: urlState });
    if (urlAgent) filters.push({ id: "agent", value: urlAgent });
    if (urlRestart === "1") filters.push({ id: "restart", value: "pending" });
    return filters.length ? { filters } : undefined;
  }, [urlState, urlAgent, urlRestart]);
  const { can } = useSession();
  const features = useFeatures();
  const { siteId } = useSiteScope();
  const eff = useEffective().data?.devices;
  const qc = useQueryClient();
  const confirm = useConfirm();
  const nav = useNavigate();

  const q = useQuery({
    queryKey: ["devices", status],
    queryFn: () => api<{ items: Device[]; total: number }>("GET", `/devices?limit=500${status === "all" ? "" : `&status=${status}`}`),
    refetchInterval: 60_000,
  });
  const pending = useQuery({
    queryKey: ["devices", "pending-count"],
    queryFn: () => api<{ total: number }>("GET", "/devices?status=pending&limit=1"),
  });
  // Fleet-wide numbers for the tiles (people who can open Reports see them).
  const overview = useQuery({ queryKey: ["report-overview"], queryFn: () => api<ReportOverview>("GET", "/reports/overview"), enabled: can("reports:read"), refetchInterval: 60_000 });

  const del = useMutation({
    mutationFn: (ids: string[]) => api<{ deleted: number; skipped: number }>("POST", "/devices/delete", { ids }),
    onSuccess: (r) => {
      toast.success(`Deleted ${r.deleted} device${r.deleted === 1 ? "" : "s"}${r.skipped ? `; ${r.skipped} skipped (only revoked devices can be deleted)` : ""}.`);
      void qc.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const refresh = useMutation({
    mutationFn: (id: string) => api("POST", `/devices/${id}/refresh`, {}),
    onSuccess: () => toast.info("Refresh requested. The device reports back within a minute."),
    onError: (e) => toast.error(errorMessage(e)),
  });

  const namingRe = useMemo(() => {
    if (!eff?.naming_pattern) return null;
    try {
      return new RegExp(eff.naming_pattern);
    } catch {
      return null; // the server accepted it as RE2; a rare syntax difference simply turns the flag off here
    }
  }, [eff?.naming_pattern]);
  const columns = useMemo<Column<Device>[]>(
    () => [
      {
        id: "hostname",
        header: "Device",
        value: (d) => d.hostname,
        primary: true,
        required: true,
        width: 220,
        cell: (d) => (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            <span>{d.hostname}</span>
            {namingRe && !namingRe.test(d.hostname) && (
              <StatusPill kind="warning" size="sm" icon={Icons.Warning} title="The name does not match the pattern set under Settings > Device defaults">
                Unexpected name
              </StatusPill>
            )}
            {d.pending_reboot && (
              <StatusPill kind="warning" size="sm" icon={Icons.Restart}>
                Restart pending
              </StatusPill>
            )}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        value: (d) => d.status,
        width: 130,
        cell: (d) => <Status value={d.status} size="sm" />,
        filter: { type: "select", options: ["active", "pending", "revoked", "retired"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })) },
      },
      {
        id: "connection",
        header: "Connection",
        value: (d) => (d.status === "active" ? (d.online ? "online" : "offline") : ""),
        width: 130,
        cell: (d) => (d.status === "active" ? <Status value={d.online ? "online" : "offline"} size="sm" /> : <span className="lp-muted">—</span>),
        filter: {
          type: "select",
          options: [
            { value: "online", label: "Online" },
            { value: "offline", label: "Offline" },
          ],
        },
        csv: (d) => (d.status === "active" ? (d.online ? "online" : "offline") : ""),
      },
      {
        id: "os",
        header: "Operating system",
        value: (d) => d.os_caption ?? "",
        width: 230,
        cell: (d) => (
          <>
            {d.os_caption || "—"}
            {d.os_build && <span className="lp-dt__cell-sub lp-mono">{d.os_build}</span>}
          </>
        ),
        filter: { type: "text" },
      },
      { id: "model", header: "Model", value: (d) => [d.manufacturer, d.model].filter(Boolean).join(" "), width: 190 },
      { id: "user", header: "User", value: (d) => d.logged_on_user ?? "", width: 140 },
      { id: "software", header: "Software", value: (d) => d.software_count ?? 0, align: "right", width: 100, cell: (d) => <span className="lp-num">{d.software_count || "—"}</span> },
      {
        id: "seen",
        header: "Last seen",
        value: (d) => (d.last_seen_at ? new Date(d.last_seen_at).getTime() : 0),
        width: 130,
        cell: (d) => <span title={d.last_seen_at ? new Date(d.last_seen_at).toLocaleString() : ""}>{d.online ? "now" : ago(d.last_seen_at)}</span>,
        csv: (d) => d.last_seen_at ?? "",
      },
      { id: "agent", header: "Agent", value: (d) => d.agent_version ?? "", width: 110, cell: (d) => <span className="lp-mono">{d.agent_version || "—"}</span>, filter: { type: "text" } },
      {
        id: "restart",
        header: "Restart",
        value: (d) => (d.pending_reboot ? "pending" : ""),
        width: 110,
        defaultHidden: true,
        filter: { type: "select", options: [{ value: "pending", label: "Restart pending" }] },
        cell: (d) => (d.pending_reboot ? "Pending" : <span className="lp-muted">—</span>),
      },
    ],
    [namingRe],
  );
  const customCols = useMemo<Column<Device>[]>(
    () =>
      (eff?.custom_fields ?? []).map((f) => ({
        id: `custom_${f.key}`,
        header: f.label,
        width: 150,
        defaultHidden: !f.show_in_list,
        value: (d: Device) => ((d as Device & { custom?: Record<string, string> }).custom ?? {})[f.key] ?? "",
        filter: f.type === "select" ? { type: "select" as const, options: f.options.map((o) => ({ value: o, label: o })) } : { type: "text" as const },
      })),
    [eff?.custom_fields],
  );
  // The organization's default columns (Settings > Device defaults) apply until a person arranges their own.
  const cols = useMemo(() => {
    const want = eff?.default_columns;
    const all = [...columns, ...customCols];
    return want && want.length ? all.map((c) => (c.id.startsWith("custom_") ? c : { ...c, defaultHidden: c.required ? false : !want.includes(c.id) })) : all;
  }, [columns, customCols, eff?.default_columns]);

  const rows = useMemo(() => (siteId ? q.data?.items.filter((d) => d.site_id === siteId) : q.data?.items), [q.data, siteId]);
  const o = overview.data;
  const active = o?.devices.active ?? 0;
  const online = o?.devices.online ?? 0;
  const canDelete = can("devices:write");

  return (
    <Page>
      <PageHeader
        title="Devices"
        description="Every Windows device that reports to this server, with its health at a glance."
        actions={
          can("enrollment:write") ? (
            <Button component={Link} to="/enrollment" leftSection={<Icons.Plus size={16} aria-hidden />}>
              Add devices
            </Button>
          ) : undefined
        }
      />
      {overview.isLoading ? (
        <TileSkeleton count={5} />
      ) : o ? (
        <StatGrid compact label="Fleet summary">
          <StatTile label="Active devices" value={active} kind="accent" icon={<Icons.NavDevices size={16} aria-hidden />} onClick={() => setStatus("active")} selected={status === "active"} hint={`${o.devices.pending ?? 0} pending, ${o.devices.revoked ?? 0} revoked`} />
          <StatTile label="Online now" value={online} kind="success" icon={<Icons.Online size={16} aria-hidden />} hint={active ? `${Math.round((100 * online) / active)}% of active devices` : undefined} />
          <StatTile label="Offline" value={Math.max(active - online, 0)} kind="neutral" icon={<Icons.Offline size={16} aria-hidden />} hint={`${o.devices.not_seen_for_a_week ?? 0} not seen for a week`} />
          <StatTile label="Waiting for approval" value={pending.data?.total ?? o.devices.pending ?? 0} kind="warning" icon={<Icons.Clock size={16} aria-hidden />} onClick={() => setStatus("pending")} selected={status === "pending"} />
          <StatTile label="Waiting for a restart" value={o.devices.reboot_pending ?? 0} kind={(o.devices.reboot_pending ?? 0) > 0 ? "warning" : "neutral"} icon={<Icons.Restart size={16} aria-hidden />} />
          {features.windowsUpdates && <StatTile label="Not patch compliant" value={o.compliance.non_compliant ?? 0} kind={(o.compliance.non_compliant ?? 0) > 0 ? "danger" : "success"} icon={<Icons.NavUpdates size={16} aria-hidden />} to="/reports" hint="Open the patch compliance report" />}
        </StatGrid>
      ) : null}
      <DataTable<Device>
        id="devices"
        label="Devices"
        data={rows}
        loading={q.isLoading}
        error={q.error}
        key={(eff?.default_columns ?? []).join(",") + (eff?.custom_fields ?? []).map((f) => f.key).join(",")}
        columns={cols}
        rowId={(d) => d.id}
        rowHref={(d) => `/devices/${d.id}`}
        onRowClick={(d) => nav(`/devices/${d.id}`)}
        rowTestId="device-row"
        rowLabel={(d) => d.hostname}
        searchPlaceholder="Search devices, users, models…"
        exportName="devices"
        initialSort={{ id: "hostname" }}
        preset={preset}
        selectable={canDelete ? (d) => d.status === "revoked" : false}
        toolbar={
          <SegmentedControl
            aria-label="Show devices by status"
            value={status}
            onChange={setStatus}
            data={[
              { value: "all", label: "All" },
              { value: "pending", label: `Pending${pending.data?.total ? ` (${pending.data.total})` : ""}` },
              { value: "active", label: "Active" },
              { value: "revoked", label: "Revoked" },
            ]}
          />
        }
        bulkActions={(rows, clear) => (
          <Button
            color="red"
            variant="light"
            size="compact-sm"
            leftSection={<Icons.Trash size={14} aria-hidden />}
            loading={del.isPending}
            onClick={async () => {
              const ok = await confirm({
                title: `Delete ${rows.length} device${rows.length === 1 ? "" : "s"}?`,
                message: "Each device and everything stored about it (hardware, software inventory, jobs, certificates) is removed permanently. The audit log keeps the record. Only revoked devices can be deleted.",
                confirmLabel: "Delete permanently",
                danger: true,
              });
              if (ok) {
                del.mutate(rows.map((r) => r.id));
                clear();
              }
            }}
          >
            Delete selected
          </Button>
        )}
        rowActions={(d) =>
          can("devices:write") && d.status === "active" ? (
            <IconButton label={`Refresh ${d.hostname}`} icon={<Icons.NavAgentUpdates size={16} aria-hidden />} size="sm" onClick={() => refresh.mutate(d.id)} />
          ) : null
        }
        empty={
          <EmptyState
            icon={<Icons.NavDevices size={26} />}
            title="No devices yet"
            description="Create an enrollment token under Enrollment and run the install command on a Windows device. It appears here within a minute."
            actions={
              <Button component={Link} to="/enrollment">
                Go to Enrollment
              </Button>
            }
          />
        }
      />
    </Page>
  );
}
