import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, Anchor, Button, Checkbox, Group, Menu, Modal, SegmentedControl, Select, Stack, Text } from "@mantine/core";
import { api, errorMessage, type RestartPolicy, type WindowsUpdate } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { Card, DataTable, Donut, EmptyState, IconButton, Icons, Page, PageHeader, SeverityBadge, StackedBar, StatGrid, StatTile, StatusPill, TileSkeleton, toast, useConfirm, type Column, type PillKind } from "../ui";

const classifications = ["Security Updates", "Critical Updates", "Definition Updates", "Drivers", "Feature Packs", "Service Packs", "Update Rollups", "Updates", "Upgrades", "Tools"];

/** Kept for components that still colour Mantine badges by severity (the device page). New code uses SeverityBadge. */
export const severityColor: Record<string, string> = { Critical: "red", Important: "orange", Moderate: "yellow", Low: "gray" };

const DECISION: Record<string, { kind: PillKind; label: string; icon: typeof Icons.Check; hint: string }> = {
  approved: { kind: "success", label: "Approved", icon: Icons.Check, hint: "Decided by an administrator" },
  declined: { kind: "neutral", label: "Declined", icon: Icons.Close, hint: "Decided by an administrator" },
  hidden: { kind: "neutral", label: "Hidden", icon: Icons.EyeOff, hint: "Decided by an administrator" },
  "": { kind: "warning", label: "Pending", icon: Icons.Clock, hint: "Waiting for a decision" },
};

/** The approval state of an update: icon, color and text. */
export function DecisionBadge({ u, size }: { u: Pick<WindowsUpdate, "decision" | "decision_source">; size?: "sm" | "md" }) {
  const d = DECISION[u.decision] ?? DECISION[""]!;
  const rule = u.decision_source === "rule";
  return (
    <StatusPill kind={d.kind} icon={d.icon} size={size} title={rule ? "Approved automatically by a rule" : d.hint}>
      {d.label}
      {rule ? " (rule)" : ""}
    </StatusPill>
  );
}

/** Severity as a sortable rank: Critical first. */
const RANK: Record<string, number> = { critical: 0, important: 1, moderate: 2, low: 3 };
const rank = (s: string | null | undefined) => RANK[(s ?? "").toLowerCase()] ?? 4;
const SEVERITY_NAMES = ["Critical", "Important", "Moderate", "Low", "Unspecified"];

const sameRows = (a: WindowsUpdate[], b: WindowsUpdate[]) => a.length === b.length && a.every((r, i) => r === b[i]);
const kbOf = (u: WindowsUpdate) => (u.kb ?? []).map((k) => `KB${k.replace(/^KB/i, "")}`);

const LIMIT = 500;

export function UpdatesPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  // Dashboard tiles and the command palette link here with ?severity=, ?q= and ?missing=0|1.
  const [urlParams, setUrlParams] = useSearchParams();
  const urlSeverity = SEVERITY_NAMES.includes(urlParams.get("severity") ?? "") ? urlParams.get("severity")! : "";
  const urlQuery = (urlParams.get("q") ?? "").slice(0, 100);
  const [decision, setDecision] = useState("all");
  const [onlyMissing, setOnlyMissing] = useState(urlParams.get("missing") !== "0");
  const [open, setOpen] = useState<WindowsUpdate | null>(null);
  const [visible, setVisible] = useState<WindowsUpdate[]>([]);
  const params = new URLSearchParams({ limit: String(LIMIT), offset: "0" });
  if (decision !== "all") params.set("decision", decision);
  if (onlyMissing) params.set("missing", "true");
  if (urlSeverity && urlSeverity !== "Unspecified") params.set("severity", urlSeverity);
  if (urlQuery) params.set("q", urlQuery);
  const list = useQuery({
    queryKey: ["updates", "list", params.toString()],
    queryFn: () => api<{ items: WindowsUpdate[]; total: number }>("GET", `/updates?${params}`),
    refetchInterval: 60_000,
  });
  const decide = useMutation({
    mutationFn: ({ ids, d }: { ids: string[]; d: string; done?: () => void }) => api<{ changed: number; hide_jobs: number }>("POST", "/updates/decision", { update_ids: ids, decision: d }),
    onSuccess: (r, v) => {
      toast.success(`${r.changed} update${r.changed === 1 ? "" : "s"} ${v.d === "none" ? "reset to pending" : v.d}${r.hide_jobs ? `; ${r.hide_jobs} device job${r.hide_jobs === 1 ? "" : "s"} queued` : ""}.`);
      v.done?.();
      void qc.invalidateQueries({ queryKey: ["updates"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const canDecide = can("updates:write");

  const columns = useMemo<Column<WindowsUpdate>[]>(
    () => [
      {
        id: "title",
        header: "Update",
        required: true,
        primary: true,
        wrap: true,
        width: 420,
        value: (u) => `${u.title} ${kbOf(u).join(" ")}`,
        csv: (u) => u.title,
        cell: (u) => (
          <span style={{ display: "grid", gap: 4 }}>
            <Anchor component="button" type="button" size="sm" ta="left" onClick={() => setOpen(u)}>
              {u.title}
            </Anchor>
            <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
              {kbOf(u).map((k) => (
                <span key={k} className="lp-mono lp-muted">
                  {k}
                </span>
              ))}
              {u.is_driver && (
                <StatusPill kind="info" size="sm" icon={Icons.Server}>
                  Driver
                </StatusPill>
              )}
              {(u.holds ?? 0) > 0 && (
                <StatusPill kind="danger" size="sm" icon={Icons.Pause} title="A ring failed its success threshold; later rings are held back. See Rings, rules and sources.">
                  Held
                </StatusPill>
              )}
            </span>
          </span>
        ),
      },
      { id: "kb", header: "KB number", defaultHidden: true, width: 130, value: (u) => kbOf(u).join(" "), filter: { type: "text" }, cell: (u) => <span className="lp-mono">{kbOf(u).join(", ") || "—"}</span> },
      {
        id: "classification",
        header: "Classification",
        width: 160,
        value: (u) => u.classification ?? "",
        filter: { type: "select", options: classifications.map((c) => ({ value: c, label: c })) },
        cell: (u) => u.classification || "—",
      },
      {
        id: "severity",
        header: "Severity",
        width: 130,
        value: (u) => rank(u.severity),
        csv: (u) => u.severity ?? "",
        filter: { type: "select", options: SEVERITY_NAMES.map((n, i) => ({ value: String(i), label: n })) },
        cell: (u) => <SeverityBadge severity={u.severity} size="sm" />,
      },
      {
        id: "released",
        header: "Released",
        width: 120,
        value: (u) => (u.release_date ? new Date(u.release_date).getTime() : 0),
        csv: (u) => u.release_date ?? "",
        cell: (u) => (u.release_date ? new Date(u.release_date).toLocaleDateString() : "—"),
      },
      { id: "missing", header: "Missing", align: "right", width: 90, value: (u) => u.devices_missing ?? 0, cell: (u) => <span className="lp-num">{u.devices_missing ?? 0}</span> },
      { id: "installed", header: "Installed", align: "right", width: 95, defaultHidden: true, value: (u) => u.devices_installed ?? 0, cell: (u) => <span className="lp-num">{u.devices_installed ?? 0}</span> },
      {
        id: "devices",
        header: "Devices",
        width: 230,
        value: (u) => u.devices_missing ?? 0,
        csv: (u) => `${u.devices_missing} missing, ${u.devices_installed} installed, ${u.devices_failed ?? 0} failed, ${u.devices_pending_reboot ?? 0} need a restart`,
        cell: (u) => (
          <span style={{ display: "grid", gap: 2 }}>
            <span>
              <b className="lp-num">{u.devices_missing}</b> missing
              {(u.devices_pending_reboot ?? 0) > 0 && <>, {u.devices_pending_reboot} need a restart</>}
            </span>
            <span className="lp-muted">
              {u.devices_installed} installed
              {(u.devices_failed ?? 0) > 0 && (
                <>
                  {" "}
                  ·{" "}
                  <StatusPill kind="danger" size="sm">
                    {u.devices_failed} failed
                  </StatusPill>
                </>
              )}
            </span>
          </span>
        ),
      },
      { id: "decision", header: "Decision", width: 140, value: (u) => u.decision || "pending", csv: (u) => (u.decision || "pending") + (u.decision_source === "rule" ? " (rule)" : ""), cell: (u) => <DecisionBadge u={u} size="sm" /> },
      { id: "seen", header: "First seen", width: 150, defaultHidden: true, value: (u) => (u.first_seen_at ? new Date(u.first_seen_at).getTime() : 0), csv: (u) => u.first_seen_at ?? "", cell: (u) => dateTime(u.first_seen_at) },
    ],
    [],
  );

  const rows = list.data?.items;
  const sev = [0, 1, 2, 3].map((r) => visible.filter((u) => rank(u.severity) === r).length);
  const byDecision = (d: string) => visible.filter((u) => u.decision === d).length;
  const pending = byDecision("");
  const missingDevices = visible.reduce((s, u) => s + (u.devices_missing ?? 0), 0);

  return (
    <Page>
      <PageHeader
        title="Windows updates"
        description="Everything Windows Update has offered your devices. Approve an update and the rings install it, pilot first. Updates stay untouched until you approve them or a rule does."
        actions={
          can("updates:policy") ? (
            <Button component={Link} to="/automations?tab=windows" variant="default" leftSection={<Icons.NavPolicy size={16} aria-hidden />}>
              Rings, rules and sources
            </Button>
          ) : undefined
        }
      />
      {(urlSeverity || urlQuery) && (
        <div className="lp-chips" role="status">
          <span>Showing</span>
          {urlSeverity && <span className="lp-chip lp-chip--static">Severity: {urlSeverity}</span>}
          {urlQuery && <span className="lp-chip lp-chip--static">Search: {urlQuery}</span>}
          <Button size="compact-sm" variant="default" onClick={() => setUrlParams({}, { replace: true })}>
            Clear filters
          </Button>
        </div>
      )}

      {list.isLoading ? (
        <TileSkeleton count={6} />
      ) : list.data ? (
        <>
          <StatGrid compact label="Updates by severity">
            <StatTile label="Critical" value={sev[0]} kind="critical" icon={<Icons.Critical size={16} aria-hidden />} hint="Install first" />
            <StatTile label="Important" value={sev[1]} kind="important" icon={<Icons.Flame size={16} aria-hidden />} />
            <StatTile label="Moderate" value={sev[2]} kind="moderate" icon={<Icons.Caution size={16} aria-hidden />} />
            <StatTile label="Low" value={sev[3]} kind="low" icon={<Icons.Info size={16} aria-hidden />} />
            <StatTile label="Awaiting a decision" value={pending} kind={pending > 0 ? "warning" : "success"} icon={<Icons.Clock size={16} aria-hidden />} hint="Not approved, declined or hidden yet" />
            <StatTile label="Devices missing updates" value={missingDevices} kind={missingDevices > 0 ? "warning" : "success"} icon={<Icons.NavDevices size={16} aria-hidden />} hint="Summed over the updates shown" />
          </StatGrid>
          <div style={{ display: "grid", gap: "var(--lp-space-4)", gridTemplateColumns: "repeat(auto-fit, minmax(300px, 1fr))" }}>
            <Card title="By severity" description="The updates in the table below, after your filters.">
              <Donut
                label="Updates by severity"
                center={visible.length}
                sub="updates"
                slices={[
                  { label: "Critical", value: sev[0]!, token: "critical" },
                  { label: "Important", value: sev[1]!, token: "important" },
                  { label: "Moderate", value: sev[2]!, token: "moderate" },
                  { label: "Low", value: sev[3]!, token: "low" },
                  { label: "Unspecified", value: visible.length - sev.reduce((a, b) => a + b, 0), token: "neutral" },
                ]}
              />
            </Card>
            <Card title="By decision" description="What has been decided so far.">
              <StackedBar
                label="Updates by decision"
                slices={[
                  { label: "Approved", value: byDecision("approved"), token: "success" },
                  { label: "Pending", value: pending, token: "warning" },
                  { label: "Declined", value: byDecision("declined"), token: "neutral" },
                  { label: "Hidden", value: byDecision("hidden"), token: "info" },
                ]}
              />
            </Card>
          </div>
        </>
      ) : null}

      {list.data && list.data.total > list.data.items.length && (
        <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />} title={`Showing ${list.data.items.length} of ${list.data.total} updates`}>
          Narrow the list with the decision buttons or the missing-only switch to see the rest.
        </Alert>
      )}

      <DataTable<WindowsUpdate>
        id="updates"
        label="Windows updates"
        data={rows}
        loading={list.isLoading}
        error={list.error}
        columns={columns}
        rowId={(u) => u.update_id}
        rowTestId="update-row"
        rowLabel={(u) => u.title}
        searchPlaceholder="Search title or KB number…"
        exportName="windows-updates"
        initialSort={{ id: "severity" }}
        selectable={canDecide}
        onRowClick={setOpen}
        onVisibleRows={(r) => setVisible((cur) => (sameRows(cur, r) ? cur : r))}
        toolbar={
          <>
            <SegmentedControl
              aria-label="Show updates by decision"
              value={decision}
              onChange={setDecision}
              data={[
                { value: "all", label: "All" },
                { value: "pending", label: "Pending" },
                { value: "approved", label: "Approved" },
                { value: "declined", label: "Declined" },
                { value: "hidden", label: "Hidden" },
              ]}
            />
            <Checkbox label="Only updates some device is missing" checked={onlyMissing} onChange={(e) => setOnlyMissing(e.currentTarget.checked)} />
          </>
        }
        bulkActions={(sel, clear) => {
          const ids = sel.map((u) => u.update_id);
          return (
            <>
              <Button size="compact-sm" leftSection={<Icons.Check size={14} aria-hidden />} loading={decide.isPending} onClick={() => decide.mutate({ ids, d: "approved", done: clear })}>
                Approve
              </Button>
              <Button size="compact-sm" variant="default" leftSection={<Icons.Close size={14} aria-hidden />} onClick={() => decide.mutate({ ids, d: "declined", done: clear })}>
                Decline
              </Button>
              <Button size="compact-sm" variant="default" leftSection={<Icons.EyeOff size={14} aria-hidden />} onClick={() => decide.mutate({ ids, d: "hidden", done: clear })}>
                Hide on devices
              </Button>
              <Button size="compact-sm" variant="subtle" leftSection={<Icons.Undo size={14} aria-hidden />} onClick={() => decide.mutate({ ids, d: "none", done: clear })}>
                Reset to pending
              </Button>
            </>
          );
        }}
        rowActions={(u) => (
          <Menu position="bottom-end" withinPortal>
            <Menu.Target>
              <IconButton label={`Actions for ${u.title}`} icon={<Icons.More size={16} aria-hidden />} size="sm" />
            </Menu.Target>
            <Menu.Dropdown>
              <Menu.Item onClick={() => setOpen(u)}>Devices and details</Menu.Item>
              {canDecide && (
                <>
                  <Menu.Divider />
                  <Menu.Item disabled={u.decision === "approved"} onClick={() => decide.mutate({ ids: [u.update_id], d: "approved" })}>
                    Approve
                  </Menu.Item>
                  <Menu.Item disabled={u.decision === "declined"} onClick={() => decide.mutate({ ids: [u.update_id], d: "declined" })}>
                    Decline
                  </Menu.Item>
                  <Menu.Item disabled={u.decision === "hidden"} onClick={() => decide.mutate({ ids: [u.update_id], d: "hidden" })}>
                    Hide on devices
                  </Menu.Item>
                  <Menu.Item disabled={u.decision === ""} onClick={() => decide.mutate({ ids: [u.update_id], d: "none" })}>
                    Reset to pending
                  </Menu.Item>
                </>
              )}
            </Menu.Dropdown>
          </Menu>
        )}
        empty={
          <EmptyState
            icon={<Icons.NavUpdates size={26} />}
            title="No updates to show"
            description={
              <>
                Devices report what Windows Update offers shortly after they connect and then every day. Open a device and use <b>Windows updates → Scan now</b> to ask for it right away.
              </>
            }
          />
        }
      />
      {open && <UpdateDetail u={open} onClose={() => setOpen(null)} />}
    </Page>
  );
}

const restartOptions = [
  { value: "never", label: "Do not restart (the device keeps asking to be restarted)" },
  { value: "outside_active_hours", label: "Restart outside 08:00–17:00 with a 15 minute notice" },
];

interface DeviceState {
  device_id: string;
  hostname: string;
  online: boolean;
  state: string;
  last_error: string;
  attempt_state: string;
  attempt_failures: number;
  ring: string;
}

const STATE_PILL: Record<string, { kind: PillKind; label: string; icon?: typeof Icons.Check }> = {
  missing: { kind: "warning", label: "Missing" },
  downloaded: { kind: "info", label: "Downloaded", icon: Icons.Download },
  installed: { kind: "success", label: "Installed" },
  failed: { kind: "danger", label: "Failed" },
  pending_reboot: { kind: "warning", label: "Needs restart", icon: Icons.Restart },
  hidden: { kind: "neutral", label: "Hidden", icon: Icons.EyeOff },
};

function UpdateDetail({ u, onClose }: { u: WindowsUpdate; onClose: () => void }) {
  const { can } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [restart, setRestart] = useState("never");
  const q = useQuery({
    queryKey: ["updates", "devices", u.update_id],
    queryFn: () => api<{ items: DeviceState[] }>("GET", `/updates/${u.update_id}/devices?limit=1000`),
  });
  const install = useMutation({
    mutationFn: (deviceIds: string[]) => {
      const r: RestartPolicy = restart === "never" ? { allow: "never" } : { allow: "outside_active_hours", active_start: 8 * 60, active_end: 17 * 60, notify_minutes: 15 };
      return api<{ jobs: number }>("POST", `/updates/${u.update_id}/install`, { device_ids: deviceIds, restart: r });
    },
    onSuccess: (r) => {
      toast.success(`Install queued on ${r.jobs} device${r.jobs === 1 ? "" : "s"}.`);
      void qc.invalidateQueries({ queryKey: ["updates"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const missing = (q.data?.items ?? []).filter((d) => d.state === "missing" || d.state === "downloaded");
  const columns = useMemo<Column<DeviceState>[]>(
    () => [
      {
        id: "device",
        header: "Device",
        required: true,
        width: 200,
        value: (d) => d.hostname,
        cell: (d) => (
          <Anchor component={Link} to={`/devices/${d.device_id}`} size="sm">
            {d.hostname}
          </Anchor>
        ),
      },
      {
        id: "state",
        header: "State",
        width: 150,
        value: (d) => d.state,
        csv: (d) => d.state,
        cell: (d) => {
          const s = STATE_PILL[d.state];
          return s ? (
            <StatusPill kind={s.kind} icon={s.icon} size="sm">
              {s.label}
            </StatusPill>
          ) : (
            d.state.replace("_", " ")
          );
        },
        filter: { type: "select", options: Object.entries(STATE_PILL).map(([value, s]) => ({ value, label: s.label })) },
      },
      { id: "ring", header: "Ring", width: 120, value: (d) => d.ring ?? "", cell: (d) => d.ring || "—" },
      {
        id: "attempt",
        header: "Last install attempt",
        width: 220,
        wrap: true,
        value: (d) => (d.attempt_state ? `${d.attempt_state}${d.attempt_failures ? ` (${d.attempt_failures} failure${d.attempt_failures === 1 ? "" : "s"})` : ""}` : ""),
        cell: (d) => (d.attempt_state ? `${d.attempt_state}${d.attempt_failures ? ` (${d.attempt_failures} failure${d.attempt_failures === 1 ? "" : "s"})` : ""}` : "—"),
      },
    ],
    [],
  );
  return (
    <Modal opened onClose={onClose} title={u.title} size="xl">
      <Stack>
        <Group gap="xs">
          <DecisionBadge u={u} />
          <SeverityBadge severity={u.severity} />
          {u.reboot_required && (
            <StatusPill kind="warning" icon={Icons.Restart}>
              Needs a restart
            </StatusPill>
          )}
          <Text size="sm" c="dimmed">
            {u.classification} · released {u.release_date ? new Date(u.release_date).toLocaleDateString() : "unknown"} · first seen {dateTime(u.first_seen_at)}
          </Text>
        </Group>
        {u.note && <Text size="sm">Note: {u.note}</Text>}
        {u.support_url && (
          <Anchor href={u.support_url} target="_blank" rel="noopener noreferrer" size="sm">
            Microsoft support article
          </Anchor>
        )}
        <DataTable<DeviceState>
          id="update-devices"
          label="Devices with this update"
          data={q.data?.items}
          loading={q.isLoading}
          error={q.error}
          columns={columns}
          rowId={(d) => d.device_id}
          rowLabel={(d) => d.hostname}
          searchPlaceholder="Search devices…"
          exportName="update-devices"
          pageSize={10}
          empty={<EmptyState icon={<Icons.NavDevices size={26} />} title="No device reports this update" />}
        />
        {can("updates:write") && missing.length > 0 && (
          <Group align="flex-end">
            <Select label="After installing" data={restartOptions} value={restart} onChange={(v) => setRestart(v ?? "never")} allowDeselect={false} style={{ flex: 1 }} />
            <Button
              leftSection={<Icons.Download size={16} aria-hidden />}
              onClick={async () => {
                const ok = await confirm({
                  title: `Install on ${missing.length} device${missing.length === 1 ? "" : "s"} now?`,
                  message: `This installs the update now on ${missing.length} device${missing.length === 1 ? "" : "s"}, ignoring the rings.`,
                  confirmLabel: "Install now",
                });
                if (ok) install.mutate(missing.map((d) => d.device_id));
              }}
              loading={install.isPending}
            >
              Install now on {missing.length} device{missing.length === 1 ? "" : "s"}
            </Button>
          </Group>
        )}
      </Stack>
    </Modal>
  );
}
