import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Group, Modal, MultiSelect, NumberInput, Select, Skeleton, Stack, TextInput } from "@mantine/core";
import { api, errorMessage, type Group as Grp, type RestartPolicy, type UpdateRing, type UpdateRule, type UpdateSettings, type WuPolicy } from "../api/client";
import { hhmm, parseHHMM } from "../api/format";
import { PRODUCT_NAME } from "../brand.generated";
import { ringDefaults, ruleDefaults, ruleTemplates, weekOrder } from "../settings/updateDefaults";
import { useEffective } from "../settings/useEffective";
import { Card, DataTable, EmptyState, IconButton, Icons, SeverityBadge, StatusPill, toast, useConfirm, type Column } from "../ui";

const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const classifications = ["Security Updates", "Critical Updates", "Definition Updates", "Drivers", "Feature Packs", "Service Packs", "Update Rollups", "Updates", "Upgrades", "Tools"];
const severities = ["Critical", "Important", "Moderate", "Low", "Unrated"];

const serviceOptions = [
  { value: "default", label: "Whatever each device is configured for (WSUS if set by policy)" },
  { value: "windows_update", label: "Windows Update (internet)" },
  { value: "microsoft_update", label: "Microsoft Update (Office and other Microsoft products too)" },
];

const restartLabel = (r?: RestartPolicy) => {
  if (!r || !r.allow || r.allow === "never") return "never";
  if (r.allow === "outside_active_hours") return `outside ${hhmm(r.active_start ?? 480)}–${hhmm(r.active_end ?? 1020)}`;
  return `by deadline (${r.deadline_hours ?? 24} h)`;
};

/** The Windows tab of Automations: where devices look for Windows updates, what is approved on its own, what is held, and what WSUS or Intune policy overrides. */
const enabledPill = (enabled: boolean | undefined) =>
  enabled === false ? (
    <StatusPill kind="neutral" size="sm" icon={Icons.Pause}>
      Disabled
    </StatusPill>
  ) : (
    <StatusPill kind="success" size="sm">
      Enabled
    </StatusPill>
  );

const enabledFilter = { type: "select" as const, options: [{ value: "enabled", label: "Enabled" }, { value: "disabled", label: "Disabled" }] };

// ----- source settings -----

export function SourceCard({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["updates", "settings"], queryFn: () => api<UpdateSettings>("GET", "/update-settings") });
  const [service, setService] = useState<string>("default");
  const [drivers, setDrivers] = useState(false);
  useEffect(() => {
    if (q.data) (setService(q.data.service), setDrivers(!!q.data.include_drivers));
  }, [q.data]);
  const save = useMutation({
    mutationFn: () => api("PUT", "/update-settings", { service, include_drivers: drivers }),
    onSuccess: () => (toast.success("Saved. Devices will rescan with the new settings."), qc.invalidateQueries({ queryKey: ["updates", "settings"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const dirty = !!q.data && (q.data.service !== service || !!q.data.include_drivers !== drivers);
  return (
    <Card
      title="Update source"
      description="Where devices look for updates. Devices managed by WSUS or Windows Update for Business policies keep following that policy; see the conflicts below."
      footer={
        canEdit && !q.isLoading ? (
          <Group justify="flex-end">
            <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!dirty} leftSection={<Icons.Save size={16} aria-hidden />}>
              Save
            </Button>
          </Group>
        ) : undefined
      }
    >
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.isLoading ? (
        <Skeleton height={36} width={480} maw="100%" />
      ) : (
        <Group align="flex-end">
          <Select label="Service" data={serviceOptions} value={service} onChange={(v) => setService(v ?? "default")} allowDeselect={false} disabled={!canEdit} w={480} maw="100%" />
          <Checkbox label="Include drivers" checked={drivers} onChange={(e) => setDrivers(e.currentTarget.checked)} disabled={!canEdit} mb={6} />
        </Group>
      )}
    </Card>
  );
}

// ----- rings -----

export function RingsCard({ canEdit, context = "windows" }: { canEdit: boolean; context?: "windows" | "software" }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const rings = useQuery({ queryKey: ["updates", "rings"], queryFn: () => api<{ items: UpdateRing[] }>("GET", "/update-rings") });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const [edit, setEdit] = useState<UpdateRing | "new" | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/update-rings/${id}`),
    onSuccess: () => (toast.success("Ring deleted."), qc.invalidateQueries({ queryKey: ["updates", "rings"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const items = rings.data?.items ?? [];
  const groupList = groups.data?.items;
  const columns = useMemo<Column<UpdateRing>[]>(() => {
    const groupName = (id: string) => groupList?.find((g) => g.id === id)?.name ?? id.slice(0, 8);
    const groupText = (r: UpdateRing) => (r.group_ids ?? []).map(groupName).join(", ");
    return [
      { id: "ordinal", header: "#", width: 60, value: (r) => r.ordinal, cell: (r) => <span className="lp-num">{r.ordinal}</span> },
      { id: "name", header: "Name", required: true, width: 190, value: (r) => r.name },
      { id: "enabled", header: "Status", width: 120, value: (r) => (r.enabled === false ? "disabled" : "enabled"), cell: (r) => enabledPill(r.enabled), filter: enabledFilter },
      { id: "groups", header: "Groups", width: 220, wrap: true, value: groupText, cell: (r) => groupText(r) || "—" },
      { id: "delay", header: "Delay", align: "right", width: 90, value: (r) => r.delay_days ?? 0, cell: (r) => <span className="lp-num">{r.delay_days ?? 0} d</span> },
      { id: "soak", header: "Soak", align: "right", width: 90, value: (r) => r.soak_hours ?? 0, cell: (r) => <span className="lp-num">{r.soak_hours ?? 0} h</span> },
      { id: "threshold", header: "Success needed", align: "right", width: 140, value: (r) => r.success_threshold, cell: (r) => <span className="lp-num">{r.success_threshold}%</span> },
      { id: "window", header: "Window", width: 210, value: (r) => (r.window ? `${(r.window.days ?? []).map((d) => dayNames[d]).join(" ") || "daily"} ${hhmm(r.window.start_minute)} +${r.window.duration_minutes} min` : "any time") },
      ...(context === "windows" ? [{ id: "restart", header: "Restart", width: 190, value: (r: UpdateRing) => restartLabel(r.restart) }] : []),
    ];
  }, [groupList, context]);
  return (
    <Card
      title="Rings"
      description={
        context === "software"
          ? "Pilot first, then broader. A device belongs to the first ring (in order) that lists one of its groups. A software policy that rolls out in stages gives each ring the new version in turn, and gives devices in no ring their update last. Windows updates use the same rings."
          : "Pilot first, then broader. A device belongs to the first ring (in order) that lists one of its groups. For Windows updates, devices in no ring are not updated automatically. Software policies that roll out in stages use the same rings, and give devices in no ring their update last."
      }
      actions={
        canEdit && (
          <Button size="xs" onClick={() => setEdit("new")} leftSection={<Icons.Plus size={14} aria-hidden />}>
            Add ring
          </Button>
        )
      }
    >
      <DataTable<UpdateRing>
        id="update-rings"
        label="Update rings"
        data={rings.data?.items}
        loading={rings.isLoading}
        error={rings.error}
        columns={columns}
        rowId={(r) => r.id ?? String(r.ordinal)}
        rowLabel={(r) => r.name}
        initialSort={{ id: "ordinal" }}
        searchPlaceholder="Search rings…"
        exportName="update-rings"
        rowActions={(r) =>
          canEdit && r.id ? (
            <>
              <IconButton label={`Edit ring ${r.name}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEdit(r)} />
              <IconButton
                label={`Delete ring ${r.name}`}
                icon={<Icons.Trash size={16} aria-hidden />}
                size="sm"
                color="red"
                onClick={async () => {
                  if (await confirm({ title: `Delete ring "${r.name}"?`, message: "Devices in its groups stop receiving approved updates through this ring until they belong to another ring.", confirmLabel: "Delete ring", danger: true })) del.mutate(r.id!);
                }}
              />
            </>
          ) : null
        }
        empty={
          <EmptyState
            icon={<Icons.Timeline size={26} />}
            title="No rings yet"
            description={
              context === "software"
                ? "Without rings, a software policy updates every device in its groups at once. Add a pilot ring (a small group) and a broad ring (everyone else) to roll new versions out in stages."
                : "Without rings, approved updates are never installed automatically. Add a pilot ring (a small group) and a broad ring (everyone else)."
            }
          />
        }
      />
      {edit && <RingModal context={context} ring={edit === "new" ? undefined : edit} nextOrdinal={Math.min(20, items.reduce((m, r) => Math.max(m, r.ordinal), 0) + 1)} groups={groups.data?.items ?? []} onClose={() => setEdit(null)} />}
    </Card>
  );
}

function RingModal({ ring, nextOrdinal, groups, context, onClose }: { ring?: UpdateRing; nextOrdinal: number; groups: Grp[]; context: "windows" | "software"; onClose: () => void }) {
  const qc = useQueryClient();
  // A new ring starts from the organization's update defaults (Settings > Update defaults); an existing one shows its own values.
  const eff = useEffective().data;
  const dflt = ringDefaults(eff?.updates);
  const dayData = weekOrder(eff?.appearance.first_day_of_week).map((i) => ({ value: String(i), label: dayNames[i]! }));
  const [name, setName] = useState(ring?.name ?? "");
  const [ordinal, setOrdinal] = useState<number | string>(ring?.ordinal ?? nextOrdinal);
  const [groupIDs, setGroupIDs] = useState<string[]>(ring?.group_ids ?? []);
  const [delay, setDelay] = useState<number | string>(ring?.delay_days ?? 0);
  const [soak, setSoak] = useState<number | string>(ring?.soak_hours ?? 24);
  const [threshold, setThreshold] = useState<number | string>(ring?.success_threshold ?? 90);
  const [useWindow, setUseWindow] = useState(ring ? !!ring.window : dflt.useWindow);
  const [days, setDays] = useState<string[]>(ring ? (ring.window?.days ?? []).map(String) : dflt.days);
  const [start, setStart] = useState(hhmm(ring?.window?.start_minute ?? dflt.windowStart));
  const [mins, setMins] = useState<number | string>(ring?.window?.duration_minutes ?? dflt.windowMinutes);
  const [restart, setRestart] = useState<string>(ring?.restart?.allow ?? dflt.restart);
  const [activeStart, setActiveStart] = useState(hhmm(ring?.restart?.active_start ?? dflt.activeStart));
  const [activeEnd, setActiveEnd] = useState(hhmm(ring?.restart?.active_end ?? dflt.activeEnd));
  const [notify, setNotify] = useState<number | string>(ring?.restart?.notify_minutes ?? dflt.notify);
  const [deadline, setDeadline] = useState<number | string>(ring?.restart?.deadline_hours ?? dflt.deadline);
  const [enabled, setEnabled] = useState(ring?.enabled !== false);
  const [error, setError] = useState("");

  const save = useMutation({
    mutationFn: () => {
      const body: UpdateRing = {
        name: name.trim(),
        ordinal: Number(ordinal),
        group_ids: groupIDs,
        delay_days: Number(delay) || 0,
        soak_hours: Number(soak) || 0,
        success_threshold: Number(threshold),
        enabled,
        restart: restart === "never" ? { allow: "never" } : { allow: restart as "outside_active_hours" | "deadline", active_start: parseHHMM(activeStart), active_end: parseHHMM(activeEnd), notify_minutes: Number(notify) || 15, deadline_hours: Number(deadline) || 24 },
      };
      if (useWindow) body.window = { days: days.map(Number), start_minute: parseHHMM(start), duration_minutes: Number(mins) || 60 };
      return ring?.id ? api("PUT", `/update-rings/${ring.id}`, body) : api("POST", "/update-rings", body);
    },
    onSuccess: () => (toast.success("Ring saved."), qc.invalidateQueries({ queryKey: ["updates"] }), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  const valid = name.trim() !== "" && Number(ordinal) >= 1 && Number(threshold) >= 1 && Number(threshold) <= 100;
  return (
    <Modal opened onClose={onClose} title={ring ? `Edit ring ${ring.name}` : "Add ring"} size="lg">
      <Stack>
        <Group grow align="flex-start">
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={200} data-autofocus />
          <NumberInput label="Order" description="1 goes first" min={1} max={20} value={ordinal} onChange={setOrdinal} />
        </Group>
        <MultiSelect label="Groups" description="Devices in any of these groups belong to this ring" data={groups.map((g) => ({ value: g.id, label: g.name }))} value={groupIDs} onChange={setGroupIDs} searchable />
        <Group grow align="flex-start">
          <NumberInput label="Delay (days)" description={context === "software" ? "After the new version is available (and approved) before this ring may install" : "After approval before this ring may install"} min={0} max={365} value={delay} onChange={setDelay} />
          <NumberInput label="Soak (hours)" description="How long the next ring waits after this one started" min={0} max={2160} value={soak} onChange={setSoak} />
          <NumberInput label="Success needed (%)" description="Of reporting devices" min={1} max={100} value={threshold} onChange={setThreshold} />
        </Group>
        <Checkbox label="Only install inside a maintenance window (device-local time)" checked={useWindow} onChange={(e) => setUseWindow(e.currentTarget.checked)} />
        {useWindow && (
          <Group align="flex-end">
            <MultiSelect label="Days" data={dayData} value={days} onChange={setDays} w={240} placeholder="Every day" />
            <TextInput label="Starts" value={start} onChange={(e) => setStart(e.currentTarget.value)} w={90} aria-label="Window start" />
            <NumberInput label="Minutes" min={1} max={1440} value={mins} onChange={setMins} w={110} />
          </Group>
        )}
        {context === "windows" && (
          <>
            <Select
              label="Restart after installing"
              data={[
                { value: "never", label: "Never restart automatically" },
                { value: "outside_active_hours", label: "Outside active hours, with a countdown users can see" },
                { value: "deadline", label: "At the latest this long after the install, with a countdown" },
              ]}
              value={restart}
              onChange={(v) => setRestart(v ?? "never")}
              allowDeselect={false}
            />
            {restart !== "never" && (
              <Group align="flex-end">
                <TextInput label="Active hours from" value={activeStart} onChange={(e) => setActiveStart(e.currentTarget.value)} w={110} />
                <TextInput label="to" value={activeEnd} onChange={(e) => setActiveEnd(e.currentTarget.value)} w={90} />
                <NumberInput label="Countdown (minutes)" min={1} max={1440} value={notify} onChange={setNotify} w={150} />
                {restart === "deadline" && <NumberInput label="Deadline (hours)" min={1} max={720} value={deadline} onChange={setDeadline} w={140} />}
              </Group>
            )}
          </>
        )}
        <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        {error && <Alert color="red">{error}</Alert>}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => (setError(""), save.mutate())} loading={save.isPending} disabled={!valid}>
            Save ring
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// ----- rules -----

export function RulesCard({ canEdit }: { canEdit: boolean }) {
  const qc = useQueryClient();
  const confirm = useConfirm();
  const rules = useQuery({ queryKey: ["updates", "rules"], queryFn: () => api<{ items: UpdateRule[] }>("GET", "/update-rules") });
  const [edit, setEdit] = useState<UpdateRule | "new" | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/update-rules/${id}`),
    onSuccess: () => (toast.success("Rule deleted."), qc.invalidateQueries({ queryKey: ["updates", "rules"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const columns = useMemo<Column<UpdateRule>[]>(
    () => [
      { id: "name", header: "Name", required: true, width: 220, value: (r) => r.name },
      { id: "enabled", header: "Status", width: 120, value: (r) => (r.enabled === false ? "disabled" : "enabled"), cell: (r) => enabledPill(r.enabled), filter: enabledFilter },
      { id: "classifications", header: "Classifications", width: 220, wrap: true, value: (r) => (r.classifications ?? []).join(", ") || "any" },
      {
        id: "severities",
        header: "Severities",
        width: 240,
        wrap: true,
        value: (r) => (r.severities ?? []).join(", ") || "any",
        cell: (r) =>
          (r.severities ?? []).length === 0 ? (
            "any"
          ) : (
            <span style={{ display: "inline-flex", gap: 4, flexWrap: "wrap" }}>
              {(r.severities ?? []).map((v) =>
                v === "Unrated" ? (
                  <StatusPill key={v} kind="neutral" size="sm">
                    Unrated
                  </StatusPill>
                ) : (
                  <SeverityBadge key={v} severity={v} size="sm" />
                ),
              )}
            </span>
          ),
      },
      { id: "drivers", header: "Drivers", width: 100, value: (r) => (r.include_drivers ? "yes" : "no") },
      { id: "wait", header: "Wait", width: 170, value: (r) => r.delay_days ?? 0, cell: (r) => `${r.delay_days ?? 0} d after release` },
    ],
    [],
  );
  return (
    <Card
      title="Auto-approval rules"
      description="An update that matches an enabled rule is approved automatically once it is old enough. A decision you make by hand always wins over a rule."
      actions={
        canEdit && (
          <Button size="xs" onClick={() => setEdit("new")} leftSection={<Icons.Plus size={14} aria-hidden />}>
            Add rule
          </Button>
        )
      }
    >
      <DataTable<UpdateRule>
        id="update-rules"
        label="Auto-approval rules"
        data={rules.data?.items}
        loading={rules.isLoading}
        error={rules.error}
        columns={columns}
        rowId={(r) => r.id ?? r.name}
        rowLabel={(r) => r.name}
        initialSort={{ id: "name" }}
        searchPlaceholder="Search rules…"
        exportName="update-rules"
        rowActions={(r) =>
          canEdit && r.id ? (
            <>
              <IconButton label={`Edit rule ${r.name}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEdit(r)} />
              <IconButton
                label={`Delete rule ${r.name}`}
                icon={<Icons.Trash size={16} aria-hidden />}
                size="sm"
                color="red"
                onClick={async () => {
                  if (await confirm({ title: `Delete rule "${r.name}"?`, message: "Approvals it already made stay.", confirmLabel: "Delete rule", danger: true })) del.mutate(r.id!);
                }}
              />
            </>
          ) : null
        }
        empty={<EmptyState icon={<Icons.NavSoftwarePolicy size={26} />} title="No rules" description="Every update waits for you to approve it." />}
      />
      {edit && <RuleModal rule={edit === "new" ? undefined : edit} onClose={() => setEdit(null)} />}
    </Card>
  );
}

function RuleModal({ rule, onClose }: { rule?: UpdateRule; onClose: () => void }) {
  const qc = useQueryClient();
  const updDefaults = useEffective().data?.updates;
  const rd = ruleDefaults(updDefaults);
  const templates = rule ? [] : ruleTemplates(updDefaults);
  const [name, setName] = useState(rule?.name ?? "");
  const [cls, setCls] = useState<string[]>(rule?.classifications ?? []);
  const [sev, setSev] = useState<string[]>(rule?.severities ?? []);
  const [drivers, setDrivers] = useState(rule ? !!rule.include_drivers : rd.drivers);
  const [delay, setDelay] = useState<number | string>(rule?.delay_days ?? rd.delay);
  const [enabled, setEnabled] = useState(rule?.enabled !== false);
  const [error, setError] = useState("");
  const save = useMutation({
    mutationFn: () => {
      const body: UpdateRule = { name: name.trim(), classifications: cls, severities: sev as UpdateRule["severities"], include_drivers: drivers, delay_days: Number(delay) || 0, enabled };
      return rule?.id ? api("PUT", `/update-rules/${rule.id}`, body) : api("POST", "/update-rules", body);
    },
    onSuccess: () => (toast.success("Rule saved."), qc.invalidateQueries({ queryKey: ["updates"] }), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={rule ? `Edit rule ${rule.name}` : "Add rule"}>
      <Stack>
        {templates.length > 0 && (
          <Select
            label="Start from a template"
            description="Fills in the fields below; you can still change them. Templates are set under Settings > Update defaults."
            data={templates.map((t) => ({ value: t.id, label: t.name }))}
            value={null}
            placeholder="Choose a template"
            clearable
            comboboxProps={{ withinPortal: true }}
            onChange={(id) => {
              const t = templates.find((x) => x.id === id);
              if (!t) return;
              setName((n) => n || t.name);
              setCls(t.classifications);
              setSev(t.severities);
              setDrivers(t.include_drivers);
              setDelay(t.delay_days);
            }}
          />
        )}
        <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={200} data-autofocus />
        <MultiSelect label="Classifications" description="Empty = any" data={classifications} value={cls} onChange={setCls} />
        <MultiSelect label="Severities" description="Empty = any" data={severities} value={sev} onChange={setSev} />
        <Checkbox label="Also approve drivers" checked={drivers} onChange={(e) => setDrivers(e.currentTarget.checked)} />
        <NumberInput label="Wait (days after release)" min={0} max={365} value={delay} onChange={setDelay} />
        <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
        {error && <Alert color="red">{error}</Alert>}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => (setError(""), save.mutate())} loading={save.isPending} disabled={name.trim() === ""}>
            Save rule
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

// ----- holds and conflicts -----

type Conflict = { device_id: string; hostname: string; policy?: WuPolicy };

export function ConflictsCard() {
  const q = useQuery({ queryKey: ["updates", "conflicts"], queryFn: () => api<{ items: Conflict[] }>("GET", "/update-conflicts") });
  const items = q.data?.items ?? [];
  const columns = useMemo<Column<Conflict>[]>(
    () => [
      { id: "device", header: "Device", required: true, primary: true, width: 220, value: (c) => c.hostname },
      { id: "source", header: "Effective source", width: 200, value: (c) => c.policy?.effective_source ?? "" },
      { id: "notes", header: "Notes", width: 380, wrap: true, value: (c) => (c.policy?.notes ?? []).join("; ") },
    ],
    [],
  );
  if (q.isLoading || items.length === 0) return null;
  return (
    <Card title="Devices managed by another update policy" description={`WSUS, deferral policies or disabled automatic updates on these devices can delay or block what ${PRODUCT_NAME} installs.`}>
      <DataTable<Conflict>
        id="update-conflicts"
        label="Policy conflicts"
        data={items}
        columns={columns}
        rowId={(c) => c.device_id}
        rowHref={(c) => `/devices/${c.device_id}`}
        rowLabel={(c) => c.hostname}
        initialSort={{ id: "device" }}
        searchPlaceholder="Search devices…"
        exportName="update-policy-conflicts"
      />
    </Card>
  );
}
