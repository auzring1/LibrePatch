import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { Alert, Button, Group, Select, SegmentedControl, Text } from "@mantine/core";
import { api, errorMessage, type DeviceView } from "../api/client";
import { dateTime } from "../api/format";
import { Card, DataTable, Icons, StatusPill, type Column } from "../ui";
import {
  EVENT_LEVELS,
  EVENT_LOGS,
  EVENT_SINCE,
  START_LABEL,
  eventLevel,
  isFinalStatus,
  kb,
  waitingText,
  type EventRow,
  type ProcessRow,
  type ServiceRow,
  type ViewData,
  type ViewKind,
} from "./inspect";

const processColumns: Column<ProcessRow>[] = [
  { id: "name", header: "Program", value: (p) => p.name, primary: true, required: true, width: 200 },
  { id: "pid", header: "PID", value: (p) => p.pid, align: "right", width: 80 },
  { id: "parent", header: "Parent", value: (p) => p.parent_pid, align: "right", width: 80, defaultHidden: true },
  { id: "memory", header: "Memory", value: (p) => p.working_set_kb, cell: (p) => (p.working_set_kb ? kb(p.working_set_kb) : "—"), csv: (p) => String(p.working_set_kb), align: "right", width: 100 },
  { id: "threads", header: "Threads", value: (p) => p.threads, align: "right", width: 80, defaultHidden: true },
  { id: "session", header: "Session", value: (p) => p.session, align: "right", width: 80 },
  { id: "path", header: "Path", value: (p) => p.path ?? "", wrap: true, minWidth: 260 },
];

const serviceColumns: Column<ServiceRow>[] = [
  { id: "display", header: "Service", value: (s) => s.display || s.name, primary: true, required: true, width: 260, wrap: true },
  { id: "name", header: "Name", value: (s) => s.name, width: 180, defaultHidden: true },
  {
    id: "state",
    header: "State",
    value: (s) => s.state,
    cell: (s) => <StatusPill kind={s.state === "running" ? "success" : "neutral"} size="sm">{s.state || "unknown"}</StatusPill>,
    width: 110,
    filter: { type: "select", options: ["running", "stopped", "paused", "starting", "stopping"].map((v) => ({ value: v, label: v })) },
  },
  { id: "start", header: "Starts", value: (s) => START_LABEL[s.start] ?? s.start, width: 150 },
  { id: "account", header: "Runs as", value: (s) => s.account, width: 180 },
  { id: "path", header: "Program", value: (s) => s.path, wrap: true, minWidth: 260, defaultHidden: true },
];

const eventColumns: Column<EventRow>[] = [
  { id: "time", header: "Time", value: (e) => new Date(e.time * 1000), cell: (e) => dateTime(new Date(e.time * 1000).toISOString()), width: 170 },
  {
    id: "level",
    header: "Level",
    value: (e) => eventLevel(e.level),
    cell: (e) => <StatusPill kind={e.level <= 2 ? "danger" : e.level === 3 ? "warning" : "neutral"} size="sm">{eventLevel(e.level)}</StatusPill>,
    width: 100,
  },
  { id: "provider", header: "Source", value: (e) => e.provider, width: 200, wrap: true },
  { id: "id", header: "Event", value: (e) => e.id, align: "right", width: 80 },
  { id: "message", header: "Message", value: (e) => e.message, wrap: true, minWidth: 320, primary: true },
];

/**
 * Read-only views of a device: running programs, services and recent event log entries. Nothing here changes anything on the
 * computer; the answer is kept on the server for an hour (administrators only, audited).
 */
export function InspectTab({ id, online, hostname }: { id: string; online: boolean; hostname: string }) {
  const [kind, setKind] = useState<ViewKind>("processes");
  const [log, setLog] = useState("System");
  const [level, setLevel] = useState("3");
  const [since, setSince] = useState("1440");
  const [shown, setShown] = useState<ViewKind | null>(null);
  const [data, setData] = useState<ViewData<unknown> | null>(null);
  const [progress, setProgress] = useState("");
  const alive = useRef(true);
  useEffect(() => () => void (alive.current = false), []);

  const run = useMutation({
    mutationFn: async () => {
      setData(null);
      setProgress(waitingText("queued", ""));
      const body = kind === "events" ? { kind, log, max_level: Number(level), since_minutes: Number(since), max_events: 200 } : { kind };
      const { job_id } = await api<{ job_id: string }>("POST", `/devices/${id}/inspect`, body);
      for (let i = 0; i < 60 && alive.current; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const v = await api<DeviceView>("GET", `/devices/${id}/views/${job_id}`);
        if (v.status === "succeeded" && v.data) return { kind, data: v.data as unknown as ViewData<unknown> };
        if (isFinalStatus(v.status)) throw new Error(waitingText(v.status, v.status_reason) || "The device did not return anything.");
        setProgress(waitingText(v.status, v.status_reason));
      }
      throw new Error("The device did not answer in time.");
    },
    onSuccess: (r) => (setShown(r.kind), setData(r.data), setProgress("")),
    onError: () => setProgress(""),
  });

  return (
    <Card
      title="Look at this computer"
      description={`Read-only: ${hostname} reports what is running now. Nothing on it is changed. The Security event log is never offered, and the answer is deleted from the server after an hour.`}
    >
      <div style={{ display: "grid", gap: "var(--lp-space-3)" }}>
        <Group align="flex-end" wrap="wrap">
          <SegmentedControl
            aria-label="What to look at"
            value={kind}
            onChange={(v) => setKind(v as ViewKind)}
            data={[
              { value: "processes", label: "Programs" },
              { value: "services", label: "Services" },
              { value: "events", label: "Event log" },
            ]}
          />
          {kind === "events" && (
            <>
              <Select label="Log" data={EVENT_LOGS} value={log} onChange={(v) => v && setLog(v)} allowDeselect={false} w={150} />
              <Select label="Show" data={EVENT_LEVELS} value={level} onChange={(v) => v && setLevel(v)} allowDeselect={false} w={210} />
              <Select label="How far back" data={EVENT_SINCE} value={since} onChange={(v) => v && setSince(v)} allowDeselect={false} w={150} />
            </>
          )}
          <Button onClick={() => run.mutate()} loading={run.isPending} disabled={!online} leftSection={<Icons.Search size={16} aria-hidden />}>
            Show
          </Button>
        </Group>
        {!online && (
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
            The device is offline. It can only be looked at while it is connected.
          </Alert>
        )}
        {run.isPending && progress && <Text size="sm" c="dimmed">{progress}</Text>}
        {run.error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {errorMessage(run.error)}
          </Alert>
        )}
        {data && shown && (
          <>
            <Text size="sm" c="dimmed">
              Taken {dateTime(new Date(data.taken_at * 1000).toISOString())}
              {data.truncated ? `; showing ${data.items.length} of ${data.total} (the list was shortened to fit)` : `; ${data.total} ${data.total === 1 ? "entry" : "entries"}`}.
            </Text>
            {shown === "processes" && (
              <DataTable<ProcessRow> id="inspect-processes" label="Running programs" data={data.items as ProcessRow[]} columns={processColumns} rowId={(p) => String(p.pid)} initialSort={{ id: "name" }} searchPlaceholder="Search programs" exportName="processes" pageSize={50} />
            )}
            {shown === "services" && (
              <DataTable<ServiceRow> id="inspect-services" label="Services" data={data.items as ServiceRow[]} columns={serviceColumns} rowId={(s) => s.name} initialSort={{ id: "display" }} searchPlaceholder="Search services" exportName="services" pageSize={50} />
            )}
            {shown === "events" && (
              <DataTable<EventRow> id="inspect-events" label="Event log" data={(data.items as EventRow[]).map((e, i) => ({ ...e, _i: i }))} columns={eventColumns} rowId={(e) => String(e._i)} initialSort={{ id: "time", desc: true }} searchPlaceholder="Search events" exportName="events" pageSize={50} />
            )}
          </>
        )}
      </div>
    </Card>
  );
}
