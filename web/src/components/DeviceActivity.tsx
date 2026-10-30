import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type AuditEntry } from "../api/client";
import { dateTime } from "../api/format";
import { DataTable, EmptyState, Icons, Status, StatusPill, type Column } from "../ui";

const LIMIT = 100;
// A stable empty list: a new [] on every render makes the table reset its page again and again while loading.
const NONE: AuditEntry[] = [];

const ACTION_LABELS: Record<string, string> = {
  "device.enroll": "Device enrolled",
  "device.approve": "Device approved",
  "device.revoke": "Device revoked",
  "device.revoke_requested": "Revoke requested (uninstalling the agent first)",
  "device.profile_remove": "User profile removal requested",
  "device.delete": "Device deleted",
  "device.refresh": "Information refresh requested",
  "device.reboot": "Restart requested",
  "device.certificate_issue": "Client certificate issued",
  "device.certificate_renew": "Client certificate renewed",
  "software.uninstall": "Software uninstall requested",
  "wu.install": "Windows update install requested",
  "wu.decision": "Windows update decision",
  "wu.hold": "Windows update held",
  "wu.hold_release": "Windows update hold released",
  "job.retry": "Job retried",
  "deployment.create": "Deployment created",
  "deployment.cancel": "Deployment canceled",
  "group.members": "Group members changed",
  "agent.security_event": "Agent security event",
  "gateway.protocol_violation": "Protocol violation",
};

/** A readable name for an audit action word such as `device.certificate_renew`. */
export function auditActionLabel(action: string): string {
  const known = ACTION_LABELS[action];
  if (known) return known;
  const text = action.replace(/[._]+/g, " ").trim();
  return text ? text[0]!.toUpperCase() + text.slice(1) : "—";
}

/** "key: value" pairs of the simple (non-nested) fields of an entry's details, shortened. */
export function auditDetailsSummary(details: AuditEntry["details"] | null | undefined, max = 140): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(details ?? {})) {
    if (v === null || v === undefined || v === "" || typeof v === "object") continue;
    parts.push(`${k.replace(/_/g, " ")}: ${String(v)}`);
  }
  const text = parts.join(" · ");
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function Outcome({ value }: { value: string }) {
  if (value === "denied")
    return (
      <StatusPill kind="warning" size="sm" icon={Icons.Lock}>
        Denied
      </StatusPill>
    );
  return <Status value={value} size="sm" />;
}

const actor = (a: AuditEntry) => a.actor_name || (a.actor_type === "device" ? "This device" : a.actor_type === "system" ? "System" : a.actor_type);

/** The audit-log entries about this device. Needs `audit:read` on the organization; the page only offers the tab to people who have it. */
export function ActivityTab({ id, hostname }: { id: string; hostname: string }) {
  const q = useQuery({
    queryKey: ["device", id, "activity"],
    queryFn: () => api<{ items: AuditEntry[] }>("GET", `/audit?target=${encodeURIComponent(id)}&limit=${LIMIT}`),
  });
  const columns = useMemo<Column<AuditEntry>[]>(
    () => [
      { id: "time", header: "Time", value: (a) => new Date(a.ts).getTime(), sortable: true, width: 190, cell: (a) => <span style={{ whiteSpace: "nowrap" }}>{dateTime(a.ts)}</span>, csv: (a) => a.ts },
      { id: "actor", header: "Actor", value: (a) => `${actor(a)}${a.actor_ip ? ` · ${a.actor_ip}` : ""}`, sortable: true, width: 220 },
      { id: "action", header: "Action", value: (a) => auditActionLabel(a.action), sortable: true, required: true, width: 250, csv: (a) => a.action },
      { id: "outcome", header: "Outcome", value: (a) => a.outcome, sortable: true, width: 120, cell: (a) => <Outcome value={a.outcome} />, filter: { type: "select", options: ["success", "denied", "error"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })) } },
      { id: "details", header: "Details", value: (a) => auditDetailsSummary(a.details, 400), width: 380, wrap: true, cell: (a) => auditDetailsSummary(a.details) || <span className="lp-muted">—</span> },
    ],
    [],
  );
  return (
    <DataTable<AuditEntry>
      id="device-activity"
      label="Device activity"
      data={q.data?.items ?? NONE}
      loading={q.isLoading}
      error={q.error}
      columns={columns}
      rowId={(a) => String(a.id)}
      rowLabel={(a) => `${auditActionLabel(a.action)} at ${a.ts}`}
      searchPlaceholder="Search activity"
      exportName={`${hostname}-activity`}
      initialSort={{ id: "time", desc: true }}
      empty={<EmptyState icon={<Icons.Activity size={26} />} title="No activity recorded" description="Actions taken on this device, such as approvals, restarts and uninstalls, appear here." />}
    />
  );
}
