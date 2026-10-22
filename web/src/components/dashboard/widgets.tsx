import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ago } from "../../api/format";
import type { Dashboard } from "../../api/client";
import { Card, Donut, Icons, SeverityBadge, StatGrid, StatTile, StatusPill, type PillKind } from "../../ui";
import { ComplianceChart } from "./ComplianceChart";
import { REASON_TEXT, type Reason, historySummary, humanAction, kbLabel, missingUpdateLink, normaliseHistory, positiveKind } from "./format";
import type { WidgetId } from "./layout";

type Props = { d: Dashboard };

const ICON = 16;

/** Tiles that the data allows, in display order. The widget is hidden when there are none. */
export function tileList(d: Dashboard) {
  const tiles: { key: string; label: string; value: string | number; kind?: PillKind | "accent"; hint?: string; to: string; icon: ReactNode }[] = [];
  const dev = d.devices;
  if (dev) {
    tiles.push({ key: "online", label: "Online devices", value: dev.online ?? 0, kind: "success", hint: `of ${dev.total ?? 0} devices`, to: "/devices?state=online", icon: <Icons.Online size={ICON} aria-hidden="true" /> });
    tiles.push({ key: "offline", label: "Offline devices", value: dev.offline ?? 0, to: "/devices?state=offline", icon: <Icons.Offline size={ICON} aria-hidden="true" /> });
    if ((dev.pending ?? 0) > 0) tiles.push({ key: "pending", label: "Waiting for approval", value: dev.pending ?? 0, kind: "warning", hint: "New devices to review", to: "/devices?status=pending", icon: <Icons.Clock size={ICON} aria-hidden="true" /> });
  }
  if (d.software) {
    const s = d.software;
    tiles.push({
      key: "apps",
      label: "Apps out of date",
      value: s.apps,
      kind: positiveKind(s.apps, "warning"),
      hint: s.apps === 0 ? "every app is current" : `on ${s.devices} ${s.devices === 1 ? "device" : "devices"}`,
      to: "/software-updates",
      icon: <Icons.NavSoftwareUpdates size={ICON} aria-hidden="true" />,
    });
  }
  if (d.needs_restart != null) tiles.push({ key: "restart", label: "Devices needing restart", value: d.needs_restart, kind: positiveKind(d.needs_restart, "warning"), to: "/devices?restart=1", icon: <Icons.Restart size={ICON} aria-hidden="true" /> });
  if (d.missing_critical_devices != null) tiles.push({ key: "critical", label: "Devices missing critical updates", value: d.missing_critical_devices, kind: positiveKind(d.missing_critical_devices, "danger"), to: "/updates?severity=Critical&missing=1", icon: <Icons.Critical size={ICON} aria-hidden="true" /> });
  if (d.failed_jobs_24h != null) tiles.push({ key: "failed", label: "Failed jobs, last 24 h", value: d.failed_jobs_24h, kind: positiveKind(d.failed_jobs_24h, "danger"), to: "/deployments?failed=1", icon: <Icons.NavDeployments size={ICON} aria-hidden="true" /> });
  return tiles;
}

export function TilesWidget({ d }: Props) {
  const tiles = tileList(d);
  return (
    <StatGrid label="Key numbers">
      {tiles.map(({ key, ...t }) => (
        <StatTile key={key} {...t} />
      ))}
    </StatGrid>
  );
}

export function AppsWidget({ d }: Props) {
  const s = d.software;
  if (!s) return null;
  const rows = s.top ?? [];
  const manual = s.apps - s.automated;
  return (
    <Card
      title="Apps out of date"
      description={s.apps === 0 ? "Installed apps with a newer version available" : `${s.apps} ${s.apps === 1 ? "app" : "apps"} on ${s.devices} ${s.devices === 1 ? "device" : "devices"}${s.vendor > 0 ? `; ${s.vendor} left to their own updater` : ""}`}
      flush
      footer={<Link to="/software-updates" className="lp-dash-foot">Open Software updates</Link>}
    >
      {rows.length === 0 ? (
        <p className="lp-dash-empty">Every app is up to date{s.vendor > 0 ? `, apart from ${s.vendor} that update${s.vendor === 1 ? "s" : ""} itself` : ""}.</p>
      ) : (
        <>
          <ul className="lp-dash-list">
            {rows.map((a) => (
              <li key={a.package_id ?? a.name}>
                <Link className="lp-dash-row" to="/software-updates">
                  <span className="lp-dash-row__main">
                    <span className="lp-dash-row__title">{a.name}</span>
                    <span className="lp-dash-row__meta">newest: {a.latest_version}</span>
                  </span>
                  <span className="lp-dash-row__side">
                    {a.automated ? (
                      <StatusPill kind="success" size="sm">
                        Kept updated
                      </StatusPill>
                    ) : null}
                    <span className="lp-dash-count">
                      {a.devices} {a.devices === 1 ? "device" : "devices"}
                    </span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {manual > 0 && (
            <p className="lp-dash-empty">
              {manual} {manual === 1 ? "app is" : "apps are"} not kept updated by a policy. <Link to="/software-updates">{s.all_apps_policy ? "See why" : "Automate them"}</Link>
            </p>
          )}
        </>
      )}
    </Card>
  );
}

export function ComplianceWidget({ d }: Props) {
  const c = d.compliance;
  if (!c) return null;
  const days = normaliseHistory(c.history);
  const slices = [
    { label: "Compliant", value: c.compliant ?? 0, token: "success", state: "compliant" },
    { label: "Not compliant", value: c.non_compliant ?? 0, token: "danger", state: "non_compliant" },
    { label: "Not scanned", value: c.unknown ?? 0, token: "neutral", state: "unknown" },
  ];
  const total = slices.reduce((s, x) => s + x.value, 0);
  return (
    <Card title="Patch compliance over time" description="Devices per compliance state, one snapshot per day" footer={<Link to="/reports" className="lp-dash-foot">Open reports</Link>}>
      <div className="lp-dash-compliance">
        <div>
          {days.length >= 2 ? (
            <ComplianceChart days={days} />
          ) : (
            <>
              <p className="lp-dash-empty" style={{ padding: 0 }}>
                {days.length === 0 ? "No history yet. " : `Only one day recorded (${historySummary(days).replace(/^Compliance on /, "")}). `}
                History builds up as the server takes hourly snapshots.
              </p>
            </>
          )}
        </div>
        <div>
          <Donut label="Compliance now" center={total} sub="devices" size={120} slices={slices.map(({ label, value, token }) => ({ label, value, token }))} />
          <ul className="lp-dash-states" aria-label="Show devices by compliance">
            {slices.map((s) => (
              <li key={s.state}>
                <Link to={`/reports?state=${s.state}`}>
                  <span className="lp-dot" style={{ background: `var(--lp-${s.token}-solid)` }} aria-hidden="true" />
                  {s.label}
                  <b>{s.value}</b>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  );
}

export function TopMissingWidget({ d }: Props) {
  const rows = d.top_missing ?? [];
  return (
    <Card title="Top missing updates" description="Updates missing on the most devices" flush footer={<Link to="/updates" className="lp-dash-foot">View all updates</Link>}>
      {rows.length === 0 ? (
        <p className="lp-dash-empty">No updates are missing on any device.</p>
      ) : (
        <ul className="lp-dash-list">
          {rows.map((u, i) => (
            <li key={u.update_id ?? i}>
              <Link className="lp-dash-row" to={missingUpdateLink(u)}>
                <span className="lp-dash-row__main">
                  <span className="lp-dash-row__title">{u.title || "Untitled update"}</span>
                  {(u.kb ?? []).length > 0 && <span className="lp-dash-row__meta">{(u.kb ?? []).map(kbLabel).join(", ")}</span>}
                </span>
                <span className="lp-dash-row__side">
                  <SeverityBadge severity={u.severity} size="sm" />
                  <span className="lp-dash-count">{u.devices ?? 0} {(u.devices ?? 0) === 1 ? "device" : "devices"}</span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

const REASON_PILL: Record<Reason, { kind: PillKind; icon: typeof Icons.Offline }> = {
  offline: { kind: "neutral", icon: Icons.Offline },
  reboot_pending: { kind: "warning", icon: Icons.Restart },
  critical_missing: { kind: "critical", icon: Icons.Critical },
  failed_updates: { kind: "danger", icon: Icons.Danger },
};

export function AttentionWidget({ d }: Props) {
  const rows = d.attention ?? [];
  return (
    <Card title="Devices needing attention" description="Worst first" flush footer={<Link to="/devices" className="lp-dash-foot">View all devices</Link>}>
      {rows.length === 0 ? (
        <p className="lp-dash-empty">No device needs attention right now.</p>
      ) : (
        <ul className="lp-dash-list">
          {rows.map((r, i) => (
            <li key={r.device_id ?? i}>
              <Link className="lp-dash-row" to={`/devices/${r.device_id}`}>
                <span className="lp-dash-row__main">
                  <span className="lp-dash-row__title">{r.hostname || "Unnamed device"}</span>
                </span>
                <span className="lp-dash-row__side">
                  {(r.reasons ?? []).map((reason) => {
                    const p = REASON_PILL[reason] ?? { kind: "neutral" as PillKind, icon: Icons.Unknown };
                    return (
                      <StatusPill key={reason} kind={p.kind} icon={p.icon} size="sm">
                        {REASON_TEXT[reason] ?? String(reason).replace(/_/g, " ")}
                      </StatusPill>
                    );
                  })}
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function ActivityWidget({ d, now }: Props & { now?: number }) {
  const rows = d.activity ?? [];
  return (
    <Card title="Recent activity" description="Latest entries in the audit log" flush footer={<Link to="/audit" className="lp-dash-foot">View audit log</Link>}>
      <ul className="lp-dash-list">
        {rows.map((a) => (
          <li key={a.id}>
            <div className="lp-dash-row">
              <span className="lp-dash-row__main">
                <span className="lp-dash-row__title">{humanAction(a.action)}</span>
                <span className="lp-dash-row__meta">
                  {a.actor_name || a.actor_type}
                  {" · "}
                  <time dateTime={a.ts}>{ago(a.ts, now)}</time>
                </span>
              </span>
              {a.outcome !== "success" && (
                <span className="lp-dash-row__side">
                  {a.outcome === "denied" ? (
                    <StatusPill kind="warning" size="sm" icon={Icons.Lock}>
                      Denied
                    </StatusPill>
                  ) : (
                    <StatusPill kind="danger" size="sm">
                      Failed
                    </StatusPill>
                  )}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function AgentsWidget({ d }: Props) {
  const rows = [...(d.agent_versions ?? [])].sort((a, b) => (b.devices ?? 0) - (a.devices ?? 0));
  const max = Math.max(1, ...rows.map((r) => r.devices ?? 0));
  return (
    <Card title="Agent versions" description="Devices per agent version">
      {rows.length === 0 ? (
        <p className="lp-dash-empty" style={{ padding: 0 }}>No agent has reported a version yet.</p>
      ) : (
        <ul className="lp-dash-bars">
          {rows.map((r) => (
            <li key={r.version}>
              <Link to={`/devices?agent=${encodeURIComponent(r.version ?? "")}`} aria-label={`${r.devices ?? 0} devices on version ${r.version || "unknown"}`}>
                <code>{r.version || "unknown"}</code>
                <span className="lp-dash-bars__track" aria-hidden="true">
                  <span className="lp-dash-bars__fill" style={{ width: `${(100 * (r.devices ?? 0)) / max}%`, display: "block" }} />
                </span>
                <span className="lp-dash-count">{r.devices ?? 0}</span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** Which widgets the data allows this person to see. A section the server left out (or an empty log) is not offered. */
export function availableWidgets(d: Dashboard): WidgetId[] {
  const out: WidgetId[] = [];
  if (tileList(d).length > 0) out.push("tiles");
  if (d.software) out.push("apps");
  if (d.compliance) out.push("compliance", "top-missing");
  if (d.devices) out.push("attention", "agents");
  if ((d.activity ?? []).length > 0) out.push("activity");
  return out;
}
