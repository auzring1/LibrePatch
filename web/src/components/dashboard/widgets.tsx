import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { ago } from "../../api/format";
import type { Dashboard, VulnerabilityOverview } from "../../api/client";
import { Button } from "@mantine/core";
import { Card, Donut, Icons, SeverityBadge, StatTile, StatusPill, type PillKind } from "../../ui";
import { describeAudit } from "../auditText";
import { complianceSummary } from "../compliance";
import { ComplianceChart } from "./ComplianceChart";
import { REASON_TEXT, type Reason, historySummary, kbLabel, missingUpdateLink, normaliseHistory, positiveKind } from "./format";
import { startSteps } from "./start";

/** Every widget may carry its own title and a row count (Customize > widget settings). */
type Props = { d: Dashboard; title?: string; count?: number };

const rowsOf = <T,>(rows: readonly T[], count?: number) => (count && count > 0 ? rows.slice(0, count) : [...rows]);

const ICON = 16;

export type Tile = { key: string; label: string; value: string | number; kind?: PillKind | "accent"; hint?: string; to: string; icon: ReactNode };

/** Every number a stat tile can show, keyed by metric. A metric the data does not allow (no permission) is absent. */
export function allTiles(d: Dashboard): Tile[] {
  const tiles: Tile[] = [];
  const dev = d.devices;
  if (dev) {
    tiles.push({ key: "online", label: "Online devices", value: dev.online ?? 0, kind: "success", hint: `of ${dev.total ?? 0} devices`, to: "/devices?state=online", icon: <Icons.Online size={ICON} aria-hidden="true" /> });
    tiles.push({ key: "offline", label: "Offline devices", value: dev.offline ?? 0, to: "/devices?state=offline", icon: <Icons.Offline size={ICON} aria-hidden="true" /> });
    tiles.push({ key: "total", label: "Devices", value: dev.total ?? 0, kind: "accent", to: "/devices", icon: <Icons.NavDevices size={ICON} aria-hidden="true" /> });
    tiles.push({ key: "pending", label: "Waiting for approval", value: dev.pending ?? 0, kind: positiveKind(dev.pending ?? 0, "warning"), hint: "New devices to review", to: "/devices?status=pending", icon: <Icons.Clock size={ICON} aria-hidden="true" /> });
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
  if (d.compliance) {
    const c = complianceSummary(d.compliance);
    tiles.push({ key: "compliant", label: "Patch compliant", value: c.value, kind: c.kind, hint: c.hint, to: "/reports", icon: <Icons.NavUpdates size={ICON} aria-hidden="true" /> });
  }
  return tiles;
}

/** What the original "Key numbers" strip showed: the tiles above, without the ones that only matter when non-zero. */
export function tileList(d: Dashboard): Tile[] {
  return allTiles(d).filter((t) => (t.key !== "pending" || Number(t.value) > 0) && t.key !== "total" && t.key !== "compliant");
}

/** One stat tile for a metric, or null while the person may not see it. */
export function StatWidget({ d, metric, title }: { d: Dashboard; metric?: string; title?: string }) {
  const t = allTiles(d).find((x) => x.key === metric);
  if (!t) return <p className="lp-dash-empty">This number is not available to you.</p>;
  const { key: _key, ...tile } = t;
  return <StatTile {...tile} label={title || tile.label} />;
}

/** The first steps, as a checklist; each one links to where it is done. */
export function StartWidget({ d, canOrg, onDismiss }: Props & { canOrg: (perm: string) => boolean; onDismiss: () => void }) {
  const steps = startSteps(d, canOrg);
  const left = steps.filter((s) => !s.done).length;
  return (
    <Card
      title="Getting started"
      description={left === 1 ? "One step left" : `${left} steps left`}
      footer={
        <Button variant="default" size="compact-sm" onClick={onDismiss}>
          Hide this
        </Button>
      }
    >
      <ol className="lp-dash-steps" aria-label="Getting started steps">
        {steps.map((s) => (
          <li key={s.id} data-done={s.done ? "true" : "false"}>
            <span className="lp-dash-steps__mark" aria-hidden="true">
              {s.done ? <Icons.Success size={20} /> : <Icons.Unknown size={20} />}
            </span>
            <span className="lp-dash-steps__body">
              <span className="lp-dash-steps__title">
                {s.title}
                {s.done && <span className="lp-visually-hidden"> (done)</span>}
              </span>
              <span className="lp-dash-row__meta">{s.text}</span>
            </span>
            {!s.done && (
              <Button component={Link} to={s.to} variant="default" size="compact-md">
                {s.cta}
              </Button>
            )}
          </li>
        ))}
      </ol>
    </Card>
  );
}

export function AppsWidget({ d, title, count }: Props) {
  const s = d.software;
  if (!s) return null;
  const rows = rowsOf(s.top ?? [], count);
  const manual = s.apps - s.automated;
  return (
    <Card
      title={title || "Apps out of date"}
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

/** Number of days of history for a range setting such as "14d" (7 when unset or unreadable). */
export function rangeDays(range?: string): number {
  const m = /^(\d{1,3})([dh])$/.exec(range ?? "");
  if (!m) return 30;
  return m[2] === "h" ? Math.max(1, Math.ceil(Number(m[1]) / 24)) : Math.max(1, Number(m[1]));
}

export function ComplianceWidget({ d, title, range }: Props & { range?: string }) {
  const c = d.compliance;
  if (!c) return null;
  const days = normaliseHistory(c.history).slice(-rangeDays(range));
  const slices = [
    { label: "Compliant", value: c.compliant ?? 0, token: "success", state: "compliant" },
    { label: "Not compliant", value: c.non_compliant ?? 0, token: "danger", state: "non_compliant" },
    { label: "Not scanned", value: c.unknown ?? 0, token: "neutral", state: "unknown" },
  ];
  const total = slices.reduce((s, x) => s + x.value, 0);
  const summary = complianceSummary(c);
  return (
    <Card title={title || "Patch compliance over time"} description={`Devices per compliance state, one snapshot per day${range ? `, last ${rangeDays(range)} days` : ""}`} footer={<Link to="/reports" className="lp-dash-foot">Open reports</Link>}>
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
          <Donut label="Compliance now" center={total} sub="devices" size={120} legend={false} slices={slices.map(({ label, value, token }) => ({ label, value, token }))} />
          {total > 0 && summary.scanned === 0 && (
            <p className="lp-dash-empty" style={{ padding: "var(--lp-space-2) 0 0", maxWidth: "18rem" }}>
              No device has reported a Windows Update scan yet, so there is nothing to judge. Devices are scanned on a schedule; you can also scan one from its page.
            </p>
          )}
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

export function TopMissingWidget({ d, title, count }: Props) {
  const rows = rowsOf(d.top_missing ?? [], count);
  return (
    <Card title={title || "Top missing updates"} description="Updates missing on the most devices" flush footer={<Link to="/updates" className="lp-dash-foot">View all updates</Link>}>
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

export function AttentionWidget({ d, title, count }: Props) {
  const rows = rowsOf(d.attention ?? [], count);
  return (
    <Card title={title || "Devices needing attention"} description="Worst first" flush footer={<Link to="/devices" className="lp-dash-foot">View all devices</Link>}>
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

export function ActivityWidget({ d, now, title, count }: Props & { now?: number }) {
  const rows = rowsOf(d.activity ?? [], count);
  return (
    <Card title={title || "Recent activity"} description="Latest entries in the audit log" flush footer={<Link to="/audit" className="lp-dash-foot">View audit log</Link>}>
      <ul className="lp-dash-list">
        {rows.map((a) => (
          <li key={a.id}>
            <div className="lp-dash-row">
              <span className="lp-dash-row__main">
                <span className="lp-dash-row__title">{describeAudit(a)}</span>
                <span className="lp-dash-row__meta">
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

export function AgentsWidget({ d, title, count }: Props) {
  const rows = rowsOf([...(d.agent_versions ?? [])].sort((a, b) => (b.devices ?? 0) - (a.devices ?? 0)), count);
  const max = Math.max(1, ...rows.map((r) => r.devices ?? 0));
  return (
    <Card title={title || "Agent versions"} description="Devices per agent version">
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

/** Known vulnerabilities, exploited first. Loaded on its own (needs reports:read and the lookup switched on). */
export function VulnerabilitiesWidget({ data, title, count }: { data?: VulnerabilityOverview; title?: string; count?: number }) {
  const s = data?.summary;
  const rows = rowsOf(data?.items ?? [], count ?? 5);
  return (
    <Card
      title={title || "Vulnerabilities"}
      description={s ? `${s.exploited} exploited, ${s.critical} critical, on ${s.devices} ${s.devices === 1 ? "device" : "devices"}` : "Loading…"}
      flush
      footer={<Link to="/vulnerabilities" className="lp-dash-foot">Open Vulnerabilities</Link>}
    >
      {!data ? (
        <p className="lp-dash-empty">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="lp-dash-empty">No known vulnerabilities affect your devices.</p>
      ) : (
        <ul className="lp-dash-list">
          {rows.map((v) => (
            <li key={v.id}>
              <Link className="lp-dash-row" to="/vulnerabilities">
                <span className="lp-dash-row__main">
                  <span className="lp-dash-row__title lp-mono">{v.id}</span>
                  <span className="lp-dash-row__meta">{(v.products ?? []).join(", ")}</span>
                </span>
                <span className="lp-dash-row__side">
                  {v.exploited && (
                    <StatusPill kind="danger" size="sm">
                      Exploited
                    </StatusPill>
                  )}
                  <span className="lp-dash-count">
                    {v.devices} {v.devices === 1 ? "device" : "devices"}
                  </span>
                </span>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** A tile that opens a report or page. */
export function ShortcutWidget({ label, hint, to, title }: { label?: string; hint?: string; to?: string; title?: string }) {
  if (!to) return <p className="lp-dash-empty">Choose where this tile leads (Edit, then the gear on the widget).</p>;
  return (
    <Link to={to} className="lp-tile lp-dash-shortcut" title={hint}>
      <span className="lp-tile__label">
        <Icons.External size={ICON} aria-hidden="true" />
        Open
      </span>
      <span className="lp-dash-shortcut__name">{title || label}</span>
    </Link>
  );
}

/** Plain text, with web addresses made into links. */
export function TextWidget({ text, title }: { text?: string; title?: string }) {
  const parts = (text ?? "").split(/(https?:\/\/[^\s<>"']+)/g);
  return (
    <Card title={title || undefined} aria-label={title ? undefined : "Note"}>
      <p className="lp-dash-text">
        {parts.length === 1 && !text ? <span className="lp-dash-empty" style={{ padding: 0 }}>Empty note.</span> : null}
        {parts.map((p, i) =>
          /^https?:\/\//.test(p) ? (
            <a key={i} href={p} target="_blank" rel="noopener noreferrer">
              {p}
            </a>
          ) : (
            p
          ),
        )}
      </p>
    </Card>
  );
}
