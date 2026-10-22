import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { Alert, Button } from "@mantine/core";
import { api, errorMessage, type ComplianceRow, type ReportOverview } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { useFeatures } from "../settings/features";
import { useBranding } from "../branding/BrandingProvider";
import { complianceSummary } from "../components/compliance";
import { LifecycleCard } from "../components/LifecycleCard";
import { Card, DataTable, Donut, EmptyState, Icons, Page, PageHeader, StackedBar, StatGrid, StatTile, Status, StatusPill, TileSkeleton, type Column } from "../ui";

interface JobRow {
  type: string;
  ok: number;
  failed: number;
  other: number;
  all: number;
}

export function ReportsPage() {
  const { can } = useSession();
  const { windowsUpdates } = useFeatures();
  const brand = useBranding();
  const [urlParams] = useSearchParams();
  const urlState = urlParams.get("state");
  const preset = useMemo(() => (urlState === "non_compliant" || urlState === "unknown" ? { filters: [{ id: "state", value: urlState }] } : undefined), [urlState]);
  const ov = useQuery({ queryKey: ["reports", "overview"], queryFn: () => api<ReportOverview>("GET", "/reports/overview"), refetchInterval: 60_000 });
  const rows = useQuery({ queryKey: ["reports", "compliance"], queryFn: () => api<{ items: ComplianceRow[] }>("GET", "/reports/compliance"), enabled: windowsUpdates });
  const o = ov.data;
  const compliant = o?.compliance.compliant ?? 0;
  const nonCompliant = o?.compliance.non_compliant ?? 0;
  const unknown = o?.compliance.unknown ?? 0;
  const summary = complianceSummary(o?.compliance);

  const bad = useMemo(() => (rows.data?.items ?? []).filter((r) => r.state !== "compliant"), [rows.data]);
  const jobs = useMemo<JobRow[]>(() => {
    const byType = new Map<string, Record<string, number>>();
    for (const j of o?.jobs_30d ?? []) byType.set(j.type, { ...(byType.get(j.type) ?? {}), [j.status]: j.count });
    return [...byType.entries()].map(([type, s]) => {
      const ok = (s.succeeded ?? 0) + (s.succeeded_reboot ?? 0);
      const failed = (s.failed ?? 0) + (s.rejected ?? 0);
      const all = Object.values(s).reduce((a, b) => a + b, 0);
      return { type, ok, failed, other: all - ok - failed, all };
    });
  }, [o]);

  const badColumns = useMemo<Column<ComplianceRow>[]>(
    () => [
      { id: "device", header: "Device", required: true, primary: true, width: 220, value: (r) => r.hostname },
      {
        id: "state",
        header: "State",
        width: 170,
        value: (r) => r.state,
        csv: (r) => (r.state === "non_compliant" ? "non-compliant" : "not scanned lately"),
        cell: (r) => <Status value={r.state === "non_compliant" ? "non_compliant" : "unknown"} label={r.state === "non_compliant" ? "Not compliant" : "Not scanned lately"} size="sm" />,
        filter: {
          type: "select",
          options: [
            { value: "non_compliant", label: "Not compliant" },
            { value: "unknown", label: "Not scanned lately" },
          ],
        },
      },
      { id: "approved", header: "Approved missing", align: "right", width: 150, value: (r) => r.approved_missing ?? 0, cell: (r) => <span className="lp-num">{r.approved_missing}</span> },
      { id: "critical", header: "Critical missing", align: "right", width: 150, value: (r) => r.critical_missing ?? 0, cell: (r) => <span className="lp-num">{r.critical_missing}</span> },
      { id: "failed", header: "Failed", align: "right", width: 100, value: (r) => r.failed_updates ?? 0, cell: (r) => <span className="lp-num">{r.failed_updates}</span> },
      { id: "scan", header: "Last scan", width: 180, value: (r) => (r.last_scan_at ? new Date(r.last_scan_at).getTime() : 0), csv: (r) => r.last_scan_at ?? "", cell: (r) => dateTime(r.last_scan_at) },
    ],
    [],
  );

  const jobColumns = useMemo<Column<JobRow>[]>(
    () => [
      { id: "type", header: "Type", required: true, width: 220, value: (j) => j.type.replace(/_/g, " ") },
      { id: "ok", header: "Succeeded", align: "right", width: 120, value: (j) => j.ok, cell: (j) => <span className="lp-num">{j.ok}</span> },
      {
        id: "failed",
        header: "Failed",
        align: "right",
        width: 120,
        value: (j) => j.failed,
        cell: (j) =>
          j.failed > 0 ? (
            <StatusPill kind="danger" size="sm">
              {j.failed}
            </StatusPill>
          ) : (
            <span className="lp-num">0</span>
          ),
      },
      { id: "other", header: "Other", align: "right", width: 100, value: (j) => j.other, cell: (j) => <span className="lp-num">{j.other}</span> },
      { id: "rate", header: "Success rate", align: "right", width: 130, value: (j) => (j.all ? Math.round((100 * j.ok) / j.all) : 0), cell: (j) => <span className="lp-num">{j.all ? Math.round((100 * j.ok) / j.all) : 0}%</span> },
    ],
    [],
  );

  const active = o?.devices.active ?? 0;
  const online = o?.devices.online ?? 0;
  const restart = o?.devices.reboot_pending ?? 0;

  return (
    <Page>
      <PageHeader
        title={brand.org_name ? `${brand.org_name} · Reports` : "Reports"}
        description={windowsUpdates ? "How well your devices are patched, and what the server has been doing for them." : "Your devices at a glance, their operating-system support, and what the server has been doing for them."}
        actions={
          can("inventory:export") ? (
            <>
              {windowsUpdates && (
                <>
                  <Button component="a" href="/api/v1/reports/compliance.html" target="_blank" rel="noopener" variant="default" leftSection={<Icons.External size={16} aria-hidden />}>
                    Printable patch compliance report
                  </Button>
                  <Button component="a" href="/api/v1/reports/compliance.csv" download variant="default" leftSection={<Icons.Download size={16} aria-hidden />}>
                    Export patch compliance (CSV)
                  </Button>
                </>
              )}
              <Button component="a" href="/api/v1/reports/lifecycle.csv" download variant="default" leftSection={<Icons.Download size={16} aria-hidden />}>
                Export OS support (CSV)
              </Button>
            </>
          ) : undefined
        }
      />
      {ov.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(ov.error)}
        </Alert>
      )}
      {ov.isLoading && <TileSkeleton count={8} />}
      {o && (
        <>
          <StatGrid label="Fleet summary">
            <StatTile label="Devices" value={active} kind="accent" icon={<Icons.NavDevices size={16} aria-hidden />} to="/devices" />
            <StatTile label="Online now" value={online} kind="success" icon={<Icons.Online size={16} aria-hidden />} hint={active ? `${Math.round((100 * online) / active)}% of devices` : undefined} />
            {windowsUpdates && <StatTile label="Patch compliant" value={summary.value} kind={summary.kind} icon={<Icons.NavUpdates size={16} aria-hidden />} hint={summary.hint} />}
            <StatTile label="Waiting for a restart" value={restart} kind={restart > 0 ? "warning" : "neutral"} icon={<Icons.Restart size={16} aria-hidden />} />
            {windowsUpdates && <StatTile label="Non-compliant" value={nonCompliant} kind={nonCompliant > 0 ? "danger" : "neutral"} icon={<Icons.Danger size={16} aria-hidden />} />}
            {windowsUpdates && <StatTile label="Not scanned lately" value={unknown} kind="neutral" icon={<Icons.Unknown size={16} aria-hidden />} />}
            <StatTile label="Not seen for a week" value={o.devices.not_seen_for_a_week ?? 0} kind={(o.devices.not_seen_for_a_week ?? 0) > 0 ? "warning" : "neutral"} icon={<Icons.Offline size={16} aria-hidden />} />
            <StatTile label="Pending approval" value={o.devices.pending ?? 0} kind={(o.devices.pending ?? 0) > 0 ? "warning" : "neutral"} icon={<Icons.Clock size={16} aria-hidden />} />
          </StatGrid>
          <div style={{ display: "grid", gap: "var(--lp-space-4)", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))" }}>
            {windowsUpdates && (
              <Card title="Compliance" description="Compliant = no approved or critical update missing, no failed install, and a Windows Update scan within the last week.">
                <Donut
                  label="Device compliance"
                  center={summary.value}
                  sub="compliant"
                  slices={[
                    { label: "Compliant", value: compliant, token: "success" },
                    { label: "Not compliant", value: nonCompliant, token: "danger" },
                    { label: "Not scanned lately", value: unknown, token: "neutral" },
                  ]}
                />
              </Card>
            )}
            <Card title="Fleet" description="Active devices by connection, plus the ones that need attention.">
              <StackedBar
                label="Active devices by connection"
                slices={[
                  { label: "Online", value: online, token: "success" },
                  { label: "Offline", value: Math.max(active - online, 0), token: "neutral" },
                ]}
              />
              <div style={{ marginTop: "var(--lp-space-4)" }}>
                <StackedBar
                  label="Devices that need attention"
                  slices={[
                    { label: "Waiting for a restart", value: restart, token: "warning" },
                    { label: "Not seen for a week", value: o.devices.not_seen_for_a_week ?? 0, token: "chart-2" },
                    { label: "Pending approval", value: o.devices.pending ?? 0, token: "info" },
                  ]}
                />
              </div>
            </Card>
          </div>
        </>
      )}
      <LifecycleCard />
      {windowsUpdates && (
        <Card title="Devices to look at" description="Devices that are not compliant, or have not reported a Windows Update scan lately.">
          <DataTable<ComplianceRow>
            id="reports-noncompliant"
            label="Devices that are not compliant"
            data={rows.isLoading ? undefined : bad}
            loading={rows.isLoading}
            error={rows.error}
            columns={badColumns}
            preset={preset}
            rowId={(r) => r.device_id}
            rowHref={(r) => `/devices/${r.device_id}`}
            rowLabel={(r) => r.hostname}
            searchPlaceholder="Search devices…"
            exportName="devices-to-look-at"
            initialSort={{ id: "critical", desc: true }}
            empty={<EmptyState icon={<Icons.Success size={26} />} title="Every scanned device is compliant" description="Nothing needs attention right now." />}
          />
        </Card>
      )}
      {o && (
        <Card title="Jobs in the last 30 days" description="What the server asked devices to do, by type.">
          <DataTable<JobRow>
            id="reports-jobs"
            label="Jobs in the last 30 days"
            data={jobs}
            columns={jobColumns}
            rowId={(j) => j.type}
            searchPlaceholder="Search job types…"
            exportName="jobs-30-days"
            initialSort={{ id: "type" }}
            empty={<EmptyState icon={<Icons.NavDeployments size={26} />} title="No jobs yet" />}
          />
        </Card>
      )}
    </Page>
  );
}
