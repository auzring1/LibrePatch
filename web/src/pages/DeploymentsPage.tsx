import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Button, Group } from "@mantine/core";
import { api, type DeploymentSummary } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { DataTable, EmptyState, Icons, Page, PageHeader, StatGrid, StatTile, Status, StatusPill, TileSkeleton, type Column } from "../ui";
import { DeploymentProgress } from "../ui/DeploymentProgress";

/** A deployment's state as a pill. `lowercase` keeps the API word as the pill's text (the detail page's status marker). */
export function DeploymentStatus({ status, lowercase }: { status: string; lowercase?: boolean }) {
  const word = status === "cancelled" ? "canceled" : status;
  const text = (s: string) => (lowercase ? s : s[0]!.toUpperCase() + s.slice(1));
  const pill =
    status === "active" ? (
      <StatusPill kind="info" icon={Icons.Play}>
        {text(word)}
      </StatusPill>
    ) : (
      <Status value={word} label={text(word)} />
    );
  // The text stays the plain API word in the page; it is capitalized by style only.
  return lowercase ? <span style={{ textTransform: "capitalize" }}>{pill}</span> : pill;
}

const JOB: Record<string, { kind: "success" | "warning" | "danger" | "info" | "neutral"; label: string; icon?: typeof Icons.Clock }> = {
  sent: { kind: "neutral", label: "Sent", icon: Icons.Clock },
  accepted: { kind: "info", label: "Accepted", icon: Icons.Check },
  succeeded_reboot: { kind: "success", label: "Succeeded, restart needed", icon: Icons.Restart },
  rejected: { kind: "danger", label: "Rejected" },
  expired: { kind: "warning", label: "Expired", icon: Icons.Clock },
};

/** A job's state as a pill (used here, on the deployment page and on the device page). */
export function JobBadge({ status }: { status: string }) {
  const j = JOB[status];
  if (j)
    return (
      <StatusPill kind={j.kind} icon={j.icon}>
        {j.label}
      </StatusPill>
    );
  return <Status value={status === "cancelled" ? "canceled" : status} />;
}

const PAGE = 50;
// A stable empty list: a new [] on every render makes the table reset its page again and again while loading.
const NONE: DeploymentSummary[] = [];

export function DeploymentsPage() {
  const { can } = useSession();
  const nav = useNavigate();
  const [urlParams, setUrlParams] = useSearchParams();
  const onlyFailed = urlParams.get("failed") === "1"; // the dashboard's failed-jobs tile
  const [offset, setOffset] = useState(0);
  const q = useQuery({
    queryKey: ["deployments", "list", offset],
    queryFn: () => api<{ items: DeploymentSummary[] }>("GET", `/deployments?limit=${PAGE}&offset=${offset}`),
    refetchInterval: 30_000,
  });
  const all = q.data?.items;
  const items = useMemo(() => (onlyFailed ? all?.filter((d) => d.jobs_failed > 0) : all), [all, onlyFailed]);

  const columns = useMemo<Column<DeploymentSummary>[]>(
    () => [
      {
        id: "name",
        header: "Deployment",
        value: (d) => d.name,
        primary: true,
        required: true,
        sortable: true,
        width: 260,
        cell: (d) => (
          <>
            {d.name}
            <span className="lp-dt__cell-sub">
              {d.action} · {d.scope}
            </span>
          </>
        ),
      },
      {
        id: "package",
        header: "Package",
        value: (d) => d.package_name,
        sortable: true,
        width: 220,
        cell: (d) => (
          <>
            {d.package_name}
            <span className="lp-dt__cell-sub">{d.version ?? "newest"}</span>
          </>
        ),
        filter: { type: "text" },
      },
      {
        id: "status",
        header: "Status",
        value: (d) => d.status,
        sortable: true,
        width: 140,
        cell: (d) => <DeploymentStatus status={d.status} />,
        filter: { type: "select", options: ["active", "paused", "completed", "cancelled"].map((v) => ({ value: v, label: v[0]!.toUpperCase() + v.slice(1) })) },
      },
      {
        id: "progress",
        header: "Progress",
        value: (d) => (d.jobs_total ? (d.jobs_succeeded + d.jobs_failed) / d.jobs_total : 0),
        sortable: true,
        width: 240,
        cell: (d) => <DeploymentProgress total={d.jobs_total} succeeded={d.jobs_succeeded} failed={d.jobs_failed} />,
        csv: (d) => `${d.jobs_succeeded + d.jobs_failed} of ${d.jobs_total} finished, ${d.jobs_failed} failed`,
      },
      {
        id: "created",
        header: "Created",
        value: (d) => (d.created_at ? new Date(d.created_at).getTime() : 0),
        sortable: true,
        width: 190,
        cell: (d) => dateTime(d.created_at),
        csv: (d) => d.created_at ?? "",
      },
    ],
    [],
  );

  const active = items?.filter((d) => d.status === "active").length ?? 0;
  const completed = items?.filter((d) => d.status === "completed").length ?? 0;
  const succeeded = items?.reduce((s, d) => s + d.jobs_succeeded, 0) ?? 0;
  const failed = items?.reduce((s, d) => s + d.jobs_failed, 0) ?? 0;

  return (
    <Page>
      <PageHeader
        title="Deployments"
        description="Install, update or remove software on devices. Progress updates live as devices report back."
        actions={
          can("deployments:write") ? (
            <Button component={Link} to="/deployments/new" leftSection={<Icons.Plus size={16} aria-hidden />}>
              New deployment
            </Button>
          ) : undefined
        }
      />
      {onlyFailed && (
        <div className="lp-chips" role="status">
          <span>Showing</span>
          <span className="lp-chip lp-chip--static">Deployments with failed jobs</span>
          <Button size="compact-sm" variant="default" onClick={() => setUrlParams({}, { replace: true })}>
            Show all deployments
          </Button>
        </div>
      )}
      {q.isLoading ? (
        <TileSkeleton count={4} />
      ) : items && items.length > 0 ? (
        <StatGrid compact label="Deployment summary">
          <StatTile label="Running" value={active} kind="info" icon={<Icons.Play size={16} aria-hidden />} hint="Deployments in progress" />
          <StatTile label="Completed" value={completed} kind="neutral" icon={<Icons.Check size={16} aria-hidden />} hint="Deployments that finished" />
          <StatTile label="Jobs succeeded" value={succeeded} kind="success" icon={<Icons.Success size={16} aria-hidden />} hint="Across the deployments listed" />
          <StatTile label="Jobs failed" value={failed} kind={failed > 0 ? "danger" : "neutral"} icon={<Icons.Danger size={16} aria-hidden />} hint={failed > 0 ? "Open a deployment to retry them" : "Nothing needs attention"} />
        </StatGrid>
      ) : null}
      <DataTable<DeploymentSummary>
        id="deployments"
        label="Deployments"
        data={items ?? NONE}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={(d) => d.id}
        rowHref={(d) => `/deployments/${d.id}`}
        onRowClick={(d) => nav(`/deployments/${d.id}`)}
        rowTestId="deployment-row"
        rowLabel={(d) => d.name}
        searchPlaceholder="Search deployments and packages…"
        exportName="deployments"
        pageSize={PAGE}
        empty={
          <EmptyState
            icon={<Icons.NavDeployments size={26} />}
            title="No deployments yet"
            description="Import a package in the Catalog, then deploy it to devices or groups."
            actions={
              <Button component={Link} to="/catalog">
                Go to Catalog
              </Button>
            }
          />
        }
      />
      {(offset > 0 || (all?.length ?? 0) === PAGE) && (
        <Group>
          <Button variant="default" leftSection={<Icons.ChevronLeft size={16} aria-hidden />} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
            Newer
          </Button>
          <Button variant="default" rightSection={<Icons.ChevronRight size={16} aria-hidden />} disabled={(all?.length ?? 0) < PAGE} onClick={() => setOffset(offset + PAGE)}>
            Older
          </Button>
        </Group>
      )}
    </Page>
  );
}
