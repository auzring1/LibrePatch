import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert } from "@mantine/core";
import { api, errorMessage, type LifecycleReport, type LifecycleRow } from "../api/client";
import { Card, DataTable, EmptyState, Icons, StatGrid, StatTile, StatusPill, TileSkeleton, type Column } from "../ui";
import { LIFECYCLE_KIND, LIFECYCLE_LABEL, whenSupportEnds, type LifecycleStatus } from "./lifecycle";

/** Which devices run an operating system that Microsoft no longer supports, or soon will not. */
export function LifecycleCard() {
  const q = useQuery({ queryKey: ["reports", "lifecycle"], queryFn: () => api<LifecycleReport>("GET", "/reports/lifecycle") });
  const rep = q.data;
  const look = useMemo(() => (rep?.items ?? []).filter((r) => r.status !== "supported"), [rep]);

  const columns = useMemo<Column<LifecycleRow>[]>(
    () => [
      { id: "device", header: "Device", required: true, primary: true, width: 200, value: (r) => r.hostname },
      {
        id: "status",
        header: "Support",
        width: 150,
        value: (r) => LIFECYCLE_LABEL[r.status as LifecycleStatus] ?? r.status,
        cell: (r) => (
          <StatusPill kind={LIFECYCLE_KIND[r.status as LifecycleStatus] ?? "neutral"} size="sm">
            {LIFECYCLE_LABEL[r.status as LifecycleStatus] ?? r.status}
          </StatusPill>
        ),
        filter: {
          type: "select",
          options: [
            { value: LIFECYCLE_LABEL.unsupported, label: LIFECYCLE_LABEL.unsupported },
            { value: LIFECYCLE_LABEL.ending_soon, label: LIFECYCLE_LABEL.ending_soon },
            { value: LIFECYCLE_LABEL.unknown, label: LIFECYCLE_LABEL.unknown },
          ],
        },
      },
      { id: "os", header: "Operating system", width: 240, value: (r) => [r.product || r.os, r.release].filter(Boolean).join(" ") },
      { id: "edition", header: "Edition", width: 160, value: (r) => r.edition },
      { id: "build", header: "Build", align: "right", width: 90, value: (r) => r.build, cell: (r) => <span className="lp-num">{r.build || "—"}</span> },
      { id: "end", header: "Support ends", width: 150, value: (r) => r.end_of_support ?? "", cell: (r) => r.end_of_support ?? "—" },
      { id: "left", header: "", width: 170, value: (r) => r.days_left ?? 0, csv: (r) => whenSupportEnds(r.days_left), cell: (r) => <span className="lp-muted">{whenSupportEnds(r.days_left)}</span> },
      { id: "note", header: "Note", width: 360, value: (r) => r.note },
    ],
    [],
  );

  const s = rep?.summary;
  return (
    <>
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.isLoading && <TileSkeleton count={4} />}
      {s && (
        <StatGrid label="Operating system support">
          <StatTile label="Out of support" value={s.unsupported} kind={s.unsupported > 0 ? "danger" : "neutral"} icon={<Icons.Danger size={16} aria-hidden />} />
          <StatTile label="Ending soon" value={s.ending_soon} kind={s.ending_soon > 0 ? "warning" : "neutral"} hint={`within ${rep?.warn_days} days`} icon={<Icons.Clock size={16} aria-hidden />} />
          <StatTile label="Supported" value={s.supported} kind="success" icon={<Icons.Success size={16} aria-hidden />} />
          <StatTile label="Unknown" value={s.unknown} kind="neutral" hint="not in the table yet" icon={<Icons.Unknown size={16} aria-hidden />} />
        </StatGrid>
      )}
      <Card
        title="Operating system support"
        description={`Devices whose Windows version is out of support, ending soon, or not recognized. The end dates come from a table built into the server, last reviewed ${rep?.data_as_of ?? "…"}; check them against Microsoft's lifecycle pages before you rely on them.`}
      >
        <DataTable<LifecycleRow>
          id="reports-lifecycle"
          label="Devices by operating system support"
          data={q.isLoading ? undefined : look}
          loading={q.isLoading}
          error={q.error}
          columns={columns}
          rowId={(r) => r.device_id}
          rowHref={(r) => `/devices/${r.device_id}`}
          rowLabel={(r) => r.hostname}
          searchPlaceholder="Search devices…"
          exportName="operating-system-support"
          initialSort={{ id: "left" }}
          empty={<EmptyState icon={<Icons.Success size={26} />} title="Every device runs a supported operating system" description="Nothing is out of support or ending soon." />}
        />
      </Card>
    </>
  );
}
