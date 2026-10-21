import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Alert } from "@mantine/core";
import { api, errorMessage, type Device, type DeviceVulnerability } from "../api/client";
import { SeverityPill, ExploitedPill } from "../pages/VulnerabilitiesPage";
import { Card, DataTable, EmptyState, Icons, type Column } from "../ui";
import { fixText, nvdLink } from "./vulnerabilities";

/** The known vulnerabilities in the programs and the Windows version of one device. */
export function VulnerabilitiesTab({ device: d }: { device: Device }) {
  const q = useQuery({ queryKey: ["device", d.id, "vulnerabilities"], queryFn: () => api<{ items: DeviceVulnerability[]; enabled: boolean; has_data: boolean }>("GET", `/devices/${d.id}/vulnerabilities`) });
  const columns = useMemo<Column<DeviceVulnerability>[]>(
    () => [
      {
        id: "cve",
        header: "CVE",
        required: true,
        primary: true,
        width: 150,
        value: (v) => v.id,
        cell: (v) => (
          <a href={nvdLink(v.id)} target="_blank" rel="noopener noreferrer" className="lp-mono">
            {v.id}
          </a>
        ),
      },
      { id: "severity", header: "Severity", width: 130, value: (v) => v.cvss ?? 0, csv: (v) => `${v.severity} ${v.cvss ?? ""}`, cell: (v) => <SeverityPill v={v} /> },
      { id: "exploited", header: "Exploited", width: 170, value: (v) => (v.exploited ? "Exploited" : "No"), cell: (v) => <ExploitedPill v={v} /> },
      { id: "software", header: "Software", width: 220, wrap: true, value: (v) => v.product },
      { id: "installed", header: "Installed", width: 150, value: (v) => v.installed, cell: (v) => <span className="lp-mono">{v.installed}</span> },
      { id: "fix", header: "Update to", width: 240, wrap: true, value: (v) => fixText(v).replace(`${v.product} `, "") },
      { id: "summary", header: "What it is", width: 380, wrap: true, value: (v) => v.summary },
    ],
    [],
  );
  if (q.error) {
    return (
      <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
        {errorMessage(q.error)}
      </Alert>
    );
  }
  const noData = q.data && !q.data.has_data;
  return (
    <Card title="Known vulnerabilities" description="Matched on this server against the public CISA and NIST lists, for Windows and the programs under Vulnerabilities > Programs that are looked up. Programs that are not on that list are not checked.">
      {noData ? (
        <EmptyState
          icon={<Icons.Info size={26} />}
          title={q.data?.enabled ? "No vulnerability data yet" : "The lookup is turned off"}
          description={
            q.data?.enabled ? (
              <>
                The first download is still to come. See <Link to="/vulnerabilities">Vulnerabilities</Link>.
              </>
            ) : (
              <>
                Turn on “Look up known vulnerabilities” under Settings &gt; Vulnerability data. See <Link to="/vulnerabilities">Vulnerabilities</Link>.
              </>
            )
          }
        />
      ) : (
        <DataTable<DeviceVulnerability>
          id="device-vulnerabilities"
          label="Known vulnerabilities on this device"
          data={q.isLoading ? undefined : q.data?.items}
          loading={q.isLoading}
          columns={columns}
          rowId={(v) => `${v.id}/${v.product}`}
          rowLabel={(v) => v.id}
          searchPlaceholder="Search…"
          exportName={`vulnerabilities-${d.hostname}`}
          initialSort={{ id: "severity", desc: true }}
          empty={<EmptyState icon={<Icons.Success size={26} />} title="No known vulnerabilities" description="Among Windows and the programs the lookup knows about." />}
        />
      )}
    </Card>
  );
}
