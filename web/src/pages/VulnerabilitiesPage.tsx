import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Alert, Button, Modal, Stack, Table, Text } from "@mantine/core";
import { api, errorMessage, type Vulnerability, type VulnerabilityDevice, type VulnerabilityOverview, type VulnerabilitySyncReport } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { TrackedProductsCard } from "../components/TrackedProductsCard";
import { describeData, dueText, fixText, nvdLink, scoreText, SEVERITY_KIND, SEVERITY_LABEL } from "../components/vulnerabilities";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, StatGrid, StatTile, StatusPill, TileSkeleton, toast, type Column } from "../ui";

export function SeverityPill({ v }: { v: Pick<Vulnerability, "severity" | "cvss"> }) {
  const score = scoreText(v.cvss);
  return (
    <StatusPill kind={SEVERITY_KIND[v.severity] ?? "neutral"} size="sm">
      {SEVERITY_LABEL[v.severity] ?? v.severity}
      {score ? ` ${score}` : ""}
    </StatusPill>
  );
}

export function ExploitedPill({ v }: { v: Pick<Vulnerability, "exploited" | "ransomware" | "exploited_name"> }) {
  if (!v.exploited) return <span className="lp-muted">—</span>;
  return (
    <StatusPill kind="danger" size="sm" icon={Icons.Flame} title={`${v.exploited_name || "On the CISA list of known exploited vulnerabilities"}${v.ransomware ? ". Known to be used in ransomware campaigns." : ""}`}>
      {v.ransomware ? "Exploited, ransomware" : "Exploited"}
    </StatusPill>
  );
}

export function VulnerabilitiesPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const [open, setOpen] = useState<Vulnerability | null>(null);
  const q = useQuery({ queryKey: ["vulnerabilities"], queryFn: () => api<VulnerabilityOverview>("GET", "/vulnerabilities?limit=1000"), refetchInterval: 120_000 });
  const sync = useMutation({
    mutationFn: () => api<VulnerabilitySyncReport>("POST", "/vulnerabilities/sync"),
    onSuccess: (r) => {
      const bits = [r.kev === "downloaded" ? `CISA list: ${r.kev_items} entries` : r.kev === "unchanged" ? "CISA list unchanged" : r.kev === "failed" ? "CISA list failed" : "", r.products ? `${r.products} product${r.products === 1 ? "" : "s"} updated` : "", r.pending ? `${r.pending} waiting for the next run` : ""].filter(Boolean);
      (r.errors.length ? toast.error : toast.success)(`${bits.join("; ") || "Nothing was due."}${r.errors.length ? ` Problems: ${r.errors.join("; ")}` : ""}`);
      void qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const d = q.data;
  const state = describeData(d?.status);
  const s = d?.summary;

  const columns = useMemo<Column<Vulnerability>[]>(
    () => [
      { id: "cve", header: "CVE", required: true, primary: true, width: 150, value: (v) => v.id, cell: (v) => <span className="lp-mono">{v.id}</span> },
      {
        id: "severity",
        header: "Severity",
        width: 130,
        value: (v) => v.cvss ?? 0,
        csv: (v) => `${SEVERITY_LABEL[v.severity] ?? v.severity} ${scoreText(v.cvss)}`.trim(),
        cell: (v) => <SeverityPill v={v} />,
      },
      {
        id: "exploited",
        header: "Exploited",
        width: 180,
        value: (v) => (v.exploited ? (v.ransomware ? "Exploited, ransomware" : "Exploited") : "No"),
        cell: (v) => <ExploitedPill v={v} />,
        filter: {
          type: "select",
          options: [
            { value: "Exploited", label: "Exploited" },
            { value: "Exploited, ransomware", label: "Exploited, ransomware" },
          ],
        },
      },
      { id: "software", header: "Affected software", width: 260, wrap: true, value: (v) => v.products.join(", ") },
      { id: "devices", header: "Devices", align: "right", width: 90, value: (v) => v.devices, cell: (v) => <span className="lp-num">{v.devices}</span> },
      { id: "fix", header: "Fix", width: 300, wrap: true, value: (v) => fixText(v) },
      { id: "published", header: "Published", width: 130, value: (v) => (v.published ? new Date(v.published).getTime() : 0), csv: (v) => v.published ?? "", cell: (v) => (v.published ? dateTime(v.published).split(",")[0] : "—") },
      { id: "summary", header: "What it is", width: 420, wrap: true, value: (v) => v.summary },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Vulnerabilities"
        description="Known security problems (CVEs) in the programs and Windows versions your devices run, matched on this server against the public CISA and NIST lists. Vulnerabilities that are known to be exploited come first."
        actions={
          <>
            {can("settings:integrations") && d?.status.enabled && (
              <Button variant="default" onClick={() => sync.mutate()} loading={sync.isPending} leftSection={<Icons.Refresh size={16} aria-hidden />}>
                Update now
              </Button>
            )}
            {can("inventory:export") && (
              <Button component="a" href="/api/v1/vulnerabilities.csv" download variant="default" leftSection={<Icons.Download size={16} aria-hidden />}>
                Export (CSV)
              </Button>
            )}
          </>
        }
      />
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.isLoading && <TileSkeleton count={5} />}
      {d && state.title !== "Up to date" && (
        <Alert color={state.kind === "warning" ? "yellow" : state.kind === "info" ? "blue" : "gray"} title={state.title} icon={<Icons.Info size={18} aria-hidden />}>
          {state.text}
          {can("settings:integrations") && (
            <div style={{ marginTop: "var(--lp-space-2)" }}>
              <Button component={Link} to="/settings/vulnerabilities" size="compact-sm" variant="default">
                Open the settings
              </Button>
            </div>
          )}
        </Alert>
      )}
      {s && state.ok && (
        <StatGrid label="Vulnerability summary">
          <StatTile label="Known exploited" value={s.exploited} kind={s.exploited > 0 ? "danger" : "success"} icon={<Icons.Flame size={16} aria-hidden />} hint="on the CISA list: fix these first" />
          <StatTile label="Critical" value={s.critical} kind={s.critical > 0 ? "danger" : "neutral"} icon={<Icons.Critical size={16} aria-hidden />} />
          <StatTile label="High" value={s.high} kind={s.high > 0 ? "warning" : "neutral"} icon={<Icons.Warning size={16} aria-hidden />} />
          <StatTile label="Devices affected" value={s.devices} kind={s.devices > 0 ? "warning" : "success"} icon={<Icons.NavDevices size={16} aria-hidden />} hint={`of ${s.devices_active} active`} />
          <StatTile label="Not checked" value={Math.max(s.devices_active - s.devices_covered, 0)} kind="neutral" icon={<Icons.Unknown size={16} aria-hidden />} hint="no program or Windows version the lookup knows" />
        </StatGrid>
      )}
      {d && state.ok && (
        <Card title="Vulnerabilities that affect your devices" description="Select one to see which devices have it and what to update. The software list is limited to the programs under Programs that are looked up, plus Windows itself.">
          <DataTable<Vulnerability>
            id="vulnerabilities"
            label="Vulnerabilities"
            data={q.isLoading ? undefined : d.items}
            loading={q.isLoading}
            error={q.error ? new Error(errorMessage(q.error)) : undefined}
            columns={columns}
            rowId={(v) => v.id}
            rowLabel={(v) => v.id}
            onRowClick={(v) => setOpen(v)}
            searchPlaceholder="Search CVE, software or text…"
            exportName="vulnerabilities"
            initialSort={{ id: "devices", desc: true }}
            empty={<EmptyState icon={<Icons.Success size={26} />} title="No known vulnerabilities affect your devices" description="Among the programs and Windows versions the lookup knows about." />}
          />
        </Card>
      )}
      <TrackedProductsCard />
      {open && <VulnerabilityModal v={open} onClose={() => setOpen(null)} />}
    </Page>
  );
}

function VulnerabilityModal({ v, onClose }: { v: Vulnerability; onClose: () => void }) {
  const q = useQuery({ queryKey: ["vulnerabilities", v.id, "devices"], queryFn: () => api<{ items: VulnerabilityDevice[] }>("GET", `/vulnerabilities/${encodeURIComponent(v.id)}/devices`) });
  const due = dueText(v.kev_due);
  return (
    <Modal opened onClose={onClose} title={v.id} size="xl">
      <Stack>
        <div style={{ display: "flex", flexWrap: "wrap", gap: "var(--lp-space-2)", alignItems: "center" }}>
          <SeverityPill v={v} />
          <ExploitedPill v={v} />
          <a href={nvdLink(v.id)} target="_blank" rel="noopener noreferrer">
            NVD page
          </a>
        </div>
        {v.summary && <Text>{v.summary}</Text>}
        {v.exploited && (
          <Alert color="red" title={v.exploited_name || "Known to be exploited"} icon={<Icons.Flame size={18} aria-hidden />}>
            {v.required_action && <p style={{ margin: 0 }}>{v.required_action}</p>}
            {due && <p style={{ margin: "var(--lp-space-1) 0 0" }}>{due}.</p>}
          </Alert>
        )}
        <Text size="sm">
          <strong>Fix:</strong> {fixText(v)}
        </Text>
        <Table aria-label={`Devices affected by ${v.id}`} verticalSpacing={4} fz="sm">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Device</Table.Th>
              <Table.Th>Affected</Table.Th>
              <Table.Th>Installed</Table.Th>
              <Table.Th>Update to</Table.Th>
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.isLoading && (
              <Table.Tr>
                <Table.Td colSpan={4}>Loading…</Table.Td>
              </Table.Tr>
            )}
            {(q.data?.items ?? []).map((h) => (
              <Table.Tr key={`${h.device_id}/${h.product}`}>
                <Table.Td>
                  <Link to={`/devices/${h.device_id}?tab=vulnerabilities`} onClick={onClose}>
                    {h.hostname}
                  </Link>
                </Table.Td>
                <Table.Td>{h.product}</Table.Td>
                <Table.Td className="lp-mono">{h.installed}</Table.Td>
                <Table.Td className="lp-mono">{h.fixed_in || "—"}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        {q.error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {errorMessage(q.error)}
          </Alert>
        )}
      </Stack>
    </Modal>
  );
}
