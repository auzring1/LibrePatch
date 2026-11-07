import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Drawer } from "@mantine/core";
import { useDebouncedValue } from "@mantine/hooks";
import { api, errorMessage, type SoftwareTitle, type TitleInstall } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { DataTable, EmptyState, Icons, Page, PageHeader, StatGrid, StatTile, StatusPill, TileSkeleton, Status, type Column } from "../ui";
import { LinkButton, ServerSearch, ServerSearchScope } from "../ui/PageBits";

interface TitleDetail {
  id: string;
  name: string;
  publisher: string;
  versions: { version: string; device_count: number }[];
}

export function SoftwarePage() {
  const { can } = useSession();
  const [text, setText] = useState("");
  const [q] = useDebouncedValue(text.trim(), 250);
  const [system, setSystem] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["software", "list", q, system],
    queryFn: () => api<{ items: SoftwareTitle[]; total: number }>("GET", `/software?limit=200&q=${encodeURIComponent(q)}${system ? "&include_system=true" : ""}`),
  });
  const csv = `/api/v1/reports/software.csv?q=${encodeURIComponent(q)}${system ? "&include_system=true" : ""}`;

  const columns = useMemo<Column<SoftwareTitle>[]>(
    () => [
      {
        id: "name",
        header: "Product",
        value: (t) => t.name,
        required: true,
        primary: true,
        width: 320,
        cell: (t) => <LinkButton onClick={() => setSelected(t.id)}>{t.name}</LinkButton>,
      },
      { id: "publisher", header: "Publisher", value: (t) => t.publisher || "", width: 240 },
      { id: "devices", header: "Devices", value: (t) => t.device_count, align: "right", width: 110, cell: (t) => <span className="lp-num">{t.device_count}</span> },
      { id: "versions", header: "Versions", value: (t) => t.version_count, align: "right", width: 110, cell: (t) => <span className="lp-num">{t.version_count}</span> },
    ],
    [],
  );

  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const top = items.reduce<SoftwareTitle | undefined>((best, t) => (!best || t.device_count > best.device_count ? t : best), undefined);
  const multi = items.filter((t) => t.version_count > 1).length;
  const truncated = total > items.length;

  return (
    <Page>
      <PageHeader
        title="Software"
        description="Everything installed across your devices, grouped by product. Open a product to see which versions are out there and where."
        actions={
          can("inventory:export") ? (
            <Button component="a" href={csv} variant="default" download leftSection={<Icons.Download size={16} aria-hidden />}>
              Export CSV
            </Button>
          ) : undefined
        }
      />
      {list.isLoading ? (
        <TileSkeleton count={3} />
      ) : items.length > 0 ? (
        <StatGrid compact label="Software summary">
          <StatTile label="Products" value={total} kind="accent" icon={<Icons.NavSoftware size={16} aria-hidden />} hint={q ? `matching “${q}”` : system ? "including system components" : "excluding system components"} />
          <StatTile label="With several versions" value={multi} kind={multi > 0 ? "warning" : "success"} icon={<Icons.Timeline size={16} aria-hidden />} hint={truncated ? `among the first ${items.length} products` : "worth a look for version drift"} />
          {top && <StatTile label="Most widely installed" value={top.device_count} kind="info" icon={<Icons.NavDevices size={16} aria-hidden />} hint={`devices have ${top.name}`} />}
        </StatGrid>
      ) : null}
      {truncated && (
        <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>
          Showing {items.length} of {total} products. Narrow the search to see the rest.
        </Alert>
      )}
      <ServerSearchScope>
        <DataTable<SoftwareTitle>
          id="software"
          label="Products"
          data={list.data?.items}
          loading={list.isLoading}
          error={list.error ? new Error(errorMessage(list.error)) : undefined}
          columns={columns}
          rowId={(t) => t.id}
          rowLabel={(t) => t.name}
          rowTestId="title-row"
          onRowClick={(t) => setSelected(t.id)}
          initialSort={{ id: "devices", desc: true }}
          toolbar={
            <>
              <ServerSearch value={text} onChange={setText} label="Search software" placeholder="Search products or publishers" />
              <Checkbox label="Include system components" checked={system} onChange={(e) => setSystem(e.currentTarget.checked)} />
            </>
          }
          empty={
            <EmptyState
              icon={<Icons.NavSoftware size={26} />}
              title="No matching products yet"
              description="Devices report what is installed shortly after they connect. Adjust the search or include system components to widen the list."
            />
          }
        />
      </ServerSearchScope>
      <TitleDrawer id={selected} onClose={() => setSelected(null)} />
    </Page>
  );
}

function TitleDrawer({ id, onClose }: { id: string | null; onClose: () => void }) {
  const { can } = useSession();
  const [version, setVersion] = useState<string | null>(null);
  const detail = useQuery({ queryKey: ["software", "title", id], queryFn: () => api<TitleDetail>("GET", `/software/${id}`), enabled: !!id });
  const installs = useQuery({
    queryKey: ["software", "installs", id, version],
    queryFn: () => api<{ items: TitleInstall[]; total: number }>("GET", `/software/${id}/installs?limit=500${version ? `&version=${encodeURIComponent(version)}` : ""}`),
    enabled: !!id,
  });
  const d = detail.data;

  const columns = useMemo<Column<TitleInstall>[]>(
    () => [
      { id: "device", header: "Device", value: (i) => i.hostname, primary: true, required: true, width: 200 },
      {
        id: "connection",
        header: "Connection",
        value: (i) => (i.online ? "online" : "offline"),
        width: 120,
        cell: (i) => <Status value={i.online ? "online" : "offline"} size="sm" />,
        filter: {
          type: "select",
          options: [
            { value: "online", label: "Online" },
            { value: "offline", label: "Offline" },
          ],
        },
      },
      { id: "version", header: "Version", value: (i) => i.version || "", width: 130, cell: (i) => <span className="lp-mono">{i.version || "—"}</span> },
      { id: "scope", header: "Scope", value: (i) => i.scope, width: 100 },
      { id: "seen", header: "Last seen", value: (i) => (i.last_seen_at ? new Date(i.last_seen_at).getTime() : 0), width: 180, cell: (i) => dateTime(i.last_seen_at), csv: (i) => i.last_seen_at ?? "" },
    ],
    [],
  );

  return (
    <Drawer
      opened={!!id}
      onClose={() => {
        setVersion(null);
        onClose();
      }}
      position="right"
      size="xl"
      title={d?.name ?? "Product details"}
    >
      <div className="lp-block">
        {detail.isLoading && <TileSkeleton count={1} />}
        {detail.error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {errorMessage(detail.error)}
          </Alert>
        )}
        {d && (
          <>
            <p className="lp-hint">{d.publisher || "Unknown publisher"}</p>
            <h3 className="lp-subhead">Versions</h3>
            <p className="lp-hint">Choose a version to list only the devices that have it.</p>
            <div className="lp-mini__scroll">
              <table className="lp-mini" aria-label="Versions">
                <thead>
                  <tr>
                    <th scope="col">Version</th>
                    <th scope="col" data-align="right">
                      Devices
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {d.versions.map((v) => (
                    <tr key={v.version}>
                      <td>
                        <button type="button" className="lp-linkbtn lp-mono" aria-pressed={version === v.version} onClick={() => setVersion(version === v.version ? null : v.version)}>
                          {v.version || "(unknown)"}
                        </button>{" "}
                        {version === v.version && (
                          <StatusPill kind="info" size="sm" icon={Icons.Filter}>
                            filtered
                          </StatusPill>
                        )}
                      </td>
                      <td data-align="right">
                        <span className="lp-num">{v.device_count} devices</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="lp-row" style={{ justifyContent: "space-between" }}>
              <h3 className="lp-subhead">Devices{version ? ` with ${version}` : ""}</h3>
              {can("inventory:export") && (
                <Button component="a" size="xs" variant="default" href={`/api/v1/reports/software.csv?title_id=${id}`} download leftSection={<Icons.Download size={14} aria-hidden />}>
                  Export CSV
                </Button>
              )}
            </div>
            <DataTable<TitleInstall>
              id="software-installs"
              label="Devices with this software"
              data={installs.data?.items}
              loading={installs.isLoading}
              error={installs.error ? new Error(errorMessage(installs.error)) : undefined}
              columns={columns}
              rowId={(i) => `${i.device_id}|${i.version}|${i.scope}|${i.user_sid ?? ""}|${i.source}|${i.install_location ?? ""}`}
              rowHref={(i) => `/devices/${i.device_id}`}
              rowLabel={(i) => i.hostname}
              pageSize={10}
              initialSort={{ id: "device" }}
              searchPlaceholder="Search devices"
              empty={<EmptyState icon={<Icons.NavDevices size={26} />} title="No devices" description="No device reports this version right now." />}
            />
          </>
        )}
      </div>
    </Drawer>
  );
}
