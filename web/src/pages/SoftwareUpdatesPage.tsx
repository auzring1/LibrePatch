import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Anchor, Button, Group, Menu, Modal, Table, Text, Tooltip } from "@mantine/core";
import { Link } from "react-router-dom";
import { api, errorMessage, type FleetUpdate, type WingetIndexStatus } from "../api/client";
import { useSession } from "../api/session";
import { ConfirmDeployUpdates, useDeployUpdates } from "../components/FleetDeploy";
import { ensurePackage } from "../components/updateDeploy";
import { dateTime } from "../api/format";
import { DataTable, EmptyState, Icons, IconButton, Page, PageHeader, StatusPill, toast, type Column } from "../ui";
import { NewPolicyModal, type PolicyPreset } from "./PoliciesPage";

const KEY = ["software-updates"];

/** How many devices have an older copy, and which versions they run. */
const versions = (u: FleetUpdate) => [...new Set(u.devices.map((d) => d.installed_version))];

function DevicesModal({ update, onClose }: { update: FleetUpdate; onClose: () => void }) {
  return (
    <Modal opened onClose={onClose} title={`${update.package_name}: devices to update`} size="lg">
      <Table verticalSpacing={4} fz="sm" aria-label={`Devices with an older ${update.package_name}`}>
        <Table.Thead>
          <Table.Tr>
            <Table.Th>Device</Table.Th>
            <Table.Th>Installed</Table.Th>
            <Table.Th>Latest</Table.Th>
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {update.devices.map((d) => (
            <Table.Tr key={`${d.device_id}|${d.scope}|${d.installed_version}`}>
              <Table.Td>
                <Anchor component={Link} to={`/devices/${d.device_id}?tab=software-updates`} size="sm" onClick={onClose}>
                  {d.hostname}
                </Anchor>
              </Table.Td>
              <Table.Td ff="monospace">{d.installed_version}</Table.Td>
              <Table.Td ff="monospace">{update.latest_version}</Table.Td>
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Modal>
  );
}

/** Programs from the catalog that are out of date somewhere in the fleet, with a way to update every device at once. */
export function SoftwareUpdatesPage() {
  const { canOrg } = useSession();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: KEY, queryFn: () => api<{ items: FleetUpdate[] }>("GET", "/software/updates") });
  const index = useQuery({ queryKey: ["catalog", "index"], queryFn: () => api<WingetIndexStatus>("GET", "/catalog/index"), enabled: canOrg("catalog:read") });
  const refresh = useMutation({
    mutationFn: () => api<WingetIndexStatus>("POST", "/catalog/index/refresh", {}),
    onSuccess: () => (toast.success("The winget index is up to date."), void qc.invalidateQueries({ queryKey: ["catalog", "index"] }), void qc.invalidateQueries({ queryKey: KEY })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const deploy = useDeployUpdates();
  const [confirm, setConfirm] = useState<{ items: FleetUpdate[]; force: boolean } | null>(null);
  const [clear, setClear] = useState<(() => void) | null>(null);
  const [showDevices, setShowDevices] = useState<FleetUpdate | null>(null);
  const [automate, setAutomate] = useState<PolicyPreset | null>(null);
  const canAct = canOrg("deployments:write");
  // "Keep updated automatically" makes a software policy (D132). An app that is not in the catalog yet is added first.
  const canAutomate = canOrg("policies:write");
  // A package from the winget index is added to the catalog first (catalog:write); pushing the update of an app that updates
  // itself also needs catalog:override.
  const canAdd = canOrg("catalog:write");
  const canForce = canAdd && canOrg("catalog:override");
  const startable = (u: FleetUpdate) => u.deployable && (u.in_catalog || canAdd);
  const automatable = (u: FleetUpdate) => u.deployable && (u.in_catalog || canAdd);
  const automateOne = async (u: FleetUpdate) => {
    try {
      const packageId = await ensurePackage(u);
      void qc.invalidateQueries({ queryKey: ["catalog"] });
      setAutomate({ kind: "keep_updated", packageId, name: `Keep ${u.package_name} updated` });
    } catch (e) {
      toast.error(errorMessage(e), u.package_name);
    }
  };

  const columns = useMemo<Column<FleetUpdate>[]>(
    () => [
      {
        id: "package",
        header: "Package",
        required: true,
        width: 260,
        value: (u) => u.package_name,
        cell: (u) => (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            {u.in_catalog ? (
              <Anchor component={Link} to={`/catalog/${u.package_id}`} size="sm">
                {u.package_name}
              </Anchor>
            ) : (
              <Tooltip label={`${u.winget_id}: from the winget repository, added to your catalog when you deploy it`}>
                <span style={{ fontSize: "var(--lp-text-sm)" }}>{u.package_name}</span>
              </Tooltip>
            )}
            {!u.in_catalog && (
              <StatusPill kind="info" size="sm">
                Not in catalog yet
              </StatusPill>
            )}
            {!u.verified && (
              <StatusPill kind="warning" size="sm">
                Unverified
              </StatusPill>
            )}
          </span>
        ),
      },
      { id: "latest", header: "Latest version", width: 150, value: (u) => u.latest_version, cell: (u) => <span className="lp-mono">{u.latest_version}</span> },
      {
        id: "installed",
        header: "Installed versions",
        width: 220,
        value: (u) => versions(u).join(", "),
        cell: (u) => <span className="lp-mono">{versions(u).slice(0, 3).join(", ")}{versions(u).length > 3 ? ` +${versions(u).length - 3}` : ""}</span>,
      },
      {
        id: "devices",
        header: "Devices to update",
        width: 150,
        value: (u) => u.devices.length,
        cell: (u) => (
          <Anchor component="button" type="button" size="sm" onClick={() => setShowDevices(u)} aria-label={`Show the ${u.devices.length} devices that need ${u.package_name}`}>
            {u.devices.length} device{u.devices.length === 1 ? "" : "s"}
          </Anchor>
        ),
      },
      {
        id: "status",
        header: "Status",
        width: 170,
        value: (u) => (u.deployable ? "update available" : "vendor updates"),
        cell: (u) =>
          u.deployable ? (
            <StatusPill kind="info" size="sm">
              Update available
            </StatusPill>
          ) : (
            <StatusPill kind="neutral" size="sm" title={u.reason}>
              Vendor updates
            </StatusPill>
          ),
        filter: { type: "select", options: [{ value: "update available", label: "Update available" }, { value: "vendor updates", label: "Vendor updates" }] },
      },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Software updates"
        description="Installed programs that have a newer version available, from your catalog and from the winget repository. Programs that are not in the catalog yet are recognised automatically and added when you deploy them. Apps that update themselves are left to their vendor unless you choose otherwise."
        actions={
          canAutomate ? (
            <Button variant="default" leftSection={<Icons.NavSoftwarePolicy size={16} aria-hidden />} onClick={() => setAutomate({ kind: "keep_all", name: "Keep all apps updated" })}>
              Automate all updates…
            </Button>
          ) : undefined
        }
      />
      {index.data && (
        <Group gap="sm" role="status" aria-label="Winget index">
          <Text size="sm" c="dimmed">
            {!index.data.enabled
              ? "The winget source is turned off on this server, so only your catalog is checked."
              : index.data.package_count > 0
                ? `Winget index: ${index.data.package_count.toLocaleString()} packages, downloaded ${index.data.fetched_at ? dateTime(index.data.fetched_at) : "never"}.`
                : "The winget index has not been downloaded yet. It is fetched in the background shortly after the server starts."}
            {index.data.error ? ` Last attempt failed: ${index.data.error}` : ""}
          </Text>
          {index.data.enabled && canAdd && (
            <Button size="compact-xs" variant="default" loading={refresh.isPending} onClick={() => refresh.mutate()}>
              Refresh now
            </Button>
          )}
        </Group>
      )}
      <DataTable<FleetUpdate>
        id="software-updates"
        label="Software updates"
        data={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={(u) => (u.in_catalog ? u.package_id : `winget:${u.winget_id}`)}
        rowTestId="software-update-row"
        rowLabel={(u) => u.package_name}
        searchPlaceholder="Search packages"
        exportName="software-updates"
        selectable={canAct ? startable : false}
        empty={<EmptyState icon={<Icons.Success size={26} />} title="Everything is up to date" description="Every installed program that is in your catalog is at its newest allowed version on every device." />}
        bulkActions={(rows, clr) => (
          <Button size="compact-sm" onClick={() => (setClear(() => clr), setConfirm({ items: rows.filter(startable), force: false }))}>
            Deploy updates
          </Button>
        )}
        rowActions={
          canAct || canAutomate
            ? (u) => (
                <Menu position="bottom-end" withinPortal>
                  <Menu.Target>
                    <IconButton label={`Actions for ${u.package_name}`} icon={<Icons.More size={16} aria-hidden />} size="sm" />
                  </Menu.Target>
                  <Menu.Dropdown>
                    {canAct && (
                      <Menu.Item disabled={!startable(u)} onClick={() => setConfirm({ items: [u], force: false })}>
                        Update {u.devices.length} device{u.devices.length === 1 ? "" : "s"} to {u.latest_version}
                      </Menu.Item>
                    )}
                    {canAct && !u.deployable && canForce && (
                      <Menu.Item onClick={() => setConfirm({ items: [u], force: true })}>Update anyway (the app updates itself)…</Menu.Item>
                    )}
                    {canAutomate && (
                      <Menu.Item disabled={!automatable(u)} onClick={() => void automateOne(u)}>
                        Keep {u.package_name} updated automatically…
                      </Menu.Item>
                    )}
                    <Menu.Item onClick={() => setShowDevices(u)}>Show devices</Menu.Item>
                  </Menu.Dropdown>
                </Menu>
              )
            : undefined
        }
      />
      {showDevices && <DevicesModal update={showDevices} onClose={() => setShowDevices(null)} />}
      {automate && <NewPolicyModal preset={automate} onClose={() => setAutomate(null)} />}
      {confirm && (
        <ConfirmDeployUpdates
          items={confirm.items}
          force={confirm.force}
          busy={deploy.isPending}
          onCancel={() => setConfirm(null)}
          onConfirm={(c) => deploy.mutate({ items: confirm.items, confirm: c, force: confirm.force }, { onSettled: () => (setConfirm(null), clear?.()) })}
        />
      )}
    </Page>
  );
}
