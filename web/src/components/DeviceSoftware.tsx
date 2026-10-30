import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Anchor, Button, Checkbox, Group, Menu, Modal, Stack, Switch, Table, Text, Tooltip } from "@mantine/core";
import { Link } from "react-router-dom";
import {
  api,
  errorMessage,
  type AvailableUpdate,
  type UpdateCheck,
  type DeploymentPlan,
  type DeviceSoftware,
  type DeviceUser,
  type SoftwareChange,
} from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { PRODUCT_NAME } from "../brand.generated";
import { deployUpdate } from "./updateDeploy";
import { Card, DataTable, EmptyState, Icons, IconButton, StatusPill, toast, type Column } from "../ui";

const rowKey = (s: { source: string; scope: string; user_sid?: string; item_key?: string }) => `${s.source}|${s.scope}|${s.user_sid ?? ""}|${s.item_key ?? ""}`;
const ref = (s: { source: string; scope: string; user_sid?: string; item_key?: string }) => ({ source: s.source, scope: s.scope, user_sid: s.user_sid ?? "", item_key: s.item_key ?? "" });

function useUpdates(id: string) {
  const { can } = useSession();
  return useQuery({
    queryKey: ["device", id, "updates"],
    queryFn: () => api<{ items: AvailableUpdate[]; checks: UpdateCheck[] }>("GET", `/devices/${id}/updates`),
    enabled: can("deployments:read"),
  });
}

/** Queues "update" deployments (one per package and scope) for the chosen updates on this device. */
function useDeployUpdates(deviceId: string, hostname: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ items, confirm, force }: { items: AvailableUpdate[]; confirm: boolean; force?: boolean }) => {
      const groups = new Map<string, AvailableUpdate>();
      for (const u of items) groups.set(`${u.package_id}|${u.winget_id ?? ""}|${u.scope}`, u);
      const results: { name: string; plan?: DeploymentPlan; error?: string }[] = [];
      for (const u of groups.values()) {
        try {
          const plan = await deployUpdate({ update: u, name: `Update ${u.package_name} on ${hostname}`, scope: u.scope, deviceIds: [deviceId], confirmUnverified: confirm, force });
          results.push({ name: u.package_name, plan });
        } catch (e) {
          results.push({ name: u.package_name, error: errorMessage(e) });
        }
      }
      return results;
    },
    onSuccess: (results) => {
      for (const r of results) {
        if (r.error) toast.error(r.error, r.name);
        else toast.success( `${r.name}: update queued (${r.plan?.jobs ?? 0} job${r.plan?.jobs === 1 ? "" : "s"}). Follow it on the Jobs tab.`);
      }
      void qc.invalidateQueries({ queryKey: ["device-jobs", deviceId] });
      void qc.invalidateQueries({ queryKey: ["device", deviceId, "updates"] });
      void qc.invalidateQueries({ queryKey: ["software-updates"] });
      void qc.invalidateQueries({ queryKey: ["deployments"] });
      void qc.invalidateQueries({ queryKey: ["catalog"] });
    },
  });
}

function UpdateConfirm({ items, force, onCancel, onConfirm, busy }: { items: AvailableUpdate[]; force?: boolean; onCancel: () => void; onConfirm: (confirmed: boolean) => void; busy: boolean }) {
  const unverified = items.filter((u) => !u.verified);
  const toAdd = items.filter((u) => u.in_catalog === false);
  const [ok, setOk] = useState(false);
  return (
    <Modal opened onClose={onCancel} title={`Deploy ${items.length} update${items.length === 1 ? "" : "s"}`}>
      <Stack>
        <Table verticalSpacing={2} fz="sm" aria-label="Updates to deploy">
          <Table.Tbody>
            {items.map((u) => (
              <Table.Tr key={rowKey(u)}>
                <Table.Td>{u.name}</Table.Td>
                <Table.Td ff="monospace">
                  {u.installed_version} → {u.latest_version}
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="sm" c="dimmed">
          Older copies the new installer does not replace by itself are removed first. Each update becomes a signed job on this device.
        </Text>
        {toAdd.length > 0 && (
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />} title="Added to your catalog first">
            {[...new Set(toAdd.map((u) => u.package_name))].join(", ")} {toAdd.length === 1 ? "is" : "are"} not in your catalog yet. {PRODUCT_NAME} adds {toAdd.length === 1 ? "it" : "them"} from the winget repository now; the installer is downloaded from the vendor by the device and checked against the published SHA-256.
          </Alert>
        )}
        {force && (
          <Alert color="orange" icon={<Icons.Warning size={18} aria-hidden />} title="This app normally updates itself">
            {PRODUCT_NAME} leaves updates to the vendor's own updater by default. Continuing sets the package to push updates anyway (you can change this on its catalog page).
          </Alert>
        )}
        {unverified.length > 0 && (
          <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Unverified packages">
            <Checkbox
              label={`${unverified.map((u) => u.package_name).join(", ")} ${unverified.length === 1 ? "has" : "have"} not been marked as verified. I accept deploying ${unverified.length === 1 ? "it" : "them"}; this is recorded in the audit log.`}
              checked={ok}
              onChange={(e) => setOk(e.currentTarget.checked)}
            />
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button onClick={() => onConfirm(ok)} loading={busy} disabled={unverified.length > 0 && !ok}>
            Deploy
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

function UninstallConfirm({ rows, hostname, onCancel, onConfirm, busy }: { rows: DeviceSoftware[]; hostname: string; onCancel: () => void; onConfirm: () => void; busy: boolean }) {
  return (
    <Modal opened onClose={onCancel} title={`Uninstall ${rows.length} program${rows.length === 1 ? "" : "s"} from ${hostname}?`}>
      <Stack>
        <Table verticalSpacing={2} fz="sm" aria-label="Programs to uninstall">
          <Table.Tbody>
            {rows.map((s) => (
              <Table.Tr key={rowKey(s)}>
                <Table.Td>{s.name}</Table.Td>
                <Table.Td ff="monospace">{s.version || "—"}</Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
        <Text size="sm" c="dimmed">
          The device removes each program with its own uninstaller, silently. Programs that offer no silent uninstaller fail with an explanation. Per-user programs are removed in that user's session.
        </Text>
        <Group justify="flex-end">
          <Button variant="default" onClick={onCancel}>
            Cancel
          </Button>
          <Button color="red" onClick={onConfirm} loading={busy}>
            Uninstall
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

const updatePill = (u: AvailableUpdate | undefined) =>
  u ? (
    <Tooltip label={u.deployable ? (u.in_catalog === false ? `${u.package_name} ${u.latest_version} was found in the winget repository and is added to your catalog when you deploy it` : `${u.package_name} ${u.latest_version} is in the catalog`) : (u.reason ?? "")}>
      <span>
        <StatusPill kind={u.deployable ? "warning" : "neutral"} size="sm" icon={u.deployable ? Icons.ArrowUp : Icons.Info}>
          {u.deployable ? `Update to ${u.latest_version}` : "Vendor updates"}
        </StatusPill>
      </span>
    </Tooltip>
  ) : (
    <span className="lp-muted">—</span>
  );

/** What the update check concluded for a program that has no update: up to date, or why it could not be checked. */
const checkPill = (c: UpdateCheck | undefined) => {
  if (!c) return <span className="lp-muted">—</span>;
  const label = c.status === "current" ? "Up to date" : c.status === "unrecognised" ? "Not recognised" : "Not checked";
  return (
    <Tooltip label={c.message} multiline maw={360}>
      {c.status === "unrecognised" ? (
        <span>
          <StatusPill kind="neutral" size="sm" icon={Icons.Info}>
            {label}
          </StatusPill>
        </span>
      ) : (
        <span className="lp-muted">{label}</span>
      )}
    </Tooltip>
  );
};

const checkText = (c: UpdateCheck | undefined) => (c ? (c.status === "current" ? "up to date" : c.status === "unrecognised" ? "not recognised" : "not checked") : "");

export function SoftwareTab({ id, hostname, active }: { id: string; hostname: string; active: boolean }) {
  const { can, canOrg } = useSession();
  const canAddToCatalog = canOrg("catalog:write"); // an update found in the winget index adds its package to the catalog first
  const qc = useQueryClient();
  const [system, setSystem] = useState(false);
  const [history, setHistory] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState<DeviceSoftware[] | null>(null);
  const [confirmUpdate, setConfirmUpdate] = useState<AvailableUpdate[] | null>(null);
  const [clear, setClear] = useState<(() => void) | null>(null);
  const q = useQuery({
    queryKey: ["device", id, "software", system],
    queryFn: () =>
      api<{ items: DeviceSoftware[]; total: number; truncated: boolean; updated_at: string | null }>(
        "GET",
        `/devices/${id}/software${system ? "?include_system=true" : ""}`,
      ),
  });
  const hist = useQuery({
    queryKey: ["device", id, "software-history"],
    queryFn: () => api<{ items: SoftwareChange[] }>("GET", `/devices/${id}/software/history?limit=100`),
    enabled: history,
  });
  const users = useQuery({ queryKey: ["device", id, "users"], queryFn: () => api<{ items: DeviceUser[] }>("GET", `/devices/${id}/users`) });
  const updates = useUpdates(id);
  const updateByRow = useMemo(() => new Map((updates.data?.items ?? []).map((u) => [rowKey(u), u])), [updates.data]);
  const checkByRow = useMemo(() => new Map((updates.data?.checks ?? []).map((c) => [rowKey(c), c])), [updates.data]);
  const deploy = useDeployUpdates(id, hostname);
  const uninstall = useMutation({
    mutationFn: (rows: DeviceSoftware[]) =>
      api<{ job_ids: string[]; skipped: { device: string; reason: string }[] }>("POST", `/devices/${id}/software/uninstall`, { items: rows.map(ref) }),
    onSuccess: (r) => {
      if (r.job_ids.length) toast.success(`Uninstall queued for ${r.job_ids.length} program${r.job_ids.length === 1 ? "" : "s"}. Follow it on the Jobs tab.`);
      for (const s of r.skipped) toast.warning(s.reason, s.device);
      setConfirmUninstall(null);
      clear?.();
      void qc.invalidateQueries({ queryKey: ["device-jobs", id] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });

  const who = (sid: string) => {
    if (!sid) return "all users";
    const u = users.data?.items.find((x) => x.sid === sid);
    return u ? (u.domain ? `${u.domain}\\${u.username}` : u.username) : sid;
  };
  const canAct = active && can("deployments:write");

  const columns = useMemo<Column<DeviceSoftware>[]>(
    () => [
      { id: "name", header: "Name", value: (s) => s.name, required: true, width: 260 },
      { id: "version", header: "Version", value: (s) => s.version ?? "", width: 130, cell: (s) => <span className="lp-mono">{s.version || "—"}</span> },
      { id: "publisher", header: "Publisher", value: (s) => s.publisher ?? "", width: 190 },
      { id: "for", header: "Installed for", value: (s) => who(s.user_sid ?? ""), width: 150 },
      { id: "type", header: "Type", value: (s) => s.source, width: 110, defaultHidden: true, cell: (s) => <StatusPill kind="neutral" size="sm" icon={null}>{s.source}</StatusPill>, filter: { type: "text" } },
      {
        id: "update",
        header: "Update status",
        value: (s) => (updateByRow.get(rowKey(s))?.deployable ? "update available" : updateByRow.has(rowKey(s)) ? "vendor updates" : checkText(checkByRow.get(rowKey(s)))),
        width: 190,
        cell: (s) => (updateByRow.has(rowKey(s)) ? updatePill(updateByRow.get(rowKey(s))) : checkPill(checkByRow.get(rowKey(s)))),
        filter: {
          type: "select",
          options: [
            { value: "update available", label: "Update available" },
            { value: "vendor updates", label: "Vendor updates" },
            { value: "up to date", label: "Up to date" },
            { value: "not recognised", label: "Not recognised" },
            { value: "not checked", label: "Not checked" },
          ],
        },
      },
      { id: "installed", header: "Installed", value: (s) => s.install_date || s.first_seen_at || "", width: 150, cell: (s) => s.install_date || dateTime(s.first_seen_at) },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [updateByRow, checkByRow, users.data],
  );

  return (
    <Stack>
      {q.data?.truncated && (
        <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
          The agent reported only part of this device's software (item limit reached).
        </Alert>
      )}
      <DataTable<DeviceSoftware>
        id="device-software"
        scope={id}
        label="Installed software"
        data={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={rowKey}
        rowTestId="software-row"
        rowLabel={(s) => s.name}
        searchPlaceholder="Filter by name or publisher"
        exportName={`${hostname}-software`}
        initialSort={{ id: "name" }}
        selectable={canAct}
        empty={<EmptyState icon={<Icons.NavSoftware size={26} />} title="No software reported yet" description="The device sends its inventory a few minutes after it first connects." />}
        toolbar={
          <Group gap="lg">
            <Switch label="Show system components" checked={system} onChange={(e) => setSystem(e.currentTarget.checked)} />
            <Switch label="Change history" checked={history} onChange={(e) => setHistory(e.currentTarget.checked)} />
          </Group>
        }
        bulkActions={(rows, clr) => {
          const ups = rows.map((s) => updateByRow.get(rowKey(s))).filter((u): u is AvailableUpdate => !!u && u.deployable && (u.in_catalog !== false || canAddToCatalog));
          return (
            <>
              <Button size="compact-sm" disabled={ups.length === 0} onClick={() => (setClear(() => clr), setConfirmUpdate(ups))}>
                Deploy Updates
              </Button>
              <Button size="compact-sm" color="red" variant="light" onClick={() => (setClear(() => clr), setConfirmUninstall(rows))}>
                Uninstall Software
              </Button>
            </>
          );
        }}
        rowActions={
          canAct
            ? (s) => {
                const u = updateByRow.get(rowKey(s));
                return (
                  <Menu position="bottom-end" withinPortal>
                    <Menu.Target>
                      <IconButton label={`Actions for ${s.name}`} icon={<Icons.More size={16} aria-hidden />} size="sm" />
                    </Menu.Target>
                    <Menu.Dropdown>
                      {u?.deployable && (u.in_catalog !== false || canAddToCatalog) && <Menu.Item onClick={() => setConfirmUpdate([u])}>Deploy update to {u.latest_version}</Menu.Item>}
                      <Menu.Item color="red" onClick={() => setConfirmUninstall([s])}>
                        Uninstall Software
                      </Menu.Item>
                    </Menu.Dropdown>
                  </Menu>
                );
              }
            : undefined
        }
      />
      {history && (
        <Card title="Recent changes" flush>
          {hist.isLoading && <Text p="md" c="dimmed">Loading…</Text>}
          {hist.data && hist.data.items.length === 0 && <EmptyState title="No changes recorded" description="Changes appear after the first report." />}
          {!!hist.data?.items.length && (
            <Table aria-label="Software changes" verticalSpacing={4} fz="sm">
              <Table.Tbody>
                {hist.data.items.map((h) => (
                  <Table.Tr key={h.id}>
                    <Table.Td>{dateTime(h.observed_at)}</Table.Td>
                    <Table.Td>
                      <StatusPill kind={h.change === "added" ? "success" : h.change === "removed" ? "danger" : "info"} size="sm">
                        {h.change[0]!.toUpperCase() + h.change.slice(1)}
                      </StatusPill>
                    </Table.Td>
                    <Table.Td>{h.name}</Table.Td>
                    <Table.Td className="lp-mono">{h.change === "version" ? `${h.old_version} → ${h.new_version}` : h.change === "added" ? h.new_version : h.old_version}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          )}
        </Card>
      )}
      {confirmUninstall && <UninstallConfirm rows={confirmUninstall} hostname={hostname} onCancel={() => setConfirmUninstall(null)} onConfirm={() => uninstall.mutate(confirmUninstall)} busy={uninstall.isPending} />}
      {confirmUpdate && (
        <UpdateConfirm
          items={confirmUpdate}
          onCancel={() => setConfirmUpdate(null)}
          busy={deploy.isPending}
          onConfirm={(c) => deploy.mutate({ items: confirmUpdate, confirm: c }, { onSettled: () => (setConfirmUpdate(null), clear?.()) })}
        />
      )}
    </Stack>
  );
}

export function MissingUpdatesTab({ id, hostname, active }: { id: string; hostname: string; active: boolean }) {
  const { can, canOrg } = useSession();
  const q = useUpdates(id);
  const [confirm, setConfirm] = useState<{ items: AvailableUpdate[]; force: boolean } | null>(null);
  const [clear, setClear] = useState<(() => void) | null>(null);
  const deploy = useDeployUpdates(id, hostname);
  const canAct = active && can("deployments:write");
  // An update that comes from the winget index adds its package to the catalog first, which needs catalog:write; pushing the
  // update of an app that updates itself also needs catalog:override.
  const canAdd = canOrg("catalog:write");
  const canForce = canAdd && canOrg("catalog:override");
  const startable = (u: AvailableUpdate) => (u.in_catalog !== false || canAdd) && u.deployable;
  const columns = useMemo<Column<AvailableUpdate>[]>(
    () => [
      { id: "name", header: "Name", value: (u) => u.name, required: true, width: 240 },
      { id: "installed", header: "Installed version", value: (u) => u.installed_version, width: 150, cell: (u) => <span className="lp-mono">{u.installed_version}</span> },
      { id: "latest", header: "Latest version", value: (u) => u.latest_version, width: 150, cell: (u) => <span className="lp-mono">{u.latest_version}</span> },
      {
        id: "package",
        header: "Package",
        value: (u) => u.package_name,
        width: 230,
        cell: (u) => (
          <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
            {u.in_catalog === false ? (
              <Tooltip label={`${u.winget_id}: from the winget repository, added to your catalog when you deploy it${u.matched_by ? ` (recognised by ${u.matched_by === "product_code" ? "its product code" : "its name and publisher"})` : ""}`}>
                <span style={{ fontSize: "var(--lp-text-sm)" }}>{u.package_name}</span>
              </Tooltip>
            ) : (
              <Anchor component={Link} to={`/catalog/${u.package_id}`} size="sm">
                {u.package_name}
              </Anchor>
            )}
            {u.in_catalog === false && (
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
      {
        id: "status",
        header: "Status",
        value: (u) => (u.deployable ? "update available" : "vendor updates"),
        width: 180,
        cell: (u) => updatePill(u),
        filter: { type: "select", options: [{ value: "update available", label: "Update available" }, { value: "vendor updates", label: "Vendor updates" }] },
      },
    ],
    [],
  );
  return (
    <Stack>
      <Text size="sm" c="dimmed">
        Updates come from your <Anchor component={Link} to="/catalog">Catalog</Anchor> and from the winget repository: programs that are not in the catalog yet are recognised automatically and added when you deploy them.
      </Text>
      <DataTable<AvailableUpdate>
        id="device-software-updates"
        scope={id}
        label="Software updates"
        data={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={rowKey}
        rowTestId="update-row"
        rowLabel={(u) => u.name}
        searchPlaceholder="Search updates"
        exportName={`${hostname}-software-updates`}
        selectable={canAct ? startable : false}
        empty={<EmptyState icon={<Icons.Success size={26} />} title="No missing updates" description="Every installed program that is in your catalog is at its newest allowed version." />}
        bulkActions={(rows, clr) => (
          <Button size="compact-sm" onClick={() => (setClear(() => clr), setConfirm({ items: rows.filter(startable), force: false }))}>
            Deploy Updates
          </Button>
        )}
        rowActions={
          canAct
            ? (u) => (
                <Menu position="bottom-end" withinPortal>
                  <Menu.Target>
                    <IconButton label={`Actions for ${u.name}`} icon={<Icons.More size={16} aria-hidden />} size="sm" />
                  </Menu.Target>
                  <Menu.Dropdown>
                    <Menu.Item disabled={!startable(u)} onClick={() => setConfirm({ items: [u], force: false })}>
                      Deploy update to {u.latest_version}
                    </Menu.Item>
                    {!u.deployable && canForce && (
                      <Menu.Item onClick={() => setConfirm({ items: [u], force: true })}>Update anyway (the app updates itself)…</Menu.Item>
                    )}
                  </Menu.Dropdown>
                </Menu>
              )
            : undefined
        }
      />
      {confirm && (
        <UpdateConfirm
          items={confirm.items}
          force={confirm.force}
          onCancel={() => setConfirm(null)}
          busy={deploy.isPending}
          onConfirm={(c) => deploy.mutate({ items: confirm.items, confirm: c, force: confirm.force }, { onSettled: () => (setConfirm(null), clear?.()) })}
        />
      )}
    </Stack>
  );
}
