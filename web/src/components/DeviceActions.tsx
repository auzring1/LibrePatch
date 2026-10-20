import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Button, Menu, Tooltip } from "@mantine/core";
import { api, errorMessage, type Device } from "../api/client";
import { useSession } from "../api/session";
import { Icons, toast } from "../ui";
import {
  fetchWindowsUpdates,
  fromOnlineCheck,
  InstallModal,
  installable,
  RestartModal,
  useInstallUpdates,
  useRebootDevice,
  useScanUpdates,
  windowsUpdatesKey,
  type Item,
} from "./DeviceWindowsUpdates";

interface PendingAction {
  mutate: () => void;
  isPending: boolean;
}

interface Props {
  device: Device;
  approve: PendingAction;
  refreshDevice: PendingAction;
  /** Opens the revoke dialog (the device page owns it). */
  onRevoke: () => void;
  /** Asks for confirmation, then deletes. */
  onDelete: () => void;
}

/**
 * The device page's actions. Each one keeps the permission it always had and is hidden, not disabled, without it:
 * approve, refresh, revoke/reject and delete need `devices:write`; scan, install and restart are the Windows updates
 * tab's actions (`updates:read` to see that tab, `updates:write` to act) on an active device.
 */
export function DeviceActions({ device: d, approve, refreshDevice, onRevoke, onDelete }: Props) {
  const { can } = useSession();
  const qc = useQueryClient();
  const canDevices = can("devices:write");
  const canUpdates = can("updates:read") && can("updates:write") && d.status === "active";
  const scan = useScanUpdates(d.id);
  const install = useInstallUpdates(d.id);
  const reboot = useRebootDevice(d.id);
  const [loadingInstall, setLoadingInstall] = useState(false);
  const [installFor, setInstallFor] = useState<{ items: Item[]; online: boolean } | null>(null);
  const [restartOpen, setRestartOpen] = useState(false);
  // Wake-on-LAN: another online computer on the same network sends the packet (D125).
  const wake = useMutation({
    mutationFn: () => api<{ job_id: string; helper: string }>("POST", `/devices/${d.id}/wake`, {}),
    onSuccess: (r) => toast.success(`Wake-up packet requested through ${r.helper}. If the computer is set up for Wake-on-LAN it connects within a minute or two.`),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const canWake = can("devices:wake") && d.status === "active" && !d.online;

  const openInstall = async () => {
    setLoadingInstall(true);
    try {
      const wu = await qc.fetchQuery({ queryKey: windowsUpdatesKey(d.id), queryFn: () => fetchWindowsUpdates(d.id), staleTime: 0 });
      const items = installable(wu.items);
      const online = fromOnlineCheck(wu);
      if (items.length === 0) toast.info("Nothing to install: no missing Windows updates are known for this device. Scan for updates first.");
      else if (online && !can("updates:policy")) toast.info("These updates come from an online check, which only people with the update-policy permission can install. Scan for updates to go back to the usual source.");
      else setInstallFor({ items, online });
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setLoadingInstall(false);
    }
  };

  const canReject = d.status === "pending" || d.status === "active";
  const canDelete = d.status === "revoked" || d.status === "retired";
  const hasMore = canDevices && (canReject || canDelete);

  return (
    <>
      {canDevices && d.status === "pending" && (
        <Button onClick={() => approve.mutate()} loading={approve.isPending} leftSection={<Icons.Check size={16} aria-hidden />}>
          Approve
        </Button>
      )}
      {canUpdates && (
        <>
          <Button variant="default" onClick={() => scan.mutate()} loading={scan.isPending} leftSection={<Icons.NavAgentUpdates size={16} aria-hidden />}>
            Scan for updates
          </Button>
          <Button variant="default" onClick={() => void openInstall()} loading={loadingInstall || install.isPending} leftSection={<Icons.Download size={16} aria-hidden />}>
            Install updates
          </Button>
          <Button variant="default" onClick={() => setRestartOpen(true)} loading={reboot.isPending} leftSection={<Icons.Restart size={16} aria-hidden />}>
            Restart
          </Button>
        </>
      )}
      {canWake && (
        <Tooltip label="Another online computer on the same network sends a Wake-on-LAN packet">
          <Button variant="default" onClick={() => wake.mutate()} loading={wake.isPending} leftSection={<Icons.Play size={16} aria-hidden />}>
            Wake up
          </Button>
        </Tooltip>
      )}
      {canDevices && d.status === "active" && (
        <Tooltip label={d.online ? "Ask the device to send its hardware, software and user information now" : "The device is offline"}>
          <Button variant="default" onClick={() => refreshDevice.mutate()} loading={refreshDevice.isPending} disabled={!d.online} leftSection={<Icons.NavAgentUpdates size={16} aria-hidden />}>
            Refresh
          </Button>
        </Tooltip>
      )}
      {hasMore && (
        <Menu position="bottom-end" withinPortal>
          <Menu.Target>
            <Button variant="default" aria-label="More actions" leftSection={<Icons.More size={16} aria-hidden />}>
              More
            </Button>
          </Menu.Target>
          <Menu.Dropdown>
            {canReject && (
              <Menu.Item color="red" leftSection={<Icons.Danger size={16} aria-hidden />} onClick={onRevoke}>
                {d.status === "pending" ? "Reject device" : "Revoke device"}
              </Menu.Item>
            )}
            {canDelete && (
              <Menu.Item color="red" leftSection={<Icons.Trash size={16} aria-hidden />} onClick={onDelete}>
                Delete device
              </Menu.Item>
            )}
          </Menu.Dropdown>
        </Menu>
      )}
      {installFor && (
        <InstallModal
          items={installFor.items}
          online={installFor.online}
          busy={install.isPending}
          onCancel={() => setInstallFor(null)}
          onConfirm={(restart) => install.mutate({ ids: installFor.items.map((i) => i.update_id), restart, online: installFor.online }, { onSuccess: () => setInstallFor(null) })}
        />
      )}
      {restartOpen && <RestartModal busy={reboot.isPending} onCancel={() => setRestartOpen(false)} onConfirm={(m) => reboot.mutate(m, { onSuccess: () => setRestartOpen(false) })} />}
    </>
  );
}
