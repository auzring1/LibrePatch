import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Alert, Button, Checkbox, Modal, Stack, Tabs, Text, TextInput } from "@mantine/core";
import { api, errorMessage, type Device } from "../api/client";
import { ago } from "../api/format";
import { useSession } from "../api/session";
import { useFeatures } from "../settings/features";
import { DeviceActions } from "../components/DeviceActions";
import { ActivityTab } from "../components/DeviceActivity";
import { HardwareTab } from "../components/DeviceHardware";
import { InspectTab } from "../components/DeviceInspect";
import { JobsTab } from "../components/DeviceJobs";
import { OverviewTab } from "../components/DeviceOverview";
import { SoftwareTab } from "../components/DeviceSoftware";
import { VulnerabilitiesTab } from "../components/DeviceVulnerabilities";
import { SoftwareUpdatesTab, UpdatesTab } from "../components/DeviceUpdates";
import { resolveDeviceTab, type DeviceTab } from "../components/deviceTabs";
import { Card, Icons, Page, PageHeader, Status, StatusPill, TableSkeleton, toast, useConfirm } from "../ui";

export function DevicePage() {
  const { id = "" } = useParams();
  const qc = useQueryClient();
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [reason, setReason] = useState("");
  // Revoking an enrolled computer also uninstalls its agent, unless this is turned off (D158).
  const [uninstallAgent, setUninstallAgent] = useState(true);
  const q = useQuery({ queryKey: ["device", id], queryFn: () => api<Device>("GET", `/devices/${id}`), enabled: !!id });
  const refresh = () => qc.invalidateQueries({ queryKey: ["devices"] }).then(() => qc.invalidateQueries({ queryKey: ["device", id] }));
  const approve = useMutation({
    mutationFn: () => api("POST", `/devices/${id}/approve`, {}),
    onSuccess: () => (toast.success("Device approved."), refresh()),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const revoke = useMutation({
    mutationFn: (uninstall: boolean) => api<{ pending?: boolean } | undefined>("POST", `/devices/${id}/revoke`, { reason, uninstall_agent: uninstall }),
    onSuccess: (res, uninstall) => {
      setRevokeOpen(false);
      setReason("");
      if (uninstall && res?.pending) toast.info("The computer is being told to uninstall its agent. It is revoked as soon as it has.");
      else toast.success("Device revoked and disconnected.");
      void refresh();
      void qc.invalidateQueries({ queryKey: ["device-jobs", id] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const refreshDevice = useMutation({
    mutationFn: async () => {
      const { job_id } = await api<{ job_id: string }>("POST", `/devices/${id}/refresh`, {});
      // The agent answers within seconds; wait for the job so the page can show fresh data.
      for (let i = 0; i < 30; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const j = await api<{ status: string }>("GET", `/jobs/${job_id}`);
        if (["succeeded", "succeeded_reboot", "failed", "expired", "cancelled", "rejected"].includes(j.status)) return j.status;
      }
      return "timeout";
    },
    onSuccess: (status) => {
      void qc.invalidateQueries({ queryKey: ["devices"] });
      void qc.invalidateQueries({ queryKey: ["device", id] });
      void qc.invalidateQueries({ queryKey: ["device-jobs", id] });
      if (status === "succeeded") toast.success("Device information refreshed.");
      else toast.warning("The device did not confirm the refresh in time. It will update when the device reports.");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const confirm = useConfirm();
  const nav = useNavigate();
  const del = useMutation({
    mutationFn: () => api("DELETE", `/devices/${id}`),
    onSuccess: () => {
      toast.success("Device deleted.");
      void qc.invalidateQueries({ queryKey: ["devices"] });
      nav("/devices");
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const d = q.data;
  const { loading: sessionLoading, can, canOrg } = useSession();
  const features = useFeatures();
  const access = { hasUpdates: can("updates:read") && features.windowsUpdates, hasSoftwareUpdates: can("deployments:read"), hasJobs: can("deployments:read"), hasInspect: can("devices:inspect") && d?.status === "active", hasActivity: canOrg("audit:read") };
  const [params, setParams] = useSearchParams();
  const rawTab = params.get("tab");
  const tab = resolveDeviceTab(rawTab, access);
  const selectTab = (next: DeviceTab, replace = true) =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        if (next === "overview") n.delete("tab");
        else n.set("tab", next);
        return n;
      },
      { replace },
    );
  // Old or unknown ?tab= values are rewritten to the tab that now holds their content (replace, so Back still works).
  useEffect(() => {
    if (!sessionLoading && rawTab !== null && rawTab !== tab) selectTab(tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionLoading, rawTab, tab]);

  const askDelete = async () => {
    if (!d) return;
    const ok = await confirm({
      title: "Delete device",
      message: `This removes ${d.hostname} and everything stored about it: hardware, software inventory, user profiles, jobs and client certificates. The audit log keeps the record that it existed. This cannot be undone. If the machine still has the agent, uninstall it first or it will need a new enrollment token.`,
      confirmLabel: "Delete permanently",
      danger: true,
    });
    if (ok) del.mutate();
  };

  return (
    <Page>
      <PageHeader
        title={d?.hostname ?? "Device"}
        crumb={d?.hostname ?? "Device"}
        description={d ? [d.os_caption, d.os_build].filter(Boolean).join(" · ") || undefined : undefined}
        actions={d ? <DeviceActions device={d} approve={approve} refreshDevice={refreshDevice} onRevoke={() => setRevokeOpen(true)} onDelete={() => void askDelete()} /> : undefined}
      />
      {q.isLoading && <TableSkeleton rows={4} cols={3} />}
      {q.error && <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>{errorMessage(q.error)}</Alert>}
      {d && (
        <>
          <div role="group" aria-label="Device status" style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "var(--lp-space-2) var(--lp-space-3)" }}>
            {d.status === "active" && <Status value={d.online ? "online" : "offline"} />}
            <Status value={d.status} />
            {d.pending_reboot && <StatusPill kind="warning" icon={Icons.Restart}>Restart pending</StatusPill>}
            <span className="lp-muted" style={{ fontSize: "var(--lp-text-sm)" }}>
              {d.online ? "Connected now" : d.last_seen_at ? `Last seen ${ago(d.last_seen_at)}` : "Never seen"}
            </span>
          </div>
          {d.status === "pending" && d.replaces_device_id && (
            <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="Re-enrollment of known hardware">
              This device has the same hardware identity as an existing device. Approving it revokes the old identity ({d.replaces_device_id}).
            </Alert>
          )}
          {d.status === "active" && d.revoke_pending && (
            <Alert color="orange" icon={<Icons.Warning size={18} aria-hidden />} title="Revoke pending">
              <Stack gap={6}>
                <Text size="sm">
                  {d.online ? "This computer is uninstalling its agent." : "This computer is offline, so it will uninstall its agent when it next connects."} It is revoked as soon as it has. Until then it still counts as active.
                </Text>
                <div>
                  <Button size="xs" color="red" variant="default" onClick={() => revoke.mutate(false)} loading={revoke.isPending}>
                    Revoke now without uninstalling
                  </Button>
                </div>
              </Stack>
            </Alert>
          )}
          {d.status === "revoked" && d.status_reason && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              Revoked: {d.status_reason}
            </Alert>
          )}
          <Card flush>
            <Tabs value={tab} onChange={(v) => v && selectTab(resolveDeviceTab(v, access))} keepMounted={false} style={{ padding: "var(--lp-space-2) var(--lp-space-4) var(--lp-space-4)" }}>
              <Tabs.List>
                <Tabs.Tab value="overview">Overview</Tabs.Tab>
                <Tabs.Tab value="hardware">Hardware</Tabs.Tab>
                <Tabs.Tab value="software">Installed software{d.software_count ? ` (${d.software_count})` : ""}</Tabs.Tab>
                <Tabs.Tab value="vulnerabilities">Vulnerabilities</Tabs.Tab>
                {access.hasSoftwareUpdates && <Tabs.Tab value="software-updates">Software updates</Tabs.Tab>}
                {access.hasUpdates && <Tabs.Tab value="updates">Windows updates</Tabs.Tab>}
                {access.hasJobs && <Tabs.Tab value="jobs">Jobs</Tabs.Tab>}
                {access.hasInspect && <Tabs.Tab value="inspect">Inspect</Tabs.Tab>}
                {access.hasActivity && <Tabs.Tab value="activity">Activity</Tabs.Tab>}
              </Tabs.List>

              <Tabs.Panel value="overview" pt="md">
                <OverviewTab device={d} />
              </Tabs.Panel>
              <Tabs.Panel value="hardware" pt="md">
                <HardwareTab device={d} />
              </Tabs.Panel>
              <Tabs.Panel value="software" pt="md">
                <SoftwareTab id={id} hostname={d.hostname} active={d.status === "active"} />
              </Tabs.Panel>
              <Tabs.Panel value="vulnerabilities" pt="md">
                <VulnerabilitiesTab device={d} />
              </Tabs.Panel>
              {access.hasSoftwareUpdates && (
                <Tabs.Panel value="software-updates" pt="md">
                  <SoftwareUpdatesTab id={id} hostname={d.hostname} active={d.status === "active"} />
                </Tabs.Panel>
              )}
              {access.hasUpdates && (
                <Tabs.Panel value="updates" pt="md">
                  <UpdatesTab id={id} active={d.status === "active"} />
                </Tabs.Panel>
              )}
              {access.hasJobs && (
                <Tabs.Panel value="jobs" pt="md">
                  <JobsTab id={id} />
                </Tabs.Panel>
              )}
              {access.hasInspect && (
                <Tabs.Panel value="inspect" pt="md">
                  <InspectTab id={id} online={!!d.online} hostname={d.hostname} />
                </Tabs.Panel>
              )}
              {access.hasActivity && (
                <Tabs.Panel value="activity" pt="md">
                  <ActivityTab id={id} hostname={d.hostname} />
                </Tabs.Panel>
              )}
            </Tabs>
          </Card>
        </>
      )}
      <Modal opened={revokeOpen} onClose={() => setRevokeOpen(false)} title="Revoke device">
        <Stack>
          <Text size="sm">
            {uninstallAgent && d?.status === "active"
              ? "The computer is told to uninstall its agent first, and is revoked as soon as it has: it can never reconnect with its current identity. If it is offline, this waits until it connects (up to 28 days)."
              : "The device is disconnected immediately and can never reconnect with its current identity. To manage it again, reinstall the agent with a new enrollment token."}
          </Text>
          {d?.status === "active" && (
            <Checkbox
              label="Also uninstall the agent from the computer"
              description={uninstallAgent ? "Removes the service, its key and its files. Programs and user files are not touched." : "The agent stays installed and keeps trying to connect, uselessly."}
              checked={uninstallAgent}
              onChange={(e) => setUninstallAgent(e.currentTarget.checked)}
            />
          )}
          <TextInput label="Reason (recorded in the audit log)" value={reason} onChange={(e) => setReason(e.currentTarget.value)} maxLength={500} />
          <Button color="red" onClick={() => revoke.mutate(uninstallAgent && d?.status === "active")} loading={revoke.isPending}>
            {uninstallAgent && d?.status === "active" ? "Uninstall the agent and revoke" : "Revoke device"}
          </Button>
        </Stack>
      </Modal>
    </Page>
  );
}
