import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, SimpleGrid, Stack, Table, Text } from "@mantine/core";
import { api, errorMessage, type Device, type DeviceUser, type JobDetail } from "../api/client";
import { useSession } from "../api/session";
import { ago, dateTime, duration } from "../api/format";
import { Card, EmptyState, IconButton, Icons, StatGrid, StatTile, StatusPill, TableSkeleton, toast, useConfirm } from "../ui";
import { jobReason } from "./jobReasons";
import { CustomFieldsCard } from "./DeviceCustomFields";
import { Field } from "./DeviceField";
import { RestartCard } from "./DeviceRestart";

const small = { fontSize: "var(--lp-text-lg)", overflowWrap: "anywhere" } as const;

/** The device at a glance, the full details, and the user profiles on it (formerly the Users tab). */
export function OverviewTab({ device: d }: { device: Device }) {
  const hw = d.hardware;
  return (
    <Stack>
      <StatGrid label="Device summary">
        <StatTile label="Operating system" value={<span style={small}>{d.os_caption || "—"}</span>} kind="accent" hint={[hw?.os_display_version, d.os_build].filter(Boolean).join(" · ") || undefined} />
        <StatTile label="Agent version" value={<span style={small}>{d.agent_version || "—"}</span>} kind="info" />
        <StatTile label="Last seen" value={<span style={small}>{d.online ? "Connected now" : ago(d.last_seen_at)}</span>} kind={d.online ? "success" : "neutral"} hint={d.last_seen_at ? dateTime(d.last_seen_at) : undefined} />
        <StatTile label="Logged-on user" value={<span style={small}>{d.logged_on_user || "—"}</span>} kind="neutral" />
        <StatTile label="Uptime" value={<span style={small}>{duration(d.uptime_s)}</span>} kind="neutral" />
        <StatTile label="Software" value={<span className="lp-num">{d.software_count || "—"}</span>} kind="accent" hint={d.software_updated_at ? `updated ${ago(d.software_updated_at)}` : "not reported yet"} />
      </StatGrid>
      <SimpleGrid cols={{ base: 1, sm: 2 }}>
        <Field label="Device ID" value={d.id} />
        <Field label="Last seen" value={d.online ? "connected now" : ago(d.last_seen_at)} />
        <Field label="Operating system" value={`${d.os_caption ?? ""} ${hw?.os_display_version ?? ""}`} />
        <Field label="Build" value={d.os_build} />
        <Field label="Logged-on user" value={d.logged_on_user} />
        <Field label="Last logged-on user" value={hw?.last_logged_on_user} />
        <Field label="Uptime" value={duration(d.uptime_s)} />
        <Field label="IP (last connection)" value={d.last_ip} />
        <Field label="Agent version" value={d.agent_version} />
        <Field label="Shares downloads" value={d.peer_port ? `yes, on port ${d.peer_port}` : "no"} />
        <Field label="Enrolled" value={dateTime(d.enrolled_at)} />
        <Field label="Software inventory" value={d.software_updated_at ? `${d.software_count} items, updated ${ago(d.software_updated_at)}` : "not reported yet"} />
      </SimpleGrid>
      <RestartCard device={d} />
      <CustomFieldsCard deviceId={d.id} />
      <Card title="User profiles" description="Accounts with a profile on this device.">
        <UsersList device={d} />
      </Card>
    </Stack>
  );
}

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
const accountName = (u: DeviceUser) => (u.domain ? `${u.domain}\\${u.username}` : u.username);

/** Follows a profile-removal job until the device has answered, and says what happened in plain words. */
async function followRemoval(jobId: string, who: string, refresh: () => void) {
  for (let i = 0; i < 45; i++) {
    await wait(2_000);
    let j: JobDetail;
    try {
      j = await api<JobDetail>("GET", `/jobs/${jobId}`);
    } catch {
      continue;
    }
    if (j.status === "succeeded") {
      toast.success(j.result?.message || `Removed the profile of ${who}.`);
      return refresh();
    }
    if (["failed", "expired", "rejected", "cancelled"].includes(j.status)) {
      toast.error(j.result?.message || jobReason(j.status_reason) || `The profile of ${who} was not removed.`);
      return refresh();
    }
  }
  toast.info(`The device has not answered yet. Check the Jobs tab for the profile of ${who}.`);
  refresh();
}

function UsersList({ device: d }: { device: Device }) {
  const id = d.id;
  const { can } = useSession();
  const confirm = useConfirm();
  const qc = useQueryClient();
  const [busy, setBusy] = useState<string[]>([]);
  const canRemove = can("devices:profiles") && d.status === "active";
  const q = useQuery({ queryKey: ["device", id, "users"], queryFn: () => api<{ items: DeviceUser[] }>("GET", `/devices/${id}/users`) });
  const refresh = () => (void qc.invalidateQueries({ queryKey: ["device", id, "users"] }), void qc.invalidateQueries({ queryKey: ["device-jobs", id] }));
  const remove = async (u: DeviceUser) => {
    const who = accountName(u);
    const ok = await confirm({
      title: `Remove the profile of ${who}?`,
      message: (
        <Stack gap={6}>
          <Text size="sm">
            This deletes <b>{who}</b>'s profile on <b>{d.hostname}</b> the way Windows does it: the profile folder ({u.profile_path}) with their desktop, documents, downloads and app data, and its entry in the registry. <b>It cannot be undone.</b>
          </Text>
          <Text size="sm">The account itself is not deleted, and they get a fresh profile the next time they sign in. If they are signed in, nothing is removed.</Text>
          {u.last_logon_at && <Text size="sm" c="dimmed">Last signed in: {dateTime(u.last_logon_at)}.</Text>}
        </Stack>
      ),
      confirmLabel: "Remove profile",
      danger: true,
    });
    if (!ok) return;
    setBusy((b) => [...b, u.sid]);
    try {
      const { job_id } = await api<{ job_id: string }>("POST", `/devices/${id}/users/${encodeURIComponent(u.sid)}/remove-profile`, { confirm: true });
      toast.info(`Removing the profile of ${who}…`);
      await followRemoval(job_id, who, refresh);
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setBusy((b) => b.filter((x) => x !== u.sid));
    }
  };
  if (q.isLoading) return <TableSkeleton rows={3} cols={4} />;
  if (q.error) return <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>{errorMessage(q.error)}</Alert>;
  if (!q.data?.items.length) return <EmptyState icon={<Icons.NavUsers size={26} />} title="No user profiles reported yet" />;
  return (
    <Table.ScrollContainer minWidth={600}>
      <Table aria-label="Users" verticalSpacing={4} fz="sm">
        <Table.Thead>
          <Table.Tr>
            <Table.Th>User</Table.Th>
            <Table.Th>Last logon</Table.Th>
            <Table.Th>State</Table.Th>
            <Table.Th>Profile</Table.Th>
            {canRemove && <Table.Th />}
          </Table.Tr>
        </Table.Thead>
        <Table.Tbody>
          {q.data.items.map((u) => (
            <Table.Tr key={u.sid}>
              <Table.Td>
                {u.domain ? `${u.domain}\\${u.username}` : u.username}
                {u.is_admin && (
                  <span style={{ marginLeft: 8 }}>
                    <StatusPill kind="warning" size="sm" icon={Icons.Shield}>
                      Admin
                    </StatusPill>
                  </span>
                )}
                <Text size="xs" c="dimmed" ff="monospace">
                  {u.sid}
                </Text>
              </Table.Td>
              <Table.Td>{u.last_logon_at ? dateTime(u.last_logon_at) : "—"}</Table.Td>
              <Table.Td>{u.loaded ? <StatusPill kind="success" size="sm" icon={Icons.Online}>Signed in</StatusPill> : "—"}</Table.Td>
              <Table.Td ff="monospace" fz="xs">
                {u.profile_path || "—"}
              </Table.Td>
              {canRemove && (
                <Table.Td ta="right">
                  {u.profile_path ? (
                    <IconButton
                      label={u.loaded ? "Signed in now: sign them out before removing the profile" : d.online ? `Remove the profile of ${accountName(u)}` : "The device is offline"}
                      icon={<Icons.Trash size={16} aria-hidden />}
                      color="red"
                      disabled={u.loaded || !d.online || busy.includes(u.sid)}
                      onClick={() => void remove(u)}
                    />
                  ) : null}
                </Table.Td>
              )}
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
