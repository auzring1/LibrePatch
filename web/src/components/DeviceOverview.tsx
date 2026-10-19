import { useQuery } from "@tanstack/react-query";
import { Alert, SimpleGrid, Stack, Table, Text } from "@mantine/core";
import { api, errorMessage, type Device, type DeviceUser } from "../api/client";
import { ago, dateTime, duration } from "../api/format";
import { Card, EmptyState, Icons, StatGrid, StatTile, StatusPill, TableSkeleton } from "../ui";
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
        <Field label="Enrolled" value={dateTime(d.enrolled_at)} />
        <Field label="Software inventory" value={d.software_updated_at ? `${d.software_count} items, updated ${ago(d.software_updated_at)}` : "not reported yet"} />
      </SimpleGrid>
      <RestartCard device={d} />
      <CustomFieldsCard deviceId={d.id} />
      <Card title="User profiles" description="Accounts with a profile on this device.">
        <UsersList id={d.id} />
      </Card>
    </Stack>
  );
}

function UsersList({ id }: { id: string }) {
  const q = useQuery({ queryKey: ["device", id, "users"], queryFn: () => api<{ items: DeviceUser[] }>("GET", `/devices/${id}/users`) });
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
            </Table.Tr>
          ))}
        </Table.Tbody>
      </Table>
    </Table.ScrollContainer>
  );
}
