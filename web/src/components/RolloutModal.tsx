import { Modal, Stack, Table, Text } from "@mantine/core";
import type { SoftwarePolicy } from "../api/client";
import { dateTime } from "../api/format";
import { StatusPill } from "../ui";
import { STAGE_KIND, STAGE_LABEL, summarizeRollout, type StageState } from "./rollout";

/** How the newest version of a package is moving through a policy's rings. */
export function RolloutModal({ policy, onClose }: { policy: SoftwarePolicy; onClose: () => void }) {
  const r = policy.rollout;
  const s = summarizeRollout(r);
  return (
    <Modal opened onClose={onClose} title={`Rollout: ${policy.name}`} size="lg">
      <Stack>
        {!r && <Text>This policy has no version to roll out right now.</Text>}
        {r && (
          <>
            <Text>
              {policy.package_name} <strong>{r.version}</strong>, found {dateTime(r.imported_at)}.
            </Text>
            {s && (
              <div>
                <StatusPill kind={s.kind}>{s.text}</StatusPill>
              </div>
            )}
            {r.approval !== "not_required" && (
              <Text size="sm" c="dimmed">
                Approval: {r.approval === "approved" ? `approved ${r.approved_at ? dateTime(r.approved_at) : ""}` : r.approval === "declined" ? "declined" : "waiting for an administrator"}.
              </Text>
            )}
            {r.available_at && (
              <Text size="sm" c="dimmed">
                The first ring may install from {dateTime(r.available_at)}.
              </Text>
            )}
            <Table aria-label="Rollout stages" verticalSpacing={6} fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Stage</Table.Th>
                  <Table.Th ta="right">Devices</Table.Th>
                  <Table.Th ta="right">Still need it</Table.Th>
                  <Table.Th ta="right">Installed</Table.Th>
                  <Table.Th ta="right">Failed</Table.Th>
                  <Table.Th>State</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {r.stages.map((st) => (
                  <Table.Tr key={st.name}>
                    <Table.Td>{st.name}</Table.Td>
                    <Table.Td ta="right">{st.devices}</Table.Td>
                    <Table.Td ta="right">{st.waiting}</Table.Td>
                    <Table.Td ta="right">{st.installed}</Table.Td>
                    <Table.Td ta="right">{st.failed}</Table.Td>
                    <Table.Td>
                      <StatusPill kind={STAGE_KIND[st.state as StageState]} size="sm" title={st.reason}>
                        {STAGE_LABEL[st.state as StageState]}
                      </StatusPill>
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
            <Text size="xs" c="dimmed">
              Rings are set under Update rings and rules and are shared with Windows updates. A device belongs to the first ring that lists it; devices in no ring get the version last.
            </Text>
          </>
        )}
      </Stack>
    </Modal>
  );
}
