import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Group, Modal, Stack, Table, Text, Textarea } from "@mantine/core";
import { api, errorMessage, type SoftwareApprovalItem, type SoftwareApprovals } from "../api/client";
import { useSession } from "../api/session";
import { ago } from "../api/format";
import { Card, Icons, StatusPill, toast } from "../ui";

/** What needs an administrator's attention: new software versions waiting for approval, and rings that held a rollout. */
export function SoftwareApprovalsCard() {
  const { canOrg } = useSession();
  const canApprove = canOrg("deployments:write");
  const canRelease = canOrg("policies:write");
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["software-approvals"], queryFn: () => api<SoftwareApprovals>("GET", "/software/approvals"), refetchInterval: 60_000 });
  const [declining, setDeclining] = useState<SoftwareApprovalItem | null>(null);
  const [note, setNote] = useState("");
  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["software-approvals"] });
    void qc.invalidateQueries({ queryKey: ["policies"] });
  };
  const decide = useMutation({
    mutationFn: (v: { item: SoftwareApprovalItem; decision: "approved" | "declined" | "reset"; note?: string }) =>
      api("POST", "/software/approvals", { package_id: v.item.package_id, version: v.item.version, decision: v.decision, note: v.note ?? "" }),
    onSuccess: (_d, v) => {
      toast.success(v.decision === "approved" ? `${v.item.package_name} ${v.item.version} approved.` : v.decision === "declined" ? `${v.item.package_name} ${v.item.version} declined.` : "Back to waiting.");
      setDeclining(null);
      setNote("");
      refresh();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const release = useMutation({
    mutationFn: (id: string) => api("POST", `/software/holds/${id}/release`),
    onSuccess: () => (toast.success("Hold released: the version moves on to the next ring."), refresh()),
    onError: (e) => toast.error(errorMessage(e)),
  });

  const d = q.data;
  if (q.error) {
    return (
      <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
        {errorMessage(q.error)}
      </Alert>
    );
  }
  if (!d || (d.pending.length === 0 && d.holds.length === 0 && d.recent.length === 0)) return null;
  return (
    <>
      {d.pending.length > 0 && (
        <Card title="Waiting for your approval" description="A new version of these programs is available. A policy that needs approval will not roll it out until you approve it.">
          <Table.ScrollContainer minWidth={640}>
            <Table aria-label="Versions waiting for approval" verticalSpacing={6} fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Program</Table.Th>
                  <Table.Th>New version</Table.Th>
                  <Table.Th>Policies</Table.Th>
                  <Table.Th ta="right">Devices waiting</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {d.pending.map((i) => (
                  <Table.Tr key={`${i.package_id}/${i.version}`}>
                    <Table.Td>{i.package_name}</Table.Td>
                    <Table.Td>
                      {i.version}
                      {i.imported_at && (
                        <Text size="xs" c="dimmed">
                          found {ago(i.imported_at)}
                        </Text>
                      )}
                    </Table.Td>
                    <Table.Td>{i.policies.join(", ")}</Table.Td>
                    <Table.Td ta="right">{i.devices}</Table.Td>
                    <Table.Td>
                      {canApprove && (
                        <Group gap="xs" justify="flex-end" wrap="nowrap">
                          <Button size="xs" onClick={() => decide.mutate({ item: i, decision: "approved" })} loading={decide.isPending && decide.variables?.item === i}>
                            Approve
                          </Button>
                          <Button size="xs" variant="default" onClick={() => setDeclining(i)}>
                            Decline…
                          </Button>
                        </Group>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      )}
      {d.holds.length > 0 && (
        <Card title="Held rollouts" description="A ring missed its success threshold, so the version was not sent to the later rings. Look at the failed jobs, then release the hold to continue.">
          <Table.ScrollContainer minWidth={640}>
            <Table aria-label="Held rollouts" verticalSpacing={6} fz="sm">
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>Program</Table.Th>
                  <Table.Th>Policy</Table.Th>
                  <Table.Th>Held after</Table.Th>
                  <Table.Th>Why</Table.Th>
                  <Table.Th />
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {d.holds.map((h) => (
                  <Table.Tr key={h.id}>
                    <Table.Td>
                      {h.package_name} {h.version}
                    </Table.Td>
                    <Table.Td>{h.policy}</Table.Td>
                    <Table.Td>
                      <StatusPill kind="danger" size="sm" icon={Icons.Pause}>
                        {h.ring}
                      </StatusPill>
                    </Table.Td>
                    <Table.Td>{h.reason}</Table.Td>
                    <Table.Td>
                      {canRelease && (
                        <Button size="xs" variant="default" loading={release.isPending && release.variables === h.id} onClick={() => release.mutate(h.id)}>
                          Release hold
                        </Button>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Table.ScrollContainer>
        </Card>
      )}
      {d.recent.length > 0 && (
        <details>
          <summary style={{ cursor: "pointer" }}>Recent approval decisions ({d.recent.length})</summary>
          <Table aria-label="Recent approval decisions" verticalSpacing={4} fz="sm" mt="xs">
            <Table.Tbody>
              {d.recent.map((i) => (
                <Table.Tr key={`${i.package_id}/${i.version}`}>
                  <Table.Td>
                    {i.package_name} {i.version}
                  </Table.Td>
                  <Table.Td>
                    <StatusPill kind={i.decision === "approved" ? "success" : "neutral"} size="sm">
                      {i.decision === "approved" ? "Approved" : "Declined"}
                    </StatusPill>
                  </Table.Td>
                  <Table.Td>
                    {i.decided_by || "—"} {i.decided_at ? ago(i.decided_at) : ""}
                  </Table.Td>
                  <Table.Td>{i.note}</Table.Td>
                  <Table.Td>
                    {canApprove && (
                      <Button size="xs" variant="subtle" onClick={() => decide.mutate({ item: i, decision: "reset" })}>
                        Undo
                      </Button>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </details>
      )}
      <Modal opened={!!declining} onClose={() => setDeclining(null)} title={declining ? `Decline ${declining.package_name} ${declining.version}?` : ""}>
        <Stack>
          <Text size="sm">The version will not be rolled out by any policy. A newer version will ask for approval again.</Text>
          <Textarea label="Why (optional, kept in the audit log)" value={note} onChange={(e) => setNote(e.currentTarget.value)} maxLength={1000} autosize minRows={2} />
          <Group justify="flex-end">
            <Button variant="default" onClick={() => setDeclining(null)}>
              Cancel
            </Button>
            <Button color="red" loading={decide.isPending} onClick={() => declining && decide.mutate({ item: declining, decision: "declined", note })}>
              Decline
            </Button>
          </Group>
        </Stack>
      </Modal>
    </>
  );
}
