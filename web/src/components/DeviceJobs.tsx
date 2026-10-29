import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Alert, Anchor, Button, Table, Text } from "@mantine/core";
import { api, errorMessage, type DeviceJob } from "../api/client";
import { dateTime } from "../api/format";
import { JobBadge } from "../pages/DeploymentsPage";
import { JobModal } from "../pages/DeploymentPage";
import { jobReason } from "./jobReasons";
import { EmptyState, Icons, TableSkeleton } from "../ui";

export function JobsTab({ id }: { id: string }) {
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["device-jobs", id], queryFn: () => api<{ items: DeviceJob[] }>("GET", `/devices/${id}/jobs`), refetchInterval: 10_000 });
  return (
    <>
      {q.isLoading && <TableSkeleton rows={3} cols={4} />}
      {q.error && <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>{errorMessage(q.error)}</Alert>}
      {q.data && q.data.items.length === 0 && <EmptyState icon={<Icons.NavDeployments size={26} />} title="No jobs yet" description="Jobs sent to this device by deployments and update rules appear here." />}
      {!!q.data?.items.length && (
        <Table verticalSpacing="xs" fz="sm" aria-label="Device jobs">
          <Table.Thead>
            <Table.Tr>
              <Table.Th>Job</Table.Th>
              <Table.Th>Status</Table.Th>
              <Table.Th>Created</Table.Th>
              <Table.Th />
            </Table.Tr>
          </Table.Thead>
          <Table.Tbody>
            {q.data.items.map((j) => (
              <Table.Tr key={j.id}>
                <Table.Td>
                  {j.deployment_id ? (
                    <Anchor component={Link} to={`/deployments/${j.deployment_id}`} size="sm">
                      {j.title}
                    </Anchor>
                  ) : (
                    j.title
                  )}
                </Table.Td>
                <Table.Td>
                  <JobBadge status={j.status} />
                  {j.status_reason && (
                    <Text size="xs" c="dimmed">
                      {jobReason(j.status_reason)}
                    </Text>
                  )}
                </Table.Td>
                <Table.Td>{dateTime(j.created_at)}</Table.Td>
                <Table.Td ta="right">
                  <Button size="compact-xs" variant="default" onClick={() => setOpen(j.id)}>
                    Details
                  </Button>
                </Table.Td>
              </Table.Tr>
            ))}
          </Table.Tbody>
        </Table>
      )}
      {open && <JobModal id={open} onClose={() => setOpen(null)} />}
    </>
  );
}
