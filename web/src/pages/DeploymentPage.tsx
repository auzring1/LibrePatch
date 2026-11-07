import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import { Alert, Button, Code, Group, Modal, ScrollArea, Stack, Table, Text } from "@mantine/core";
import { api, errorMessage, type DeploymentDetail, type DeploymentJob, type JobDetail } from "../api/client";
import { dateTime } from "../api/format";
import { describePrompts } from "../components/prompts";
import { jobCanBeCancelled, jobReason } from "../components/jobReasons";
import { useSession } from "../api/session";
import { Card, DataTable, Icons, Page, PageHeader, Skel, StatusPill, toast, useConfirm, type Column } from "../ui";
import { DeploymentStatus, JobBadge } from "./DeploymentsPage";

const order = ["queued", "sent", "accepted", "waiting", "running", "succeeded", "succeeded_reboot", "failed", "rejected", "expired", "cancelled"];
const retryable = new Set(["failed", "expired", "rejected", "cancelled"]);
const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

// A stable empty list: a new [] on every render makes the table reset its page again and again while loading.
const NONE: DeploymentJob[] = [];
const when = (j: DeploymentJob) => j.finished_at ?? j.started_at ?? j.sent_at ?? j.created_at;

function Facts({ items }: { items: [string, React.ReactNode][] }) {
  return (
    <dl style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(210px, 1fr))", gap: "var(--lp-space-4)", margin: 0 }}>
      {items.map(([k, v]) => (
        <div key={k} style={{ minWidth: 0 }}>
          <dt className="lp-muted" style={{ fontSize: "var(--lp-text-sm)" }}>
            {k}
          </dt>
          <dd style={{ margin: 0, overflowWrap: "anywhere" }}>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function DeploymentPage() {
  const { id = "" } = useParams();
  const { can } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [open, setOpen] = useState<string | null>(null);
  const d = useQuery({ queryKey: ["deployment", id], queryFn: () => api<DeploymentDetail>("GET", `/deployments/${id}`), enabled: !!id, refetchInterval: 30_000 });
  const jobs = useQuery({
    queryKey: ["deployment", id, "jobs"],
    queryFn: () => api<{ items: DeploymentJob[] }>("GET", `/deployments/${id}/jobs?limit=1000`),
    enabled: !!id,
    refetchInterval: 30_000,
  });
  const cancel = useMutation({
    mutationFn: () => api("POST", `/deployments/${id}/cancel`, {}),
    onSuccess: () => (toast.success("Deployment cancelled."), qc.invalidateQueries({ queryKey: ["deployment", id] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const retry = useMutation({
    mutationFn: (jobId: string) => api("POST", `/jobs/${jobId}/retry`, {}),
    onSuccess: () => (toast.success("Retry queued."), qc.invalidateQueries({ queryKey: ["deployment", id] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const x = d.data;
  const canWrite = can("deployments:write");

  const columns = useMemo<Column<DeploymentJob>[]>(
    () => [
      {
        id: "device",
        header: "Device",
        value: (j) => j.hostname,
        primary: true,
        required: true,
        sortable: true,
        width: 180,
        cell: (j) => (
          <>
            {j.hostname}
            {j.user_sid && <span className="lp-dt__cell-sub">user {j.user_sid}</span>}
          </>
        ),
      },
      {
        id: "job",
        header: "Job",
        value: (j) => j.title,
        sortable: true,
        width: 210,
        cell: (j) => (
          <>
            {j.title}
            {(j.attempt ?? 1) > 1 && <span className="lp-dt__cell-sub">attempt {j.attempt}</span>}
          </>
        ),
      },
      {
        id: "status",
        header: "Status",
        value: (j) => j.status,
        sortable: true,
        width: 190,
        wrap: true,
        cell: (j) => (
          <>
            <JobBadge status={j.status} />
            {j.status_reason && <span className="lp-dt__cell-sub">{jobReason(j.status_reason)}</span>}
          </>
        ),
        csv: (j) => (j.status_reason ? `${j.status} (${j.status_reason})` : j.status),
        filter: { type: "select", options: order.map((s) => ({ value: s, label: s.replace(/_/g, " ") })) },
      },
      {
        id: "updated",
        header: "Updated",
        value: (j) => {
          const t = when(j);
          return t ? new Date(t).getTime() : 0;
        },
        sortable: true,
        width: 175,
        cell: (j) => dateTime(when(j)),
        csv: (j) => when(j) ?? "",
      },
      {
        id: "actions",
        header: "Actions",
        width: 200,
        csv: false,
        align: "right",
        cell: (j) => (
          <Group gap="xs" justify="flex-end" wrap="nowrap">
            <Button size="compact-sm" variant="default" onClick={() => setOpen(j.id)} aria-label={`Details for ${j.hostname}`}>
              Details
            </Button>
            {canWrite && retryable.has(j.status) && (
              <Button size="compact-sm" variant="light" leftSection={<Icons.Restore size={14} aria-hidden />} onClick={() => retry.mutate(j.id)} loading={retry.isPending && retry.variables === j.id}>
                Retry
              </Button>
            )}
          </Group>
        ),
      },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [canWrite, retry.isPending, retry.variables],
  );

  const counts = x ? order.filter((s) => (x.job_counts ?? {})[s]) : [];
  const title = x?.name ?? "Deployment";

  return (
    <Page>
      <PageHeader
        title={title}
        crumb={title}
        description={x ? `${x.action} ${x.package_name ?? ""} ${x.version ?? "(newest)"} · ${x.scope}` : undefined}
        actions={
          canWrite && x?.status === "active" ? (
            <Button
              variant="light"
              color="red"
              leftSection={<Icons.Close size={16} aria-hidden />}
              loading={cancel.isPending}
              onClick={async () => {
                const ok = await confirm({ title: "Cancel this deployment?", message: "Everything that has not finished is cancelled. Jobs already running on devices finish on their own.", confirmLabel: "Cancel deployment", cancelLabel: "Keep it running", danger: true });
                if (ok) cancel.mutate();
              }}
            >
              Cancel deployment
            </Button>
          ) : undefined
        }
      />
      {d.isLoading && (
        <Card title="Summary">
          <Stack gap="xs" role="status" aria-label="Loading">
            <Skel w="40%" h={16} />
            <Skel w="60%" h={16} />
          </Stack>
        </Card>
      )}
      {d.error && (
        <Alert color="red" title="Could not load the deployment" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(d.error)}
        </Alert>
      )}
      {x && (
        <Card title="Summary">
          <Stack gap="md">
            <Facts
              items={[
                ["Status", <span key="s" data-testid="deployment-status"><DeploymentStatus status={x.status} lowercase /></span>],
                ["Package", `${x.package_name ?? "—"} ${x.version ?? "(newest)"}`],
                ["Action and scope", `${x.action} · ${x.scope}`],
                ["Created", dateTime(x.created_at)],
                ["Not before", dateTime(x.starts_at)],
                ["Gives up", dateTime(x.expires_at)],
              ]}
            />
            {counts.length > 0 && (
              <div>
                <Text size="sm" className="lp-muted" mb={6}>
                  Jobs by state
                </Text>
                <Group gap="md">
                  {counts.map((s) => (
                    <span key={s} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
                      <b className="lp-num">{(x.job_counts ?? {})[s]}</b>
                      <JobBadge status={s} />
                    </span>
                  ))}
                </Group>
              </div>
            )}
            {x.window && (
              <Text size="sm">
                <Icons.Clock size={14} aria-hidden style={{ verticalAlign: "-2px", marginRight: 6 }} />
                Maintenance window: {(x.window.days ?? []).map((n) => days[n]).join(", ") || "every day"} from {String(Math.floor(x.window.start_minute / 60)).padStart(2, "0")}:{String(x.window.start_minute % 60).padStart(2, "0")} for{" "}
                {x.window.duration_minutes} minutes
                {x.window.tz ? ` (${x.window.tz})` : ", device-local time"}
              </Text>
            )}
            {describePrompts(x.prompts) && (
              <Text size="sm">
                <Icons.Info size={14} aria-hidden style={{ verticalAlign: "-2px", marginRight: 6 }} />
                Messages to the user: {describePrompts(x.prompts)}
              </Text>
            )}
            {x.unverified_confirmed && (
              <div>
                <StatusPill kind="warning">Deployed with unverified-package confirmation</StatusPill>
              </div>
            )}
          </Stack>
        </Card>
      )}
      {x && <h2 className="lp-card__title">Jobs per device</h2>}
      {x && (
        <DataTable<DeploymentJob>
          id="deployment-jobs"
          label="Jobs"
          data={jobs.data?.items ?? NONE}
          loading={jobs.isLoading}
          error={jobs.error}
          columns={columns}
          rowId={(j) => j.id}
          rowHref={(j) => `/devices/${j.device_id}`}
          onRowClick={(j) => setOpen(j.id)}
          rowTestId="job-row"
          rowLabel={(j) => j.hostname}
          searchPlaceholder="Search devices and jobs…"
          exportName="deployment-jobs"
          pageSize={50}
        />
      )}
      {open && <JobModal id={open} onClose={() => setOpen(null)} />}
    </Page>
  );
}

export function JobModal({ id, onClose }: { id: string; onClose: () => void }) {
  const qc = useQueryClient();
  const { canOrg } = useSession();
  const q = useQuery({ queryKey: ["job", id], queryFn: () => api<JobDetail>("GET", `/jobs/${id}`), refetchInterval: 5_000 });
  const j = q.data;
  const cancel = useMutation({
    mutationFn: () => api("POST", `/jobs/${id}/cancel`, {}),
    onSuccess: () => {
      toast.success("Cancelled. A job that is running on the PC is ended there.");
      void qc.invalidateQueries({ queryKey: ["job", id] });
      void qc.invalidateQueries({ queryKey: ["device-jobs"] });
      void qc.invalidateQueries({ queryKey: ["deployment"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={j?.title ?? "Job"} size="xl">
      {q.isLoading && (
        <Stack gap="xs" role="status" aria-label="Loading">
          <Skel w="50%" h={16} />
          <Skel w="80%" h={16} />
        </Stack>
      )}
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {j && (
        <Stack>
          <Group>
            <JobBadge status={j.status} />
            <Text size="sm">{j.hostname}</Text>
            {j.status_reason && (
              <Text size="sm" c="dimmed">
                {jobReason(j.status_reason)}
              </Text>
            )}
            {j.reboot_required && (
              <StatusPill kind="warning" icon={Icons.Restart}>
                Restart required
              </StatusPill>
            )}
          </Group>
          <Text size="sm">
            Attempt {j.attempt} · created {dateTime(j.created_at)} · not before {dateTime(j.not_before)} · expires {dateTime(j.expires_at)}
          </Text>
          {jobCanBeCancelled(j.status) && canOrg("deployments:write") && (
            <Group>
              <Button size="compact-sm" color="red" variant="light" loading={cancel.isPending} onClick={() => cancel.mutate()}>
                Cancel this job
              </Button>
              <Text size="xs" c="dimmed">
                Stops it, even if it is running or stuck on the PC.
              </Text>
            </Group>
          )}
          {j.result && (
            <Stack gap={4}>
              {j.result.message && <Text size="sm">{j.result.message}</Text>}
              <Text size="xs" c="dimmed">
                exit code {j.exit_code ?? "—"} · detection {j.detection_passed == null ? "—" : j.detection_passed ? "passed" : "failed"}
                {j.result.installed_version ? ` · installed ${j.result.installed_version}` : ""}
                {j.result.already_satisfied ? " · already satisfied" : ""}
              </Text>
              {j.result.log_tail && (
                <>
                  <Text size="sm" fw={500}>
                    Installer log (tail)
                  </Text>
                  <ScrollArea.Autosize mah={240}>
                    <Code block>{j.result.log_tail}</Code>
                  </ScrollArea.Autosize>
                </>
              )}
            </Stack>
          )}
          <Text size="sm" fw={500}>
            Timeline
          </Text>
          <Table verticalSpacing={2} fz="xs" aria-label="Job timeline">
            <Table.Tbody>
              {(j.events ?? []).map((e) => (
                <Table.Tr key={e.id}>
                  <Table.Td w={170}>{dateTime(e.time)}</Table.Td>
                  <Table.Td w={110}>{e.kind}</Table.Td>
                  <Table.Td>{e.message}</Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </Stack>
      )}
    </Modal>
  );
}
