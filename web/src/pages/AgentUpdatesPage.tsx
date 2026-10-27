import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, FileInput, Group, MultiSelect, NumberInput, Select, Stack, Switch } from "@mantine/core";
import { api, errorMessage, uploadAgentRelease, type AgentRelease, type AgentRollout, type AgentRolloutStatus, type Group as Grp } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, StatGrid, StatTile, StatusPill, TileSkeleton, toast, useConfirm, type Column } from "../ui";

interface Overview {
  items: AgentRelease[];
  rollout: AgentRollout;
  status: AgentRolloutStatus;
}

type Version = AgentRolloutStatus["versions"][number];

export function AgentUpdatesPage() {
  const { canOrg } = useSession();
  const canWrite = canOrg("releases:write");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["agent-releases"], queryFn: () => api<Overview>("GET", "/agent-releases"), refetchInterval: 30_000 });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["agent-releases"] });
  const setStatus = useMutation({
    mutationFn: (v: { id: string; status: "available" | "withdrawn" }) => api("POST", `/agent-releases/${v.id}/status`, { status: v.status }),
    onSuccess: refresh,
    onError: (e) => toast.error(errorMessage(e)),
  });
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/agent-releases/${id}`),
    onSuccess: () => (toast.success("Release deleted."), refresh()),
    onError: (e) => toast.error(errorMessage(e)),
  });

  const d = q.data;

  const releaseColumns = useMemo<Column<AgentRelease>[]>(
    () => [
      { id: "version", header: "Version", required: true, width: 140, value: (r) => r.version, cell: (r) => <span className="lp-mono">{r.version}</span> },
      { id: "platform", header: "Platform", width: 130, value: (r) => `${r.os}/${r.arch}`, filter: { type: "text" } },
      { id: "uploaded", header: "Uploaded", width: 180, value: (r) => new Date(r.created_at).getTime(), csv: (r) => r.created_at, cell: (r) => dateTime(r.created_at) },
      { id: "devices", header: "Devices on it", align: "right", width: 130, value: (r) => r.devices_on ?? 0, cell: (r) => <span className="lp-num">{r.devices_on}</span> },
      {
        id: "state",
        header: "State",
        width: 200,
        value: (r) => (r.is_target ? "target" : r.status === "withdrawn" ? "withdrawn" : "available"),
        cell: (r) => (
          <span style={{ display: "inline-flex", gap: 6, flexWrap: "wrap" }}>
            {r.is_target && (
              <StatusPill kind="success" size="sm" icon={Icons.Success}>
                Target
              </StatusPill>
            )}
            {r.status === "withdrawn" ? (
              <StatusPill kind="neutral" size="sm" icon={Icons.Pause}>
                Withdrawn
              </StatusPill>
            ) : (
              !r.is_target && (
                <StatusPill kind="info" size="sm" icon={Icons.Check}>
                  Available
                </StatusPill>
              )
            )}
          </span>
        ),
        filter: {
          type: "select",
          options: [
            { value: "target", label: "Target" },
            { value: "available", label: "Available" },
            { value: "withdrawn", label: "Withdrawn" },
          ],
        },
      },
    ],
    [],
  );

  const versionColumns = useMemo<Column<Version>[]>(
    () => [
      { id: "version", header: "Version", required: true, width: 180, value: (v) => v.version, cell: (v) => <span className="lp-mono">{v.version}</span> },
      { id: "devices", header: "Devices", align: "right", width: 120, value: (v) => v.devices, cell: (v) => <span className="lp-num">{v.devices}</span> },
      { id: "online", header: "Online", align: "right", width: 120, value: (v) => v.online, cell: (v) => <span className="lp-num">{v.online}</span> },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Agent updates"
        description={
          <>
            Agents update themselves to a release signed with your update key. A release that came with your server image appears here by itself; you can also upload one (the binary and its signed <code>.lprel</code> bundle). Choose it as the target (or switch on automatic rollout), and the agents move over in batches: a pilot group first, then everyone. An agent verifies the vendor signature itself, switches to the new copy and goes back to the old one automatically if the new one does not connect within ten minutes.
          </>
        }
      />
      {q.isLoading && <TileSkeleton count={4} />}
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {d && (
        <>
          <StatGrid compact label="Rollout summary">
            <StatTile label="Updated" value={d.status.updated} kind="success" icon={<Icons.Success size={16} aria-hidden />} />
            <StatTile label="In progress" value={d.status.queued} kind={d.status.queued > 0 ? "info" : "neutral"} icon={<Icons.NavAgentUpdates size={16} aria-hidden />} />
            <StatTile label="Failed" value={d.status.failed} kind={d.status.failed > 0 ? "danger" : "neutral"} icon={<Icons.Danger size={16} aria-hidden />} />
            <StatTile
              label="Pilot"
              value={d.status.pilot_devices > 0 ? `${d.status.pilot_updated}/${d.status.pilot_devices}` : "—"}
              kind={d.status.pilot_failed > 0 ? "danger" : d.status.waiting ? "warning" : "neutral"}
              icon={<Icons.Clock size={16} aria-hidden />}
              hint={d.status.pilot_devices > 0 ? `${d.status.pilot_failed} failed` : "No pilot group"}
            />
          </StatGrid>

          <Card title="Versions in use" description="Which agent version each device reports.">
            <DataTable<Version>
              id="agent-versions"
              label="Agent versions in use"
              data={d.status.versions}
              columns={versionColumns}
              rowId={(v) => v.version}
              rowLabel={(v) => v.version}
              initialSort={{ id: "devices", desc: true }}
              searchPlaceholder="Search versions…"
              exportName="agent-versions"
              empty={<EmptyState icon={<Icons.NavDevices size={26} />} title="No agents have reported a version yet" />}
            />
          </Card>

          <Card title="Releases" description="Uploaded agent builds. The target release is what devices move to.">
            <DataTable<AgentRelease>
              id="agent-releases"
              label="Agent releases"
              data={d.items}
              columns={releaseColumns}
              rowId={(r) => r.id}
              rowTestId="release-row"
              rowLabel={(r) => r.version}
              initialSort={{ id: "uploaded", desc: true }}
              searchPlaceholder="Search releases…"
              exportName="agent-releases"
              rowActions={(r) =>
                canWrite ? (
                  <>
                    <Button
                      size="compact-xs"
                      variant="default"
                      aria-label={`${r.status === "available" ? "Withdraw" : "Make available"} release ${r.version}`}
                      leftSection={r.status === "available" ? <Icons.Pause size={12} aria-hidden /> : <Icons.Play size={12} aria-hidden />}
                      onClick={() => setStatus.mutate({ id: r.id, status: r.status === "available" ? "withdrawn" : "available" })}
                    >
                      {r.status === "available" ? "Withdraw" : "Make available"}
                    </Button>
                    {!r.is_target && (
                      <Button
                        size="compact-xs"
                        variant="default"
                        color="red"
                        aria-label={`Delete release ${r.version}`}
                        leftSection={<Icons.Trash size={12} aria-hidden />}
                        onClick={async () => {
                          if (await confirm({ title: `Delete release ${r.version}?`, message: "The uploaded binary and bundle are removed. Devices already on it keep running.", confirmLabel: "Delete release", danger: true })) del.mutate(r.id);
                        }}
                      >
                        Delete
                      </Button>
                    )}
                  </>
                ) : null
              }
              empty={<EmptyState icon={<Icons.NavAgentUpdates size={26} />} title="No release uploaded yet" description={canWrite ? "Upload a signed release below to start a rollout." : undefined} />}
            />
          </Card>
          {canWrite && <UploadCard onDone={refresh} />}
          <RolloutCard rollout={d.rollout} status={d.status} releases={d.items} groups={groups.data?.items ?? []} canWrite={canWrite} onSaved={refresh} />
        </>
      )}
    </Page>
  );
}

function UploadCard({ onDone }: { onDone: () => void }) {
  const [bin, setBin] = useState<File | null>(null);
  const [bundle, setBundle] = useState<File | null>(null);
  const [error, setError] = useState("");
  const up = useMutation({
    mutationFn: () => uploadAgentRelease(bin!, bundle!),
    onSuccess: (r) => (setBin(null), setBundle(null), setError(""), toast.success(`Release ${r.version} uploaded.`), onDone()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Card
      title="Upload a release"
      description="The agent binary and the signed bundle that goes with it."
      footer={
        <Group justify="flex-end">
          <Button onClick={() => up.mutate()} loading={up.isPending} disabled={!bin || !bundle} leftSection={<Icons.Export size={16} aria-hidden />}>
            Upload
          </Button>
        </Group>
      }
    >
      <Stack gap="sm" maw={560}>
        <FileInput label="Agent binary" placeholder="librepatch-agent.exe" value={bin} onChange={setBin} />
        <FileInput label="Signed bundle (.lprel)" placeholder="librepatch-agent-1.2.3.lprel" value={bundle} onChange={setBundle} accept=".lprel,application/json" />
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
      </Stack>
    </Card>
  );
}

function RolloutCard({ rollout, status, releases, groups, canWrite, onSaved }: { rollout: AgentRollout; status: AgentRolloutStatus; releases: AgentRelease[]; groups: Grp[]; canWrite: boolean; onSaved: () => void }) {
  const [target, setTarget] = useState<string | null>(rollout.release_id ?? null);
  const [pilots, setPilots] = useState<string[]>(rollout.pilot_group_ids);
  const [soak, setSoak] = useState<number | string>(rollout.soak_hours);
  const [thr, setThr] = useState<number | string>(rollout.success_threshold);
  const [batch, setBatch] = useState<number | string>(rollout.batch_per_tick);
  const [paused, setPaused] = useState(rollout.paused);
  const [auto, setAuto] = useState(rollout.auto_new_release);
  const [error, setError] = useState("");
  useEffect(() => {
    setTarget(rollout.release_id ?? null);
    setPilots(rollout.pilot_group_ids);
    setSoak(rollout.soak_hours);
    setThr(rollout.success_threshold);
    setBatch(rollout.batch_per_tick);
    setPaused(rollout.paused);
    setAuto(rollout.auto_new_release);
  }, [rollout]);
  const save = useMutation({
    mutationFn: () => api("PUT", "/agent-rollout", { release_id: target, pilot_group_ids: pilots, soak_hours: Number(soak) || 0, success_threshold: Number(thr) || 90, batch_per_tick: Number(batch) || 100, paused, auto_new_release: auto }),
    onSuccess: () => (setError(""), toast.success("Rollout saved."), onSaved()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Card
      title="Rollout"
      description="Which release devices move to, who goes first, and how fast."
      actions={
        rollout.paused ? (
          <StatusPill kind="warning" icon={Icons.Pause}>
            Paused
          </StatusPill>
        ) : target ? (
          <StatusPill kind="success">Rolling out</StatusPill>
        ) : (
          <StatusPill kind="neutral">No target</StatusPill>
        )
      }
      footer={
        canWrite ? (
          <Group justify="flex-end">
            <Button onClick={() => save.mutate()} loading={save.isPending} leftSection={<Icons.Save size={16} aria-hidden />}>
              Save rollout
            </Button>
          </Group>
        ) : undefined
      }
    >
      <Stack gap="sm" maw={640}>
        {rollout.paused && rollout.paused_reason && (
          <Alert color="orange" title="Rollout is on hold" icon={<Icons.Warning size={18} aria-hidden />}>
            {rollout.paused_reason}
          </Alert>
        )}
        {status.waiting && (
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>
            Devices outside the pilot are waiting: {status.waiting}.
          </Alert>
        )}
        {target && (
          <p style={{ margin: 0, fontSize: "var(--lp-text-sm)" }}>
            Updated {status.updated}, failed {status.failed}, in progress {status.queued}
            {status.pilot_devices > 0 ? `; pilot ${status.pilot_updated}/${status.pilot_devices} updated, ${status.pilot_failed} failed` : ""}.
          </p>
        )}
        <Select
          label="Target release"
          description="Devices on other versions are updated to it. None = stop updating."
          data={releases.filter((r) => r.status === "available").map((r) => ({ value: r.id, label: `${r.version} (${r.os}/${r.arch})` }))}
          value={target}
          onChange={setTarget}
          clearable
          disabled={!canWrite}
        />
        <MultiSelect label="Pilot groups" description="These devices update first. Empty = everyone at once." data={groups.map((g) => ({ value: g.id, label: g.name }))} value={pilots} onChange={setPilots} searchable disabled={!canWrite} />
        <Group grow align="flex-start">
          <NumberInput label="Soak (hours)" description="Wait after the pilot" min={0} max={720} value={soak} onChange={setSoak} disabled={!canWrite} />
          <NumberInput label="Pilot success needed (%)" min={1} max={100} value={thr} onChange={setThr} disabled={!canWrite} />
          <NumberInput label="Devices per minute" min={1} max={1000} value={batch} onChange={setBatch} disabled={!canWrite} />
        </Group>
        <Switch
          label="Roll out new versions automatically"
          description="Each server image carries the agent it was built with. When you update the server and that agent is newer than the target, it becomes the target by itself and moves through the pilot group, soak time and success rate above. Off: you choose each target."
          checked={auto}
          onChange={(e) => setAuto(e.currentTarget.checked)}
          disabled={!canWrite}
        />
        <Switch label="Pause the rollout" checked={paused} onChange={(e) => setPaused(e.currentTarget.checked)} disabled={!canWrite} />
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
      </Stack>
    </Card>
  );
}
