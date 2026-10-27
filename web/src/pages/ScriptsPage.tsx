import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Code, Group, Modal, MultiSelect, NumberInput, Select, Stack, Text, TextInput, Textarea } from "@mantine/core";
import { api, errorMessage, type Device, type Group as Grp, type ScriptDetail, type ScriptItem, type ScriptOutput, type ScriptRun, type ScriptRunDetail } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { jobOutcome, refusedHint, runIsOpen, runStatus, shortSha } from "../components/scripts";
import { Card, DataTable, EmptyState, Icons, IconButton, Page, PageHeader, StatusPill, toast, useConfirm, type Column } from "../ui";

interface Status {
  enabled: boolean;
  require_approval: boolean;
  other_approvers: number;
  max_devices: number;
}

export function ScriptsPage() {
  const { can, session } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const canWrite = can("scripts:write");
  const canRun = can("scripts:run");
  const scripts = useQuery({ queryKey: ["scripts"], queryFn: () => api<{ items: ScriptItem[] }>("GET", "/scripts") });
  const runs = useQuery({ queryKey: ["script-runs"], queryFn: () => api<{ items: ScriptRun[] }>("GET", "/scripts/runs"), refetchInterval: 10_000 });
  const status = useQuery({ queryKey: ["script-status"], queryFn: () => api<Status>("GET", "/scripts/status") });
  const [edit, setEdit] = useState<string | "new" | null>(null);
  const [runFor, setRunFor] = useState<ScriptItem | null>(null);
  const [view, setView] = useState<string | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/scripts/${id}`),
    onSuccess: () => (toast.success("Script deleted."), void qc.invalidateQueries({ queryKey: ["scripts"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const waiting = (runs.data?.items ?? []).filter((r) => r.needs_approval);

  const scriptColumns = useMemo<Column<ScriptItem>[]>(
    () => [
      { id: "name", header: "Script", value: (s) => s.name, required: true, width: 240 },
      { id: "description", header: "What it does", value: (s) => s.description, wrap: true, minWidth: 260 },
      { id: "version", header: "Version", value: (s) => s.version, align: "right", width: 90 },
      { id: "runs", header: "Runs", value: (s) => s.runs, align: "right", width: 80 },
      { id: "last", header: "Last run", value: (s) => s.last_run_at ?? "", cell: (s) => (s.last_run_at ? dateTime(s.last_run_at) : "never"), width: 170 },
      { id: "updated", header: "Changed", value: (s) => s.updated_at, cell: (s) => dateTime(s.updated_at), width: 170, defaultHidden: true },
    ],
    [],
  );
  const runColumns = useMemo<Column<ScriptRun>[]>(
    () => [
      { id: "when", header: "Asked", value: (r) => r.requested_at, cell: (r) => dateTime(r.requested_at), width: 170 },
      { id: "script", header: "Script", value: (r) => `${r.script_name} v${r.version}`, required: true, width: 220 },
      {
        id: "status",
        header: "State",
        value: (r) => runStatus(r.status).label,
        cell: (r) => <StatusPill kind={runStatus(r.status).kind} size="sm">{runStatus(r.status).label}</StatusPill>,
        width: 190,
      },
      { id: "devices", header: "Devices", value: (r) => r.devices, align: "right", width: 80 },
      { id: "ok", header: "Finished", value: (r) => r.succeeded, align: "right", width: 90 },
      { id: "failed", header: "Failed", value: (r) => r.failed, align: "right", width: 80 },
      { id: "by", header: "Asked by", value: (r) => r.requested_by, width: 160 },
      { id: "reason", header: "Why", value: (r) => r.reason, wrap: true, minWidth: 220 },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Scripts"
        description="PowerShell scripts you keep here can be run on computers you choose, as SYSTEM. Every version is kept, and every run is recorded with why."
        actions={
          canWrite ? (
            <Button onClick={() => setEdit("new")} leftSection={<Icons.Plus size={16} aria-hidden />}>
              Add script
            </Button>
          ) : undefined
        }
      />
      <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />} title="This is powerful">
        A script runs with full control of each computer. Test it on one computer first. A computer whose agent was installed with <Code>--no-scripts</Code> (MSI: <Code>ALLOWSCRIPTS=0</Code>) refuses the job, and the server cannot change that. Running scripts can be switched off for everyone under Settings → Scripts.
        {status.data?.require_approval ? " Every run needs another administrator’s approval." : " You can require a second administrator’s approval under Settings → Scripts."}
      </Alert>

      {waiting.length > 0 && (
        <Card title={`Waiting for approval (${waiting.length})`} description="Look at the script before you approve it: that exact text is what will be sent.">
          <Stack gap="xs">
            {waiting.map((r) => (
              <Group key={r.id} justify="space-between" wrap="nowrap">
                <Text size="sm">
                  <b>{r.script_name}</b> v{r.version} on {r.devices} device{r.devices === 1 ? "" : "s"}, asked by {r.requested_by || "someone"} on {dateTime(r.requested_at)}: {r.reason}
                </Text>
                <Button size="xs" variant="default" onClick={() => setView(r.id)}>
                  Look at it
                </Button>
              </Group>
            ))}
          </Stack>
        </Card>
      )}

      <DataTable<ScriptItem>
        id="scripts"
        label="Scripts"
        data={scripts.data?.items}
        loading={scripts.isLoading}
        error={scripts.error ? new Error(errorMessage(scripts.error)) : undefined}
        columns={scriptColumns}
        rowId={(s) => s.id}
        rowLabel={(s) => s.name}
        initialSort={{ id: "name" }}
        searchPlaceholder="Search scripts"
        onRowClick={(s) => setEdit(s.id)}
        rowActions={(s) => (
          <>
            {canRun && <IconButton label={`Run ${s.name}`} icon={<Icons.Play size={16} aria-hidden />} size="sm" onClick={() => setRunFor(s)} />}
            {canWrite && (
              <IconButton
                label={`Delete ${s.name}`}
                icon={<Icons.Trash size={16} aria-hidden />}
                size="sm"
                color="red"
                onClick={async () => {
                  const ok = await confirm({ title: `Delete “${s.name}”?`, message: "The script and its versions are removed. Earlier runs keep their own copy of what they ran.", confirmLabel: "Delete script", danger: true });
                  if (ok) del.mutate(s.id);
                }}
              />
            )}
          </>
        )}
        empty={<EmptyState icon={<Icons.NavScripts size={26} />} title="No scripts yet" description="Add a PowerShell script, then run it on one computer to try it." />}
      />

      <h2 className="lp-card__title">Runs</h2>
      <DataTable<ScriptRun>
        id="script-runs"
        label="Script runs"
        data={runs.data?.items}
        loading={runs.isLoading}
        columns={runColumns}
        rowId={(r) => r.id}
        rowLabel={(r) => r.script_name}
        initialSort={{ id: "when", desc: true }}
        searchPlaceholder="Search runs"
        onRowClick={(r) => setView(r.id)}
        empty={<EmptyState icon={<Icons.Play size={26} />} title="Nothing has been run yet" description="Runs appear here with their state and the output from each computer." />}
      />

      {edit && <ScriptModal id={edit === "new" ? null : edit} canWrite={canWrite} onClose={() => setEdit(null)} />}
      {runFor && <RunModal script={runFor} status={status.data} onClose={() => setRunFor(null)} onStarted={(id) => (setRunFor(null), setView(id))} />}
      {view && <RunDetailModal id={view} me={session?.user.id ?? ""} onClose={() => setView(null)} />}
    </Page>
  );
}

function ScriptModal({ id, canWrite, onClose }: { id: string | null; canWrite: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const detail = useQuery({ queryKey: ["script", id], queryFn: () => api<ScriptDetail>("GET", `/scripts/${id}`), enabled: !!id });
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState("");
  const [note, setNote] = useState("");
  const [error, setError] = useState("");
  const d = detail.data;
  useEffect(() => {
    if (d) (setName(d.name), setDescription(d.description), setContent(d.content));
  }, [d]);
  const loadVersion = async (v: string | null) => {
    if (!v || !id) return;
    try {
      const old = await api<ScriptDetail>("GET", `/scripts/${id}?version=${v}`);
      setContent(old.content);
      toast.info(`Version ${v} is in the editor. Save to make it the newest version.`);
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), description: description.trim(), content, note: note.trim() };
      return id ? api("PUT", `/scripts/${id}`, body) : api("POST", "/scripts", body);
    },
    onSuccess: () => (toast.success("Script saved."), void qc.invalidateQueries({ queryKey: ["scripts"] }), void qc.invalidateQueries({ queryKey: ["script", id] }), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={id ? `Script: ${d?.name ?? ""}` : "Add script"} size="xl">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), save.mutate())}>
        <Stack>
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={100} disabled={!canWrite} data-autofocus />
          <TextInput label="What it does" value={description} onChange={(e) => setDescription(e.currentTarget.value)} maxLength={500} disabled={!canWrite} />
          <Textarea
            label="PowerShell"
            description="Runs as SYSTEM with Windows PowerShell 5.1, no profile, no prompts. Its output (up to 16 KB from the end) and exit code come back to this page, and are kept 30 days."
            value={content}
            onChange={(e) => setContent(e.currentTarget.value)}
            autosize
            minRows={12}
            maxRows={28}
            disabled={!canWrite}
            styles={{ input: { fontFamily: "var(--lp-font-mono, monospace)", fontSize: "var(--lp-text-sm)" } }}
            spellCheck={false}
            required
          />
          {id && d && (
            <Group align="flex-end">
              <Select
                label="Earlier versions"
                placeholder={`Version ${d.version} is the newest`}
                data={d.versions.map((v) => ({ value: String(v.version), label: `v${v.version}, ${dateTime(v.created_at)}${v.created_by ? `, ${v.created_by}` : ""}${v.note ? `: ${v.note}` : ""} (${shortSha(v.sha256)})` }))}
                onChange={(v) => void loadVersion(v)}
                clearable
                w={460}
                disabled={!canWrite}
              />
              <Text size="xs" c="dimmed" mb={8}>
                Fingerprint of this version: <Code>{shortSha(d.sha256)}</Code>
              </Text>
            </Group>
          )}
          {canWrite && id && <TextInput label="What changed (kept with the version)" value={note} onChange={(e) => setNote(e.currentTarget.value)} maxLength={200} />}
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              {canWrite ? "Cancel" : "Close"}
            </Button>
            {canWrite && (
              <Button type="submit" loading={save.isPending} disabled={!name.trim() || !content.trim()}>
                Save script
              </Button>
            )}
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RunModal({ script, status, onClose, onStarted }: { script: ScriptItem; status?: Status; onClose: () => void; onStarted: (id: string) => void }) {
  const qc = useQueryClient();
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const devices = useQuery({ queryKey: ["devices", "active"], queryFn: () => api<{ items: Device[] }>("GET", "/devices?status=active&limit=500") });
  const detail = useQuery({ queryKey: ["script", script.id], queryFn: () => api<ScriptDetail>("GET", `/scripts/${script.id}`) });
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [deviceIds, setDeviceIds] = useState<string[]>([]);
  const [timeout, setTimeoutS] = useState<number | string>(300);
  const [reason, setReason] = useState("");
  const [sure, setSure] = useState(false);
  const [error, setError] = useState("");
  const start = useMutation({
    mutationFn: () => api<ScriptRun>("POST", "/scripts/runs", { script_id: script.id, version: script.version, group_ids: groupIds, device_ids: deviceIds, timeout_s: Number(timeout) || 300, reason: reason.trim() }),
    onSuccess: (r) => {
      toast.success(r.needs_approval ? "Asked. Another administrator has to approve it before anything is sent." : "Started.");
      void qc.invalidateQueries({ queryKey: ["script-runs"] });
      onStarted(r.id);
    },
    onError: (e) => setError(errorMessage(e)),
  });
  const hasTargets = groupIds.length + deviceIds.length > 0;
  const off = status?.enabled === false;
  const blocked = (!!status?.require_approval && status.other_approvers === 0) || off;
  return (
    <Modal opened onClose={onClose} title={`Run “${script.name}” (version ${script.version})`} size="lg">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), start.mutate())}>
        <Stack>
          <details>
            <summary>Show the script that will be sent{detail.data ? ` (fingerprint ${shortSha(detail.data.sha256)})` : ""}</summary>
            <pre className="lp-mono" style={{ whiteSpace: "pre-wrap", maxHeight: 260, overflow: "auto", fontSize: "var(--lp-text-xs)", margin: "var(--lp-space-2) 0 0" }}>{detail.data?.content ?? "…"}</pre>
          </details>
          <MultiSelect label="Groups" data={(groups.data?.items ?? []).map((g) => ({ value: g.id, label: g.name }))} value={groupIds} onChange={setGroupIds} searchable placeholder="Choose groups" />
          <MultiSelect
            label="Devices"
            data={(devices.data?.items ?? []).map((d) => ({ value: d.id, label: d.hostname }))}
            value={deviceIds}
            onChange={setDeviceIds}
            searchable
            placeholder="Choose devices"
            description={`At most ${status?.max_devices ?? 500} computers per run. Try it on one first.`}
          />
          <NumberInput label="Stop the script after (seconds)" min={10} max={3600} value={timeout} onChange={setTimeoutS} maw={260} />
          <TextInput label="Why are you running it?" description="Recorded with the run and in the audit log." value={reason} onChange={(e) => setReason(e.currentTarget.value)} maxLength={200} required />
          {off && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              Running scripts is switched off. An administrator can switch it on under Settings → Scripts.
            </Alert>
          )}
          {status?.require_approval && !blocked && <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>Another administrator has to approve this run before anything is sent.</Alert>}
          {blocked && !off && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              Runs need another administrator’s approval, and there is no other active administrator, so this run could never start. Add an administrator, or turn the requirement off under Settings → Scripts.
            </Alert>
          )}
          <Checkbox checked={sure} onChange={(e) => setSure(e.currentTarget.checked)} label="I have read the script and understand it runs as SYSTEM on the computers I chose." />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={start.isPending} disabled={!hasTargets || !reason.trim() || !sure || blocked} leftSection={<Icons.Play size={16} aria-hidden />}>
              {status?.require_approval ? "Ask for approval" : "Run"}
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RunDetailModal({ id, me, onClose }: { id: string; me: string; onClose: () => void }) {
  const { can } = useSession();
  const qc = useQueryClient();
  const q = useQuery({
    queryKey: ["script-run", id],
    queryFn: () => api<ScriptRunDetail>("GET", `/scripts/runs/${id}`),
    refetchInterval: (query) => (query.state.data && !runIsOpen(query.state.data.status, query.state.data.jobs) ? false : 3000),
  });
  const [note, setNote] = useState("");
  const [output, setOutput] = useState<{ host: string; out: ScriptOutput } | null>(null);
  const refresh = () => (void qc.invalidateQueries({ queryKey: ["script-run", id] }), void qc.invalidateQueries({ queryKey: ["script-runs"] }));
  const act = useMutation({
    mutationFn: (what: "approve" | "reject" | "cancel") => api("POST", `/scripts/runs/${id}/${what}`, what === "cancel" ? {} : { note: note.trim() }),
    onSuccess: refresh,
    onError: (e) => toast.error(errorMessage(e)),
  });
  const showOutput = async (jobId: string, host: string) => {
    try {
      setOutput({ host, out: await api<ScriptOutput>("GET", `/scripts/runs/${id}/jobs/${jobId}/output`) });
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };
  const r = q.data;
  const mine = !!r && r.requested_by_id === me;
  return (
    <Modal opened onClose={onClose} title={r ? `${r.script_name} (version ${r.version})` : "Run"} size="xl">
      {!r ? (
        <Text c="dimmed">Loading…</Text>
      ) : (
        <Stack>
          <Group gap="md">
            <StatusPill kind={runStatus(r.status).kind}>{runStatus(r.status).label}</StatusPill>
            <Text size="sm">
              Asked by {r.requested_by || "someone"} on {dateTime(r.requested_at)} for {r.devices} device{r.devices === 1 ? "" : "s"}; stops after {r.timeout_s} seconds.
            </Text>
          </Group>
          <Text size="sm">Why: {r.reason}</Text>
          {r.decided_by && (
            <Text size="sm" c="dimmed">
              Decided by {r.decided_by}
              {r.decided_at ? ` on ${dateTime(r.decided_at)}` : ""}
              {r.decision_note ? `: ${r.decision_note}` : ""}
            </Text>
          )}
          <details open={r.needs_approval}>
            <summary>The script that {r.needs_approval ? "will be" : "was"} sent (fingerprint {shortSha(r.sha256)})</summary>
            <pre className="lp-mono" style={{ whiteSpace: "pre-wrap", maxHeight: 300, overflow: "auto", fontSize: "var(--lp-text-xs)", margin: "var(--lp-space-2) 0 0" }}>{r.content}</pre>
          </details>
          {r.needs_approval && can("scripts:approve") && (
            <Card title="Your decision" description={mine ? "You asked for this run, so someone else has to approve it." : "Approving sends exactly the script above to the chosen devices."}>
              <Stack>
                <TextInput label="Note (optional)" value={note} onChange={(e) => setNote(e.currentTarget.value)} maxLength={200} />
                <Group>
                  <Button onClick={() => act.mutate("approve")} loading={act.isPending} disabled={mine} leftSection={<Icons.Check size={16} aria-hidden />}>
                    Approve and send
                  </Button>
                  <Button variant="default" color="red" onClick={() => act.mutate("reject")} disabled={act.isPending}>
                    Reject
                  </Button>
                </Group>
              </Stack>
            </Card>
          )}
          {r.jobs.length > 0 && (
            <table className="lp-table" aria-label="Devices of this run" style={{ width: "100%", fontSize: "var(--lp-text-sm)" }}>
              <thead>
                <tr style={{ textAlign: "left" }}>
                  <th>Computer</th>
                  <th>Result</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {r.jobs.map((j) => {
                  const o = jobOutcome(j.status, j.status_reason, j.exit_code);
                  const hint = refusedHint(j.status_reason);
                  return (
                    <tr key={j.job_id}>
                      <td>{j.hostname}</td>
                      <td>
                        <StatusPill kind={o.kind} size="sm">{o.label}</StatusPill>
                        {hint && <Text size="xs" c="dimmed">{hint}</Text>}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        {j.has_output && (
                          <Button size="xs" variant="default" onClick={() => void showOutput(j.job_id, j.hostname)}>
                            Output
                          </Button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
          <Group justify="space-between">
            {can("scripts:run") && (r.status === "pending_approval" || runIsOpen(r.status, r.jobs)) ? (
              <Button variant="default" color="red" onClick={() => act.mutate("cancel")} loading={act.isPending}>
                {r.status === "pending_approval" ? "Withdraw the request" : "Cancel what has not started"}
              </Button>
            ) : (
              <span />
            )}
            <Button variant="default" onClick={onClose}>
              Close
            </Button>
          </Group>
        </Stack>
      )}
      {output && (
        <Modal opened onClose={() => setOutput(null)} title={`Output on ${output.host}`} size="lg">
          <Stack>
            <Text size="sm" c="dimmed">
              Exit code {output.out.exit_code}; {dateTime(output.out.created_at)}. Only the last 16 KB are kept.
            </Text>
            <pre className="lp-mono" style={{ whiteSpace: "pre-wrap", maxHeight: 420, overflow: "auto", fontSize: "var(--lp-text-xs)", margin: 0 }}>{output.out.output || "(no output)"}</pre>
          </Stack>
        </Modal>
      )}
    </Modal>
  );
}
