import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Group, Modal, MultiSelect, NumberInput, Select, Stack, TextInput } from "@mantine/core";
import { api, errorMessage, type Group as Grp, type Pkg, type SoftwarePolicy } from "../api/client";
import { useSession } from "../api/session";
import { RolloutModal } from "../components/RolloutModal";
import { summarizeRollout } from "../components/rollout";
import { SoftwareApprovalsCard } from "../components/SoftwareApprovalsCard";
import { DataTable, EmptyState, Icons, IconButton, Page, PageHeader, StatGrid, StatTile, StatusPill, TileSkeleton, toast, useConfirm, type Column } from "../ui";

const kindLabel: Record<string, string> = { keep_updated: "Keep updated", baseline: "Install on new devices" };

export function PoliciesPage() {
  const { canOrg } = useSession();
  const canWrite = canOrg("policies:write");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["policies"], queryFn: () => api<{ items: SoftwarePolicy[] }>("GET", "/policies") });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const [edit, setEdit] = useState<SoftwarePolicy | "new" | null>(null);
  const [viewing, setViewing] = useState<SoftwarePolicy | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/policies/${id}`),
    onSuccess: () => (toast.success("Policy deleted."), qc.invalidateQueries({ queryKey: ["policies"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const groupName = (id: string) => groups.data?.items.find((g) => g.id === id)?.name ?? id.slice(0, 8);

  const columns = useMemo<Column<SoftwarePolicy>[]>(
    () => [
      { id: "name", header: "Name", value: (p) => p.name, required: true, width: 240 },
      {
        id: "state",
        header: "State",
        value: (p) => (p.enabled ? "enabled" : "disabled"),
        width: 120,
        cell: (p) =>
          p.enabled ? (
            <StatusPill kind="success" size="sm">
              Enabled
            </StatusPill>
          ) : (
            <StatusPill kind="neutral" size="sm" icon={Icons.Pause}>
              Disabled
            </StatusPill>
          ),
        filter: {
          type: "select",
          options: [
            { value: "enabled", label: "Enabled" },
            { value: "disabled", label: "Disabled" },
          ],
        },
      },
      {
        id: "kind",
        header: "What",
        value: (p) => kindLabel[p.kind] ?? p.kind,
        width: 190,
        filter: {
          type: "select",
          options: Object.entries(kindLabel).map(([, label]) => ({ value: label, label })),
        },
      },
      { id: "package", header: "Package", value: (p) => p.package_name, width: 200 },
      // The group names resolve once the groups have loaded, so the value follows `groups.data`.
      { id: "groups", header: "Groups", value: (p) => p.group_ids.map(groupName).join(", "), width: 220, wrap: true },
      {
        id: "rollout",
        header: "Rollout",
        width: 320,
        wrap: true,
        value: (p) => summarizeRollout(p.rollout)?.text ?? [p.use_rings ? "rings" : "", p.require_approval ? "approval" : ""].filter(Boolean).join(" + "),
        cell: (p) => {
          const r = summarizeRollout(p.rollout);
          if (!r) return <span className="lp-muted">{p.enabled ? (p.use_rings || p.require_approval ? "—" : "Straight to all devices") : "—"}</span>;
          return (
            <StatusPill kind={r.kind} size="sm">
              {r.text}
            </StatusPill>
          );
        },
      },
      { id: "delay", header: "Delay", value: (p) => p.delay_days, align: "right", width: 90, cell: (p) => <span className="lp-num">{p.delay_days} d</span>, csv: (p) => String(p.delay_days) },
      { id: "handled", header: "Devices handled", value: (p) => p.devices_attempted, align: "right", width: 140, cell: (p) => <span className="lp-num">{p.devices_attempted}</span> },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groups.data],
  );

  const items = q.data?.items ?? [];
  const enabled = items.filter((p) => p.enabled).length;
  const handled = items.reduce((n, p) => n + p.devices_attempted, 0);

  return (
    <Page>
      <PageHeader
        title="Software policies"
        description="A policy keeps a package current on a group (after a delay you choose), or installs it on devices that newly join a group. Each run creates an ordinary deployment you can follow under Deployments; a device that fails three times is left alone."
        actions={
          canWrite ? (
            <Button onClick={() => setEdit("new")} leftSection={<Icons.Plus size={16} aria-hidden />}>
              Add policy
            </Button>
          ) : undefined
        }
      />
      {q.isLoading ? (
        <TileSkeleton count={3} />
      ) : items.length > 0 ? (
        <StatGrid label="Policy summary">
          <StatTile label="Policies" value={items.length} kind="accent" icon={<Icons.NavSoftwarePolicy size={16} aria-hidden />} />
          <StatTile label="Enabled" value={enabled} kind="success" icon={<Icons.Play size={16} aria-hidden />} hint={items.length - enabled > 0 ? `${items.length - enabled} disabled` : "all policies are running"} />
          <StatTile label="Devices handled" value={handled} kind="info" icon={<Icons.NavDevices size={16} aria-hidden />} hint="attempts across all policies" />
        </StatGrid>
      ) : null}
      <SoftwareApprovalsCard />
      <DataTable<SoftwarePolicy>
        id="policies"
        label="Software policies"
        data={q.data?.items}
        loading={q.isLoading}
        error={q.error ? new Error(errorMessage(q.error)) : undefined}
        columns={columns}
        rowId={(p) => p.id}
        rowLabel={(p) => p.name}
        initialSort={{ id: "name" }}
        searchPlaceholder="Search policies"
        exportName="software-policies"
        rowActions={
          canWrite
            ? (p) => (
                <>
                  {(p.use_rings || p.require_approval) && <IconButton label={`Show the rollout of ${p.name}`} icon={<Icons.NavDeployments size={16} aria-hidden />} size="sm" onClick={() => setViewing(p)} />}
                  <IconButton label={`Edit policy ${p.name}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEdit(p)} />
                  <IconButton
                    label={`Delete policy ${p.name}`}
                    icon={<Icons.Trash size={16} aria-hidden />}
                    size="sm"
                    color="red"
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Delete policy “${p.name}”?`,
                        message: "The policy stops creating deployments. Deployments it already created are not affected.",
                        confirmLabel: "Delete policy",
                        danger: true,
                      });
                      if (ok) del.mutate(p.id);
                    }}
                  />
                </>
              )
            : undefined
        }
        empty={<EmptyState icon={<Icons.NavSoftwarePolicy size={26} />} title="No policies yet" description="Add a policy to keep a package current on a group, or to install it on devices that newly join one." />}
      />
      {viewing && <RolloutModal policy={viewing} onClose={() => setViewing(null)} />}
      {edit && <PolicyModal policy={edit === "new" ? undefined : edit} groups={groups.data?.items ?? []} onClose={() => setEdit(null)} />}
    </Page>
  );
}

function PolicyModal({ policy, groups, onClose }: { policy?: SoftwarePolicy; groups: Grp[]; onClose: () => void }) {
  const qc = useQueryClient();
  const pkgs = useQuery({ queryKey: ["catalog", "packages", ""], queryFn: () => api<{ items: Pkg[] }>("GET", "/catalog/packages?limit=500") });
  const [name, setName] = useState(policy?.name ?? "");
  const [kind, setKind] = useState<string>(policy?.kind ?? "keep_updated");
  const [pkg, setPkg] = useState<string | null>(policy?.package_id ?? null);
  const [gs, setGs] = useState<string[]>(policy?.group_ids ?? []);
  const [delay, setDelay] = useState<number | string>(policy?.delay_days ?? 0);
  const [onlyNew, setOnlyNew] = useState(policy?.only_new_devices ?? true);
  const [unverified, setUnverified] = useState(policy?.unverified_confirmed ?? false);
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [useRings, setUseRings] = useState(policy?.use_rings ?? false);
  const [approval, setApproval] = useState(policy?.require_approval ?? false);
  const [error, setError] = useState("");
  const chosen = pkgs.data?.items.find((p) => p.id === pkg);
  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), kind, package_id: pkg, group_ids: gs, delay_days: Number(delay) || 0, only_new_devices: onlyNew, unverified_confirmed: unverified, enabled, use_rings: kind === "keep_updated" && useRings, require_approval: approval };
      return policy ? api("PUT", `/policies/${policy.id}`, body) : api("POST", "/policies", body);
    },
    onSuccess: () => (toast.success("Policy saved."), void qc.invalidateQueries({ queryKey: ["policies"] }), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={policy ? `Edit ${policy.name}` : "Add policy"} size="lg">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), save.mutate())}>
        <Stack>
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={200} data-autofocus />
          <Select
            label="What it does"
            data={[
              { value: "keep_updated", label: "Keep the package at its newest version where it is installed" },
              { value: "baseline", label: "Install the package on devices that newly join the groups" },
            ]}
            value={kind}
            onChange={(v) => setKind(v ?? "keep_updated")}
            allowDeselect={false}
          />
          <Select label="Package" data={(pkgs.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))} value={pkg} onChange={setPkg} searchable required placeholder="Pick a package from the catalog" />
          <MultiSelect label="Groups" data={groups.map((g) => ({ value: g.id, label: g.name }))} value={gs} onChange={setGs} searchable required />
          <NumberInput label="Wait after a new version appears (days)" min={0} max={365} value={delay} onChange={setDelay} />
          {kind === "baseline" && <Checkbox label="Only devices enrolled after this policy was created" checked={onlyNew} onChange={(e) => setOnlyNew(e.currentTarget.checked)} />}
          {kind === "keep_updated" && (
            <Checkbox
              label="Roll new versions out in stages, through the update rings"
              description="The first ring gets the version first; the next ring follows when the first has done well (see Update rings and rules). Devices that are in no ring get it last."
              checked={useRings}
              onChange={(e) => setUseRings(e.currentTarget.checked)}
            />
          )}
          <Checkbox
            label="Wait for my approval of each new version"
            description="A new version is not rolled out until an administrator or operator approves it under Waiting for your approval. Leave this off to keep updates fully automatic."
            checked={approval}
            onChange={(e) => setApproval(e.currentTarget.checked)}
          />
          {chosen && chosen.source === "winget" && !chosen.verified && (
            <Checkbox label="I accept that this winget package has not been marked as verified" checked={unverified} onChange={(e) => setUnverified(e.currentTarget.checked)} />
          )}
          <Checkbox label="Enabled" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!name.trim() || !pkg || gs.length === 0}>
              Save policy
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
