import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Anchor, Button, Checkbox, Group, Modal, MultiSelect, NumberInput, ScrollArea, Select, Stack, Table, TagsInput, Text, TextInput } from "@mantine/core";
import { Link } from "react-router-dom";
import { api, errorMessage, type Group as Grp, type PackageDetail, type Pkg, type SoftwareAutoFilter, type SoftwarePolicy, type SoftwarePolicyApp, type SoftwarePolicyPreview } from "../api/client";
import { ago, dateTime } from "../api/format";
import { useSession } from "../api/session";
import { InstallPromptsFields } from "../components/InstallPromptsFields";
import { NEEDS_ATTENTION, describeFilter, policyState, until } from "../components/policyStatus";
import { describePrompts, fromPrompts, needsPrograms, toPrompts, type PromptsForm } from "../components/prompts";
import { RolloutModal } from "../components/RolloutModal";
import { summarizeRollout } from "../components/rollout";
import { SoftwareApprovalsCard } from "../components/SoftwareApprovalsCard";
import { DataTable, EmptyState, Icons, IconButton, StatGrid, StatTile, StatusPill, TileSkeleton, toast, useConfirm, type Column } from "../ui";

const kindLabel: Record<string, string> = { keep_updated: "Keep one app updated", keep_all: "Keep all apps updated", baseline: "Install on new devices" };

/** What a new policy starts with when it is made from somewhere else (the Software updates page). */
export interface PolicyPreset {
  kind: "keep_updated" | "keep_all";
  packageId?: string;
  name?: string;
}

/** The policy form, opened from another page: it loads the groups itself. */
export function NewPolicyModal({ preset, onClose }: { preset: PolicyPreset; onClose: () => void }) {
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  return <PolicyModal preset={preset} groups={groups.data?.items ?? []} onClose={onClose} />;
}

/** The Software tab of Automations: one policy keeps one package current (or installs it on new devices), optionally in stages through the rings and with approval. */
export function SoftwarePoliciesPanel() {
  const { canOrg } = useSession();
  const canWrite = canOrg("policies:write");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["policies"], queryFn: () => api<{ items: SoftwarePolicy[] }>("GET", "/policies") });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const [edit, setEdit] = useState<SoftwarePolicy | "new" | null>(null);
  const [viewing, setViewing] = useState<SoftwarePolicy | null>(null);
  const [appsOf, setAppsOf] = useState<SoftwarePolicy | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/policies/${id}`),
    onSuccess: () => (toast.success("Policy deleted."), qc.invalidateQueries({ queryKey: ["policies"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const items = useMemo(() => q.data?.items ?? [], [q.data]);
  const groupName = (id: string) => groups.data?.items.find((g) => g.id === id)?.name ?? id.slice(0, 8);

  const columns = useMemo<Column<SoftwarePolicy>[]>(
    () => [
      { id: "name", header: "Name", value: (p) => p.name, required: true, width: 240 },
      {
        id: "status",
        header: "Status",
        value: (p) => policyState(p.state).label,
        width: 330,
        wrap: true,
        csv: (p) => `${policyState(p.state).label}: ${p.state_text}`,
        cell: (p) => (
          <div>
            <StatusPill kind={policyState(p.state).kind} size="sm" icon={p.state === "off" ? Icons.Pause : undefined}>
              {policyState(p.state).label}
            </StatusPill>
            <div className="lp-muted" style={{ fontSize: "var(--lp-text-sm)", marginTop: 2 }}>
              {p.state_text}
            </div>
          </div>
        ),
        filter: {
          type: "select",
          options: [...new Set(items.map((p) => policyState(p.state).label))].sort().map((label) => ({ value: label, label })),
        },
      },
      {
        id: "checked",
        header: "Last checked",
        width: 130,
        value: (p) => (p.last_check_at ? new Date(p.last_check_at).getTime() : 0),
        csv: (p) => p.last_check_at ?? "",
        cell: (p) => <span title={p.last_check_at ? dateTime(p.last_check_at) : undefined}>{p.last_check_at ? ago(p.last_check_at) : "—"}</span>,
      },
      {
        id: "next",
        header: "Next check",
        width: 120,
        defaultHidden: true,
        value: (p) => (p.next_check_at ? new Date(p.next_check_at).getTime() : 0),
        csv: (p) => p.next_check_at ?? "",
        cell: (p) => <span title={p.next_check_at ? dateTime(p.next_check_at) : undefined}>{until(p.next_check_at)}</span>,
      },
      {
        id: "install",
        header: "Last install",
        width: 140,
        value: (p) => (p.last_run_at ? new Date(p.last_run_at).getTime() : 0),
        csv: (p) => p.last_run_at ?? "",
        cell: (p) =>
          p.last_run_at ? (
            p.last_deployment_id ? (
              <Anchor component={Link} to={`/deployments/${p.last_deployment_id}`} size="sm" title={`${dateTime(p.last_run_at)}: open the deployment`}>
                {ago(p.last_run_at)}
              </Anchor>
            ) : (
              <span>{ago(p.last_run_at)}</span>
            )
          ) : (
            <span className="lp-muted">Never</span>
          ),
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
      {
        id: "package",
        header: "Package",
        value: (p) => (p.auto ? `All apps (${p.apps})` : p.package_name),
        width: 200,
        cell: (p) =>
          p.auto ? (
            <Anchor component="button" type="button" size="sm" onClick={() => setAppsOf(p)} aria-label={`Show the ${p.apps} apps of ${p.name}`}>
              {p.apps} app{p.apps === 1 ? "" : "s"}
            </Anchor>
          ) : (
            p.package_name
          ),
      },
      // The group names resolve once the groups have loaded, so the value follows `groups.data`.
      { id: "groups", header: "Groups", value: (p) => p.group_ids.map(groupName).join(", "), width: 220, wrap: true },
      {
        id: "messages",
        header: "Messages to the user",
        width: 280,
        defaultHidden: true,
        wrap: true,
        value: (p) => describePrompts(p.prompts) || "Silent",
      },
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
      { id: "delay", header: "Delay", defaultHidden: true, value: (p) => p.delay_days, align: "right", width: 90, cell: (p) => <span className="lp-num">{p.delay_days} d</span>, csv: (p) => String(p.delay_days) },
      { id: "handled", header: "Devices handled", defaultHidden: true, value: (p) => p.devices_attempted, align: "right", width: 140, cell: (p) => <span className="lp-num">{p.devices_attempted}</span> },
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [groups.data, items],
  );

  const enabled = items.filter((p) => p.enabled).length;
  const attention = items.filter((p) => p.enabled && NEEDS_ATTENTION.has(p.state)).length;

  return (
    <>
      <Group justify="space-between" align="flex-end" wrap="wrap">
        <Text size="sm" c="dimmed" maw="72ch">
          A policy keeps one app current on a group, or all of your apps at once (after a delay you choose), or installs an app on devices that newly join a group. Every five minutes the server checks each policy and says here what it found; when something needs doing it creates an ordinary deployment you can follow under Deployments. A device that fails three times is left alone.
        </Text>
        {canWrite && (
          <Button onClick={() => setEdit("new")} leftSection={<Icons.Plus size={16} aria-hidden />}>
            Add policy
          </Button>
        )}
      </Group>
      {q.isLoading ? (
        <TileSkeleton count={3} />
      ) : items.length > 0 ? (
        <StatGrid label="Policy summary">
          <StatTile label="Policies" value={items.length} kind="accent" icon={<Icons.NavSoftwarePolicy size={16} aria-hidden />} />
          <StatTile label="Enabled" value={enabled} kind="success" icon={<Icons.Play size={16} aria-hidden />} hint={items.length - enabled > 0 ? `${items.length - enabled} disabled` : "all policies are running"} />
          <StatTile label="Need attention" value={attention} kind={attention > 0 ? "warning" : "neutral"} icon={<Icons.Warning size={16} aria-hidden />} hint={attention > 0 ? "approval, a held ring or a failure" : "nothing is waiting for you"} />
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
                  {p.auto && <IconButton label={`Show the apps of ${p.name}`} icon={<Icons.NavSoftware size={16} aria-hidden />} size="sm" onClick={() => setAppsOf(p)} />}
                  {!p.auto && (p.use_rings || p.require_approval) && <IconButton label={`Show the rollout of ${p.name}`} icon={<Icons.NavDeployments size={16} aria-hidden />} size="sm" onClick={() => setViewing(p)} />}
                  <IconButton label={`Edit policy ${p.name}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEdit(p)} />
                  <IconButton
                    label={`Delete policy ${p.name}`}
                    icon={<Icons.Trash size={16} aria-hidden />}
                    size="sm"
                    color="red"
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Delete policy “${p.name}”?`,
                        message: p.auto ? "The policy stops keeping your apps updated. Deployments it already created are not affected." : "The policy stops creating deployments. Deployments it already created are not affected.",
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
        empty={<EmptyState icon={<Icons.NavSoftwarePolicy size={26} />} title="No policies yet" description="Add a policy to keep your apps current on a group, or to install an app on devices that newly join one." />}
      />
      {viewing && <RolloutModal policy={viewing} onClose={() => setViewing(null)} />}
      {appsOf && <AppsModal policy={appsOf} onClose={() => setAppsOf(null)} />}
      {edit && <PolicyModal policy={edit === "new" ? undefined : edit} groups={groups.data?.items ?? []} onClose={() => setEdit(null)} />}
    </>
  );
}

/** The apps an all-apps policy handles, and where each one stands. */
function AppsModal({ policy, onClose }: { policy: SoftwarePolicy; onClose: () => void }) {
  const q = useQuery({ queryKey: ["policies", policy.id, "apps"], queryFn: () => api<{ items: SoftwarePolicyApp[] }>("GET", `/policies/${policy.id}/apps`) });
  const items = q.data?.items ?? [];
  return (
    <Modal opened onClose={onClose} title={`${policy.name}: apps`} size="xl">
      <Stack>
        <Text size="sm" c="dimmed">
          An app is added here when it has an update on a device in the policy&apos;s groups ({describeFilter(policy.filter)}). It stays, and is updated each time a new version comes out. Each app follows the policy&apos;s delay, rings and approval.
        </Text>
        {q.error ? (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {errorMessage(q.error)}
          </Alert>
        ) : items.length === 0 && !q.isLoading ? (
          <Text size="sm">No app has needed an update yet. When one does, it appears here.</Text>
        ) : (
          <ScrollArea.Autosize mah={420}>
            <Table verticalSpacing={4} fz="sm" aria-label={`Apps of ${policy.name}`}>
              <Table.Thead>
                <Table.Tr>
                  <Table.Th>App</Table.Th>
                  <Table.Th>Status</Table.Th>
                  <Table.Th>Last checked</Table.Th>
                  <Table.Th>Last install</Table.Th>
                </Table.Tr>
              </Table.Thead>
              <Table.Tbody>
                {items.map((a) => (
                  <Table.Tr key={a.policy_id}>
                    <Table.Td>
                      <Anchor component={Link} to={`/catalog/${a.package_id}`} size="sm" onClick={onClose}>
                        {a.name}
                      </Anchor>
                    </Table.Td>
                    <Table.Td>
                      <StatusPill kind={policyState(a.state).kind} size="sm" title={a.state_text}>
                        {policyState(a.state).label}
                      </StatusPill>
                      <div className="lp-muted" style={{ fontSize: "var(--lp-text-sm)" }}>
                        {a.state_text}
                      </div>
                    </Table.Td>
                    <Table.Td>{a.last_check_at ? ago(a.last_check_at) : "—"}</Table.Td>
                    <Table.Td>
                      {a.last_run_at && a.last_deployment_id ? (
                        <Anchor component={Link} to={`/deployments/${a.last_deployment_id}`} size="sm" onClick={onClose}>
                          {ago(a.last_run_at)}
                        </Anchor>
                      ) : (
                        <span className="lp-muted">Never</span>
                      )}
                    </Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </ScrollArea.Autosize>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Close
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

/** Which apps an all-apps policy would handle with these groups and this filter (nothing is saved). */
function AppsPreview({ policyId, groups, filter, onLeaveAlone }: { policyId?: string; groups: string[]; filter: SoftwareAutoFilter; onLeaveAlone: (identifier: string) => void }) {
  const q = useQuery({
    queryKey: ["policies", "preview", policyId ?? "new", groups, filter],
    queryFn: () => api<SoftwarePolicyPreview>("POST", "/policies/preview", { id: policyId, group_ids: groups, filter }),
    enabled: groups.length > 0,
    staleTime: 0,
  });
  if (groups.length === 0) return <Text size="sm" c="dimmed">Pick the groups to see which apps would be kept updated.</Text>;
  if (q.error) return <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>{errorMessage(q.error)}</Alert>;
  const r = q.data;
  if (!r) return <Text size="sm" c="dimmed">Looking at your devices…</Text>;
  return (
    <Stack gap="xs" aria-label="Apps this policy would handle">
      <Text size="sm" fw={500}>
        {r.handled === 0 ? "No app has an update to handle right now." : `${r.handled} app${r.handled === 1 ? " has" : "s have"} an update and would be kept updated.`}
        {r.skipped > 0 ? ` ${r.skipped} would be left alone.` : ""}
      </Text>
      <Text size="sm" c="dimmed">
        Only apps with an update on a device in these groups are listed. Other apps are added automatically the day they get one.
      </Text>
      {r.items.length > 0 && (
        <ScrollArea.Autosize mah={220}>
          <Table verticalSpacing={2} fz="sm" aria-label="Apps with an update">
            <Table.Tbody>
              {r.items.map((m) => (
                <Table.Tr key={m.package_id ?? m.identifier}>
                  <Table.Td>{m.name}</Table.Td>
                  <Table.Td ff="monospace">{m.latest_version}</Table.Td>
                  <Table.Td>
                    {m.devices} device{m.devices === 1 ? "" : "s"}
                  </Table.Td>
                  <Table.Td>
                    {m.handled ? (
                      <Group gap={6} wrap="nowrap">
                        <StatusPill kind="success" size="sm">
                          Kept updated
                        </StatusPill>
                        <Button size="compact-xs" variant="subtle" onClick={() => onLeaveAlone(m.identifier)}>
                          Leave alone
                        </Button>
                      </Group>
                    ) : (
                      <Text size="xs" c="dimmed">
                        {m.reason_text}
                      </Text>
                    )}
                  </Table.Td>
                </Table.Tr>
              ))}
            </Table.Tbody>
          </Table>
        </ScrollArea.Autosize>
      )}
      {r.truncated && <Text size="xs" c="dimmed">Only the first rows are listed.</Text>}
    </Stack>
  );
}

function PolicyModal({ policy, preset, groups, onClose }: { policy?: SoftwarePolicy; preset?: PolicyPreset; groups: Grp[]; onClose: () => void }) {
  const qc = useQueryClient();
  const { canOrg } = useSession();
  const pkgs = useQuery({ queryKey: ["catalog", "packages", ""], queryFn: () => api<{ items: Pkg[] }>("GET", "/catalog/packages?limit=500") });
  const [name, setName] = useState(policy?.name ?? preset?.name ?? "");
  const [kind, setKind] = useState<string>(policy?.kind ?? preset?.kind ?? "keep_updated");
  const [pkg, setPkg] = useState<string | null>(policy?.package_id ?? preset?.packageId ?? null);
  const [gs, setGs] = useState<string[]>(policy?.group_ids ?? []);
  const [delay, setDelay] = useState<number | string>(policy?.delay_days ?? 0);
  const [onlyNew, setOnlyNew] = useState(policy?.only_new_devices ?? true);
  const [unverified, setUnverified] = useState(policy?.unverified_confirmed ?? false);
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [useRings, setUseRings] = useState(policy?.use_rings ?? false);
  const [approval, setApproval] = useState(policy?.require_approval ?? false);
  const [prompts, setPrompts] = useState<PromptsForm>(fromPrompts(policy?.prompts));
  const [verifiedOnly, setVerifiedOnly] = useState(policy?.filter?.verified_only ?? true);
  const [unlisted, setUnlisted] = useState(policy?.filter?.include_unlisted ?? false);
  const [exclude, setExclude] = useState<string[]>(policy?.filter?.exclude ?? []);
  const [error, setError] = useState("");
  const all = kind === "keep_all";
  const chosen = pkgs.data?.items.find((p) => p.id === pkg);
  const detail = useQuery({ queryKey: ["catalog", "package", pkg], queryFn: () => api<PackageDetail>("GET", `/catalog/packages/${pkg}`), enabled: !!pkg && !all });
  const own = detail.data?.override.processes ?? [];
  const programs = own.length > 0 ? own : (detail.data?.overlay?.processes ?? []);
  const filter = useMemo<SoftwareAutoFilter>(() => ({ verified_only: verifiedOnly, include_unlisted: unlisted && !verifiedOnly, exclude }), [verifiedOnly, unlisted, exclude]);
  const kinds = policy
    ? policy.kind === "keep_all"
      ? [{ value: "keep_all", label: "Keep every app that has an update at its newest version" }]
      : [
          { value: "keep_updated", label: "Keep the package at its newest version where it is installed" },
          { value: "baseline", label: "Install the package on devices that newly join the groups" },
        ]
    : [
        { value: "keep_updated", label: "Keep one package at its newest version where it is installed" },
        { value: "keep_all", label: "Keep every app that has an update at its newest version (all apps)" },
        { value: "baseline", label: "Install one package on devices that newly join the groups" },
      ];
  const save = useMutation({
    mutationFn: () => {
      const common = { name: name.trim(), kind, group_ids: gs, delay_days: Number(delay) || 0, enabled, require_approval: approval, prompts: toPrompts(prompts) };
      const body = all
        ? { ...common, use_rings: useRings, filter }
        : { ...common, package_id: pkg, only_new_devices: onlyNew, unverified_confirmed: unverified, use_rings: kind === "keep_updated" && useRings };
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
          <Select label="What it does" data={kinds} value={kind} onChange={(v) => setKind(v ?? "keep_updated")} allowDeselect={false} disabled={policy?.kind === "keep_all"} />
          {!all && <Select label="Package" data={(pkgs.data?.items ?? []).map((p) => ({ value: p.id, label: p.name }))} value={pkg} onChange={setPkg} searchable required placeholder="Pick a package from the catalog" />}
          <MultiSelect label="Groups" data={groups.map((g) => ({ value: g.id, label: g.name }))} value={gs} onChange={setGs} searchable required />
          {all && (
            <Stack gap="xs">
              <Text fw={500} size="sm">
                Which apps
              </Text>
              <Checkbox
                label="Only apps that were verified on test machines (recommended)"
                description="Switch this off to also keep apps updated that nobody has verified yet. That is recorded in the audit log."
                checked={verifiedOnly}
                onChange={(e) => (setVerifiedOnly(e.currentTarget.checked), e.currentTarget.checked && setUnlisted(false))}
              />
              {canOrg("catalog:write") && (
                <Checkbox
                  label="Also add apps that are not in the catalog yet, from the winget repository"
                  description="When an installed app has an update and is not in your catalog, the server adds it from winget by itself. Needs the option above to be off."
                  checked={unlisted && !verifiedOnly}
                  disabled={verifiedOnly}
                  onChange={(e) => setUnlisted(e.currentTarget.checked)}
                />
              )}
              <TagsInput label="Leave these apps alone" description="Package identifiers such as Mozilla.Firefox. Press Enter after each one." value={exclude} onChange={setExclude} placeholder="Publisher.App" />
              <AppsPreview policyId={policy?.id} groups={gs} filter={filter} onLeaveAlone={(id) => setExclude((x) => (x.some((e) => e.toLowerCase() === id.toLowerCase()) ? x : [...x, id]))} />
              <Text size="sm" c="dimmed">
                Apps that update themselves are always left to their vendor. An app that already has a policy of its own is left to that policy.
              </Text>
            </Stack>
          )}
          <NumberInput label="Wait after a new version appears (days)" min={0} max={365} value={delay} onChange={setDelay} />
          {kind === "baseline" && <Checkbox label="Only devices enrolled after this policy was created" checked={onlyNew} onChange={(e) => setOnlyNew(e.currentTarget.checked)} />}
          {(kind === "keep_updated" || all) && (
            <Checkbox
              label="Roll new versions out in stages, through the update rings"
              description="The first ring gets the version first; the next ring follows when the first has done well (see Rings, below). Devices that are in no ring get it last."
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
          <Stack gap="xs">
            <Text fw={500} size="sm">
              Messages to the user (optional)
            </Text>
            <InstallPromptsFields value={prompts} onChange={setPrompts} programs={programs} packageId={pkg || undefined} perApp={all} />
          </Stack>
          {!all && chosen && chosen.source === "winget" && !chosen.verified && (
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
            <Button type="submit" loading={save.isPending} disabled={!name.trim() || (!all && !pkg) || gs.length === 0 || (!all && needsPrograms(prompts) && programs.length === 0)}>
              Save policy
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
