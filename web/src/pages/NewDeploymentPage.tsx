import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Alert, Button, Checkbox, Group, Loader, MultiSelect, NumberInput, SegmentedControl, Select, Stack, Table, Text, TextInput } from "@mantine/core";
import { hhmm, parseHHMM } from "../api/format";
import { api, errorMessage, type Device, type DeploymentPlan, type DeploymentRequest, type Group as Grp, type PackageDetail, type Pkg } from "../api/client";
import { Card, Icons, Page, PageHeader, StatGrid, StatTile } from "../ui";
import { InstallPromptsFields } from "../components/InstallPromptsFields";
import { SILENT, describePrompts, needsPrograms, toPrompts, type PromptsForm } from "../components/prompts";
import "./newDeployment.css";

const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

export function NewDeploymentPage() {
  const [sp] = useSearchParams();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [pkgId, setPkgId] = useState(sp.get("package") ?? "");
  const [name, setName] = useState("");
  const [action, setAction] = useState<"install" | "update" | "uninstall">("install");
  const [scope, setScope] = useState<"machine" | "user">("machine");
  const [version, setVersion] = useState("");
  const [groupIds, setGroupIds] = useState<string[]>([]);
  const [deviceIds, setDeviceIds] = useState<string[]>([]);
  const [startsAt, setStartsAt] = useState("");
  const [expiresH, setExpiresH] = useState<number | string>(72);
  const [useWindow, setUseWindow] = useState(false);
  const [days, setDays] = useState<string[]>([]);
  const [start, setStart] = useState("22:00");
  const [mins, setMins] = useState<number | string>(240);
  const [confirmed, setConfirmed] = useState(false);
  const [prompts, setPrompts] = useState<PromptsForm>(SILENT);
  const [error, setError] = useState("");
  const [plan, setPlan] = useState<DeploymentPlan | null>(null);

  const pkgs = useQuery({ queryKey: ["catalog", "packages", ""], queryFn: () => api<{ items: Pkg[] }>("GET", "/catalog/packages?limit=500") });
  const detail = useQuery({ queryKey: ["catalog", "package", pkgId], queryFn: () => api<PackageDetail>("GET", `/catalog/packages/${pkgId}`), enabled: !!pkgId });
  const groups = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const devices = useQuery({ queryKey: ["devices", "active"], queryFn: () => api<{ items: Device[] }>("GET", "/devices?status=active&limit=500") });

  const pkg = detail.data?.package ?? pkgs.data?.items.find((p) => p.id === pkgId);
  const needsConfirm = !!pkg && pkg.source === "winget" && !pkg.verified;
  const hasTargets = groupIds.length + deviceIds.length > 0;
  const versions = useMemo(() => detail.data?.versions.map((v) => v.version) ?? [], [detail.data]);
  // The programs the update replaces: the administrator's list, or the signed overlay's.
  const programs = useMemo(() => {
    const own = detail.data?.override.processes ?? [];
    return own.length > 0 ? own : (detail.data?.overlay?.processes ?? []);
  }, [detail.data]);
  const promptsApply = action !== "uninstall";

  const create = useMutation({
    mutationFn: () => {
      const body: DeploymentRequest = {
        name: name.trim() || `${action} ${pkg?.name ?? ""}`.trim(),
        action,
        package_id: pkgId,
        version: version || undefined,
        scope,
        group_ids: groupIds,
        device_ids: deviceIds,
        expires_in_hours: Number(expiresH) || 72,
        unverified_confirmed: confirmed,
      };
      const pr = promptsApply ? toPrompts(prompts) : null;
      if (pr) body.prompts = pr;
      if (startsAt) body.starts_at = new Date(startsAt).toISOString();
      if (useWindow) body.window = { days: days.map(Number), start_minute: parseHHMM(start), duration_minutes: Number(mins) || 60 };
      return api<DeploymentPlan>("POST", "/deployments", body);
    },
    onSuccess: (p) => {
      setPlan(p);
      void qc.invalidateQueries({ queryKey: ["deployments"] });
    },
    onError: (e) => setError(errorMessage(e)),
  });

  if (plan) {
    const skipped = plan.skipped ?? [];
    return (
      <Page>
        <PageHeader
          title="Deployment queued"
          description={`${plural(plan.jobs, "job")} for ${plural(plan.devices, "device")}${plan.user_jobs ? `, ${plan.user_jobs} per-user` : ""}. Online devices start right away; offline devices pick the job up when they reconnect.`}
          actions={
            <Button leftSection={<Icons.Play size={16} aria-hidden />} onClick={() => nav(`/deployments/${plan.deployment_id}`)}>
              Watch progress
            </Button>
          }
        />
        <StatGrid label="What was queued">
          <StatTile label="Jobs" value={plan.jobs} kind="accent" icon={<Icons.NavDeployments size={16} aria-hidden />} />
          <StatTile label="Devices" value={plan.devices} kind="info" icon={<Icons.NavDevices size={16} aria-hidden />} />
          <StatTile label="Skipped" value={skipped.length} kind={skipped.length ? "warning" : "neutral"} icon={<Icons.Warning size={16} aria-hidden />} />
        </StatGrid>
        {plan.per_user_policy && plan.per_user_found ? (
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>
            {plan.per_user_found} per-user installation{plan.per_user_found === 1 ? "" : "s"} found; policy: {plan.per_user_policy}.
          </Alert>
        ) : null}
        {skipped.length > 0 && (
          <Alert color="yellow" title={`${skipped.length} skipped`} icon={<Icons.Warning size={18} aria-hidden />}>
            <Table verticalSpacing={2} fz="sm" aria-label="Skipped devices">
              <Table.Tbody>
                {skipped.map((s, i) => (
                  <Table.Tr key={i}>
                    <Table.Td>{s.device}</Table.Td>
                    <Table.Td>{s.reason}</Table.Td>
                  </Table.Tr>
                ))}
              </Table.Tbody>
            </Table>
          </Alert>
        )}
      </Page>
    );
  }

  const windowOk = !useWindow || days.length > 0;
  const promptsOk = !promptsApply || !needsPrograms(prompts) || programs.length > 0;
  const valid = !!pkgId && hasTargets && (!needsConfirm || confirmed) && windowOk && promptsOk;
  const todo: { done: boolean; text: string }[] = [
    { done: !!pkgId, text: pkgId ? "Package chosen" : "Choose a package" },
    { done: hasTargets, text: hasTargets ? "Targets chosen" : "Choose at least one group or device" },
    ...(needsConfirm ? [{ done: confirmed, text: confirmed ? "Unverified package confirmed" : "Confirm the unverified package" }] : []),
    ...(useWindow ? [{ done: days.length > 0, text: days.length ? "Maintenance window set" : "Choose the days of the maintenance window" }] : []),
    ...(promptsApply && needsPrograms(prompts) ? [{ done: programs.length > 0, text: programs.length ? "Program names known" : "Add the package's program names (see 4. Messages)" }] : []),
  ];

  return (
    <Page>
      <PageHeader
        title="New deployment"
        crumb="New deployment"
        description="Choose what to install, update or remove, who gets it, and when."
      />
      <div className="lp-wizard">
        <div className="lp-wizard__main">
          <Card title="1. Package" description="Pick the software from the catalog.">
            <Stack>
              <Select
                label="Package"
                searchable
                required
                data={(pkgs.data?.items ?? []).map((p) => ({ value: p.id, label: `${p.name} (${p.identifier})` }))}
                value={pkgId || null}
                onChange={(v) => (setPkgId(v ?? ""), setVersion(""), setConfirmed(false))}
                rightSection={pkgs.isLoading ? <Loader size="xs" /> : undefined}
                placeholder="Choose from the catalog"
              />
              {needsConfirm && (
                <Alert color="yellow" title="Unverified package" icon={<Icons.Warning size={18} aria-hidden />}>
                  <Checkbox
                    label={`I understand this package has not been marked as verified and I accept deploying it. This confirmation is recorded in the audit log. (After you have tested it, an administrator can mark it verified on its catalog page.)`}
                    checked={confirmed}
                    onChange={(e) => setConfirmed(e.currentTarget.checked)}
                  />
                </Alert>
              )}
            </Stack>
          </Card>

          <Card title="2. Action" description="What happens on each device.">
            <Stack>
              <Group grow align="flex-start">
                <div>
                  <Text size="sm" fw={500} mb={4} id="dep-action-label">
                    Action
                  </Text>
                  <SegmentedControl
                    fullWidth
                    aria-labelledby="dep-action-label"
                    value={action}
                    onChange={(v) => setAction(v as typeof action)}
                    data={[
                      { value: "install", label: "Install" },
                      { value: "update", label: "Update" },
                      { value: "uninstall", label: "Uninstall" },
                    ]}
                  />
                </div>
                <div>
                  <Text size="sm" fw={500} mb={4} id="dep-scope-label">
                    Scope
                  </Text>
                  <SegmentedControl
                    fullWidth
                    aria-labelledby="dep-scope-label"
                    value={scope}
                    onChange={(v) => setScope(v as typeof scope)}
                    data={[
                      { value: "machine", label: "Machine-wide" },
                      { value: "user", label: "Per user" },
                    ]}
                  />
                </div>
              </Group>
              <Text size="sm" c="dimmed">
                {action === "update"
                  ? "Update only touches devices that have an older version installed."
                  : action === "uninstall"
                    ? "Uninstall removes every matching installation found by inventory."
                    : scope === "user"
                      ? "A per-user install runs as each user of the device, at their next logon if they are signed out."
                      : "A machine-wide install runs as the system and applies to everyone."}
              </Text>
              {action !== "uninstall" && (
                <Select
                  label="Version"
                  description="Newest allowed by the package's pin unless you choose one"
                  data={versions}
                  value={version || null}
                  onChange={(v) => setVersion(v ?? "")}
                  clearable
                  placeholder="Newest"
                />
              )}
            </Stack>
          </Card>

          <Card title="3. Targets" description="Groups and individual devices. Devices in both are deployed to once.">
            <Stack>
              <MultiSelect
                label="Groups"
                searchable
                data={(groups.data?.items ?? []).map((g) => ({ value: g.id, label: `${g.name} (${g.kind})` }))}
                value={groupIds}
                onChange={setGroupIds}
                placeholder="Dynamic and static groups"
              />
              <MultiSelect
                label="Devices"
                searchable
                data={(devices.data?.items ?? []).map((d) => ({ value: d.id, label: d.hostname }))}
                value={deviceIds}
                onChange={setDeviceIds}
                placeholder="Individual devices"
              />
            </Stack>
          </Card>

          {promptsApply && (
            <Card title="4. Messages to the user (optional)" description="Installs are silent unless you choose otherwise here.">
              <InstallPromptsFields value={prompts} onChange={setPrompts} programs={programs} packageId={pkgId || undefined} />
            </Card>
          )}

          <Card title={promptsApply ? "5. Schedule" : "4. Schedule"} description="When devices may start, and how long to keep trying.">
            <Stack>
              <TextInput label="Name" description="Optional" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={200} />
              <Group grow align="flex-start">
                <TextInput label="Not before" description="Empty = now" type="datetime-local" value={startsAt} onChange={(e) => setStartsAt(e.currentTarget.value)} />
                <NumberInput label="Give up after (hours)" min={1} max={720} value={expiresH} onChange={setExpiresH} />
              </Group>
              <Checkbox label="Only run inside a maintenance window (device-local time)" checked={useWindow} onChange={(e) => setUseWindow(e.currentTarget.checked)} />
              {useWindow && (
                <Group align="flex-end">
                  <MultiSelect label="Days" data={dayNames.map((n, i) => ({ value: String(i), label: n }))} value={days} onChange={setDays} w={260} />
                  <TextInput label="Starts" value={start} onChange={(e) => setStart(e.currentTarget.value)} w={90} aria-label="Window start" />
                  <NumberInput label="Minutes" min={1} max={1440} value={mins} onChange={setMins} w={110} />
                  <Text size="xs" c="dimmed" mb={8}>
                    ends at {hhmm((parseHHMM(start) + (Number(mins) || 0)) % 1440)}
                  </Text>
                </Group>
              )}
            </Stack>
          </Card>
        </div>

        <div className="lp-wizard__summary">
          <Card title="Summary">
            <Stack>
              <dl className="lp-wizard__facts">
                <dt>Package</dt>
                <dd>{pkg ? pkg.name : "—"}</dd>
                <dt>Version</dt>
                <dd>{action === "uninstall" ? "Any installed" : version || "Newest"}</dd>
                <dt>What</dt>
                <dd>
                  {action} · {scope === "user" ? "per user" : "machine-wide"}
                </dd>
                <dt>Targets</dt>
                <dd>{hasTargets ? [groupIds.length ? plural(groupIds.length, "group") : "", deviceIds.length ? plural(deviceIds.length, "device") : ""].filter(Boolean).join(", ") : "—"}</dd>
                <dt>Starts</dt>
                <dd>{startsAt ? new Date(startsAt).toLocaleString() : "Now"}</dd>
                <dt>Gives up</dt>
                <dd>after {Number(expiresH) || 72} hours</dd>
                {promptsApply && toPrompts(prompts) && (
                  <>
                    <dt>Messages</dt>
                    <dd>{describePrompts(toPrompts(prompts))}</dd>
                  </>
                )}
                {useWindow && (
                  <>
                    <dt>Window</dt>
                    <dd>
                      {days.length ? [...days].sort().map((d) => dayNames[Number(d)]).join(", ") : "no days chosen"} at {hhmm(parseHHMM(start))}, {Number(mins) || 60} min
                    </dd>
                  </>
                )}
              </dl>
              <ul className="lp-wizard__list" aria-label="Before you start">
                {todo.map((t) => (
                  <li key={t.text} className={t.done ? "lp-wizard__ok" : "lp-wizard__todo"}>
                    {t.done ? <Icons.Success size={16} aria-hidden /> : <Icons.Warning size={16} aria-hidden />}
                    <span>{t.text}</span>
                  </li>
                ))}
              </ul>
              {error && (
                <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
                  {error}
                </Alert>
              )}
              <Group>
                <Button onClick={() => (setError(""), create.mutate())} loading={create.isPending} disabled={!valid} leftSection={<Icons.NavDeployments size={16} aria-hidden />}>
                  Start deployment
                </Button>
                <Button variant="default" component={Link} to="/deployments">
                  Cancel
                </Button>
              </Group>
            </Stack>
          </Card>
        </div>
      </div>
    </Page>
  );
}
