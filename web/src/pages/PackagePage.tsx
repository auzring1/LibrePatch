import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Alert, Button, Checkbox, Select, Textarea, TextInput } from "@mantine/core";
import { api, errorMessage, type Detection, type Installer, type PackageDetail, type PackageOverride } from "../api/client";
import { bytes, dateTime } from "../api/format";
import { useSession } from "../api/session";
import { parsePrograms } from "../components/prompts";
import { PackageBadges } from "./CatalogPage";
import { PRODUCT_NAME } from "../brand.generated";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, StatusPill, TileSkeleton, toast, useConfirm, type Column } from "../ui";
import { Fields } from "../ui/PageBits";

const policies = [
  { value: "", label: "Use the organization default" },
  { value: "report_only", label: "Report only: never touch per-user installs" },
  { value: "update_in_place", label: "Update per-user installs in place" },
  { value: "convert_to_machine", label: "Convert: remove the per-user copy and install machine-wide" },
  { value: "remove", label: "Remove per-user installs" },
];

const selfUpdatePolicies = [
  { value: "", label: "Default (vendor updater for self-updating apps)" },
  { value: "defer_to_vendor", label: "Defer to the vendor's updater" },
  { value: "enforce", label: "Enforce the pinned version anyway" },
];

export function PackagePage() {
  const { id = "" } = useParams();
  const { can } = useSession();
  const nav = useNavigate();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["catalog", "package", id], queryFn: () => api<PackageDetail>("GET", `/catalog/packages/${id}`), enabled: !!id });
  const del = useMutation({
    mutationFn: () => api("DELETE", `/catalog/packages/${id}`),
    onSuccess: () => (toast.success("Package removed."), qc.invalidateQueries({ queryKey: ["catalog"] }), nav("/catalog")),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const d = q.data;
  const homepage = d?.package.homepage;
  return (
    <Page>
      <PageHeader
        title={d ? d.package.name : "Package"}
        description={d ? `${d.package.identifier} · ${d.package.publisher || "unknown publisher"}` : undefined}
        crumb={d?.package.name ?? "Package"}
        actions={
          d ? (
            <>
              {can("deployments:write") && (
                <Button component={Link} to={`/deployments/new?package=${d.package.id}`} leftSection={<Icons.NavDeployments size={16} aria-hidden />}>
                  Deploy
                </Button>
              )}
              {can("catalog:write") && (
                <Button
                  variant="light"
                  color="red"
                  leftSection={<Icons.Trash size={16} aria-hidden />}
                  loading={del.isPending}
                  onClick={async () => {
                    const ok = await confirm({
                      title: `Remove ${d.package.name} from the catalog?`,
                      message: "Its versions and overrides are deleted. Deployments that already ran keep their history.",
                      confirmLabel: "Remove package",
                      danger: true,
                    });
                    if (ok) del.mutate();
                  }}
                >
                  Remove
                </Button>
              )}
            </>
          ) : undefined
        }
      />
      {q.isLoading && <TileSkeleton count={3} />}
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      {d && (
        <>
          {d.package.source === "winget" && <VerificationCard detail={d} />}
          {d.overlay && <OverlayInfo overlay={d.overlay} />}
          <Card title="Details" actions={<PackageBadges p={d.package} />}>
            <div className="lp-block">
              {d.package.description && <p style={{ margin: 0 }}>{d.package.description}</p>}
              <Fields
                items={[
                  { label: "License", value: d.package.license },
                  {
                    label: "Homepage",
                    value: homepage && /^https?:\/\//i.test(homepage) ? (
                      <a href={homepage} target="_blank" rel="noopener noreferrer">
                        {homepage}
                      </a>
                    ) : (
                      homepage
                    ),
                  },
                  { label: "Effective per-user policy", value: `${d.effective_user_scope_policy} (${d.effective_user_scope_policy_source || "default"})` },
                ]}
              />
            </div>
          </Card>
          {(d.versions ?? []).length === 0 && (
            <Card>
              <EmptyState icon={<Icons.NavCatalog size={26} />} title="No versions imported" description="Import a version from winget or upload an installer to make this package deployable." />
            </Card>
          )}
          {(d.versions ?? []).map((v) => (
            <Card key={v.id} title={`Version ${v.version}`} description={`Imported ${dateTime(v.imported_at)}`} flush>
              <InstallersTable versionId={v.id} version={v.version} installers={v.installers ?? []} />
            </Card>
          ))}
          <Overrides detail={d} />
        </>
      )}
    </Page>
  );
}

/** Whether the package counts as verified, and (for administrators) the way to mark it after testing it. */
function VerificationCard({ detail }: { detail: PackageDetail }) {
  const { canOrg } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const p = detail.package;
  const v = detail.verification;
  const canMark = canOrg("catalog:override");
  const newest = detail.versions?.[0]?.version;
  const set = useMutation({
    mutationFn: (verified: boolean) => api("PUT", `/catalog/packages/${p.id}/verification`, { verified }),
    onSuccess: (_r, verified) => (toast.success(verified ? "Marked as verified." : "Verification removed."), qc.invalidateQueries({ queryKey: ["catalog"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const mark = async () => {
    const ok = await confirm({
      title: `Mark ${p.name} as verified?`,
      message: `Do this after you have tested ${p.name}${newest ? ` ${newest}` : ""} on your own computers. From then on it deploys without the confirmation, to every device, including by software policies. This is recorded in the audit log under your name. You can remove the mark at any time.`,
      confirmLabel: "Mark as verified",
    });
    if (ok) set.mutate(true);
  };
  const unmark = async () => {
    const ok = await confirm({
      title: `Remove the verified mark from ${p.name}?`,
      message: "Deploying it will ask for the confirmation again. This is recorded in the audit log.",
      confirmLabel: "Remove mark",
      danger: true,
    });
    if (ok) set.mutate(false);
  };

  if (p.verified) {
    const byTeam = p.verified_source === "organization";
    const byOverlay = p.verified_source === "overlay";
    return (
      <Alert color="green" title={byTeam ? "Verified by your organization" : byOverlay ? `Verified by the overlay “${p.verified_by ?? ""}”` : `Verified: passed the ${PRODUCT_NAME} VM test matrix`} icon={<Icons.Success size={18} aria-hidden />}>
        {byOverlay
          ? `${detail.overlay?.verified_note || "The author of the overlay tested this package."} It deploys without the confirmation.`
          : byTeam
          ? `${v?.by || "An administrator"} marked this package as verified${v?.at ? ` on ${dateTime(v.at)}` : ""}${v?.version ? `, after testing version ${v.version}` : ""}. It deploys without the confirmation.${newest && v?.version && newest !== v.version ? ` The newest imported version is ${newest}, which was not tested at that time.` : ""}`
          : "It deploys without the confirmation."}
        {canMark && byTeam && (
          <div style={{ marginTop: "var(--lp-space-2)" }}>
            <Button size="compact-sm" variant="default" loading={set.isPending} onClick={() => void unmark()}>
              Remove the verified mark
            </Button>
          </div>
        )}
      </Alert>
    );
  }
  return (
    <Alert color="yellow" title="Not verified" icon={<Icons.Warning size={18} aria-hidden />}>
      This package comes from the community winget repository and has not been tested. You will be asked to confirm before deploying, and the confirmation is recorded in the audit log.
      {canMark ? " Once you have tested it on your own computers, mark it as verified so it deploys without the prompt." : " An administrator can mark it as verified after testing it."}
      {canMark && (
        <div style={{ marginTop: "var(--lp-space-2)" }}>
          <Button size="compact-sm" loading={set.isPending} leftSection={<Icons.Success size={14} aria-hidden />} onClick={() => void mark()}>
            Mark as verified
          </Button>
        </div>
      )}
    </Alert>
  );
}

function InstallersTable({ versionId, version, installers }: { versionId: string; version: string; installers: Installer[] }) {
  const columns = useMemo<Column<Installer>[]>(
    () => [
      { id: "arch", header: "Arch", value: (i) => i.architecture, required: true, width: 100 },
      { id: "scope", header: "Scope", value: (i) => i.scope, width: 100 },
      { id: "type", header: "Type", value: (i) => i.type, width: 100 },
      { id: "size", header: "Size", value: (i) => i.size ?? 0, align: "right", width: 110, cell: (i) => <span className="lp-num">{bytes(i.size)}</span>, csv: (i) => String(i.size ?? "") },
      {
        id: "sha256",
        header: "SHA-256",
        value: (i) => i.sha256 ?? "",
        width: 190,
        cell: (i) => (
          <span className="lp-mono" title={i.sha256}>
            {i.sha256 ? i.sha256.slice(0, 16) + "…" : "—"}
          </span>
        ),
      },
      {
        id: "status",
        header: "Status",
        value: (i) => (i.unsupported ? `not deployable: ${i.unsupported}` : i.server_content ? `served by ${PRODUCT_NAME}` : "vendor download"),
        width: 260,
        wrap: true,
        cell: (i) =>
          i.unsupported ? (
            <StatusPill kind="danger" size="sm">
              Not deployable: {i.unsupported}
            </StatusPill>
          ) : (
            <StatusPill kind="success" size="sm">
              {i.server_content ? `Served by ${PRODUCT_NAME}` : "Vendor download"}
            </StatusPill>
          ),
      },
    ],
    [],
  );
  return (
    <DataTable<Installer>
      id="package-installers"
      label={`Installers of ${version}`}
      data={installers}
      columns={columns}
      rowId={(i) => `${versionId}-${i.id}`}
      rowLabel={(i) => `${i.architecture} ${i.scope} ${i.type}`}
      pageSize={10}
      searchPlaceholder="Search installers"
      empty={<EmptyState icon={<Icons.NavCatalog size={26} />} title="No installers" description="This version has no installers." />}
    />
  );
}

const detectionToText = (ds: Detection[] | undefined) =>
  (ds ?? []).map((d) => [d.kind, d.key, d.value_name ?? "", d.version ?? "", d.cmp ?? ""].join("|")).join("\n");

function textToDetection(t: string): Detection[] {
  return t
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => {
      const [kind = "registry", key = "", value_name = "", version = "", cmp = ""] = l.split("|").map((s) => s.trim());
      return { kind: kind as Detection["kind"], key, value_name, version, cmp: cmp as Detection["cmp"] };
    });
}

function Overrides({ detail }: { detail: PackageDetail }) {
  const { can } = useSession();
  const qc = useQueryClient();
  const o = detail.override;
  const [args, setArgs] = useState((o.silent_args ?? []).join(" "));
  const [pin, setPin] = useState(o.pin ?? "");
  const [excluded, setExcluded] = useState(!!o.excluded);
  const [userPolicy, setUserPolicy] = useState<string>(o.user_scope_policy ?? "");
  const [selfPolicy, setSelfPolicy] = useState<string>(o.self_update_policy ?? "");
  const [detection, setDetection] = useState(detectionToText(o.extra_detection));
  const [programs, setPrograms] = useState((o.processes ?? []).join(", "));
  const [error, setError] = useState("");
  useEffect(() => setError(""), [args, pin, excluded, userPolicy, selfPolicy, detection, programs]);
  const editable = can("catalog:override");
  const save = useMutation({
    mutationFn: () => {
      const body: PackageOverride = {
        silent_args: args.trim() ? args.trim().split(/\s+/) : [],
        extra_detection: textToDetection(detection),
        pin: pin.trim(),
        excluded,
        user_scope_policy: userPolicy as PackageOverride["user_scope_policy"],
        self_update_policy: selfPolicy as PackageOverride["self_update_policy"],
        processes: parsePrograms(programs),
      };
      return api("PUT", `/catalog/packages/${detail.package.id}/overrides`, body);
    },
    onSuccess: () => (toast.success("Overrides saved."), qc.invalidateQueries({ queryKey: ["catalog"] })),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Card
      title="Overrides"
      description={`Organization-specific changes to how this package is deployed. ${editable ? "Every change is audited." : "Only administrators can change these."}`}
      footer={
        editable ? (
          <Button onClick={() => save.mutate()} loading={save.isPending} leftSection={<Icons.Save size={16} aria-hidden />}>
            Save overrides
          </Button>
        ) : undefined
      }
    >
      <div className="lp-block">
        <TextInput
          label="Silent arguments"
          description="Replaces the manifest's switches. Only plain switches such as /S or /quiet are accepted."
          value={args}
          disabled={!editable}
          onChange={(e) => setArgs(e.currentTarget.value)}
        />
        <TextInput
          label="Version pin"
          description={'Empty (newest), "latest", "= 24.08" (exactly) or "< 25" (anything older than)'}
          value={pin}
          disabled={!editable}
          onChange={(e) => setPin(e.currentTarget.value)}
          maw={300}
        />
        <TextInput
          label="Programs this update replaces"
          description="File names such as chrome.exe, separated by commas. A deployment can then wait for them to be closed, ask the user to close them, or close them. Empty = silent installs only."
          placeholder="chrome.exe, GoogleUpdate.exe"
          value={programs}
          disabled={!editable}
          onChange={(e) => setPrograms(e.currentTarget.value)}
        />
        <Select label="Per-user installs of this app" data={policies} value={userPolicy} disabled={!editable} onChange={(v) => setUserPolicy(v ?? "")} allowDeselect={false} />
        <Select label="Self-updating behaviour" data={selfUpdatePolicies} value={selfPolicy} disabled={!editable} onChange={(v) => setSelfPolicy(v ?? "")} allowDeselect={false} />
        <Textarea
          label="Extra detection rules"
          description="One per line: kind|key|value name|version|eq or ge. Kinds: msi, registry, file, appx."
          value={detection}
          disabled={!editable}
          onChange={(e) => setDetection(e.currentTarget.value)}
          autosize
          minRows={2}
          ff="monospace"
        />
        <Checkbox label="Exclude this package from deployments" checked={excluded} disabled={!editable} onChange={(e) => setExcluded(e.currentTarget.checked)} />
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
      </div>
    </Card>
  );
}

/** What a signed overlay says about the package: where each piece of knowledge comes from. */
function OverlayInfo({ overlay: o }: { overlay: NonNullable<PackageDetail["overlay"]> }) {
  const lines: string[] = [];
  if (o.silent_args && o.silent_args.length > 0) lines.push(`Silent arguments: ${o.silent_args.join(" ")} (your own override of the arguments wins over this)`);
  if (o.detection_rules) lines.push(`${o.detection_rules} detection rule${o.detection_rules === 1 ? "" : "s"}, used together with the package's own`);
  if (o.processes && o.processes.length > 0) lines.push(`Programs it replaces: ${o.processes.join(", ")} (your own list wins over this)`);
  if (o.self_updating !== null && o.self_updating !== undefined) lines.push(o.self_updating ? "Updates itself" : "Does not update itself");
  return (
    <Alert color="blue" title={`From the overlay “${o.source}”`} icon={<Icons.NavCatalog size={18} aria-hidden />}>
      {o.note && <p style={{ margin: "0 0 var(--lp-space-2)" }}>{o.note}</p>}
      {lines.length > 0 ? (
        <ul style={{ margin: 0, paddingLeft: "var(--lp-space-4)" }}>
          {lines.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      ) : (
        !o.note && "Nothing that changes how this package is deployed."
      )}
    </Alert>
  );
}
