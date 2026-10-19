import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Alert, Button, Group, Modal, Select, Stack, Text, TextInput } from "@mantine/core";
import { api, errorMessage, uploadContent, type CustomPackage, type ImportResult, type Pkg } from "../api/client";
import { useSession } from "../api/session";
import { PRODUCT_NAME } from "../brand.generated";
import { OverlaysCard } from "../components/OverlaysCard";
import { DataTable, EmptyState, Icons, Page, PageHeader, StatGrid, StatTile, StatusPill, TileSkeleton, toast, type Column } from "../ui";
import { ServerSearch, ServerSearchScope } from "../ui/PageBits";

/** Source, verification and self-update flags of a package, as status pills (icon + color + text). */
export function PackageBadges({ p }: { p: Pkg }) {
  return (
    <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 4 }}>
      <SourcePill p={p} />
      <VerifiedPill p={p} />
      <SelfUpdatingPill p={p} />
    </span>
  );
}

function SourcePill({ p }: { p: Pkg }) {
  return (
    <StatusPill kind="neutral" size="sm" icon={Icons.NavCatalog}>
      {p.source}
    </StatusPill>
  );
}

function VerifiedPill({ p }: { p: Pkg }) {
  if (p.source !== "winget") return null;
  return p.verified ? (
    <StatusPill kind="success" size="sm" title={p.verified_source === "organization" ? "Marked as verified by an administrator after testing" : p.verified_source === "overlay" ? `Vouched for by the overlay “${p.verified_by ?? ""}”` : `Passed the ${PRODUCT_NAME} VM test matrix`}>
      Verified
    </StatusPill>
  ) : (
    <StatusPill kind="warning" size="sm" title="Not tested yet; deploying needs an explicit confirmation. An administrator can mark it as verified after testing it.">
      Unverified
    </StatusPill>
  );
}

function SelfUpdatingPill({ p }: { p: Pkg }) {
  if (!p.self_updating) return null;
  return (
    <StatusPill kind="info" size="sm" icon={Icons.NavAgentUpdates} title={`Updates itself; ${PRODUCT_NAME} defers to the vendor's updater unless you enforce versions in the package's overrides`}>
      Self-updating
    </StatusPill>
  );
}

export function CatalogPage() {
  const { can } = useSession();
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [importing, setImporting] = useState(false);
  const [custom, setCustom] = useState(false);
  const list = useQuery({
    queryKey: ["catalog", "packages", q],
    queryFn: () => api<{ items: Pkg[] }>("GET", `/catalog/packages?limit=200${q ? `&q=${encodeURIComponent(q)}` : ""}`),
  });

  const columns = useMemo<Column<Pkg>[]>(
    () => [
      {
        id: "name",
        header: "Package",
        value: (p) => p.name,
        primary: true,
        required: true,
        width: 280,
        cell: (p) => (
          <>
            {p.name}
            <span className="lp-dt__cell-sub lp-mono">{p.identifier}</span>
          </>
        ),
      },
      { id: "identifier", header: "Identifier", value: (p) => p.identifier, width: 220, defaultHidden: true },
      { id: "publisher", header: "Publisher", value: (p) => p.publisher ?? "", width: 200 },
      { id: "versions", header: "Versions", value: (p) => p.version_count ?? 0, align: "right", width: 100, cell: (p) => <span className="lp-num">{p.version_count ?? 0}</span> },
      {
        id: "source",
        header: "Source",
        value: (p) => p.source,
        width: 120,
        cell: (p) => <SourcePill p={p} />,
        filter: {
          type: "select",
          options: [
            { value: "winget", label: "winget" },
            { value: "custom", label: "custom" },
          ],
        },
      },
      {
        id: "verification",
        header: "Verification",
        value: (p) => (p.source === "winget" ? (p.verified ? "verified" : "unverified") : ""),
        width: 130,
        cell: (p) => (p.source === "winget" ? <VerifiedPill p={p} /> : <span className="lp-muted">—</span>),
        filter: {
          type: "select",
          options: [
            { value: "verified", label: "Verified" },
            { value: "unverified", label: "Unverified" },
          ],
        },
      },
      {
        id: "updates",
        header: "Updates itself",
        value: (p) => (p.self_updating ? "yes" : "no"),
        width: 150,
        cell: (p) => (p.self_updating ? <SelfUpdatingPill p={p} /> : <span className="lp-muted">—</span>),
        filter: {
          type: "select",
          options: [
            { value: "yes", label: "Self-updating" },
            { value: "no", label: "Not self-updating" },
          ],
        },
      },
    ],
    [],
  );

  const items = list.data?.items ?? [];
  const unverified = items.filter((p) => p.source === "winget" && !p.verified).length;
  const selfUpdating = items.filter((p) => p.self_updating).length;
  const customCount = items.filter((p) => p.source === "custom").length;

  return (
    <Page>
      <PageHeader
        title="Catalog"
        description="Software that can be deployed. Winget packages are imported as metadata only; each device downloads the installer from the vendor and the agent checks its SHA-256 and signature before running it."
        actions={
          can("catalog:write") ? (
            <>
              <Button onClick={() => setImporting(true)} leftSection={<Icons.Download size={16} aria-hidden />}>
                Import from winget
              </Button>
              <Button variant="default" onClick={() => setCustom(true)} leftSection={<Icons.Plus size={16} aria-hidden />}>
                Upload custom installer
              </Button>
            </>
          ) : undefined
        }
      />
      {list.isLoading ? (
        <TileSkeleton count={4} />
      ) : items.length > 0 ? (
        <StatGrid label="Catalog summary">
          <StatTile label="Packages" value={items.length} kind="accent" icon={<Icons.NavCatalog size={16} aria-hidden />} hint={q ? `matching “${q}”` : undefined} />
          <StatTile label="Unverified" value={unverified} kind={unverified > 0 ? "warning" : "success"} icon={<Icons.Warning size={16} aria-hidden />} hint="winget packages that need a confirmation to deploy" />
          <StatTile label="Self-updating" value={selfUpdating} kind="info" icon={<Icons.NavAgentUpdates size={16} aria-hidden />} hint="the vendor's updater takes over" />
          <StatTile label="Custom uploads" value={customCount} kind="neutral" icon={<Icons.Plus size={16} aria-hidden />} hint="installers you supplied" />
        </StatGrid>
      ) : null}
      <ServerSearchScope>
        <DataTable<Pkg>
          id="catalog-packages"
          label="Packages"
          data={list.data?.items}
          loading={list.isLoading}
          error={list.error ? new Error(errorMessage(list.error)) : undefined}
          columns={columns}
          rowId={(p) => p.id}
          rowHref={(p) => `/catalog/${p.id}`}
          rowLabel={(p) => p.name}
          rowTestId="package-row"
          initialSort={{ id: "name" }}
          exportName="catalog"
          toolbar={<ServerSearch value={q} onChange={setQ} label="Filter packages" placeholder="Filter imported packages" />}
          empty={
            <EmptyState
              icon={<Icons.NavCatalog size={26} />}
              title="Nothing imported yet"
              description={
                <>
                  Import a package by its winget identifier, for example <b>7zip.7zip</b> or <b>Mozilla.Firefox</b>, or upload your own installer.
                </>
              }
            />
          }
        />
      </ServerSearchScope>
      <OverlaysCard />
      {importing && <ImportModal onClose={() => setImporting(false)} onDone={(r) => (setImporting(false), nav(`/catalog/${r.package_id}`))} />}
      {custom && <CustomModal onClose={() => setCustom(false)} onDone={(r) => (setCustom(false), nav(`/catalog/${r.package_id}`))} />}
    </Page>
  );
}

function ImportModal({ onClose, onDone }: { onClose: () => void; onDone: (r: ImportResult) => void }) {
  const qc = useQueryClient();
  const [id, setId] = useState("");
  const [version, setVersion] = useState("");
  const [error, setError] = useState("");
  const search = useQuery({
    queryKey: ["catalog", "search", id],
    queryFn: () =>
      api<{
        imported: Pkg[];
        suggestions: { identifier: string; self_updating: boolean; note?: string }[];
        index?: { identifier: string; name: string; latest_version: string; in_catalog: boolean }[];
        probe?: { identifier: string; versions?: string[]; error?: string };
      }>("GET", `/catalog/search?q=${encodeURIComponent(id)}`),
    enabled: id.trim().length >= 2,
  });
  const imp = useMutation({
    mutationFn: () => api<ImportResult>("POST", "/catalog/import", { identifier: id.trim(), version: version.trim() }),
    onSuccess: (r) => {
      toast.success(`Imported ${r.identifier} ${r.version}: ${r.deployable} of ${r.installers} installers deployable.`);
      void qc.invalidateQueries({ queryKey: ["catalog"] });
      onDone(r);
    },
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title="Import from winget" size="lg">
      <Stack>
        <TextInput
          label="Search winget by name, or enter a package identifier"
          description="For example 7-Zip or 7zip.7zip. Pick a result below, or type the identifier exactly as in the winget-pkgs repository."
          value={id}
          onChange={(e) => (setId(e.currentTarget.value), setError(""))}
          data-autofocus
        />
        {search.data?.suggestions.length ? (
          <Group gap="xs">
            {search.data.suggestions.map((s) => (
              <Button key={s.identifier} size="compact-xs" variant="light" onClick={() => setId(s.identifier)}>
                {s.identifier}
              </Button>
            ))}
          </Group>
        ) : null}
        {search.data?.index?.length ? (
          <Stack gap={4} role="list" aria-label="Packages in the winget index">
            {search.data.index.map((p) => (
              <Button key={p.identifier} role="listitem" size="compact-sm" variant="subtle" justify="space-between" fullWidth disabled={p.in_catalog} onClick={() => setId(p.identifier)}>
                <span>
                  {p.name} <span className="lp-muted lp-mono">{p.identifier}</span>
                </span>
                <span className="lp-mono">{p.in_catalog ? "in catalog" : p.latest_version}</span>
              </Button>
            ))}
          </Stack>
        ) : null}
        {search.data?.probe && (
          <Text size="sm" c={search.data.probe.error ? "red" : "dimmed"}>
            {search.data.probe.error ? search.data.probe.error : `Upstream versions: ${(search.data.probe.versions ?? []).slice(0, 8).join(", ")}${(search.data.probe.versions?.length ?? 0) > 8 ? ", …" : ""}`}
          </Text>
        )}
        <TextInput label="Version" description="Leave empty for the newest" value={version} onChange={(e) => setVersion(e.currentTarget.value)} />
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => imp.mutate()} loading={imp.isPending} disabled={!id.trim()}>
            Import
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}

const typeOptions = ["msi", "inno", "nsis", "burn", "exe", "portable", "zip"];

function CustomModal({ onClose, onDone }: { onClose: () => void; onDone: (r: ImportResult) => void }) {
  const qc = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [f, setF] = useState({ identifier: "", name: "", publisher: "", version: "", type: "msi", arch: "x64", scope: "machine", args: "", product_code: "", signer_subject: "", detect_key: "", detect_file: "" });
  const [error, setError] = useState("");
  const set = (k: keyof typeof f) => (v: string | null) => setF((o) => ({ ...o, [k]: v ?? "" }));
  const save = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose an installer file.");
      const up = await uploadContent(file);
      const body: CustomPackage = {
        identifier: f.identifier.trim(),
        name: f.name.trim(),
        publisher: f.publisher.trim(),
        version: f.version.trim(),
        sha256: up.sha256,
        file_name: up.file_name,
        type: f.type as CustomPackage["type"],
        arch: f.arch as CustomPackage["arch"],
        scope: f.scope as CustomPackage["scope"],
        args: f.args.trim() ? f.args.trim().split(/\s+/) : [],
        product_code: f.product_code.trim(),
        signer_subject: f.signer_subject.trim(),
        detection: [
          ...(f.detect_key.trim() ? [{ kind: "registry" as const, key: f.detect_key.trim() }] : []),
          ...(f.detect_file.trim() ? [{ kind: "file" as const, key: f.detect_file.trim() }] : []),
        ],
      };
      return api<ImportResult>("POST", "/catalog/custom", body);
    },
    onSuccess: (r) => {
      toast.success(`Added ${r.identifier} ${r.version}.`);
      void qc.invalidateQueries({ queryKey: ["catalog"] });
      onDone(r);
    },
    onError: (e) => setError(errorMessage(e)),
  });
  const valid = file && f.identifier.trim() && f.name.trim() && f.version.trim();
  return (
    <Modal opened onClose={onClose} title="Upload a custom installer" size="lg">
      <Stack>
        <Text size="sm" c="dimmed">
          The file is stored on this server and devices download it over their mutually authenticated channel. Its SHA-256 is signed into every job. Custom packages count as verified because you supplied the file.
        </Text>
        <div>
          <Text size="sm" fw={500} mb={4}>
            Installer file
          </Text>
          <input type="file" aria-label="Installer file" onChange={(e) => setFile(e.currentTarget.files?.[0] ?? null)} />
        </div>
        <Group grow align="flex-start">
          <TextInput label="Identifier" description="Letters, digits, dots, dashes" required value={f.identifier} onChange={(e) => set("identifier")(e.currentTarget.value)} />
          <TextInput label="Name" required value={f.name} onChange={(e) => set("name")(e.currentTarget.value)} />
        </Group>
        <Group grow align="flex-start">
          <TextInput label="Publisher" value={f.publisher} onChange={(e) => set("publisher")(e.currentTarget.value)} />
          <TextInput label="Version" required value={f.version} onChange={(e) => set("version")(e.currentTarget.value)} />
        </Group>
        <Group grow>
          <Select label="Installer type" data={typeOptions} value={f.type} onChange={set("type")} allowDeselect={false} />
          <Select label="Architecture" data={["x64", "x86", "arm64", "neutral"]} value={f.arch} onChange={set("arch")} allowDeselect={false} />
          <Select label="Scope" data={["machine", "user", "any"]} value={f.scope} onChange={set("scope")} allowDeselect={false} />
        </Group>
        <TextInput label="Silent arguments" description="Space-separated, e.g. /S or /VERYSILENT /NORESTART. Leave empty for MSI." value={f.args} onChange={(e) => set("args")(e.currentTarget.value)} />
        <Group grow align="flex-start">
          <TextInput label="MSI product code" description="{GUID}; used for detection and uninstall" value={f.product_code} onChange={(e) => set("product_code")(e.currentTarget.value)} />
          <TextInput label="Uninstall registry key" description="Detection key name, if not an MSI" value={f.detect_key} onChange={(e) => set("detect_key")(e.currentTarget.value)} />
        </Group>
        <TextInput label="Detection file path" description="e.g. %ProgramFiles%\\Acme\\tool.exe; the install counts as successful when it exists" value={f.detect_file} onChange={(e) => set("detect_file")(e.currentTarget.value)} />
        <TextInput label="Required signer (optional)" description="Pin the Authenticode subject the installer must be signed by" value={f.signer_subject} onChange={(e) => set("signer_subject")(e.currentTarget.value)} />
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
        <Group justify="flex-end">
          <Button variant="default" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!valid}>
            Upload and add
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
