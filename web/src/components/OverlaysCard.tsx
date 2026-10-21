import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, FileInput, Group, Modal, NumberInput, SegmentedControl, Stack, Text, TextInput } from "@mantine/core";
import { api, errorMessage, type OverlaySource } from "../api/client";
import { useSession } from "../api/session";
import { ago } from "../api/format";
import { Card, DataTable, EmptyState, Icons, IconButton, StatusPill, toast, useConfirm, type Column } from "../ui";
import { isPublicKey, looksLikeOverlayFile, overlayCounts, overlayOrigin, overlayStatus } from "./overlays";

interface Listing {
  items: OverlaySource[];
  builtin_entries: number;
}

/** The signed overlays that tell the catalog what their authors know about packages (silent arguments, detection, verified). */
export function OverlaysCard() {
  const { can } = useSession();
  const canEdit = can("catalog:override");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["catalog", "overlays"], queryFn: () => api<Listing>("GET", "/catalog/overlays") });
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<OverlaySource | null>(null);
  const [replacing, setReplacing] = useState<OverlaySource | null>(null);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["catalog"] });

  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/catalog/overlays/${id}`),
    onSuccess: () => (toast.success("Overlay removed."), refresh()),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const check = useMutation({
    mutationFn: (id: string) => api<{ changed: boolean; version: number }>("POST", `/catalog/overlays/${id}/refresh`),
    onSuccess: (r) => (toast.success(r.changed ? `Updated to version ${r.version}.` : "Already up to date."), refresh()),
    onError: (e) => (toast.error(errorMessage(e)), refresh()),
  });

  const columns = useMemo<Column<OverlaySource>[]>(
    () => [
      { id: "name", header: "Overlay", required: true, primary: true, width: 220, value: (s) => s.label, wrap: true },
      {
        id: "status",
        header: "State",
        width: 140,
        value: (s) => overlayStatus(s).label,
        cell: (s) => {
          const st = overlayStatus(s);
          return (
            <StatusPill kind={st.kind} size="sm" title={st.title}>
              {st.label}
            </StatusPill>
          );
        },
      },
      { id: "doc", header: "Document", width: 240, value: (s) => `${s.doc_name} v${s.doc_version}`, wrap: true },
      { id: "counts", header: "Contents", width: 200, value: (s) => overlayCounts(s) },
      { id: "origin", header: "From", width: 180, value: (s) => overlayOrigin(s) },
      { id: "priority", header: "Priority", align: "right", width: 90, value: (s) => s.priority, cell: (s) => <span className="lp-num">{s.priority}</span> },
      { id: "checked", header: "Checked", width: 150, value: (s) => (s.checked_at ? new Date(s.checked_at).getTime() : 0), csv: (s) => s.checked_at ?? "", cell: (s) => (s.checked_at ? ago(s.checked_at) : "—") },
      { id: "key", header: "Key", width: 160, value: (s) => s.key_id, cell: (s) => <span className="lp-mono">{s.key_id}</span> },
    ],
    [],
  );

  const items = q.data?.items ?? [];
  return (
    <Card
      title="Overlays"
      description={`An overlay is a signed file in which someone who tested packages records the silent arguments and detection rules that work, which programs update themselves, and which packages are verified. It sits under your own package overrides. The built-in overlay has ${q.data?.builtin_entries ?? "…"} entries.`}
      actions={
        canEdit ? (
          <>
            <Button size="xs" variant="default" component="a" href="/api/v1/catalog/overlay-template" download leftSection={<Icons.Download size={14} aria-hidden />}>
              Starter file from my overrides
            </Button>
            <Button size="xs" onClick={() => setAdding(true)} leftSection={<Icons.Plus size={14} aria-hidden />}>
              Add overlay
            </Button>
          </>
        ) : undefined
      }
    >
      <DataTable<OverlaySource>
        id="catalog-overlays"
        label="Overlays"
        data={q.isLoading ? undefined : items}
        loading={q.isLoading}
        error={q.error ? new Error(errorMessage(q.error)) : undefined}
        columns={columns}
        rowId={(s) => s.id}
        rowLabel={(s) => s.label}
        initialSort={{ id: "priority" }}
        exportName="catalog-overlays"
        rowActions={
          canEdit
            ? (s) => (
                <>
                  {s.kind === "url" && <IconButton label={`Check ${s.label} for a newer version now`} icon={<Icons.Refresh size={16} aria-hidden />} size="sm" onClick={() => check.mutate(s.id)} />}
                  <IconButton label={`Upload a newer file for ${s.label}`} icon={<Icons.Upload size={16} aria-hidden />} size="sm" onClick={() => setReplacing(s)} />
                  <IconButton label={`Edit ${s.label}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEditing(s)} />
                  <IconButton
                    label={`Remove ${s.label}`}
                    icon={<Icons.Trash size={16} aria-hidden />}
                    size="sm"
                    color="red"
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Remove overlay “${s.label}”?`,
                        message: "What it says about packages stops applying: silent arguments, detection rules and verified marks that came from it. Your own overrides are not touched.",
                        confirmLabel: "Remove overlay",
                        danger: true,
                      });
                      if (ok) del.mutate(s.id);
                    }}
                  />
                </>
              )
            : undefined
        }
        empty={<EmptyState icon={<Icons.NavCatalog size={26} />} title="No overlays added" description="Only the built-in overlay applies. Add a signed overlay file, or download a starter file from your own overrides, edit it and sign it with librepatch-release overlay-sign." />}
      />
      {adding && <AddModal onClose={() => setAdding(false)} onDone={() => (setAdding(false), refresh())} />}
      {editing && <EditModal source={editing} onClose={() => setEditing(null)} onDone={() => (setEditing(null), refresh())} />}
      {replacing && <ReplaceModal source={replacing} onClose={() => setReplacing(null)} onDone={() => (setReplacing(null), refresh())} />}
    </Card>
  );
}

function AddModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [mode, setMode] = useState<"file" | "url">("file");
  const [file, setFile] = useState<File | null>(null);
  const [url, setUrl] = useState("");
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      const body: Record<string, string> = { public_key: key.trim(), label: label.trim() };
      if (mode === "url") body.url = url.trim();
      else {
        const text = file ? await file.text() : "";
        if (!looksLikeOverlayFile(text)) throw new Error("This does not look like a signed overlay file (.lpov). Sign the document with librepatch-release overlay-sign first.");
        body.bundle = text;
      }
      return api<OverlaySource>("POST", "/catalog/overlays", body);
    },
    onSuccess: (s) => (toast.success(`Added “${s.label}”: ${overlayCounts(s)}.`), onDone()),
    onError: (e) => setError(errorMessage(e)),
  });
  const ready = isPublicKey(key) && (mode === "file" ? !!file : /^https?:\/\//i.test(url.trim()));
  return (
    <Modal opened onClose={onClose} title="Add an overlay" size="lg">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), add.mutate())}>
        <Stack>
          <Text size="sm">
            The server accepts the file only if it was signed with the public key you enter here. Get the key from whoever made the overlay (the <code>overlay-sign</code> command prints it).
          </Text>
          <SegmentedControl value={mode} onChange={(v) => setMode(v as "file" | "url")} data={[{ value: "file", label: "Upload a file" }, { value: "url", label: "Fetch from an address" }]} />
          {mode === "file" ? (
            <FileInput label="Signed overlay file (.lpov)" accept=".lpov,.json,application/json" value={file} onChange={setFile} clearable required />
          ) : (
            <TextInput label="Address" description="http or https. The server checks for a newer version every 12 hours." placeholder="https://example.org/overlays/clinic.lpov" value={url} onChange={(e) => setUrl(e.currentTarget.value)} required />
          )}
          <TextInput label="Public key" description="64 hexadecimal characters" value={key} onChange={(e) => setKey(e.currentTarget.value)} required ff="monospace" />
          <TextInput label="Name (optional)" description="Shown in the catalog. Defaults to the name inside the file." value={label} onChange={(e) => setLabel(e.currentTarget.value)} maxLength={100} />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={add.isPending} disabled={!ready}>
              Add overlay
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function EditModal({ source, onClose, onDone }: { source: OverlaySource; onClose: () => void; onDone: () => void }) {
  const [label, setLabel] = useState(source.label);
  const [enabled, setEnabled] = useState(source.enabled);
  const [priority, setPriority] = useState<number | string>(source.priority);
  const [url, setUrl] = useState(source.url);
  const [error, setError] = useState("");
  const save = useMutation({
    mutationFn: () => api("PUT", `/catalog/overlays/${source.id}`, { label: label.trim(), enabled, priority: Number(priority) || 100, url: source.kind === "url" ? url.trim() : "" }),
    onSuccess: () => (toast.success("Saved."), onDone()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={`Edit ${source.label}`}>
      <form onSubmit={(e) => (e.preventDefault(), setError(""), save.mutate())}>
        <Stack>
          <TextInput label="Name" value={label} onChange={(e) => setLabel(e.currentTarget.value)} required maxLength={100} data-autofocus />
          <NumberInput label="Priority" description="When two overlays say something about the same package, the lower number wins." min={1} max={1000} value={priority} onChange={setPriority} />
          {source.kind === "url" && <TextInput label="Address" value={url} onChange={(e) => setUrl(e.currentTarget.value)} required />}
          <Checkbox label="In use" checked={enabled} onChange={(e) => setEnabled(e.currentTarget.checked)} />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending} disabled={!label.trim()}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function ReplaceModal({ source, onClose, onDone }: { source: OverlaySource; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState("");
  const send = useMutation({
    mutationFn: async () => {
      const text = file ? await file.text() : "";
      if (!looksLikeOverlayFile(text)) throw new Error("This does not look like a signed overlay file (.lpov).");
      return api<{ changed: boolean; version: number }>("POST", `/catalog/overlays/${source.id}/upload`, { bundle: text });
    },
    onSuccess: (r) => (toast.success(r.changed ? `Now at version ${r.version}.` : "That is the version already in use."), onDone()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={`Upload a newer file for ${source.label}`}>
      <form onSubmit={(e) => (e.preventDefault(), setError(""), send.mutate())}>
        <Stack>
          <Text size="sm">
            Currently version {source.doc_version}. The file must be signed with the same key ({source.key_id}) and must not be older.
          </Text>
          <FileInput label="Signed overlay file (.lpov)" accept=".lpov,.json,application/json" value={file} onChange={setFile} clearable required />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={send.isPending} disabled={!file}>
              Upload
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
