import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Group, Modal, NumberInput, Select, Stack, Switch, Text, TextInput } from "@mantine/core";
import { api, errorMessage, type EnrollmentToken, type Site } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { Card, DataTable, EmptyState, Icons, Page, PageHeader, Status, toast, useConfirm, type Column } from "../ui";
import { CommandBlock } from "../ui/CommandBlock";
import { commandText, fileSize, type InstallCommands } from "./installCommands";

interface Created {
  token: EnrollmentToken;
  enrollment_string: string;
  install_command: string;
  install: InstallCommands;
  root_ca_pin: string;
}

interface AgentDownloads {
  enabled: boolean;
  version: string;
  reason?: string;
  error?: string;
  items: { kind: "msi" | "exe"; file_name: string; size: number; sha256: string; verified: boolean; url: string; available: boolean }[];
}

/** Where the installers come from: the server fetches them from the release that matches its version. */
function AgentDownloadsCard({ d }: { d: AgentDownloads | undefined }) {
  if (!d) return null;
  const missing = d.items.filter((i) => !i.available);
  return (
    <Card title="Agent downloads" description={d.enabled ? `The agent for Windows, version ${d.version}, served by this server. Endpoints download it with the commands shown when you create a token; no sign-in is needed for the download itself.` : "The server does not hand out the agent."}>
      <Stack gap="xs">
        {!d.enabled && <Text size="sm">{d.reason || "Agent downloads are not available on this server."} Get the files from the project's release page and copy them to the PCs yourself.</Text>}
        {d.enabled &&
          d.items.map((i) => (
            <Group key={i.kind} justify="space-between" wrap="nowrap" align="flex-start">
              <div>
                <Text fw={500}>{i.kind === "msi" ? "MSI installer (GPO, Intune, RMM, or by hand)" : "Executable (single PC)"}</Text>
                <Text size="sm" c="dimmed" style={{ wordBreak: "break-all" }}>
                  {i.available ? `${i.file_name}, ${fileSize(i.size)}. SHA-256 ${i.sha256}${i.verified ? " (matches the one published with the release)" : " (computed by this server; the release publishes none for this file)"}` : "Not on this server yet."}
                </Text>
              </div>
              {i.available ? (
                <Button component="a" href={i.url} download variant="default" size="compact-md" leftSection={<Icons.Download size={14} aria-hidden />}>
                  Download
                </Button>
              ) : null}
            </Group>
          ))}
        {d.enabled && missing.length > 0 && (
          <Text size="sm" c={d.error ? "red" : "dimmed"} role={d.error ? "alert" : undefined}>
            {d.error ? `The server could not fetch the agent from the release yet: ${d.error}. It tries again by itself.` : "The server is fetching the agent from the release. This page updates by itself."}
          </Text>
        )}
      </Stack>
    </Card>
  );
}

// A stable empty list: a new [] on every render makes the table reset its page again and again while loading.
const NONE: EnrollmentToken[] = [];

export function TokensPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{ name: string; max_uses: number; expires_in_hours: number; require_approval: boolean; site_id: string | null }>({ name: "", max_uses: 10, expires_in_hours: 24, require_approval: false, site_id: null });
  const sites = useQuery({ queryKey: ["sites"], queryFn: () => api<{ items: Site[] }>("GET", "/sites") });
  const [created, setCreated] = useState<Created | null>(null);
  const downloads = useQuery({ queryKey: ["agent-downloads"], queryFn: () => api<AgentDownloads>("GET", "/agent-downloads"), refetchInterval: (query) => (query.state.data?.enabled && query.state.data.items.some((i) => !i.available) ? 15000 : false) });
  const q = useQuery({ queryKey: ["tokens"], queryFn: () => api<{ items: EnrollmentToken[] }>("GET", "/enrollment-tokens") });
  const create = useMutation({
    mutationFn: () => api<Created>("POST", "/enrollment-tokens", form),
    onSuccess: (c) => {
      setOpen(false);
      setCreated(c);
      void qc.invalidateQueries({ queryKey: ["tokens"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api("POST", `/enrollment-tokens/${id}/revoke`, {}),
    onSuccess: () => (toast.success("Token revoked."), qc.invalidateQueries({ queryKey: ["tokens"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api("DELETE", `/enrollment-tokens/${id}`),
    onSuccess: () => (toast.success("Token deleted."), qc.invalidateQueries({ queryKey: ["tokens"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const canWrite = can("enrollment:write");

  const columns = useMemo<Column<EnrollmentToken>[]>(
    () => [
      { id: "name", header: "Name", value: (t) => t.name, required: true, sortable: true, width: 260 },
      {
        id: "state",
        header: "State",
        value: (t) => t.state,
        sortable: true,
        width: 130,
        cell: (t) => <Status value={t.state} />,
        filter: {
          type: "select",
          options: [
            { value: "active", label: "Active" },
            { value: "expired", label: "Expired" },
            { value: "exhausted", label: "Used up" },
            { value: "revoked", label: "Revoked" },
          ],
        },
      },
      { id: "uses", header: "Uses", value: (t) => t.used_count, sortable: true, align: "right", width: 100, cell: (t) => <span className="lp-num">{t.used_count} / {t.max_uses}</span>, csv: (t) => `${t.used_count} / ${t.max_uses}` },
      {
        id: "approval",
        header: "Approval",
        value: (t) => (t.require_approval ? "required" : "automatic"),
        sortable: true,
        width: 130,
        filter: {
          type: "select",
          options: [
            { value: "required", label: "Required" },
            { value: "automatic", label: "Automatic" },
          ],
        },
      },
      { id: "expires", header: "Expires", value: (t) => new Date(t.expires_at).getTime(), sortable: true, width: 190, cell: (t) => dateTime(t.expires_at), csv: (t) => t.expires_at },
      { id: "created", header: "Issued", value: (t) => new Date(t.created_at).getTime(), sortable: true, width: 190, defaultHidden: true, cell: (t) => dateTime(t.created_at), csv: (t) => t.created_at },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Enrollment tokens"
        description="Tokens let new devices enroll. Keep them short-lived and limited in uses. Turn on approval to review each device before it is trusted."
        actions={
          canWrite ? (
            <Button leftSection={<Icons.Plus size={16} aria-hidden />} onClick={() => setOpen(true)}>
              New token
            </Button>
          ) : undefined
        }
      />
      <AgentDownloadsCard d={downloads.data} />
      <DataTable<EnrollmentToken>
        id="tokens"
        label="Enrollment tokens"
        data={q.data?.items ?? NONE}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={(t) => t.id}
        rowLabel={(t) => t.name}
        searchPlaceholder="Search tokens…"
        exportName="enrollment-tokens"
        initialSort={{ id: "expires", desc: true }}
        rowActions={(t) => {
          if (!canWrite) return null;
          if (t.state === "active")
            return (
              <Button
                size="compact-sm"
                variant="subtle"
                color="red"
                leftSection={<Icons.Close size={14} aria-hidden />}
                aria-label={`Revoke ${t.name}`}
                loading={revoke.isPending && revoke.variables === t.id}
                onClick={async () => {
                  const ok = await confirm({
                    title: `Revoke "${t.name}"?`,
                    message: "Devices can no longer enroll with this token. Devices that already enrolled with it are not affected.",
                    confirmLabel: "Revoke token",
                    danger: true,
                  });
                  if (ok) revoke.mutate(t.id);
                }}
              >
                Revoke
              </Button>
            );
          // Revoked, expired or used up: nothing can enroll with it any more, so it can go.
          return (
            <Button
              size="compact-sm"
              variant="subtle"
              color="red"
              leftSection={<Icons.Trash size={14} aria-hidden />}
              aria-label={`Delete ${t.name}`}
              loading={remove.isPending && remove.variables === t.id}
              onClick={async () => {
                const ok = await confirm({
                  title: `Delete "${t.name}"?`,
                  message: "The token is removed from this list. Devices that enrolled with it are not affected, and the audit log keeps the record.",
                  confirmLabel: "Delete token",
                  danger: true,
                });
                if (ok) remove.mutate(t.id);
              }}
            >
              Delete
            </Button>
          );
        }}
        empty={
          <EmptyState
            icon={<Icons.NavEnrollment size={26} />}
            title="No enrollment tokens yet"
            description={canWrite ? "Use New token above to make one, then run the install command it shows on a Windows device." : "An administrator can create a token to enroll devices."}
          />
        }
      />

      <Modal opened={open} onClose={() => setOpen(false)} title="New enrollment token">
        <form onSubmit={(e) => (e.preventDefault(), create.mutate())}>
          <Stack>
            <TextInput label="Name" placeholder="e.g. Head office laptops" value={form.name} onChange={(e) => setForm({ ...form, name: e.currentTarget.value })} required maxLength={200} data-autofocus />
            <NumberInput label="Maximum uses" min={1} max={100000} value={form.max_uses} onChange={(v) => setForm({ ...form, max_uses: Number(v) || 1 })} />
            <NumberInput label="Valid for (hours)" min={1} max={8760} value={form.expires_in_hours} onChange={(v) => setForm({ ...form, expires_in_hours: Number(v) || 1 })} />
            {(sites.data?.items.length ?? 0) > 1 && (
              <Select label="Site" description="New devices join this site" data={sites.data!.items.map((s) => ({ value: s.id, label: s.name }))} value={form.site_id} onChange={(v) => setForm({ ...form, site_id: v })} placeholder="Default site" clearable />
            )}
            <Switch label="Require administrator approval for each device" checked={form.require_approval} onChange={(e) => setForm({ ...form, require_approval: e.currentTarget.checked })} />
            <Group justify="flex-end">
              <Button variant="default" onClick={() => setOpen(false)}>
                Not now
              </Button>
              <Button type="submit" loading={create.isPending}>
                Create
              </Button>
            </Group>
          </Stack>
        </form>
      </Modal>

      <Modal opened={!!created} onClose={() => setCreated(null)} title="Token created" size="xl">
        {created && (
          <Stack>
            <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
              This is the only time the token is shown. Anyone with it can enroll devices until it expires or is used up.
            </Alert>
            <Text fw={500}>Install with the MSI, silently. Paste this one line into an elevated Command Prompt or PowerShell:</Text>
            <CommandBlock value={commandText(created.install.msi)} label="Copy MSI install command" />
            <Text fw={500}>Or install with the exe (the same, one line):</Text>
            <CommandBlock value={commandText(created.install.exe)} label="Copy exe install command" />
            {(!created.install.msi.one_liner || !created.install.exe.one_liner) ? (
              <Text size="sm" c="dimmed">
                This server does not have the agent files to hand out yet, so the line above assumes the file is already in the current folder. See "Agent downloads" on this page.
              </Text>
            ) : (
              <Text size="sm" c="dimmed">
                The line downloads the installer from this server, installs it, waits until it has finished and deletes the downloaded file. It needs Windows 10 version 1803 or later (for curl.exe) and the PC must trust this server's certificate.
              </Text>
            )}
            <Text size="sm" c="dimmed">
              The agent verifies the server's certificate authority against this pin, carried inside the token: {created.root_ca_pin}
            </Text>
          </Stack>
        )}
      </Modal>
    </Page>
  );
}
