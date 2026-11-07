import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import { api, errorMessage, type Site } from "../api/client";
import { useSession } from "../api/session";
import { DataTable, EmptyState, Icons, IconButton, Page, PageHeader, toast, useConfirm, type Column } from "../ui";
import { RowButtons } from "../ui/admin-kit";

export function SitesPage() {
  const { canOrg } = useSession();
  const canWrite = canOrg("sites:write");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const q = useQuery({ queryKey: ["sites"], queryFn: () => api<{ items: Site[] }>("GET", "/sites") });
  const [edit, setEdit] = useState<Site | "new" | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/sites/${id}`),
    onSuccess: () => {
      toast.success("Site deleted.");
      void qc.invalidateQueries({ queryKey: ["sites"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const remove = del.mutate;

  const columns = useMemo<Column<Site>[]>(
    () => [
      { id: "name", header: "Name", value: (s) => s.name, primary: true, required: true, width: 260, wrap: true },
      { id: "timezone", header: "Time zone", value: (s) => s.timezone, width: 200, cell: (s) => <span className="lp-mono">{s.timezone}</span> },
      { id: "devices", header: "Devices", value: (s) => s.devices, align: "right", width: 110, cell: (s) => <span className="lp-num">{s.devices}</span> },
      { id: "created", header: "Created", value: (s) => (s.created_at ? new Date(s.created_at).getTime() : 0), width: 150, defaultHidden: true, cell: (s) => (s.created_at ? new Date(s.created_at).toLocaleDateString() : "—"), csv: (s) => s.created_at ?? "" },
      ...(canWrite
        ? [
            {
              id: "actions",
              header: "Actions",
              required: true,
              csv: false as const,
              align: "right" as const,
              width: 96,
              cell: (s: Site) => (
                <RowButtons>
                  <IconButton label={`Edit site ${s.name}`} icon={<Icons.Edit size={16} aria-hidden />} size="sm" onClick={() => setEdit(s)} />
                  <IconButton
                    label={`Delete site ${s.name}`}
                    icon={<Icons.Trash size={16} aria-hidden />}
                    size="sm"
                    color="red"
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Delete site "${s.name}"?`,
                        message: s.devices > 0 ? `${s.devices} device${s.devices === 1 ? " is" : "s are"} at this site. This cannot be undone.` : "This cannot be undone.",
                        confirmLabel: "Delete site",
                        danger: true,
                      });
                      if (ok) remove(s.id);
                    }}
                  />
                </RowButtons>
              ),
            },
          ]
        : []),
    ],
    [canWrite, confirm, remove],
  );

  return (
    <Page>
      <PageHeader
        title="Sites"
        description="A site is a location or customer. New devices join the site named by the enrollment token they use. Give a person a role on a site and they manage that site's devices and nothing else."
        actions={
          canWrite ? (
            <Button leftSection={<Icons.Plus size={16} aria-hidden />} onClick={() => setEdit("new")}>
              Add site
            </Button>
          ) : undefined
        }
      />
      <DataTable<Site>
        id="sites"
        label="Sites"
        data={q.data?.items}
        loading={q.isLoading}
        error={q.error}
        columns={columns}
        rowId={(s) => s.id}
        rowTestId="site-row"
        rowLabel={(s) => s.name}
        searchPlaceholder="Search sites…"
        exportName="sites"
        initialSort={{ id: "name" }}
        empty={
          <EmptyState
            icon={<Icons.NavSites size={26} />}
            title="No sites yet"
            description={canWrite ? "Use Add site above for each location or customer you manage, then name it in an enrollment token." : "An administrator adds the locations or customers this server manages."}
          />
        }
      />
      {edit && <SiteModal site={edit === "new" ? undefined : edit} onClose={() => setEdit(null)} />}
    </Page>
  );
}

function SiteModal({ site, onClose }: { site?: Site; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(site?.name ?? "");
  const [tz, setTz] = useState(site?.timezone ?? "UTC");
  const [error, setError] = useState("");
  const save = useMutation({
    mutationFn: () => (site ? api("PUT", `/sites/${site.id}`, { name: name.trim(), timezone: tz }) : api("POST", "/sites", { name: name.trim(), timezone: tz })),
    onSuccess: () => {
      toast.success(site ? "Site saved." : "Site added.");
      void qc.invalidateQueries({ queryKey: ["sites"] });
      onClose();
    },
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={site ? `Edit ${site.name}` : "Add site"}>
      <form onSubmit={(e) => (e.preventDefault(), setError(""), save.mutate())}>
        <Stack>
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={200} data-autofocus />
          <TextInput label="Time zone" description="IANA name, for example Europe/Berlin" value={tz} onChange={(e) => setTz(e.currentTarget.value)} />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />} role="alert">
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={save.isPending}>
              Save
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
