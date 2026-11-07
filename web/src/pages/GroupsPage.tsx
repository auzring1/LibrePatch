import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Modal, MultiSelect, SegmentedControl, Textarea, TextInput } from "@mantine/core";
import { api, errorMessage, type Device, type Filter, type Group as Grp, type GroupMembers } from "../api/client";
import { dateTime } from "../api/format";
import { FilterEditor, newGroup } from "../components/FilterEditor";
import { useSession } from "../api/session";
import { Card, DataTable, EmptyState, Icons, IconButton, Page, PageHeader, Status, StatusPill, toast, useConfirm, type Column } from "../ui";
import { LinkButton } from "../ui/PageBits";

type Member = GroupMembers["items"][number];

function Members({ id, data, onRemove }: { id: string; data: GroupMembers; onRemove?: (id: string) => void }) {
  const columns = useMemo<Column<Member>[]>(
    () => [
      { id: "hostname", header: "Device", value: (m) => m.hostname, primary: true, required: true, width: 200 },
      { id: "model", header: "Model", value: (m) => [m.manufacturer, m.model].filter(Boolean).join(" "), width: 190 },
      { id: "os", header: "OS", value: (m) => m.os_caption ?? "", width: 210 },
      { id: "connection", header: "Connection", value: (m) => (m.online ? "online" : "offline"), width: 120, cell: (m) => <Status value={m.online ? "online" : "offline"} size="sm" /> },
    ],
    [],
  );
  return (
    <DataTable<Member>
      id={id}
      label="Matching devices"
      data={data.items}
      columns={columns}
      rowId={(m) => m.id}
      rowHref={(m) => `/devices/${m.id}`}
      rowLabel={(m) => m.hostname}
      pageSize={10}
      initialSort={{ id: "hostname" }}
      searchPlaceholder="Search devices"
      rowActions={onRemove ? (m) => <IconButton label={`Remove ${m.hostname} from the group`} icon={<Icons.Close size={16} aria-hidden />} size="sm" onClick={() => onRemove(m.id)} /> : undefined}
    />
  );
}

export function GroupsPage() {
  const { can } = useSession();
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<Grp | "new" | null>(null);
  const [viewing, setViewing] = useState<Grp | null>(null);
  const list = useQuery({ queryKey: ["groups"], queryFn: () => api<{ items: Grp[] }>("GET", "/groups") });
  const del = useMutation({
    mutationFn: (id: string) => api("DELETE", `/groups/${id}`),
    onSuccess: () => (toast.success("Group deleted."), qc.invalidateQueries({ queryKey: ["groups"] })),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const changeMembers = useMutation({
    mutationFn: (b: { add?: string[]; remove?: string[] }) => api("POST", `/groups/${viewing!.id}/members`, b),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["groups", "members"] }),
    onError: (e) => toast.error(errorMessage(e)),
  });
  const members = useQuery({
    queryKey: ["groups", "members", viewing?.id],
    queryFn: () => api<GroupMembers>("GET", `/groups/${viewing!.id}/devices?limit=500`),
    enabled: !!viewing,
  });
  const canWrite = can("groups:write");

  const columns = useMemo<Column<Grp>[]>(
    () => [
      {
        id: "name",
        header: "Group",
        value: (g) => g.name,
        required: true,
        primary: true,
        width: 260,
        cell: (g) => (
          <LinkButton id={`group-name-${g.id}`} onClick={() => setViewing(g)}>
            {g.name}
          </LinkButton>
        ),
      },
      {
        id: "kind",
        header: "Type",
        value: (g) => g.kind,
        width: 130,
        cell: (g) => (
          <StatusPill kind={g.kind === "static" ? "neutral" : "info"} size="sm" icon={g.kind === "static" ? Icons.NavGroups : Icons.Filter}>
            {g.kind}
          </StatusPill>
        ),
        filter: {
          type: "select",
          options: [
            { value: "dynamic", label: "Dynamic" },
            { value: "static", label: "Static" },
          ],
        },
      },
      { id: "description", header: "Description", value: (g) => g.description, width: 360, wrap: true },
      { id: "updated", header: "Updated", value: (g) => g.updated_at, width: 180, cell: (g) => dateTime(g.updated_at), csv: (g) => g.updated_at, defaultHidden: true },
    ],
    [],
  );

  return (
    <Page>
      <PageHeader
        title="Groups"
        description="Dynamic groups are saved filters: membership is recomputed every time you look, so a device joins or leaves as its software changes. Static groups are lists you maintain by hand."
        actions={
          canWrite ? (
            <Button onClick={() => setEditing("new")} leftSection={<Icons.Plus size={16} aria-hidden />}>
              New group
            </Button>
          ) : undefined
        }
      />
      <DataTable<Grp>
        id="groups"
        label="Groups"
        data={list.data?.items}
        loading={list.isLoading}
        error={list.error ? new Error(errorMessage(list.error)) : undefined}
        columns={columns}
        rowId={(g) => g.id}
        rowLabel={(g) => g.name}
        rowTestId="group-row"
        onRowClick={setViewing}
        initialSort={{ id: "name" }}
        searchPlaceholder="Search groups"
        exportName="groups"
        rowActions={
          canWrite
            ? (g) => (
                <>
                  <Button size="compact-sm" variant="subtle" color="gray" leftSection={<Icons.Edit size={14} aria-hidden />} aria-describedby={`group-name-${g.id}`} onClick={() => setEditing(g)}>
                    Edit
                  </Button>
                  <Button
                    size="compact-sm"
                    variant="subtle"
                    color="red"
                    leftSection={<Icons.Trash size={14} aria-hidden />}
                    aria-describedby={`group-name-${g.id}`}
                    loading={del.isPending && del.variables === g.id}
                    onClick={async () => {
                      const ok = await confirm({
                        title: `Delete group “${g.name}”?`,
                        message: "Policies and rings that use this group stop applying to its devices. The devices themselves are not affected.",
                        confirmLabel: "Delete group",
                        danger: true,
                      });
                      if (ok) del.mutate(g.id);
                    }}
                  >
                    Delete
                  </Button>
                </>
              )
            : undefined
        }
        empty={<EmptyState icon={<Icons.NavGroups size={26} />} title="No groups yet" description="Create one with New group, for example “laptops with Chrome older than 130”." />}
      />

      <Modal opened={!!viewing} onClose={() => setViewing(null)} title={viewing?.name} size="xl">
        <div className="lp-block">
          {members.isLoading && <EmptyState icon={<Icons.Spinner size={26} />} title="Loading devices" />}
          {members.error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {errorMessage(members.error)}
            </Alert>
          )}
          {members.data && (
            <>
              <div className="lp-row" style={{ justifyContent: "space-between" }}>
                <StatusPill kind="info" icon={Icons.NavDevices}>
                  {members.data.total} device{members.data.total === 1 ? "" : "s"}
                </StatusPill>
                {can("inventory:export") && viewing && (
                  <Button component="a" size="xs" variant="default" href={`/api/v1/reports/devices.csv?group_id=${viewing.id}`} download leftSection={<Icons.Download size={14} aria-hidden />}>
                    Export CSV
                  </Button>
                )}
              </div>
              {viewing?.kind === "static" && canWrite && <AddMembers existing={members.data.items.map((m) => m.id)} onAdd={(ids) => changeMembers.mutate({ add: ids })} />}
              {members.data.items.length > 0 && <Members id="group-members" data={members.data} onRemove={viewing?.kind === "static" && canWrite ? (id) => changeMembers.mutate({ remove: [id] }) : undefined} />}
            </>
          )}
        </div>
      </Modal>

      {editing && <GroupEditor group={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </Page>
  );
}

function GroupEditor({ group, onClose }: { group: Grp | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState(group?.name ?? "");
  const [description, setDescription] = useState(group?.description ?? "");
  const [kind, setKind] = useState<"dynamic" | "static">(group?.kind ?? "dynamic");
  const [filter, setFilter] = useState<Filter>(group?.filter ?? newGroup());
  const [error, setError] = useState("");
  const preview = useMutation({
    mutationFn: () => api<GroupMembers>("POST", "/groups/preview?limit=50", { filter }),
    onMutate: () => setError(""),
    onError: (e) => setError(errorMessage(e)),
  });
  const save = useMutation({
    mutationFn: () => (group ? api("PUT", `/groups/${group.id}`, group.kind === "static" ? { name, description } : { name, description, filter }) : api("POST", "/groups", kind === "static" ? { kind, name, description } : { kind, name, description, filter })),
    onSuccess: () => (toast.success("Group saved."), qc.invalidateQueries({ queryKey: ["groups"] }), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title={group ? "Edit group" : "New group"} size="xl">
      <div className="lp-block">
        {!group && (
          <SegmentedControl
            value={kind}
            onChange={(v) => setKind(v as typeof kind)}
            data={[
              { value: "dynamic", label: "Dynamic (filter)" },
              { value: "static", label: "Static (hand-picked)" },
            ]}
          />
        )}
        <TextInput label="Name" required value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={200} />
        <Textarea label="Description" value={description} onChange={(e) => setDescription(e.currentTarget.value)} maxLength={1000} autosize minRows={1} maxRows={3} />
        {kind === "dynamic" ? (
          <>
            <h3 className="lp-subhead">Devices that match</h3>
            <FilterEditor node={filter} onChange={setFilter} />
          </>
        ) : (
          <p className="lp-hint">Save the group, then open it to add devices.</p>
        )}
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
        <div className="lp-row">
          {kind === "dynamic" && (
            <Button variant="default" onClick={() => preview.mutate()} loading={preview.isPending} leftSection={<Icons.Eye size={16} aria-hidden />}>
              Preview matches
            </Button>
          )}
          <Button onClick={() => save.mutate()} loading={save.isPending} disabled={!name.trim()} leftSection={<Icons.Save size={16} aria-hidden />}>
            Save group
          </Button>
        </div>
        {preview.data && (
          <Card flush>
            <div className="lp-block" style={{ padding: "var(--lp-space-3)" }}>
              <span data-testid="preview-total">
                <StatusPill kind={preview.data.total > 0 ? "info" : "neutral"} icon={Icons.NavDevices}>
                  {preview.data.total} matching device{preview.data.total === 1 ? "" : "s"}
                </StatusPill>
              </span>
              {preview.data.items.length > 0 && <Members id="group-preview" data={preview.data} />}
            </div>
          </Card>
        )}
      </div>
    </Modal>
  );
}

function AddMembers({ existing, onAdd }: { existing: string[]; onAdd: (ids: string[]) => void }) {
  const [sel, setSel] = useState<string[]>([]);
  const devices = useQuery({ queryKey: ["devices", "active"], queryFn: () => api<{ items: Device[] }>("GET", "/devices?status=active&limit=500") });
  const data = (devices.data?.items ?? []).filter((d) => !existing.includes(d.id)).map((d) => ({ value: d.id, label: d.hostname }));
  return (
    <div className="lp-row" style={{ alignItems: "flex-end", flexWrap: "nowrap" }}>
      <MultiSelect label="Add devices" searchable data={data} value={sel} onChange={setSel} style={{ flex: 1 }} placeholder="Choose devices" />
      <Button onClick={() => (onAdd(sel), setSel([]))} disabled={!sel.length} leftSection={<Icons.Plus size={16} aria-hidden />}>
        Add
      </Button>
    </div>
  );
}
