import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ActionIcon, Alert, Button, Group, Menu, Modal, Select, Stack, Tabs, Text, TextInput } from "@mantine/core";
import { api, errorMessage, type ApiToken, type Site, type UserAccount } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { CopyText } from "../components/common";
import { RowButtons } from "../ui/admin-kit";
import { DataTable, EmptyState, Icons, Page, PageHeader, Status, StatusPill, toast, useConfirm, type Column, type PillKind } from "../ui";

const roleLabel: Record<string, string> = { admin: "Administrator", operator: "Operator", readonly: "Read-only" };
const roleLook: Record<string, { kind: PillKind; icon: typeof Icons.User }> = {
  admin: { kind: "info", icon: Icons.NavUpdates },
  operator: { kind: "neutral", icon: Icons.User },
  readonly: { kind: "neutral", icon: Icons.Eye },
};

type Kind = "disable" | "enable" | "reset-password" | "reset-mfa" | "delete";
const done: Record<Kind, string> = {
  disable: "User disabled.",
  enable: "User enabled.",
  "reset-password": "Temporary password set.",
  "reset-mfa": "Second factor reset. They set up a new one at the next sign-in.",
  delete: "User deleted.",
};

function RolePill({ role }: { role: string }) {
  const look = roleLook[role] ?? { kind: "neutral" as PillKind, icon: Icons.User };
  return (
    <StatusPill kind={look.kind} icon={look.icon} size="sm">
      {roleLabel[role] ?? role}
    </StatusPill>
  );
}

export function UsersPage() {
  const { session, canOrg } = useSession();
  const canWrite = canOrg("users:write");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<{ items: UserAccount[] }>("GET", "/users") });
  const sites = useQuery({ queryKey: ["sites"], queryFn: () => api<{ items: Site[] }>("GET", "/sites") });
  const tokens = useQuery({ queryKey: ["all-api-tokens"], queryFn: () => api<{ items: ApiToken[] }>("GET", "/api-tokens") });
  const [creating, setCreating] = useState(false);
  const [editing, setEditing] = useState<UserAccount | null>(null);
  const [secret, setSecret] = useState<{ email: string; password: string } | null>(null);
  const siteList = sites.data?.items;
  const siteName = (id: string) => siteList?.find((s) => s.id === id)?.name ?? id.slice(0, 8);
  const refresh = () => void qc.invalidateQueries({ queryKey: ["users"] });
  const revokeToken = useMutation({
    mutationFn: (id: string) => api("DELETE", `/api-tokens/${id}`),
    onSuccess: () => {
      toast.success("Token revoked.");
      void qc.invalidateQueries({ queryKey: ["all-api-tokens"] });
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const act = useMutation({
    mutationFn: async (a: { u: UserAccount; kind: Kind }) => {
      const { u, kind } = a;
      if (kind === "disable" || kind === "enable") return api("PUT", `/users/${u.id}`, { display_name: u.display_name, status: kind === "disable" ? "disabled" : "active" });
      if (kind === "reset-password") {
        const r = await api<{ temporary_password?: string }>("POST", `/users/${u.id}/reset-password`, {});
        if (r.temporary_password) setSecret({ email: u.email, password: r.temporary_password });
        return r;
      }
      if (kind === "reset-mfa") return api("POST", `/users/${u.id}/reset-mfa`, {});
      return api("DELETE", `/users/${u.id}`);
    },
    onSuccess: (_d, v) => {
      toast.success(done[v.kind]);
      refresh();
    },
    onError: (e) => toast.error(errorMessage(e)),
  });
  const doAct = act.mutate;
  const myId = session?.user.id;

  const userColumns = useMemo<Column<UserAccount>[]>(() => {
    const scopeText = (b: UserAccount["bindings"][number]) => (b.scope_type === "org" ? "whole organization" : `site ${siteName(b.scope_id)}`);
    const run = async (u: UserAccount, kind: Kind) => {
      if (kind === "reset-mfa") {
        const ok = await confirm({
          title: `Reset the second factor of ${u.email}?`,
          message: "All of their authenticators and security keys are removed. They set up a new one at the next sign-in.",
          confirmLabel: "Reset second factor",
          danger: true,
        });
        if (!ok) return;
      }
      if (kind === "delete") {
        const ok = await confirm({ title: `Delete ${u.email}?`, message: "The account and its sessions are removed. This cannot be undone.", confirmLabel: "Delete user", danger: true });
        if (!ok) return;
      }
      doAct({ u, kind });
    };
    return [
      {
        id: "user",
        header: "User",
        value: (u) => `${u.display_name} ${u.email}`,
        primary: true,
        required: true,
        width: 220,
        cell: (u) => (
          <>
            {u.display_name}
            <span className="lp-dt__cell-sub">{u.email}{u.sso ? " · single sign-on" : ""}</span>
          </>
        ),
      },
      {
        id: "status",
        header: "Status",
        value: (u) => u.status,
        width: 170,
        wrap: true,
        cell: (u) => (
          <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 4 }}>
            {u.status === "disabled" ? (
              <StatusPill kind="neutral" size="sm" icon={Icons.Pause}>
                Disabled
              </StatusPill>
            ) : (
              <Status value="active" size="sm" />
            )}
            {u.must_change_password && (
              <StatusPill kind="warning" size="sm" icon={Icons.Lock}>
                Must change password
              </StatusPill>
            )}
          </span>
        ),
        filter: {
          type: "select",
          options: [
            { value: "active", label: "Active" },
            { value: "disabled", label: "Disabled" },
          ],
        },
        csv: (u) => u.status,
      },
      {
        id: "roles",
        header: "Roles",
        value: (u) => u.bindings.map((b) => `${roleLabel[b.role] ?? b.role} ${scopeText(b)}`).join("; "),
        width: 260,
        wrap: true,
        cell: (u) => (
          <span style={{ display: "flex", flexDirection: "column", gap: 4, alignItems: "flex-start" }}>
            {u.bindings.map((b) => (
              <span key={b.id}>
                <RolePill role={b.role} />
                <span className="lp-muted"> — {scopeText(b)}{b.source === "sso" ? " (follows the sign-in provider)" : ""}</span>
              </span>
            ))}
          </span>
        ),
      },
      {
        id: "factor",
        header: "Second factor",
        value: (u) => [u.has_totp ? "authenticator" : "", u.security_keys > 0 ? `${u.security_keys} security key${u.security_keys === 1 ? "" : "s"}` : ""].filter(Boolean).join(", ") || "to be set up at next sign-in",
        width: 190,
        wrap: true,
        cell: (u) =>
          !u.has_totp && u.security_keys === 0 ? (
            <StatusPill kind="warning" size="sm" icon={Icons.Clock}>
              To be set up at next sign-in
            </StatusPill>
          ) : (
            <span style={{ display: "inline-flex", flexWrap: "wrap", gap: 4 }}>
              {u.has_totp && (
                <StatusPill kind="success" size="sm">
                  Authenticator
                </StatusPill>
              )}
              {u.security_keys > 0 && (
                <StatusPill kind="success" size="sm" icon={Icons.NavEnrollment}>
                  {u.security_keys} security key{u.security_keys === 1 ? "" : "s"}
                </StatusPill>
              )}
            </span>
          ),
      },
      {
        id: "last",
        header: "Last sign-in",
        value: (u) => (u.last_login_at ? new Date(u.last_login_at).getTime() : 0),
        width: 130,
        wrap: true,
        cell: (u) => dateTime(u.last_login_at),
        csv: (u) => u.last_login_at ?? "",
      },
      {
        id: "created",
        header: "Created",
        value: (u) => new Date(u.created_at).getTime(),
        width: 150,
        defaultHidden: true,
        cell: (u) => new Date(u.created_at).toLocaleDateString(),
        csv: (u) => u.created_at,
      },
      ...(canWrite
        ? [
            {
              id: "actions",
              header: "Actions",
              required: true,
              csv: false as const,
              align: "right" as const,
              width: 84,
              cell: (u: UserAccount) => (
                <RowButtons>
                <Menu position="bottom-end" shadow="md" withinPortal>
                  <Menu.Target>
                    <ActionIcon variant="subtle" color="gray" size="sm" aria-label={`Actions for ${u.email}`}>
                      <Icons.More size={16} aria-hidden />
                    </ActionIcon>
                  </Menu.Target>
                  <Menu.Dropdown>
                    <Menu.Item leftSection={<Icons.Edit size={15} aria-hidden />} onClick={() => setEditing(u)}>
                      Roles…
                    </Menu.Item>
                    <Menu.Item leftSection={<Icons.NavEnrollment size={15} aria-hidden />} onClick={() => void run(u, "reset-password")}>
                      Set a temporary password
                    </Menu.Item>
                    <Menu.Item leftSection={<Icons.Restore size={15} aria-hidden />} onClick={() => void run(u, "reset-mfa")}>
                      Reset second factor
                    </Menu.Item>
                    {u.id !== myId && (
                      <>
                        <Menu.Divider />
                        <Menu.Item
                          leftSection={u.status === "active" ? <Icons.Pause size={15} aria-hidden /> : <Icons.Play size={15} aria-hidden />}
                          onClick={() => void run(u, u.status === "active" ? "disable" : "enable")}
                        >
                          {u.status === "active" ? "Disable" : "Enable"}
                        </Menu.Item>
                        <Menu.Item color="red" leftSection={<Icons.Trash size={15} aria-hidden />} onClick={() => void run(u, "delete")}>
                          Delete
                        </Menu.Item>
                      </>
                    )}
                  </Menu.Dropdown>
                </Menu>
                </RowButtons>
              ),
            },
          ]
        : []),
    ];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canWrite, myId, siteList, confirm, doAct]);

  const tokenColumns = useMemo<Column<ApiToken>[]>(
    () => [
      {
        id: "name",
        header: "Name",
        value: (t) => `${t.name} ${t.prefix}`,
        primary: true,
        required: true,
        width: 240,
        cell: (t) => (
          <>
            {t.name}
            <span className="lp-dt__cell-sub lp-mono">{t.prefix}…</span>
          </>
        ),
      },
      { id: "owner", header: "Owner", value: (t) => t.owner, width: 200 },
      { id: "scopes", header: "Scopes", value: (t) => t.scopes.join(", "), width: 260, wrap: true, cell: (t) => <span className="lp-mono">{t.scopes.join(", ")}</span> },
      {
        id: "expires",
        header: "Expires",
        value: (t) => (t.revoked_at ? 0 : t.expires_at ? new Date(t.expires_at).getTime() : 0),
        width: 170,
        cell: (t) => (t.revoked_at ? <Status value="revoked" size="sm" /> : dateTime(t.expires_at)),
        csv: (t) => (t.revoked_at ? "revoked" : (t.expires_at ?? "")),
      },
      { id: "used", header: "Last used", value: (t) => (t.last_used_at ? new Date(t.last_used_at).getTime() : 0), width: 170, cell: (t) => dateTime(t.last_used_at), csv: (t) => t.last_used_at ?? "" },
      ...(canWrite
        ? [
            {
              id: "actions",
              header: "Actions",
              required: true,
              csv: false as const,
              align: "right" as const,
              width: 110,
              cell: (t: ApiToken) => (
                <RowButtons>
                  {t.revoked_at ? null : (
                  <Button
                    size="compact-xs"
                    variant="light"
                    color="red"
                    leftSection={<Icons.Close size={12} aria-hidden />}
                    onClick={async () => {
                      const ok = await confirm({ title: `Revoke the token "${t.name}"?`, message: "Anything using it stops working at once. This cannot be undone.", confirmLabel: "Revoke token", danger: true });
                      if (ok) revokeToken.mutate(t.id);
                    }}
                  >
                    Revoke
                  </Button>
                  )}
                </RowButtons>
              ),
            },
          ]
        : []),
    ],
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [canWrite, confirm, revokeToken.mutate],
  );

  return (
    <Page>
      <PageHeader
        title="Users"
        description="Everyone signs in with a password and a second factor. A role can apply to the whole organization or to a single site; a site role lets someone manage the devices of that site from their pages and nothing else."
        actions={
          canWrite ? (
            <Button leftSection={<Icons.Plus size={16} aria-hidden />} onClick={() => setCreating(true)}>
              Add user
            </Button>
          ) : undefined
        }
      />
      <Tabs defaultValue="users" keepMounted={false}>
        <Tabs.List>
          <Tabs.Tab value="users">Users</Tabs.Tab>
          <Tabs.Tab value="tokens">API tokens</Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="users" pt="md">
          <DataTable<UserAccount>
            id="users"
            label="Users"
            data={users.data?.items}
            loading={users.isLoading}
            error={users.error}
            columns={userColumns}
            rowId={(u) => u.id}
            rowTestId="user-row"
            rowLabel={(u) => u.email}
            searchPlaceholder="Search people, e-mail addresses, roles…"
            exportName="users"
            initialSort={{ id: "user" }}
            empty={<EmptyState icon={<Icons.NavUsers size={26} />} title="No users" description="People you add appear here." />}
          />
        </Tabs.Panel>
        <Tabs.Panel value="tokens" pt="md">
          <Text size="sm" c="dimmed" mb="sm">
            Tokens created by anyone in the organization. A token can do no more than its owner and its scopes allow, and stops working when its owner is disabled.
          </Text>
          <DataTable<ApiToken>
            id="org-api-tokens"
            label="API tokens of the organization"
            data={tokens.data?.items}
            loading={tokens.isLoading}
            error={tokens.error}
            columns={tokenColumns}
            rowId={(t) => t.id}
            rowLabel={(t) => t.name}
            searchPlaceholder="Search tokens…"
            exportName="api-tokens"
            initialSort={{ id: "name" }}
            empty={<EmptyState icon={<Icons.NavEnrollment size={26} />} title="No API tokens" description="Tokens that people create under Account and security appear here." />}
          />
        </Tabs.Panel>
      </Tabs>
      {creating && <CreateUserModal sites={siteList ?? []} orgId={session?.org.id ?? ""} onClose={() => setCreating(false)} onCreated={(email, pw) => (refresh(), toast.success(`${email} was added.`), pw && setSecret({ email, password: pw }))} />}
      {editing && <RolesModal user={users.data?.items.find((u) => u.id === editing.id) ?? editing} sites={siteList ?? []} orgId={session?.org.id ?? ""} onClose={() => setEditing(null)} />}
      <Modal opened={!!secret} onClose={() => setSecret(null)} title="Temporary password">
        {secret && (
          <Stack>
            <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
              Shown only once. Give it to {secret.email} privately; they must choose their own password at the first sign-in.
            </Alert>
            <CopyText value={secret.password} label="Copy password" />
          </Stack>
        )}
      </Modal>
    </Page>
  );
}

function scopeOptions(sites: Site[], orgId: string) {
  return [{ value: `org:${orgId}`, label: "Whole organization" }, ...sites.map((s) => ({ value: `site:${s.id}`, label: `Site: ${s.name}` }))];
}

function CreateUserModal({ sites, orgId, onClose, onCreated }: { sites: Site[]; orgId: string; onClose: () => void; onCreated: (email: string, password?: string) => void }) {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState<string | null>("operator");
  const [scope, setScope] = useState<string | null>(`org:${orgId}`);
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () => {
      const [scope_type, scope_id] = (scope ?? "").split(":");
      return api<{ temporary_password?: string }>("POST", "/users", { email: email.trim(), display_name: name.trim(), roles: [{ role, scope_type, scope_id }] });
    },
    onSuccess: (r) => (onCreated(email.trim(), r.temporary_password), onClose()),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Modal opened onClose={onClose} title="Add user">
      <form onSubmit={(e) => (e.preventDefault(), setError(""), create.mutate())}>
        <Stack>
          <TextInput label="Email" type="email" value={email} onChange={(e) => setEmail(e.currentTarget.value)} required data-autofocus />
          <TextInput label="Name" value={name} onChange={(e) => setName(e.currentTarget.value)} required maxLength={200} />
          <Select label="Role" data={Object.entries(roleLabel).map(([value, label]) => ({ value, label }))} value={role} onChange={setRole} allowDeselect={false} />
          <Select label="Applies to" data={scopeOptions(sites, orgId)} value={scope} onChange={setScope} allowDeselect={false} />
          <Text size="xs" c="dimmed">
            A temporary password is generated. The user must change it at the first sign-in and then set up a second factor.
          </Text>
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create user
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}

function RolesModal({ user, sites, orgId, onClose }: { user: UserAccount; sites: Site[]; orgId: string; onClose: () => void }) {
  const qc = useQueryClient();
  const [role, setRole] = useState<string | null>("operator");
  const [scope, setScope] = useState<string | null>(`org:${orgId}`);
  const [error, setError] = useState("");
  const done = () => void qc.invalidateQueries({ queryKey: ["users"] });
  const add = useMutation({
    mutationFn: () => {
      const [scope_type, scope_id] = (scope ?? "").split(":");
      return api("POST", `/users/${user.id}/roles`, { role, scope_type, scope_id });
    },
    onSuccess: () => (setError(""), done(), toast.success("Role added.")),
    onError: (e) => setError(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (bid: string) => api("DELETE", `/users/${user.id}/roles/${bid}`),
    onSuccess: () => (setError(""), done(), toast.success("Role removed.")),
    onError: (e) => setError(errorMessage(e)),
  });
  const siteName = (id: string) => sites.find((s) => s.id === id)?.name ?? id.slice(0, 8);
  return (
    <Modal opened onClose={onClose} title={`Roles of ${user.display_name}`}>
      <Stack>
        {user.bindings.map((b) => (
          <Group key={b.id} justify="space-between" wrap="nowrap">
            <Text size="sm" style={{ minWidth: 0 }}>
              <RolePill role={b.role} /> <span className="lp-muted">— {b.scope_type === "org" ? "whole organization" : `site ${siteName(b.scope_id)}`}</span>
            </Text>
            <Button size="compact-xs" variant="default" color="red" leftSection={<Icons.Trash size={12} aria-hidden />} onClick={() => remove.mutate(b.id)} aria-label={`Remove ${b.role} ${b.scope_type}`}>
              Remove
            </Button>
          </Group>
        ))}
        <Group align="flex-end">
          <Select label="Add role" data={Object.entries(roleLabel).map(([value, label]) => ({ value, label }))} value={role} onChange={setRole} allowDeselect={false} w={170} />
          <Select label="Applies to" data={scopeOptions(sites, orgId)} value={scope} onChange={setScope} allowDeselect={false} style={{ flex: 1 }} />
          <Button onClick={() => add.mutate()} loading={add.isPending}>
            Add
          </Button>
        </Group>
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
      </Stack>
    </Modal>
  );
}
