import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Alert, Button, Checkbox, Group, NumberInput, PasswordInput, Stack, Text, TextInput } from "@mantine/core";
import { api, errorMessage, type MySecurity } from "../api/client";
import { dateTime } from "../api/format";
import { useSession } from "../api/session";
import { CopyText } from "../components/common";
import { createCredential, webauthnSupported } from "../api/webauthn";
import { Card, DataTable, Icons, Page, PageHeader, Skel, Status, StatusPill, toast, useConfirm, type Column } from "../ui";
import { KeyValue, RowButtons } from "../ui/admin-kit";

type SecurityKey = MySecurity["security_keys"][number];
type Token = MySecurity["api_tokens"][number];

export function AccountPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["my-security"], queryFn: () => api<MySecurity>("GET", "/me/security") });
  const refresh = () => void qc.invalidateQueries({ queryKey: ["my-security"] });
  return (
    <Page>
      <PageHeader title="Account security" description="Your profile, password, second factor and the tokens that act on your behalf." />
      {q.error && (
        <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
          {errorMessage(q.error)}
        </Alert>
      )}
      <div className="lp-cards">
        <div className="lp-stack-y">
          <ProfileCard />
          {q.data ? <AuthenticatorCard data={q.data} /> : q.isLoading ? <LoadingCard /> : null}
        </div>
        <PasswordCard />
      </div>
      {q.data ? <KeysCard data={q.data} onChange={refresh} /> : q.isLoading ? <LoadingCard /> : null}
      {q.data ? <TokensCard data={q.data} onChange={refresh} /> : q.isLoading ? <LoadingCard /> : null}
    </Page>
  );
}

function LoadingCard() {
  return (
    <Card>
      <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
        <Skel w="40%" h={16} />
        <Skel w="80%" h={14} />
        <Skel w="60%" h={14} />
      </div>
    </Card>
  );
}

function ProfileCard() {
  const { session } = useSession();
  return (
    <Card title="Profile" description="Who you are signed in as. An administrator changes names and roles under Users.">
      {session ? (
        <KeyValue
          label="Profile"
          items={[
            { label: "Name", value: session.user.display_name },
            { label: "Email", value: session.user.email },
            { label: "Organization", value: session.org.name },
          ]}
        />
      ) : null}
    </Card>
  );
}

function PasswordCard() {
  const [cur, setCur] = useState("");
  const [n1, setN1] = useState("");
  const [n2, setN2] = useState("");
  const [error, setError] = useState("");
  const change = useMutation({
    mutationFn: () => {
      if (n1 !== n2) throw new Error("The two new passwords are not the same.");
      return api("POST", "/auth/change-password", { current_password: cur, new_password: n1 });
    },
    onSuccess: () => (setCur(""), setN1(""), setN2(""), setError(""), toast.success("Password changed. Your other sessions were signed out.")),
    onError: (e) => setError(errorMessage(e)),
  });
  return (
    <Card title="Password" description="Changing it signs out your other sessions.">
      <form onSubmit={(e) => (e.preventDefault(), change.mutate())}>
        <Stack gap="sm">
          <PasswordInput label="Current password" value={cur} onChange={(e) => setCur(e.currentTarget.value)} autoComplete="current-password" required />
          <PasswordInput label="New password" value={n1} onChange={(e) => setN1(e.currentTarget.value)} autoComplete="new-password" required />
          <PasswordInput label="Repeat the new password" value={n2} onChange={(e) => setN2(e.currentTarget.value)} autoComplete="new-password" required />
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Button type="submit" loading={change.isPending} w="fit-content" leftSection={<Icons.Lock size={16} aria-hidden />}>
            Change password
          </Button>
        </Stack>
      </form>
    </Card>
  );
}

function AuthenticatorCard({ data }: { data: MySecurity }) {
  return (
    <Card title="Authenticator app" description="The six-digit codes from an app on your phone.">
      <Stack gap="sm">
        <div>
          {data.totp ? (
            <StatusPill kind="success">Set up</StatusPill>
          ) : (
            <StatusPill kind="warning" icon={Icons.Clock}>
              Not set up
            </StatusPill>
          )}
        </div>
        <Text size="sm">To replace it, ask an administrator to reset your second factor.</Text>
      </Stack>
    </Card>
  );
}

function KeysCard({ data, onChange }: { data: MySecurity; onChange: () => void }) {
  const confirm = useConfirm();
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const add = useMutation({
    mutationFn: async () => {
      const begin = await api<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>("POST", "/me/security-keys/begin", {});
      const cred = await createCredential(begin.options);
      return api("POST", `/me/security-keys/finish?ceremony=${begin.ceremony}&name=${encodeURIComponent(name.trim())}`, cred);
    },
    onSuccess: () => (setName(""), setError(""), toast.success("Security key added."), onChange()),
    onError: (e) => setError(errorMessage(e)),
  });
  const remove = useMutation({
    mutationFn: (id: string) => api("DELETE", `/me/security-keys/${id}`),
    onSuccess: () => (toast.success("Security key removed."), onChange()),
    onError: (e) => setError(errorMessage(e)),
  });
  const removeKey = remove.mutate;
  const columns = useMemo<Column<SecurityKey>[]>(
    () => [
      { id: "name", header: "Name", value: (k) => k.name, primary: true, required: true, width: 240, cell: (k) => <span style={{ display: "inline-flex", alignItems: "center", gap: 8 }}><Icons.NavEnrollment size={16} aria-hidden />{k.name}</span> },
      { id: "added", header: "Added", value: (k) => new Date(k.created_at).getTime(), width: 190, cell: (k) => `added ${dateTime(k.created_at)}`, csv: (k) => k.created_at },
      { id: "used", header: "Last used", value: (k) => (k.last_used_at ? new Date(k.last_used_at).getTime() : 0), width: 210, cell: (k) => `last used ${dateTime(k.last_used_at)}`, csv: (k) => k.last_used_at ?? "" },
      {
        id: "actions",
        header: "Actions",
        required: true,
        csv: false,
        align: "right",
        width: 120,
        cell: (k) => (
          <RowButtons>
          <Button
            size="compact-xs"
            variant="light"
            color="red"
            leftSection={<Icons.Trash size={12} aria-hidden />}
            aria-label={`Remove key ${k.name}`}
            onClick={async () => {
              const ok = await confirm({ title: `Remove the key "${k.name}"?`, message: "You can no longer sign in with it. If it is your only second factor, ask an administrator to reset it.", confirmLabel: "Remove key", danger: true });
              if (ok) removeKey(k.id);
            }}
          >
            Remove
          </Button>
          </RowButtons>
        ),
      },
    ],
    [confirm, removeKey],
  );
  return (
    <Card title="Security keys" description="Hardware keys and platform authenticators (Windows Hello, Touch ID) that can replace the authenticator code at sign-in.">
      <Stack gap="md">
        {data.security_keys.length === 0 ? (
          <Text size="sm" c="dimmed">
            No security keys.
          </Text>
        ) : (
          <DataTable<SecurityKey> id="my-security-keys" label="Security keys" data={data.security_keys} columns={columns} rowId={(k) => k.id} rowLabel={(k) => k.name} pageSize={10} />
        )}
        {data.webauthn_available && webauthnSupported() ? (
          <Group align="flex-end">
            <TextInput label="Name for a new key" placeholder="e.g. YubiKey 5" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={100} />
            <Button onClick={() => add.mutate()} loading={add.isPending} disabled={!name.trim()} leftSection={<Icons.Plus size={16} aria-hidden />}>
              Add security key
            </Button>
          </Group>
        ) : (
          <Alert color="blue" icon={<Icons.Info size={18} aria-hidden />}>
            Security keys need the console to be opened at its https address (or localhost) in a browser that supports them.
          </Alert>
        )}
        {error && (
          <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
            {error}
          </Alert>
        )}
      </Stack>
    </Card>
  );
}

function TokensCard({ data, onChange }: { data: MySecurity; onChange: () => void }) {
  const confirm = useConfirm();
  const [name, setName] = useState("");
  const [days, setDays] = useState<number | string>(90);
  const [scopes, setScopes] = useState<string[]>([]);
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");
  const create = useMutation({
    mutationFn: () => api<{ token: string }>("POST", "/me/api-tokens", { name: name.trim(), scopes, expires_in_days: Number(days) }),
    onSuccess: (r) => (setSecret(r.token), setName(""), setScopes([]), setError(""), onChange()),
    onError: (e) => setError(errorMessage(e)),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api("DELETE", `/me/api-tokens/${id}`),
    onSuccess: () => (toast.success("Token revoked."), onChange()),
    onError: (e) => setError(errorMessage(e)),
  });
  const revokeToken = revoke.mutate;
  const columns = useMemo<Column<Token>[]>(
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
      {
        id: "actions",
        header: "Actions",
        required: true,
        csv: false,
        align: "right",
        width: 120,
        cell: (t) => (
          <RowButtons>
            {t.revoked_at ? null : (
            <Button
              size="compact-xs"
              variant="light"
              color="red"
              leftSection={<Icons.Close size={12} aria-hidden />}
              aria-label={`Revoke token ${t.name}`}
              onClick={async () => {
                const ok = await confirm({ title: `Revoke the token "${t.name}"?`, message: "Anything using it stops working at once. This cannot be undone.", confirmLabel: "Revoke token", danger: true });
                if (ok) revokeToken(t.id);
              }}
            >
              Revoke
            </Button>
            )}
          </RowButtons>
        ),
      },
    ],
    [confirm, revokeToken],
  );
  return (
    <Card title="API tokens" description={<>For scripts and integrations: send <code>Authorization: Bearer lp_…</code> to <code>/api/v1/…</code>. A token can only do what you can do and what its scopes list, expires, and stops working if your account is disabled.</>}>
      <Stack gap="md">
        {secret && (
          <Alert color="yellow" title="Copy the token now" icon={<Icons.Warning size={18} aria-hidden />} withCloseButton onClose={() => setSecret("")} closeButtonLabel="Hide the token">
            <Stack gap="xs">
              <span>It is shown only once.</span>
              <CopyText value={secret} label="Copy token" />
            </Stack>
          </Alert>
        )}
        {data.api_tokens.length > 0 && <DataTable<Token> id="my-api-tokens" label="Your API tokens" data={data.api_tokens} columns={columns} rowId={(t) => t.id} rowLabel={(t) => t.name} pageSize={10} initialSort={{ id: "name" }} />}
        <Stack gap="sm" maw={640}>
          <Group align="flex-end">
            <TextInput label="Token name" value={name} onChange={(e) => setName(e.currentTarget.value)} maxLength={100} style={{ flex: 1, minWidth: 200 }} />
            <NumberInput label="Valid for (days)" min={1} max={365} value={days} onChange={setDays} w={140} />
          </Group>
          <Checkbox.Group label="Scopes" value={scopes} onChange={setScopes}>
            <Group gap="md" mt={6}>
              {data.token_scopes.map((s) => (
                <Checkbox key={s} value={s} label={s} />
              ))}
            </Group>
          </Checkbox.Group>
          {error && (
            <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
              {error}
            </Alert>
          )}
          <Button onClick={() => create.mutate()} loading={create.isPending} disabled={!name.trim() || scopes.length === 0} w="fit-content" leftSection={<Icons.Plus size={16} aria-hidden />}>
            Create token
          </Button>
        </Stack>
      </Stack>
    </Card>
  );
}
