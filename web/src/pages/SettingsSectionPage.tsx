import { useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Alert, Code } from "@mantine/core";
import { api } from "../api/client";
import { useSession } from "../api/session";
import { DataStatusCard, EventReference, NotificationExtras, ReportRuns, ReportSendNow, ThemePolicyCard, WebhookTest } from "../settings/extras";
import { SectionForm } from "../settings/SectionForm";
import { useSettingsSchema } from "../settings/SettingsShell";
import { Card, Icons, Skel } from "../ui";

/** One schema-driven Settings section (everything except General and Branding, which have their own pages). */
export function SettingsSectionPage() {
  const { section = "" } = useParams();
  const [params] = useSearchParams();
  const { canOrg } = useSession();
  const schema = useSettingsSchema();
  if (schema.isLoading) {
    return (
      <Card>
        <Skel h={36} />
      </Card>
    );
  }
  const sec = schema.data?.sections.find((s) => s.id === section);
  if (!sec) {
    return (
      <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
        {canOrg("settings:write") || schema.data?.sections.length ? "That settings section does not exist, or you may not open it." : "You may not change settings."}
      </Alert>
    );
  }
  const focus = params.get("field");
  return (
    <>
      {sec.id === "appearance" && <ThemePolicyCard />}
      {sec.id === "sso" && <SsoRegistrationCard />}
      <SectionForm
        key={sec.id}
        section={sec}
        focus={focus}
        itemActions={sec.id === "integrations" ? (f, item) => <WebhookTest field={f} item={item} /> : sec.id === "reports" ? (f, item) => <ReportSendNow field={f} item={item} /> : undefined}
        after={
          <>
            {sec.id === "notifications" && <NotificationExtras />}
            {sec.id === "integrations" && <EventReference />}
            {sec.id === "reports" && <ReportRuns />}
            {sec.id === "data" && <DataStatusCard />}
          </>
        }
      />
    </>
  );
}

/** The address to register at the identity provider, and what to put there. */
function SsoRegistrationCard() {
  const q = useQuery({ queryKey: ["sso-info"], queryFn: () => api<{ redirect_uri: string; enabled: boolean }>("GET", "/auth/sso/info"), staleTime: 60_000 });
  return (
    <Card title="Register this server at your provider" description="Do this first, then fill in the form below.">
      <ol style={{ margin: 0, paddingLeft: "var(--lp-space-4)", display: "grid", gap: 4 }}>
        <li>
          In Microsoft Entra ID: <b>App registrations → New registration</b>. Choose “Accounts in this organizational directory only”.
        </li>
        <li>
          Add a <b>Web</b> redirect address, exactly: <Code>{q.data?.redirect_uri ?? "…"}</Code>
        </li>
        <li>
          Under <b>Certificates &amp; secrets</b> create a client secret; copy its <b>value</b> into the form.
        </li>
        <li>
          Copy the <b>Application (client) ID</b> and the <b>Directory (tenant) ID</b> (the issuer is <Code>https://login.microsoftonline.com/&lt;tenant ID&gt;/v2.0</Code>).
        </li>
        <li>
          To give roles: under <b>App roles</b> create roles such as <Code>LP.Admin</Code>, assign people or groups to them in <b>Enterprise applications → Users and groups</b>, and list them below.
        </li>
        <li>Keep a local administrator account with its own password. It always works, even if the provider is down.</li>
      </ol>
    </Card>
  );
}
