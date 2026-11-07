import { useQuery } from "@tanstack/react-query";
import { Alert, Button } from "@mantine/core";
import { api, errorMessage } from "../api/client";
import { dateTime, duration } from "../api/format";
import { useSession } from "../api/session";
import { Card, Icons, Skel } from "../ui";
import { KeyValue } from "../ui/admin-kit";

interface About {
  product: string;
  company: string;
  version: string;
  commit: string;
  go: string;
  os: string;
  arch: string;
  started_at: string;
  uptime_seconds: number;
  postgres?: string;
  database_migration?: number;
  database_ok: boolean;
  modules?: number;
  build_vcs_time?: string;
  build_vcs_modified?: string;
  counts?: Record<string, number>;
}

/** Settings > About: what is running, and a support bundle with the secrets left out. */
export function AboutPage() {
  const { canOrg } = useSession();
  const q = useQuery({ queryKey: ["settings", "about"], queryFn: () => api<About>("GET", "/settings/about"), enabled: canOrg("settings:write") });
  if (!canOrg("settings:write")) {
    return (
      <Alert color="yellow" icon={<Icons.Warning size={18} aria-hidden />}>
        Only administrators can see this page.
      </Alert>
    );
  }
  if (q.isLoading) {
    return (
      <Card>
        <Skel h={36} />
      </Card>
    );
  }
  if (q.error || !q.data) {
    return (
      <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
        {errorMessage(q.error)}
      </Alert>
    );
  }
  const a = q.data;
  return (
    <div style={{ display: "grid", gap: "var(--lp-space-4)" }}>
      <Card title={`About ${a.product}`} description={`${a.product} is made by ${a.company}.`}>
        <KeyValue
          label="Version and build"
          items={[
            { label: "Version", value: a.version, testId: "about-version" },
            { label: "Build", value: a.commit === "unknown" ? "development build" : a.commit },
            ...(a.build_vcs_time ? [{ label: "Built from source of", value: `${dateTime(a.build_vcs_time)}${a.build_vcs_modified === "true" ? " (with local changes)" : ""}` }] : []),
            { label: "Platform", value: `${a.os}/${a.arch}, ${a.go}` },
            { label: "Running since", value: `${dateTime(a.started_at)} (${duration(a.uptime_seconds)})` },
            { label: "Database", value: `PostgreSQL ${a.postgres ?? "?"}, schema version ${a.database_migration ?? "?"}, ${a.database_ok ? "reachable" : "not reachable"}` },
          ]}
        />
      </Card>
      <Card title="Support bundle" description="A zip file for whoever supports this installation: version and build, counts, the server's configuration, the settings and the latest audit and notification entries. Secrets are left out: passwords, keys, tokens and certificates are never included, and neither is device inventory.">
        <Button component="a" href="/api/v1/settings/support-bundle" download leftSection={<Icons.Download size={16} aria-hidden />}>
          Download support bundle
        </Button>
      </Card>
    </div>
  );
}
