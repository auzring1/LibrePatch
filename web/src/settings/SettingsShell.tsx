import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { Alert, Button, FileButton, Modal, Stack, Text } from "@mantine/core";
import { api, ApiError, errorMessage } from "../api/client";
import { useSession } from "../api/session";
import { Icons, Page, PageHeader, toast } from "../ui";
import { allowed, SETTINGS_SECTIONS, type NavItem } from "../ui/nav";
import { searchSettings } from "./search";
import type { SettingsSchema } from "./types";
import { UnsavedProvider } from "./useUnsaved";
import "./settings.css";

export function useSettingsSchema() {
  const { session } = useSession();
  return useQuery({ queryKey: ["settings", "schema"], queryFn: () => api<SettingsSchema>("GET", "/settings/schema"), enabled: !!session, staleTime: 5 * 60_000 });
}

/** The Settings area: a section list and a search box on the left, the section on the right. */
export function SettingsShell() {
  return (
    <UnsavedProvider>
      <Shell />
    </UnsavedProvider>
  );
}

function Shell() {
  const { can, canOrg } = useSession();
  const schema = useSettingsSchema();
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const entries: NavItem[] = useMemo(() => SETTINGS_SECTIONS.filter((s) => allowed(s, { can, canOrg })), [can, canOrg]);
  const hits = useMemo(() => (q.trim() ? searchSettings(schema.data?.sections ?? [], entries, q) : []), [q, schema.data, entries]);
  return (
    <Page>
      <PageHeader title="Settings" description="How this deployment behaves and how it looks. Every change is checked on the server and recorded in the audit log." />
      <div className="lp-set-layout">
        <aside className="lp-set-aside" aria-label="Settings navigation">
          <div role="search" className="lp-set-search">
            <label htmlFor="settings-search" className="lp-visually-hidden">
              Search settings
            </label>
            <Icons.Search size={16} aria-hidden />
            <input
              id="settings-search"
              type="search"
              placeholder="Search settings"
              value={q}
              onChange={(e) => setQ(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") setQ("");
                if (e.key === "Enter" && hits[0]) {
                  nav(hits[0].to);
                  setQ("");
                }
              }}
              autoComplete="off"
              data-testid="settings-search"
            />
          </div>
          {q.trim() ? (
            <div aria-live="polite">
              {hits.length === 0 ? (
                <p className="lp-set-none">No setting matches “{q.trim()}”.</p>
              ) : (
                <ul className="lp-set-hits" aria-label="Search results">
                  {hits.map((h) => (
                    <li key={h.to}>
                      <NavLink to={h.to} onClick={() => setQ("")}>
                        <span>{h.label}</span>
                        <small>{h.section}</small>
                      </NavLink>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <nav aria-label="Settings sections">
              <ul className="lp-set-nav">
                {entries.map((s) => (
                  <li key={s.id}>
                    <NavLink to={s.to} end={s.end} className="lp-set-nav__link">
                      <s.icon size={16} aria-hidden />
                      <span>{s.label}</span>
                    </NavLink>
                  </li>
                ))}
              </ul>
            </nav>
          )}
          {canOrg("settings:write") && <ExportImport />}
        </aside>
        <div className="lp-set-main">
          <Outlet />
        </div>
      </div>
    </Page>
  );
}


interface Report {
  section: string;
  changed: boolean;
  changes?: Record<string, { before: unknown; after: unknown }>;
  errors?: Record<string, string>;
  skipped?: string;
}
interface ImportResult {
  dry_run: boolean;
  applied: boolean;
  sections: Report[];
}

function ExportImport() {
  const qc = useQueryClient();
  const [file, setFile] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [result, setResult] = useState<ImportResult | null>(null);
  const [error, setError] = useState("");
  const run = useMutation({
    mutationFn: (dry: boolean) => api<ImportResult>("POST", `/settings/import${dry ? "?dry_run=1" : ""}`, file),
    onSuccess: (r, dry) => {
      setResult(r);
      setError("");
      if (!dry) {
        toast.success("Settings imported.");
        void qc.invalidateQueries({ queryKey: ["settings"] });
        setFile(null);
        setResult(null);
      }
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 422) {
        setError(e.message);
        return;
      }
      setError(errorMessage(e));
    },
  });
  const read = async (f: File | null) => {
    setError("");
    setResult(null);
    if (!f) return;
    try {
      const text = await f.text();
      if (text.length > 2_000_000) throw new Error("That file is too large to be a settings file.");
      setFile(JSON.parse(text));
      setName(f.name);
    } catch (e) {
      setFile(null);
      setError(e instanceof Error ? e.message : "That is not a JSON file.");
    }
  };
  const open = file !== null;
  return (
    <div className="lp-set-io">
      <Text size="xs" c="dimmed" mb={6}>
        Move settings between installations. Secrets such as the mail password and webhook secrets are never included.
      </Text>
      <Button component="a" href="/api/v1/settings/export" download size="compact-sm" variant="default" leftSection={<Icons.Export size={14} aria-hidden />} fullWidth>
        Export settings
      </Button>
      <FileButton accept="application/json,.json" onChange={(f) => void read(f)}>
        {(props) => (
          <Button {...props} size="compact-sm" variant="default" leftSection={<Icons.Download size={14} aria-hidden />} fullWidth mt={6} data-testid="import-settings">
            Import settings…
          </Button>
        )}
      </FileButton>
      {error && !open && (
        <Alert color="red" mt="xs" role="alert">
          {error}
        </Alert>
      )}
      <Modal
        opened={open}
        onClose={() => {
          setFile(null);
          setResult(null);
          setError("");
        }}
        title={`Import ${name}`}
        size="lg"
      >
        <Stack>
          <Text size="sm">Check what the file would change first. Nothing is saved until you apply it, and a file with any invalid value changes nothing.</Text>
          {error && (
            <Alert color="red" role="alert">
              {error}
            </Alert>
          )}
          {result && (
            <ul className="lp-set-report" aria-label="What the file would change">
              {result.sections.map((s) => (
                <li key={s.section}>
                  <strong>{s.section}</strong>:{" "}
                  {s.skipped ? (
                    <span>skipped ({s.skipped})</span>
                  ) : s.errors && Object.keys(s.errors).length ? (
                    <span className="lp-set-bad">
                      not valid
                      <ul>
                        {Object.entries(s.errors).map(([k, v]) => (
                          <li key={k}>
                            {k}: {v}
                          </li>
                        ))}
                      </ul>
                    </span>
                  ) : s.changed ? (
                    <span>
                      changes {Object.keys(s.changes ?? {}).join(", ")}
                    </span>
                  ) : (
                    <span>no changes</span>
                  )}
                </li>
              ))}
            </ul>
          )}
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <Button variant="default" onClick={() => run.mutate(true)} loading={run.isPending}>
              Check the file
            </Button>
            <Button onClick={() => run.mutate(false)} disabled={!result || result.sections.some((s) => s.errors && Object.keys(s.errors).length > 0)} loading={run.isPending}>
              Apply
            </Button>
          </div>
        </Stack>
      </Modal>
    </div>
  );
}
