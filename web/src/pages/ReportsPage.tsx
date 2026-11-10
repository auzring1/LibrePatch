import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { Alert, Button, Tabs } from "@mantine/core";
import { api, errorMessage, type BuiltinReport, type ReportCatalog } from "../api/client";
import { useSession } from "../api/session";
import { useBranding } from "../branding/BrandingProvider";
import { ReportsOverview } from "../components/ReportsOverview";
import { Icons, Page, PageHeader, TileSkeleton } from "../ui";
import "./reports.css";

const CATEGORIES: { id: BuiltinReport["category"]; title: string; blurb: string }[] = [
  { id: "software", title: "Software", blurb: "What is installed, and where old versions are left." },
  { id: "hardware", title: "Hardware", blurb: "Machines, memory, disks and BitLocker." },
  { id: "patching", title: "Patching", blurb: "Windows update state per device." },
  { id: "devices", title: "Devices", blurb: "Who is online, who is gone, who needs a restart." },
];

function ReportCard({ to, name, description }: { to: string; name: string; description: string }) {
  return (
    <Link to={to} className="lp-rpt-card">
      <span className="lp-rpt-card__name">{name}</span>
      <p className="lp-rpt-card__desc">{description}</p>
    </Link>
  );
}

/**
 * Reports (Administration). The Library tab is where a report starts: pick a ready-made one or one of your own, look at it,
 * then export it as CSV or PDF. The Overview tab is the fleet-at-a-glance page this section used to be.
 */
export function ReportsPage() {
  const { can } = useSession();
  const brand = useBranding();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "overview" || params.has("state") ? "overview" : "library";
  const catalog = useQuery({ queryKey: ["reports", "catalog"], queryFn: () => api<ReportCatalog>("GET", "/reports/catalog") });
  const c = catalog.data;
  const select = (next: string | null) =>
    setParams(
      (p) => {
        const n = new URLSearchParams();
        if (next === "overview") n.set("tab", "overview");
        else if (p.get("tab") && p.get("tab") !== "library") n.set("tab", p.get("tab")!);
        return n;
      },
      { replace: true },
    );

  return (
    <Page>
      <PageHeader
        title={brand.org_name ? `${brand.org_name} · Reports` : "Reports"}
        description="Choose a report, look at it here, then export it as CSV or PDF. Build your own when the ready-made ones are not quite right."
        actions={
          can("reports:write") ? (
            <Button component={Link} to="/reports/new" leftSection={<Icons.Plus size={16} aria-hidden />}>
              New custom report
            </Button>
          ) : undefined
        }
      />
      <Tabs value={tab} onChange={select} keepMounted={false}>
        <Tabs.List aria-label="Reports">
          <Tabs.Tab value="library" leftSection={<Icons.NavReports size={16} aria-hidden />}>
            Reports
          </Tabs.Tab>
          <Tabs.Tab value="overview" leftSection={<Icons.NavDevices size={16} aria-hidden />}>
            Fleet overview
          </Tabs.Tab>
        </Tabs.List>
        <Tabs.Panel value="library">
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--lp-space-6)", paddingTop: "var(--lp-space-4)" }}>
            {catalog.error && (
              <Alert color="red" icon={<Icons.Danger size={18} aria-hidden />}>
                {errorMessage(catalog.error)}
              </Alert>
            )}
            {catalog.isLoading && <TileSkeleton count={6} />}
            {c && (
              <>
                {CATEGORIES.map((cat) => {
                  const items = c.builtins.filter((b) => b.category === cat.id);
                  if (items.length === 0) return null;
                  return (
                    <section className="lp-rpt-section" key={cat.id} aria-label={`${cat.title} reports`}>
                      <div className="lp-rpt-section__head">
                        <h2 className="lp-rpt-section__title">{cat.title}</h2>
                        <span className="lp-rpt-meta">{cat.blurb}</span>
                      </div>
                      <div className="lp-rpt-grid">
                        {items.map((b) => (
                          <ReportCard key={b.id} to={`/reports/${b.id}`} name={b.name} description={b.description} />
                        ))}
                      </div>
                    </section>
                  );
                })}
                <section className="lp-rpt-section" aria-label="Custom reports">
                  <div className="lp-rpt-section__head">
                    <h2 className="lp-rpt-section__title">Custom</h2>
                    <span className="lp-rpt-meta">Reports your team built and saved.</span>
                  </div>
                  {c.saved.length === 0 ? (
                    <p className="lp-hint">
                      No custom reports yet. {can("reports:write") ? <Link to="/reports/new">Build one</Link> : "An administrator or operator can build one."} Pick the columns, filter the rows, limit it to a site or group, and save it here.
                    </p>
                  ) : (
                    <div className="lp-rpt-grid">
                      {c.saved.map((s) => (
                        <ReportCard key={s.id} to={`/reports/${s.id}`} name={s.name} description={s.description || `Custom report on ${c.datasets.find((d) => d.id === s.spec.dataset)?.label.toLowerCase() ?? s.spec.dataset}`} />
                      ))}
                    </div>
                  )}
                </section>
                {can("settings:reports") && (
                  <p className="lp-hint">
                    Want one by email on a schedule? <Link to="/settings/reports">Scheduled reports</Link> sends the patch, update and device reports as PDF or CSV.
                  </p>
                )}
              </>
            )}
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="overview">
          <div style={{ display: "flex", flexDirection: "column", gap: "var(--lp-space-4)", paddingTop: "var(--lp-space-4)" }}>
            <ReportsOverview />
          </div>
        </Tabs.Panel>
      </Tabs>
    </Page>
  );
}
