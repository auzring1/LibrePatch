import { useQuery } from "@tanstack/react-query";
import { api, type Dashboard, type VulnerabilityOverview } from "../../api/client";
import { ActivityWidget, AgentsWidget, AppsWidget, AttentionWidget, ComplianceWidget, ShortcutWidget, StartWidget, StatWidget, TextWidget, TopMissingWidget, VulnerabilitiesWidget } from "./widgets";
import { DESTINATIONS, type WidgetCtx } from "./registry";
import type { BoardWidget } from "./boards";

/** The kinds that read the dashboard numbers (and so honour a site setting). */
const NEEDS_DATA = new Set(["stat", "compliance", "apps", "top-missing", "attention", "activity", "agents", "start"]);

/** One placed widget: gets its own data (the site from its settings, else the site switcher's) and draws itself. */
export function WidgetView({ w, ctx, siteId, refresh, onDismissStart }: { w: BoardWidget; ctx: WidgetCtx; siteId: string; refresh: number; onDismissStart: () => void }) {
  const s = w.settings ?? {};
  const site = s.site || siteId;
  const refetchInterval = refresh > 0 ? refresh * 1000 : false;
  const q = useQuery({
    queryKey: ["dashboard", site],
    queryFn: () => api<Dashboard>("GET", `/dashboard${site ? `?site=${site}` : ""}`),
    enabled: NEEDS_DATA.has(w.type),
    refetchInterval,
    // The page's own copy (the site switcher's) is already loaded; a widget with another site loads its own.
    initialData: site === siteId ? ctx.d : undefined,
  });
  const vuln = useQuery({
    queryKey: ["vulnerabilities", "dashboard"],
    queryFn: () => api<VulnerabilityOverview>("GET", "/vulnerabilities?limit=20"),
    enabled: w.type === "vulnerabilities",
    refetchInterval,
  });
  const d = q.data ?? ctx.d;
  const common = { title: s.title, count: s.count };
  switch (w.type) {
    case "stat":
      return <StatWidget d={d} metric={s.metric} title={s.title} />;
    case "compliance":
      return <ComplianceWidget d={d} title={s.title} range={s.range} />;
    case "apps":
      return <AppsWidget d={d} {...common} />;
    case "top-missing":
      return <TopMissingWidget d={d} {...common} />;
    case "attention":
      return <AttentionWidget d={d} {...common} />;
    case "activity":
      return <ActivityWidget d={d} {...common} />;
    case "agents":
      return <AgentsWidget d={d} {...common} />;
    case "start":
      return <StartWidget d={d} canOrg={ctx.canOrg} onDismiss={onDismissStart} />;
    case "vulnerabilities":
      return <VulnerabilitiesWidget data={vuln.data} {...common} />;
    case "shortcut": {
      const dest = DESTINATIONS.find((x) => x.id === s.dest);
      return <ShortcutWidget label={dest?.label} hint={dest?.hint} to={dest?.show(ctx) ? dest.to : undefined} title={s.title} />;
    }
    case "text":
      return <TextWidget text={s.text} title={s.title} />;
    default:
      return null;
  }
}
