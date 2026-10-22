import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSiteScope } from "../ui/SiteScope";
import { Alert, Button } from "@mantine/core";
import { api, errorMessage, type Dashboard } from "../api/client";
import { usePreferences } from "../design/usePreferences";
import { Card, EmptyState, Icons, Page, PageHeader, Skel, TileSkeleton } from "../ui";
import { Customizer } from "../components/dashboard/Customizer";
import { ActivityWidget, AgentsWidget, AppsWidget, AttentionWidget, availableWidgets, ComplianceWidget, TilesWidget, TopMissingWidget } from "../components/dashboard/widgets";
import { moveWidget, resolveLayout, setWidgetHidden, WIDGET_IDS, type WidgetId } from "../components/dashboard/layout";
import "../components/dashboard/dashboard.css";

function CardSkeleton() {
  return (
    <Card>
      <div role="status" aria-label="Loading" style={{ display: "grid", gap: "var(--lp-space-3)" }}>
        <Skel w="40%" h={16} />
        <Skel h={90} />
        <Skel w="70%" h={12} />
        <span className="lp-visually-hidden">Loading</span>
      </div>
    </Card>
  );
}

function render(id: WidgetId, d: Dashboard) {
  switch (id) {
    case "tiles":
      return <TilesWidget d={d} />;
    case "apps":
      return <AppsWidget d={d} />;
    case "compliance":
      return <ComplianceWidget d={d} />;
    case "top-missing":
      return <TopMissingWidget d={d} />;
    case "attention":
      return <AttentionWidget d={d} />;
    case "activity":
      return <ActivityWidget d={d} />;
    case "agents":
      return <AgentsWidget d={d} />;
  }
}

export function DashboardPage() {
  const { siteId } = useSiteScope();
  const q = useQuery({ queryKey: ["dashboard", siteId], queryFn: () => api<Dashboard>("GET", `/dashboard${siteId ? `?site=${siteId}` : ""}`), refetchInterval: 60_000 });
  const { prefs, ready, update } = usePreferences();
  const [custom, setCustom] = useState(false);

  const d = q.data;
  const layout = resolveLayout(WIDGET_IDS, prefs?.dashboard);
  const available = d ? availableWidgets(d) : [];
  // The widgets this person can see, in their chosen order (what the customizer lists).
  const mine = layout.order.filter((id): id is WidgetId => available.includes(id as WidgetId));
  const shown = mine.filter((id) => layout.visible.includes(id));

  const save = (order: string[], hidden: string[]) => update({ dashboard: { order, hidden } });

  return (
    <Page>
      <PageHeader
        title="Dashboard"
        description="Fleet health and patch status at a glance."
        actions={
          <Button variant="default" leftSection={<Icons.Customize size={16} aria-hidden="true" />} onClick={() => setCustom(true)} disabled={!d || mine.length === 0}>
            Customize
          </Button>
        }
      />
      {q.isError && (
        <Alert color="red" title="The dashboard could not be loaded" role="alert">
          {errorMessage(q.error)}
        </Alert>
      )}
      {q.isLoading && (
        <>
          <TileSkeleton count={6} />
          <div className="lp-dash">
            <CardSkeleton />
            <CardSkeleton />
          </div>
        </>
      )}
      {d && mine.length === 0 && <EmptyState icon={<Icons.Dashboard size={26} />} title="Nothing to show yet" description="Your role does not include any dashboard widgets. Ask an administrator for access to devices, updates or deployments." />}
      {d && mine.length > 0 && shown.length === 0 && (
        <EmptyState
          icon={<Icons.EyeOff size={26} />}
          title="All widgets are hidden"
          description="Turn some back on to see your dashboard."
          actions={
            <Button variant="default" onClick={() => setCustom(true)}>
              Customize
            </Button>
          }
        />
      )}
      {d && shown.length > 0 && (
        <div className="lp-dash">
          {shown.map((id) => (
            <div key={id} className={id === "tiles" ? "lp-dash__full" : undefined}>
              {render(id, d)}
            </div>
          ))}
        </div>
      )}
      <Customizer
        opened={custom}
        onClose={() => setCustom(false)}
        items={mine}
        hidden={layout.hidden}
        disabled={!ready}
        onToggle={(id, visible) => save(layout.order, setWidgetHidden(layout.order, layout.hidden, id, !visible))}
        onMove={(id, dir) => save(moveWidget(layout.order, id, dir, mine), layout.hidden)}
        onReset={() => save([], [])}
      />
    </Page>
  );
}
