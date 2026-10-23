import { useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { Tabs } from "@mantine/core";
import { useSession } from "../api/session";
import { AUTOMATION_TABS, availableAutomationTabs, resolveAutomationTab, type AutomationTab } from "../components/automations";
import { HoldsCard } from "../components/Holds";
import { useFeatures } from "../settings/features";
import { Icons, Page, PageHeader } from "../ui";
import { SoftwarePoliciesPanel } from "./PoliciesPage";
import { ConflictsCard, RingsCard, RulesCard, SourceCard } from "./UpdatePolicyPage";

const stack = { display: "flex", flexDirection: "column", gap: "var(--lp-space-4)", paddingTop: "var(--lp-space-4)" } as const;

/**
 * Automations: what keeps software and Windows up to date on its own. The Software tab holds the policies (one package
 * each), what waits for approval and the rings; the Windows tab holds the update source, the auto-approval rules, held
 * updates and policy conflicts. Rings are one list shared by both, so each tab shows it with its own wording. The Windows
 * tab is not there when an administrator switched Windows updates off (Settings > Update defaults).
 */
export function AutomationsPage() {
  const { loading, can, canOrg } = useSession();
  const { windowsUpdates } = useFeatures();
  const [params, setParams] = useSearchParams();
  const access = { software: canOrg("policies:read"), windows: windowsUpdates && canOrg("updates:read") };
  const rawTab = params.get("tab");
  const tab = resolveAutomationTab(rawTab, access);
  const tabs = availableAutomationTabs(access);
  const canEdit = can("updates:policy");

  const select = (next: AutomationTab) =>
    setParams(
      (p) => {
        const n = new URLSearchParams(p);
        if (next === "software") n.delete("tab");
        else n.set("tab", next);
        return n;
      },
      { replace: true },
    );
  // An old, unknown or unavailable ?tab= value is rewritten to the tab that shows (replace, so Back still works).
  useEffect(() => {
    if (!loading && rawTab !== null && rawTab !== tab) select(tab);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, rawTab, tab]);

  return (
    <Page>
      <PageHeader
        title="Automations"
        description={
          <>
            Keep software and Windows up to date without doing it by hand. Policies decide <i>what</i> is installed, rings decide <i>who</i> gets it first, and a ring that fails its success threshold stops the rollout.
            {!canEdit && " You can look at this page; only administrators can change rings and Windows rules."}
          </>
        }
      />
      <Tabs value={tab} onChange={(v) => v && select(resolveAutomationTab(v, access))} keepMounted={false}>
        {tabs.length > 1 && (
          <Tabs.List aria-label="Automations">
            {AUTOMATION_TABS.filter((t) => tabs.includes(t)).map((t) => (
              <Tabs.Tab key={t} value={t} leftSection={t === "software" ? <Icons.NavSoftware size={16} aria-hidden /> : <Icons.NavUpdates size={16} aria-hidden />}>
                {t === "software" ? "Software" : "Windows"}
              </Tabs.Tab>
            ))}
          </Tabs.List>
        )}
        <Tabs.Panel value="software">
          <div style={stack}>
            <SoftwarePoliciesPanel />
            <RingsCard canEdit={canEdit} context="software" />
          </div>
        </Tabs.Panel>
        <Tabs.Panel value="windows">
          <div style={stack}>
            <SourceCard canEdit={canEdit} />
            <RingsCard canEdit={canEdit} context="windows" />
            <RulesCard canEdit={canEdit} />
            <HoldsCard canEdit={canEdit} />
            <ConflictsCard />
          </div>
        </Tabs.Panel>
      </Tabs>
    </Page>
  );
}
