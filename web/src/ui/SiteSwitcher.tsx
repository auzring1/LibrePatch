import { Menu } from "@mantine/core";
import * as I from "./icons";
import { useSiteScope } from "./SiteScope";

/** The organization and site area of the top bar: lists the sites and narrows the dashboard and device list to one. */
export function SiteSwitcher() {
  const { sites, siteId, setSiteId } = useSiteScope();
  if (sites.length === 0) return null;
  const current = sites.find((s) => s.id === siteId);
  const label = current ? current.name : "All sites";
  return (
    <Menu position="bottom-start" width={260} shadow="md" withinPortal>
      <Menu.Target>
        <button type="button" className="lp-sitebtn" aria-label={`Site: ${label}. Change site`} data-testid="site-switcher">
          <I.Building size={16} aria-hidden />
          <span className="lp-sitebtn__label">{label}</span>
          <I.ChevronDown size={14} aria-hidden />
        </button>
      </Menu.Target>
      <Menu.Dropdown>
        <Menu.Label>Show data for</Menu.Label>
        <Menu.Item onClick={() => setSiteId("")} aria-current={siteId === "" ? "true" : undefined} rightSection={siteId === "" ? <I.Check size={16} aria-hidden /> : null}>
          All sites
        </Menu.Item>
        {sites.map((s) => (
          <Menu.Item key={s.id} onClick={() => setSiteId(s.id)} aria-current={siteId === s.id ? "true" : undefined} rightSection={siteId === s.id ? <I.Check size={16} aria-hidden /> : null}>
            {s.name}
          </Menu.Item>
        ))}
        <Menu.Divider />
        <Menu.Label>Narrows the dashboard and the device list.</Menu.Label>
      </Menu.Dropdown>
    </Menu>
  );
}
