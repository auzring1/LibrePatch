import { useCallback, useMemo, useState } from "react";
import { usePreferences } from "../design/usePreferences";
import { useEffective } from "../settings/useEffective";

export interface NavLayout {
  /** Narrowed to an icon rail. */
  collapsed: boolean;
  /** Ids of folded groups and submenus. */
  closed: string[];
}

const KEY = "lp-nav";
const read = (): NavLayout & { chosen: boolean } => {
  try {
    const raw = window.localStorage.getItem(KEY);
    const v = JSON.parse(raw ?? "{}") as Partial<NavLayout>;
    return { collapsed: v.collapsed === true, closed: Array.isArray(v.closed) ? v.closed.filter((x) => typeof x === "string") : [], chosen: raw !== null };
  } catch {
    return { collapsed: false, closed: [], chosen: false };
  }
};
const write = (l: NavLayout) => {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(l));
  } catch {
    /* private mode: the account copy still works */
  }
};

/**
 * How the person arranged the sidebar. It is kept on their account (so it follows them to any device) and mirrored on
 * this device so the first paint is already right.
 */
export function useNavLayout() {
  const { prefs, ready, update } = usePreferences();
  const [local, setLocal] = useState(read);
  // Until the person has arranged the sidebar themselves, the organization's choice (Settings > Appearance) applies.
  const orgRail = useEffective().data?.appearance.sidebar_style === "rail";
  const layout = useMemo<NavLayout>(() => {
    if (ready && prefs?.nav) return { collapsed: prefs.nav.collapsed ?? false, closed: prefs.nav.closed ?? [] };
    return { collapsed: local.chosen ? local.collapsed : orgRail, closed: local.closed };
  }, [ready, prefs?.nav, local, orgRail]);

  const save = useCallback(
    (next: NavLayout) => {
      write(next);
      setLocal({ ...next, chosen: true });
      if (ready) update({ nav: next });
    },
    [ready, update],
  );
  const setCollapsed = useCallback((collapsed: boolean) => save({ ...layout, collapsed }), [layout, save]);
  const setOpen = useCallback((id: string, open: boolean) => save({ ...layout, closed: open ? layout.closed.filter((x) => x !== id) : [...new Set([...layout.closed, id])] }), [layout, save]);
  return { layout, setCollapsed, setOpen };
}
