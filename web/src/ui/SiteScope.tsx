import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, type Site } from "../api/client";
import { useSession } from "../api/session";

interface Scope {
  /** Sites the person may look at (devices:read), by name. */
  sites: Site[];
  /** The chosen site id, or "" for all of them. */
  siteId: string;
  setSiteId: (id: string) => void;
}

const KEY = "lp-site";
const Ctx = createContext<Scope>({ sites: [], siteId: "", setSiteId: () => undefined });
export const useSiteScope = () => useContext(Ctx);

const read = () => {
  try {
    return window.localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
};

/**
 * The site switcher's state. With one site there is nothing to choose, but the control is still shown so the
 * console is ready for a second one. The choice narrows the dashboard and the device list; it is remembered on this device.
 */
export function SiteScopeProvider({ children }: { children: ReactNode }) {
  const { session, can } = useSession();
  const [chosen, setChosen] = useState(read);
  const q = useQuery({ queryKey: ["sites"], queryFn: () => api<{ items: Site[] }>("GET", "/sites"), enabled: !!session && can("devices:read"), staleTime: 5 * 60_000 });
  const sites = useMemo(() => {
    const all = q.data?.items ?? [];
    if (!session || session.permissions.includes("devices:read")) return all;
    const mine = Object.entries(session.site_permissions ?? {})
      .filter(([, perms]) => perms.includes("devices:read"))
      .map(([id]) => id);
    return all.filter((s) => mine.includes(s.id));
  }, [q.data, session]);
  const siteId = sites.some((s) => s.id === chosen) ? chosen : "";
  useEffect(() => {
    if (q.data && chosen && siteId === "") setChosen("");
  }, [q.data, chosen, siteId]);
  const setSiteId = useCallback((id: string) => {
    setChosen(id);
    try {
      if (id) window.localStorage.setItem(KEY, id);
      else window.localStorage.removeItem(KEY);
    } catch {
      /* private mode */
    }
  }, []);
  const value = useMemo(() => ({ sites, siteId, setSiteId }), [sites, siteId, setSiteId]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
