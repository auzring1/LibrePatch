import { useEffect, useId } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../api/client";
import { useSession } from "../api/session";
import { useFeatures } from "../settings/features";
import * as I from "./icons";
import { locate, visibleNav, type NavItem } from "./nav";
import { useNavLayout } from "./useNavLayout";

interface Props {
  onNavigate?: () => void;
  id?: string;
  /** Icon rail: labels hidden (kept for screen readers), group headings not shown. */
  rail?: boolean;
}

/** The grouped, collapsible navigation. A column on wide screens, a drawer on narrow ones. */
export function SideNav({ onNavigate, id, rail = false }: Props) {
  const { can, canOrg } = useSession();
  const { layout, setOpen } = useNavLayout();
  const loc = useLocation();
  const uid = useId();
  const features = useFeatures();
  const groups = visibleNav({ can, canOrg, features });
  const here = locate(loc.pathname);
  const pending = useQuery({
    queryKey: ["devices", "pending-count"],
    queryFn: () => api<{ total: number }>("GET", "/devices?status=pending&limit=1"),
    enabled: can("devices:write"),
    refetchInterval: 120_000,
  });

  // Arriving at a page inside a folded group (a link, the command palette) unfolds it, so the highlighted entry is never
  // hidden.
  const hereGroup = here?.group.id;
  useEffect(() => {
    if (hereGroup && here?.group.label && layout.closed.includes(hereGroup)) setOpen(hereGroup, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loc.pathname]);

  const link = (l: NavItem) => {
    const count = l.id === "devices" ? (pending.data?.total ?? 0) : 0;
    return (
      <NavLink to={l.to} end={l.end} className="lp-nav__link" onClick={onNavigate} title={rail ? l.label : undefined} aria-describedby={count ? `${uid}-pending` : undefined}>
        <l.icon size={18} aria-hidden />
        <span className={rail ? "lp-visually-hidden" : "lp-nav__text"}>{l.label}</span>
        {count > 0 && !rail && (
          <span className="lp-nav__count" aria-hidden="true">
            {count}
          </span>
        )}
      </NavLink>
    );
  };

  return (
    <nav className="lp-nav-inner" aria-label="Main" id={id} data-rail={rail ? "true" : undefined}>
      {groups.map((g) => {
        const open = rail || !g.label || !layout.closed.includes(g.id);
        const listId = `${uid}-${g.id}`;
        return (
          <div className="lp-nav__group" key={g.id}>
            {g.label && !rail && (
              <button type="button" className="lp-nav__label" aria-expanded={open} aria-controls={listId} onClick={() => setOpen(g.id, !open)}>
                <span>{g.label}</span>
                <I.ChevronDown size={14} aria-hidden className="lp-nav__chev" data-open={open} />
              </button>
            )}
            <ul className="lp-nav__list" id={listId} hidden={!open} aria-label={g.label || undefined}>
              {g.items.map((l) => (
                <li key={l.id}>{link(l)}</li>
              ))}
            </ul>
          </div>
        );
      })}
      {(pending.data?.total ?? 0) > 0 && (
        <span id={`${uid}-pending`} className="lp-visually-hidden">
          {pending.data!.total} devices waiting for approval
        </span>
      )}
    </nav>
  );
}
