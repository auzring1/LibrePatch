import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { ChevronRight } from "./icons";
import { trail } from "./nav";

export interface Crumb {
  label: string;
  to?: string;
}

export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb">
      <ol className="lp-crumbs">
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={`${i}-${c.label}`}>
              {c.to && !last ? <Link to={c.to}>{c.label}</Link> : <span aria-current={last ? "page" : undefined}>{c.label}</span>}
              {!last && <ChevronRight size={14} aria-hidden="true" />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

interface HeaderProps {
  title: ReactNode;
  description?: ReactNode;
  /** Replaces the automatic trail (rarely needed). */
  breadcrumbs?: Crumb[];
  /** The name of this page below the section the navigation puts it in, e.g. a device's host name. */
  crumb?: string;
  actions?: ReactNode;
}

/** The page's single h1, with optional breadcrumbs, a description and page-level actions. */
export function PageHeader({ title, description, breadcrumbs, crumb, actions }: HeaderProps) {
  const { pathname } = useLocation();
  const auto = trail(pathname);
  const items = breadcrumbs ?? (crumb ? [...auto, { label: crumb }] : auto);
  return (
    <div>
      {items.length > 1 && <Breadcrumbs items={items} />}
      <div className="lp-pagehead">
        <div>
          <h1 className="lp-pagehead__title">{title}</h1>
          {description && <p className="lp-pagehead__desc">{description}</p>}
        </div>
        {actions && <div className="lp-pagehead__actions">{actions}</div>}
      </div>
    </div>
  );
}

/** The page column: consistent width and vertical rhythm. */
export function Page({ children }: { children: ReactNode }) {
  return <div className="lp-page">{children}</div>;
}
