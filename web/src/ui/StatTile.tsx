import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { PillKind } from "./StatusPill";

interface TileProps {
  label: string;
  value: ReactNode;
  /** Colors the accent bar on the left. */
  kind?: PillKind | "accent";
  icon?: ReactNode;
  hint?: ReactNode;
  /** Makes the tile a link. */
  to?: string;
  /** Makes the tile a toggle button (for filtering a table). */
  onClick?: () => void;
  selected?: boolean;
}

/** A number with a label: the at-a-glance unit of the dashboards. */
export function StatTile({ label, value, kind, icon, hint, to, onClick, selected }: TileProps) {
  const cls = `lp-tile${kind ? ` lp-tile--${kind}` : ""}${selected ? " lp-tile--selected" : ""}`;
  const tip = typeof hint === "string" ? hint : undefined; // a compact tile hides its hint; this keeps it one hover away
  const body = (
    <>
      <span className="lp-tile__label">
        {icon}
        {label}
      </span>
      <span className="lp-tile__value">{value}</span>
      {hint && <span className="lp-tile__hint">{hint}</span>}
    </>
  );
  if (to) {
    return (
      <Link to={to} className={cls} title={tip}>
        {body}
      </Link>
    );
  }
  if (onClick) {
    return (
      <button type="button" className={cls} onClick={onClick} aria-pressed={selected ?? false} title={tip}>
        {body}
      </button>
    );
  }
  return (
    <div className={cls} title={tip}>
      {body}
    </div>
  );
}

/**
 * A row of tiles. `compact` is for pages whose main content is a table: each tile is one short line (label and number),
 * so the table is not pushed below the fold. The hint stays for screen readers and as a tooltip.
 */
export function StatGrid({ children, label, compact }: { children: ReactNode; label?: string; compact?: boolean }) {
  return (
    <div className={`lp-tiles${compact ? " lp-tiles--compact" : ""}`} role="group" aria-label={label}>
      {children}
    </div>
  );
}
