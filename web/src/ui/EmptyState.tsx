import type { ReactNode } from "react";
import { Inbox } from "./icons";

export function EmptyState({ icon, title, description, actions }: { icon?: ReactNode; title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="lp-empty">
      <div className="lp-empty__icon" aria-hidden="true">
        {icon ?? <Inbox size={26} />}
      </div>
      <h3 className="lp-empty__title">{title}</h3>
      {description && <p className="lp-empty__desc">{description}</p>}
      {actions && <div className="lp-empty__actions">{actions}</div>}
    </div>
  );
}
