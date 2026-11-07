import "./pageBits.css";
import type { ReactNode } from "react";
import { Search } from "./icons";

/** A button that looks like a table's primary link; use it where the action opens a drawer or dialog. */
export function LinkButton({ children, onClick, id }: { children: ReactNode; onClick: () => void; id?: string }) {
  return (
    <button type="button" id={id} className="lp-linkbtn" onClick={onClick}>
      {children}
    </button>
  );
}

/** Wraps a DataTable whose rows are searched on the server: the table's own search box is hidden in favour of `ServerSearch`. */
export function ServerSearchScope({ children }: { children: ReactNode }) {
  return <div className="lp-serversearch">{children}</div>;
}

/** A search box styled like the table's, for a query that is sent to the server. Put it in the DataTable `toolbar`. */
export function ServerSearch({ value, onChange, label, placeholder }: { value: string; onChange: (v: string) => void; label: string; placeholder?: string }) {
  return (
    <label className="lp-dt__searchbox lp-serversearch__box">
      <Search size={16} aria-hidden="true" />
      <input type="search" value={value} onChange={(e) => onChange(e.currentTarget.value)} placeholder={placeholder} aria-label={label} />
    </label>
  );
}

/** A definition list of label/value pairs. */
export function Fields({ items }: { items: { label: string; value: ReactNode }[] }) {
  return (
    <dl className="lp-fields">
      {items.map((i) => (
        <div key={i.label}>
          <dt>{i.label}</dt>
          <dd>{i.value || <span className="lp-muted">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}
