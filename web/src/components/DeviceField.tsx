import type { ReactNode } from "react";

/** A label with a value below it; an empty value shows a dash. */
export function Field({ label, value, mono }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="lp-muted" style={{ fontSize: "var(--lp-text-xs)", fontWeight: 500 }}>
        {label}
      </div>
      <div className={mono ? "lp-mono" : undefined} style={{ wordBreak: "break-word" }}>
        {value || "—"}
      </div>
    </div>
  );
}
